// Pure (network-free) WebAuthn Relying Party configuration checks.
// Every function returns an array of findings: { level, code, title, detail, hint?, url? }.

import { isPublicSuffix, registrableDomain } from "./psl.js";

const DOCS = "https://www.passkeywebauthn.com";
export const LINKS = {
  rpId: `${DOCS}/webauthn-fido2-protocol-fundamentals/relying-party-and-authenticator-roles/`,
  boundaries: `${DOCS}/webauthn-fido2-protocol-fundamentals/relying-party-and-authenticator-roles/webauthn-security-boundaries-for-enterprise-apps/`,
  securityError: `${DOCS}/webauthn-fido2-protocol-fundamentals/debugging-and-observability/resolving-webauthn-securityerror/`,
  crossDevice: `${DOCS}/webauthn-fido2-protocol-fundamentals/platform-vs-roaming-authenticator-trade-offs/hybrid-transport-and-cross-device-passkeys/`,
};

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|:/; // dotted IPv4 or any colon (IPv6)

export function finding(level, code, title, detail, extra = {}) {
  return { level, code, title, detail, ...extra };
}

function normalizeHost(host) {
  return String(host).trim().toLowerCase().replace(/\.$/, "");
}

/** Validate the shape of an rpId. rpId is a bare domain — no scheme, port, or path. */
export function validateRpId(rpId) {
  const out = [];
  if (!rpId) {
    return [finding("error", "rpid-missing", "No rpId provided", "An rpId (e.g. example.com) is required.", { url: LINKS.rpId })];
  }
  const raw = String(rpId).trim();

  if (/^[a-z]+:\/\//i.test(raw)) {
    out.push(finding("error", "rpid-has-scheme", "rpId must not include a scheme",
      `Got "${raw}". The rpId is a bare domain like "example.com", not a URL. Passing an origin here is the single most common cause of SecurityError.`,
      { hint: 'Use "example.com", not "https://example.com".', url: LINKS.securityError }));
    return out;
  }
  if (raw.includes("/")) {
    out.push(finding("error", "rpid-has-path", "rpId must not include a path", `Got "${raw}". Strip everything after the host.`, { url: LINKS.rpId }));
    return out;
  }
  if (raw.includes(":")) {
    out.push(finding("error", "rpid-has-port", "rpId must not include a port", `Got "${raw}". The port belongs on the origin, not the rpId.`, { url: LINKS.rpId }));
  }
  const host = normalizeHost(raw.replace(/:.*/, ""));
  if (raw !== raw.toLowerCase()) {
    out.push(finding("warn", "rpid-not-lowercase", "rpId should be lowercase", `"${raw}" will be compared case-sensitively against a lowercased effective domain.`));
  }
  if (IP_RE.test(host)) {
    out.push(finding("error", "rpid-is-ip", "rpId cannot be an IP address", `"${host}" is an IP. WebAuthn rpIds must be domains; only "localhost" works without one.`, { url: LINKS.rpId }));
  } else if (host === "localhost") {
    out.push(finding("info", "rpid-localhost", "rpId is localhost", "Fine for local development, but passkeys registered here will not exist on your production domain.", { url: LINKS.rpId }));
  } else if (isPublicSuffix(host)) {
    out.push(finding("error", "rpid-public-suffix", "rpId is a public suffix", `"${host}" is a registry suffix (like "com" or "co.uk"), not a registrable domain. Browsers reject it.`, { url: LINKS.rpId }));
  } else if (!host.includes(".")) {
    out.push(finding("error", "rpid-single-label", "rpId is a single label", `"${host}" has no dot. Use a real domain such as example.com.`, { url: LINKS.rpId }));
  } else {
    out.push(finding("ok", "rpid-ok", "rpId is a well-formed domain", `"${host}" is a valid registrable domain.`));
  }
  return out;
}

/** Parse and validate one origin string. Returns { findings, url } (url is a WHATWG URL or null). */
export function validateOrigin(origin) {
  const out = [];
  let url = null;
  try {
    url = new URL(origin);
  } catch {
    out.push(finding("error", "origin-unparseable", "Origin is not a valid URL", `Could not parse "${origin}". Expected e.g. https://login.example.com.`, { url: LINKS.securityError }));
    return { findings: out, url: null };
  }
  const host = normalizeHost(url.hostname);
  const isLocal = host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";

  if (url.protocol === "http:") {
    if (isLocal) {
      out.push(finding("info", "origin-http-localhost", "http:// on localhost", "Allowed as a WebAuthn secure context for local development only.", { url: LINKS.securityError }));
    } else {
      out.push(finding("error", "origin-insecure", "Origin is not HTTPS", `"${origin}" uses http://. WebAuthn requires a secure context (HTTPS or localhost).`, { url: LINKS.securityError }));
    }
  } else if (url.protocol !== "https:") {
    out.push(finding("error", "origin-bad-scheme", "Unexpected origin scheme", `"${url.protocol}" is not http/https.`, { url: LINKS.securityError }));
  }
  if ((url.pathname && url.pathname !== "/") || url.search || url.hash) {
    out.push(finding("warn", "origin-has-extra", "Origin should be scheme + host (+ port) only",
      `"${origin}" includes a path/query/fragment. The expected origin your server compares against is just the origin, e.g. ${url.protocol}//${url.host}.`));
  }
  return { findings: out, url };
}

/** Check that rpId is a valid registrable suffix of a single origin's host. */
export function checkRelationship(rpId, originUrl) {
  const out = [];
  const rp = normalizeHost(rpId);
  const host = normalizeHost(originUrl.hostname);

  if (host === rp) {
    out.push(finding("ok", "rel-exact", "Origin host matches rpId", `${host} === ${rp}.`));
    return out;
  }
  if (host.endsWith("." + rp)) {
    out.push(finding("ok", "rel-subdomain", "Origin is a subdomain of rpId", `${host} is covered by rpId ${rp}.`));
    return out;
  }
  // Mismatch — try to explain why.
  const rd = registrableDomain(host);
  if (rp === "localhost" && !["localhost", "127.0.0.1"].includes(host)) {
    out.push(finding("error", "rel-localhost-vs-prod", "rpId is localhost but origin is not",
      `rpId "localhost" cannot cover origin "${originUrl.origin}". This is the classic "works locally, breaks in production" setup — the rpId must change per environment.`, { hint: `Set rpId to ${rd ?? "your production domain"} in production.`, url: LINKS.securityError }));
  } else {
    out.push(finding("error", "rel-mismatch", "rpId is not a registrable suffix of the origin",
      `Origin "${originUrl.origin}" (host ${host}) is not equal to, nor a subdomain of, rpId "${rp}". The browser will throw SecurityError.`,
      { hint: rd ? `For this origin the rpId must be "${host}" or a parent domain like "${rd}".` : undefined, url: LINKS.securityError }));
  }
  return out;
}

/**
 * Validate a parsed .well-known/webauthn document for Related Origin Requests.
 * @param {object|null} doc  Parsed JSON (or null if unavailable).
 * @param {string[]} origins The origins you expect it to authorize.
 */
export function checkWellKnown(doc, origins = []) {
  const out = [];
  if (doc == null) return out;
  if (typeof doc !== "object" || !Array.isArray(doc.origins)) {
    out.push(finding("error", "wk-shape", ".well-known/webauthn is malformed", 'Expected a JSON object with an "origins" array.', { url: LINKS.crossDevice }));
    return out;
  }
  const listed = doc.origins.map((o) => String(o));
  out.push(finding("ok", "wk-found", "Related-origin document parsed", `Lists ${listed.length} origin(s).`, { url: LINKS.crossDevice }));

  const labels = new Set();
  for (const o of listed) {
    try {
      const u = new URL(o);
      if (u.protocol !== "https:") out.push(finding("warn", "wk-insecure", "Related origin is not HTTPS", `"${o}" should be https://.`));
      const rd = registrableDomain(u.hostname);
      if (rd) labels.add(rd.split(".")[0]);
    } catch {
      out.push(finding("error", "wk-bad-origin", "Related origin is not a valid origin", `"${o}" could not be parsed.`));
    }
  }
  // Browsers process at most 5 distinct eTLD+1 labels from the list.
  if (labels.size > 5) {
    out.push(finding("warn", "wk-label-limit", "More than 5 distinct labels in related origins",
      `Found ${labels.size} distinct registrable labels. Browsers only honor the first 5 during Related Origin Requests; the rest are ignored.`, { url: LINKS.crossDevice }));
  }
  // Are the origins you care about actually authorized?
  for (const want of origins) {
    let wantOrigin;
    try { wantOrigin = new URL(want).origin; } catch { continue; }
    if (!listed.some((o) => { try { return new URL(o).origin === wantOrigin; } catch { return false; } })) {
      out.push(finding("warn", "wk-missing-origin", "Configured origin not in related-origins list",
        `"${wantOrigin}" is one of your origins but is not listed in .well-known/webauthn. Cross-origin passkey use from it will be rejected.`, { url: LINKS.crossDevice }));
    }
  }
  return out;
}
