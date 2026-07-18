// Optional network probes. Everything here is best-effort and fully skippable:
// in an offline CI runner the doctor still performs all static checks.

import { finding, LINKS } from "./checks.js";

async function withTimeout(promise, ms, onTimeout) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try {
    return await promise(ac.signal);
  } finally {
    clearTimeout(t);
  }
}

/**
 * Fetch and parse https://<rpId>/.well-known/webauthn.
 * @returns {{ findings, doc: object|null }}
 */
export async function probeWellKnown(rpId, { timeoutMs = 5000, fetchImpl = fetch } = {}) {
  const url = `https://${rpId}/.well-known/webauthn`;
  const out = [];
  try {
    const res = await withTimeout((signal) => fetchImpl(url, { signal, redirect: "follow" }), timeoutMs);
    if (res.status === 404) {
      out.push(finding("info", "wk-absent", "No .well-known/webauthn published",
        `${url} returned 404. That is fine unless you rely on Related Origin Requests to share passkeys across domains.`, { url: LINKS.crossDevice }));
      return { findings: out, doc: null };
    }
    if (!res.ok) {
      out.push(finding("warn", "wk-status", ".well-known/webauthn did not return 200", `${url} returned HTTP ${res.status}.`, { url: LINKS.crossDevice }));
      return { findings: out, doc: null };
    }
    const text = await res.text();
    try {
      return { findings: out, doc: JSON.parse(text) };
    } catch {
      out.push(finding("error", "wk-json", ".well-known/webauthn is not valid JSON", `${url} returned a non-JSON body.`, { url: LINKS.crossDevice }));
      return { findings: out, doc: null };
    }
  } catch (err) {
    out.push(finding("info", "wk-unreachable", "Could not reach .well-known/webauthn",
      `${url}: ${err && err.message ? err.message : "request failed"}. Skipping related-origin checks (offline or blocked).`));
    return { findings: out, doc: null };
  }
}

/** Confirm each origin is reachable over TLS (a failed TLS handshake surfaces here). */
export async function probeOrigins(origins, { timeoutMs = 5000, fetchImpl = fetch } = {}) {
  const out = [];
  for (const origin of origins) {
    let base;
    try { base = new URL(origin).origin; } catch { continue; }
    if (new URL(base).protocol !== "https:") continue; // localhost/http handled statically
    try {
      const res = await withTimeout((signal) => fetchImpl(base + "/", { signal, redirect: "manual" }), timeoutMs);
      out.push(finding("ok", "tls-ok", "Origin reachable over TLS", `${base} responded (HTTP ${res.status}).`));
    } catch (err) {
      const msg = err && err.message ? err.message : "request failed";
      const level = /certificate|self-signed|altname|SSL|TLS/i.test(msg) ? "error" : "info";
      out.push(finding(level, "tls-fail", "Could not complete TLS request to origin", `${base}: ${msg}`));
    }
  }
  return out;
}
