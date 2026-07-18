// A curated (deliberately partial) public-suffix helper.
//
// Determining a "registrable domain" precisely needs the full Public Suffix
// List, which is large and changes often. rp-id-doctor only needs to answer one
// question for WebAuthn: "is this rpId a bare public suffix (and therefore never
// a valid RP ID), or does it have at least one registrable label?" A curated set
// of common multi-label suffixes plus the rule "any single label is a TLD"
// answers that for the domains teams actually ship on. Unusual suffixes degrade
// to a warning rather than a false negative.

// Well-known multi-label public suffixes (not exhaustive — extend as needed).
export const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
  "co.nz", "net.nz", "org.nz", "govt.nz",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
  "com.br", "net.br", "org.br", "gov.br",
  "co.in", "net.in", "org.in", "gen.in", "firm.in",
  "com.cn", "net.cn", "org.cn", "gov.cn",
  "co.za", "org.za", "web.za",
  "com.mx", "com.ar", "com.sg", "com.hk", "com.tr", "com.tw", "com.ua",
  "co.kr", "or.kr",
  "com.pl", "net.pl", "org.pl",
  "co.il", "org.il",
  // Popular hosting suffixes where each subdomain is a separate site.
  "github.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app",
  "herokuapp.com", "web.app", "firebaseapp.com", "azurestaticapps.net",
]);

function normalize(host) {
  return String(host).trim().toLowerCase().replace(/\.$/, "");
}

/** True if `host` is itself a public suffix (a bare TLD or a listed multi-label suffix). */
export function isPublicSuffix(host) {
  const h = normalize(host);
  if (!h) return false;
  if (!h.includes(".")) return true; // a single label is a TLD, e.g. "com", "dev"
  return MULTI_LABEL_SUFFIXES.has(h);
}

/**
 * Return the registrable domain (eTLD+1) for a host, or null if `host` is a bare
 * public suffix. Uses the curated suffix set; unknown multi-part suffixes fall
 * back to the last two labels.
 */
export function registrableDomain(host) {
  const h = normalize(host);
  if (!h || isPublicSuffix(h)) return null;
  const labels = h.split(".");
  // Find the longest trailing run of labels that is a public suffix, then take
  // one more label to the left. Iterating from the front yields the longest match.
  for (let i = 0; i < labels.length; i++) {
    const candidate = labels.slice(i).join(".");
    if (isPublicSuffix(candidate)) {
      return i === 0 ? null : labels.slice(i - 1).join(".");
    }
  }
  // No known suffix matched: assume a two-label registrable domain.
  return labels.slice(-2).join(".");
}
