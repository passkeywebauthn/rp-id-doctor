// Orchestrates the static checks (always) and the network probes (optional) into
// a single report.

import { validateRpId, validateOrigin, checkRelationship, checkWellKnown } from "./checks.js";
import { probeWellKnown, probeOrigins } from "./net.js";

/**
 * Run the full doctor.
 * @param {object} config
 * @param {string} config.rpId
 * @param {string[]} config.origins
 * @param {boolean} [config.network=false]  Perform network probes.
 * @param {object} [config.wellKnownDoc]    Pre-supplied .well-known doc (skips fetch).
 * @param {function} [config.fetchImpl]     Override fetch (for tests).
 * @returns {Promise<{ findings, summary, ok }>}
 */
export async function runDoctor(config) {
  const { rpId, origins = [], network = false, wellKnownDoc, fetchImpl } = config;
  const findings = [];

  findings.push(...validateRpId(rpId));

  const originUrls = [];
  for (const origin of origins) {
    const { findings: f, url } = validateOrigin(origin);
    findings.push(...f);
    if (url) originUrls.push(url);
  }

  // rpId <-> origin relationship (only meaningful once both parse).
  const rpFatal = findings.some((x) => x.level === "error" && x.code.startsWith("rpid-"));
  if (!rpFatal && rpId) {
    for (const url of originUrls) findings.push(...checkRelationship(rpId, url));
  }

  // Related Origin Requests document.
  let doc = wellKnownDoc ?? null;
  if (network && !wellKnownDoc && rpId && !rpFatal) {
    const { findings: f, doc: fetched } = await probeWellKnown(rpId, { fetchImpl });
    findings.push(...f);
    doc = fetched;
  }
  if (doc != null) findings.push(...checkWellKnown(doc, origins));

  // TLS reachability.
  if (network) {
    findings.push(...await probeOrigins(origins, { fetchImpl }));
  }

  const summary = { error: 0, warn: 0, ok: 0, info: 0 };
  for (const f of findings) summary[f.level] = (summary[f.level] || 0) + 1;

  return { findings, summary, ok: summary.error === 0 };
}
