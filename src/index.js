// rp-id-doctor — validate a WebAuthn Relying Party's rpId / origin / related-origin
// configuration. Zero runtime dependencies. Node.js >= 18.

export { runDoctor } from "./doctor.js";
export { validateRpId, validateOrigin, checkRelationship, checkWellKnown, LINKS } from "./checks.js";
export { probeWellKnown, probeOrigins } from "./net.js";
export { isPublicSuffix, registrableDomain } from "./psl.js";
