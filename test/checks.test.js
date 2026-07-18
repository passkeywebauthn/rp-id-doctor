import test from "node:test";
import assert from "node:assert/strict";
import { validateRpId, validateOrigin, checkRelationship, checkWellKnown } from "../src/checks.js";
import { isPublicSuffix, registrableDomain } from "../src/psl.js";

const codes = (findings) => findings.map((f) => f.code);
const has = (findings, code) => findings.some((f) => f.code === code);

test("validateRpId accepts a normal domain", () => {
  assert.ok(has(validateRpId("example.com"), "rpid-ok"));
});

test("validateRpId rejects a URL passed as rpId", () => {
  const f = validateRpId("https://example.com");
  assert.ok(has(f, "rpid-has-scheme"));
  assert.equal(f[0].level, "error");
});

test("validateRpId rejects a port and a path", () => {
  assert.ok(has(validateRpId("example.com:443"), "rpid-has-port"));
  assert.ok(has(validateRpId("example.com/login"), "rpid-has-path"));
});

test("validateRpId rejects public suffixes and IPs", () => {
  assert.ok(has(validateRpId("com"), "rpid-public-suffix"));
  assert.ok(has(validateRpId("co.uk"), "rpid-public-suffix"));
  assert.ok(has(validateRpId("192.168.1.10"), "rpid-is-ip"));
});

test("validateOrigin flags http on non-localhost", () => {
  const { findings } = validateOrigin("http://example.com");
  assert.ok(has(findings, "origin-insecure"));
});

test("validateOrigin allows http on localhost and flags paths", () => {
  assert.ok(has(validateOrigin("http://localhost:3000").findings, "origin-http-localhost"));
  assert.ok(has(validateOrigin("https://example.com/login").findings, "origin-has-extra"));
});

test("relationship: exact and subdomain pass, sibling fails", () => {
  assert.ok(has(checkRelationship("example.com", new URL("https://example.com")), "rel-exact"));
  assert.ok(has(checkRelationship("example.com", new URL("https://login.example.com")), "rel-subdomain"));
  const bad = checkRelationship("example.com", new URL("https://example.org"));
  assert.ok(has(bad, "rel-mismatch"));
  assert.equal(bad[0].level, "error");
});

test("relationship: localhost rpId vs prod origin is the classic bug", () => {
  const f = checkRelationship("localhost", new URL("https://app.example.com"));
  assert.ok(has(f, "rel-localhost-vs-prod"));
});

test("well-known: valid doc, and missing configured origin is warned", () => {
  const doc = { origins: ["https://example.com", "https://example.co.uk"] };
  const f = checkWellKnown(doc, ["https://elsewhere.com"]);
  assert.ok(has(f, "wk-found"));
  assert.ok(has(f, "wk-missing-origin"));
});

test("well-known: malformed doc is an error", () => {
  assert.ok(has(checkWellKnown({ nope: true }, []), "wk-shape"));
});

test("psl helpers", () => {
  assert.equal(isPublicSuffix("com"), true);
  assert.equal(isPublicSuffix("co.uk"), true);
  assert.equal(isPublicSuffix("example.com"), false);
  assert.equal(registrableDomain("login.example.com"), "example.com");
  assert.equal(registrableDomain("foo.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("com"), null);
});
