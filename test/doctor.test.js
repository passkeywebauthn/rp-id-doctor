import test from "node:test";
import assert from "node:assert/strict";
import { runDoctor } from "../src/doctor.js";

// A fetch stub so these tests never touch the network.
function stubFetch(routes) {
  return async (url) => {
    const key = Object.keys(routes).find((k) => url.startsWith(k));
    if (!key) throw new Error("ENOTFOUND (stub)");
    const r = routes[key];
    return {
      ok: r.status >= 200 && r.status < 300,
      status: r.status,
      text: async () => r.body ?? "",
    };
  };
}

test("healthy config: no errors", async () => {
  const report = await runDoctor({
    rpId: "example.com",
    origins: ["https://example.com", "https://login.example.com"],
    network: false,
  });
  assert.equal(report.ok, true);
  assert.equal(report.summary.error, 0);
});

test("mismatched origin produces an error and ok=false", async () => {
  const report = await runDoctor({
    rpId: "example.com",
    origins: ["https://example.org"],
    network: false,
  });
  assert.equal(report.ok, false);
  assert.ok(report.findings.some((f) => f.code === "rel-mismatch"));
});

test("network probe: .well-known fetched and validated via stub", async () => {
  const fetchImpl = stubFetch({
    "https://example.com/.well-known/webauthn": {
      status: 200,
      body: JSON.stringify({ origins: ["https://example.com", "https://brand.io"] }),
    },
  });
  const report = await runDoctor({
    rpId: "example.com",
    origins: ["https://example.com"],
    network: true,
    fetchImpl,
  });
  assert.ok(report.findings.some((f) => f.code === "wk-found"));
});

test("network probe: 404 well-known is informational, not an error", async () => {
  const fetchImpl = stubFetch({
    "https://example.com/.well-known/webauthn": { status: 404 },
  });
  const report = await runDoctor({ rpId: "example.com", origins: ["https://example.com"], network: true, fetchImpl });
  assert.equal(report.ok, true);
  assert.ok(report.findings.some((f) => f.code === "wk-absent"));
});

test("pre-supplied wellKnownDoc skips fetch entirely", async () => {
  const report = await runDoctor({
    rpId: "example.com",
    origins: ["https://example.com"],
    network: false,
    wellKnownDoc: { origins: ["https://other.com"] },
  });
  assert.ok(report.findings.some((f) => f.code === "wk-missing-origin"));
});
