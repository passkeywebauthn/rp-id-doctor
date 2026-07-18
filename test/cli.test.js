import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const BIN = fileURLToPath(new URL("../bin/rp-id-doctor.js", import.meta.url));

function run(args) {
  try {
    const stdout = execFileSync("node", [BIN, ...args], { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
    return { code: 0, stdout };
  } catch (e) {
    return { code: e.status, stdout: e.stdout?.toString() ?? "" };
  }
}

test("exit 0 on a healthy config", () => {
  const { code } = run(["--rp-id", "example.com", "--origin", "https://login.example.com", "--no-network"]);
  assert.equal(code, 0);
});

test("exit 1 on a mismatched origin", () => {
  const { code, stdout } = run(["--rp-id", "example.com", "--origin", "https://evil.org", "--no-network", "--json"]);
  assert.equal(code, 1);
  const report = JSON.parse(stdout);
  assert.equal(report.ok, false);
});

test("exit 2 when required flags are missing", () => {
  const { code } = run(["--rp-id", "example.com", "--no-network"]);
  assert.equal(code, 2);
});

test("--strict turns a warning into a failure", () => {
  // A path on the origin only produces a warning; strict should fail it.
  const relaxed = run(["--rp-id", "example.com", "--origin", "https://example.com/app", "--no-network"]);
  const strict = run(["--rp-id", "example.com", "--origin", "https://example.com/app", "--no-network", "--strict"]);
  assert.equal(relaxed.code, 0);
  assert.equal(strict.code, 1);
});
