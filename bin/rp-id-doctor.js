#!/usr/bin/env node
// rp-id-doctor CLI — diagnose WebAuthn Relying Party configuration.

import { runDoctor } from "../src/index.js";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const pkg = require("../package.json");

const HELP = `rp-id-doctor — diagnose WebAuthn Relying Party (rpId / origin) configuration

USAGE
  rp-id-doctor --rp-id <domain> --origin <url> [--origin <url> ...] [options]

OPTIONS
  --rp-id <domain>    The Relying Party ID, e.g. example.com (required)
  --origin <url>      An expected origin, e.g. https://login.example.com (repeatable, required)
  --no-network        Skip all network probes (.well-known fetch, TLS reachability)
  --strict            Treat warnings as failures (exit non-zero)
  --json              Emit findings as JSON (for CI)
  --quiet             Only print warnings and errors (hide ok/info)
  --no-color          Disable ANSI color
  -h, --help          Show this help
  -v, --version       Show version

EXIT CODES
  0  no errors (warnings allowed unless --strict)
  1  configuration errors found
  2  usage error

EXAMPLES
  rp-id-doctor --rp-id example.com --origin https://login.example.com
  rp-id-doctor --rp-id example.com --origin https://app.example.com --strict --json
  rp-id-doctor --rp-id localhost --origin http://localhost:3000 --no-network

More on rpId, origins and Related Origin Requests: https://www.passkeywebauthn.com
`;

function parseArgs(argv) {
  const opts = { origins: [], network: true, color: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") opts.help = true;
    else if (a === "-v" || a === "--version") opts.version = true;
    else if (a === "--rp-id") opts.rpId = argv[++i];
    else if (a === "--origin") opts.origins.push(argv[++i]);
    else if (a === "--no-network" || a === "--offline") opts.network = false;
    else if (a === "--strict") opts.strict = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--quiet") opts.quiet = true;
    else if (a === "--no-color") opts.color = false;
    else { process.stderr.write(`error: unknown option "${a}"\n`); process.exit(2); }
  }
  return opts;
}

const ICON = { error: "✖", warn: "▲", ok: "✔", info: "•" };
const COLOR = { error: 31, warn: 33, ok: 32, info: 36 };
const ESC = String.fromCharCode(27);

function paint(level, text, useColor) {
  if (!useColor) return text;
  return `${ESC}[${COLOR[level]}m${text}${ESC}[0m`;
}

function render(report, opts) {
  const useColor = opts.color && process.stdout.isTTY;
  const order = { error: 0, warn: 1, ok: 2, info: 3 };
  const lines = [];
  const shown = report.findings
    .filter((f) => !(opts.quiet && (f.level === "ok" || f.level === "info")))
    .sort((a, b) => order[a.level] - order[b.level]);

  for (const f of shown) {
    lines.push(`${paint(f.level, ICON[f.level], useColor)} ${paint(f.level, f.title, useColor)}`);
    if (f.detail) lines.push(`    ${f.detail}`);
    if (f.hint) lines.push(`    ${paint("info", "hint:", useColor)} ${f.hint}`);
    if (f.url) lines.push(`    ${paint("info", "docs:", useColor)} ${f.url}`);
  }
  const s = report.summary;
  lines.push("");
  lines.push(`${s.error || 0} error(s), ${s.warn || 0} warning(s), ${s.ok || 0} ok, ${s.info || 0} info`);
  return lines.join("\n");
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.version) { process.stdout.write(pkg.version + "\n"); return; }
  if (opts.help) { process.stdout.write(HELP); return; }
  if (!opts.rpId || opts.origins.length === 0) {
    process.stderr.write("error: --rp-id and at least one --origin are required\n\n" + HELP);
    process.exit(2);
  }

  const report = await runDoctor({ rpId: opts.rpId, origins: opts.origins, network: opts.network });

  if (opts.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  } else {
    process.stdout.write(render(report, opts) + "\n");
  }

  const failed = report.summary.error > 0 || (opts.strict && report.summary.warn > 0);
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`rp-id-doctor: ${err && err.stack ? err.stack : err}\n`);
  process.exit(2);
});
