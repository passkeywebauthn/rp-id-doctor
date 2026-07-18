# rp-id-doctor

> A pre-flight check for your WebAuthn Relying Party configuration — catch the classic "passkey works on localhost but not in production" bugs before you ship.

Most passkey outages are not cryptographic. They are a misconfigured `rpId`, an origin that doesn't match, an `http://` slip, or a missing `.well-known/webauthn` file — and they only show up as a `SecurityError` in a browser you weren't testing. `rp-id-doctor` validates all of that from the command line or from CI, and explains each problem in plain language with a fix.

It has **no runtime dependencies** and works on Node.js ≥ 18. Static checks run fully offline; optional network probes add live checks when you want them.

Built and maintained by the team behind [passkeywebauthn.com — the Passkey & WebAuthn Engineering Hub](https://www.passkeywebauthn.com).

---

## What it checks

- **rpId shape** — rejects an `rpId` that carries a scheme, port, or path (passing an origin as the `rpId` is the number-one cause of `SecurityError`), an IP address, or a bare public suffix like `com` / `co.uk`.
- **rpId ↔ origin relationship** — confirms every origin's host is equal to, or a subdomain of, the `rpId`. This is the check that catches the [localhost-vs-production](https://www.passkeywebauthn.com/webauthn-fido2-protocol-fundamentals/relying-party-and-authenticator-roles/) mistake.
- **Origin security context** — flags non-HTTPS origins (with a localhost exemption) and origins that include a path/query/fragment.
- **Related Origin Requests** — fetches `.well-known/webauthn`, validates its shape, and warns when a configured origin is missing or when you exceed the browser's 5-label limit. See [hybrid transport and cross-device passkeys](https://www.passkeywebauthn.com/webauthn-fido2-protocol-fundamentals/platform-vs-roaming-authenticator-trade-offs/hybrid-transport-and-cross-device-passkeys/).
- **TLS reachability** — confirms each origin actually completes a TLS request.

## Install & run

```sh
# Run without installing
npx rp-id-doctor --rp-id example.com --origin https://login.example.com

# Or install it
npm install --save-dev rp-id-doctor
```

```sh
rp-id-doctor --rp-id example.com \
  --origin https://example.com \
  --origin https://login.example.com
```

Example output for a broken setup:

```text
✖ rpId is not a registrable suffix of the origin
    Origin "https://example.org" (host example.org) is not equal to, nor a subdomain of, rpId "example.com". The browser will throw SecurityError.
    hint: For this origin the rpId must be "example.org" or a parent domain.
    docs: https://www.passkeywebauthn.com/webauthn-fido2-protocol-fundamentals/debugging-and-observability/resolving-webauthn-securityerror/

1 error(s), 0 warning(s), 1 ok, 0 info
```

### Options

| Flag | Purpose |
|------|---------|
| `--rp-id <domain>` | The Relying Party ID (required). |
| `--origin <url>` | An expected origin. Repeatable; at least one required. |
| `--no-network` | Skip the `.well-known` fetch and TLS probes (fully offline). |
| `--strict` | Treat warnings as failures. |
| `--json` | Emit findings as JSON for machine consumption. |
| `--quiet` | Hide `ok`/`info`, show only warnings and errors. |
| `--no-color` | Disable ANSI color. |

Exit codes: `0` = no errors, `1` = errors found (or warnings under `--strict`), `2` = usage error.

## Use it in CI (GitHub Action)

A composite action ships in this repo. Gate a deploy on a healthy configuration:

```yaml
- uses: actions/setup-node@v4
  with:
    node-version: "20"
- uses: passkeywebauthn/rp-id-doctor@v1
  with:
    rp-id: example.com
    origins: |
      https://example.com
      https://login.example.com
    strict: "true"
```

See [`.github/workflows/example.yml`](.github/workflows/example.yml) for a full workflow.

## Use it as a library

```js
import { runDoctor } from "rp-id-doctor";

const report = await runDoctor({
  rpId: "example.com",
  origins: ["https://example.com", "https://login.example.com"],
  network: false,
});

if (!report.ok) {
  for (const f of report.findings.filter((x) => x.level === "error")) {
    console.error(f.title, "—", f.detail);
  }
}
```

Every finding is `{ level, code, title, detail, hint?, url? }`, so you can route them into your own reporter. Individual check functions (`validateRpId`, `validateOrigin`, `checkRelationship`, `checkWellKnown`) are exported too.

## A note on the public suffix list

Deciding whether an `rpId` is a bare registry suffix needs the Public Suffix List, which is large and changes often. `rp-id-doctor` ships a **curated subset** covering the domains teams actually ship on. If your suffix isn't recognized, the tool degrades to a conservative warning rather than a false alarm — open an issue or PR to extend the list.

## Development

```sh
git clone https://github.com/passkeywebauthn/rp-id-doctor.git
cd rp-id-doctor
npm test
```

Tests use Node's built-in `node:test` runner and stub the network, so they are hermetic and fast.

## License

MIT © passkeywebauthn

---

Learn more about relying-party configuration, origins, and cross-device passkeys at [passkeywebauthn.com](https://www.passkeywebauthn.com).

## Related tools

Part of a small set of open-source WebAuthn tools:

- [passkey-inspect](https://github.com/passkeywebauthn/passkey-inspect) — decode WebAuthn payloads (attestationObject, authenticatorData, COSE keys) from the CLI or as a library.
- [webauthn-ceremony-inspector](https://github.com/passkeywebauthn/webauthn-ceremony-inspector) — a browser DevTools panel that captures and decodes live WebAuthn ceremonies.
- [passkey-fixture-generator](https://github.com/passkeywebauthn/passkey-fixture-generator) — deterministic, valid registration/authentication test fixtures for backend verification.
- [authenticator-support-matrix](https://github.com/passkeywebauthn/authenticator-support-matrix) — a filterable feature matrix of platform and roaming authenticators.
- [passkey-fallback-flow-kit](https://github.com/passkeywebauthn/passkey-fallback-flow-kit) — framework-agnostic UI building blocks for passkey fallback UX.
