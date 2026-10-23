# Security notes

## Threat model

The app runs as the current user, reads text you point at, and sends **one outbound request per detection** to a host you have allowlisted. Inputs are untrusted (any text on screen may contain a hostile URL) and so are responses (the server, or a network attacker if TLS is disabled).

## Controls

| Risk | Control |
|---|---|
| Probing arbitrary hosts / SSRF | Strict allowlist; exact or `*.` suffix match on the IDNA-normalised host; IP-literal hosts, embedded credentials, non-http(s) schemes and unlisted ports rejected before any DNS lookup |
| Lookalike hosts | `example.com.evil.test`, `evilexample.com`, `user@evil` forms are covered by tests |
| Redirect abuse | Redirects are followed manually; each hop is re-validated against the allowlist, http downgrade needs the explicit opt-in, hop count capped |
| DNS rebinding / internal pivot | One resolution per hop; loopback, RFC 1918, link-local, multicast, reserved and IPv4-mapped equivalents refused unless opted in; connection pinned to the vetted IP while SNI and certificate name use the real host |
| MITM | TLS ≥ 1.2, certificate and hostname verification on; Windows trust store via `truststore`; disabling needs a confirmation dialog |
| Resource exhaustion | Connect/read/total timeouts, streaming body cap (default 256 KiB), `Accept-Encoding: identity` (no decompression bombs), result cache |
| Secret leakage | Original path/query never sent (probe path replaces it); no cookies, Authorization or proxy settings; Cookie/Authorization/Host cannot be added as extra headers; history keeps host only; logs contain host and status, not URLs |
| Config tampering | Config is plain JSON in the user profile; validated on load and save; atomic writes |
| Clipboard side effects | Selection copy is skipped for console programs and for non-text clipboard contents; text clipboard restored |

## Operational advice

- The probe path should be one that your WAF policy answers with its block page. Tell your SOC about the tool's User-Agent and probe path so the probes are not mistaken for attacks.
- Keep the repository free of internal hostnames and real response bodies. `.gitignore` excludes `config.json`, logs and history. Use `config.example.json` placeholders in documentation and tests (`*.test` names are reserved and never resolve on the public internet).
- Review extra CA bundles before adding them; they extend what the app trusts.
- Sign release binaries and publish the SHA-256 from the release workflow.

## Not covered

- Regular-expression denial of service from deliberately pathological rules in a config you import.
- A compromised workstation (the app cannot defend against code already running as the user).

## Reporting

Open a private security advisory on the repository rather than a public issue.
