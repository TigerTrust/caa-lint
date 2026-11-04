# caa-lint

Lint CAA DNS records for a domain. Fail CI when CAA is missing or when the CAs you expect aren't authorized.

> Built by [TigerTrust](https://tigertrust.io). Apache-2.0.

## Why

CAA (RFC 8659) is a DNS-level circuit breaker against mis-issuance: it tells
public CAs which issuers you have authorized. A missing or over-permissive
CAA record is a common cause of real-world mis-issuance incidents.

This tool climbs the label tree (RFC 8659 §3) to find CAA, parses the
`issue` / `issuewild` / `iodef` / `issuemail` tags, and flags common
problems — missing records, `issue ";"` deny-all, wildcard gap, and
unauthorized expected issuers.

## Install

```sh
go install github.com/tigertrust/caa-lint/cmd/caa-lint@latest
```

## Quick start

### Check a single domain

```sh
caa-lint --domain example.com
```

```
Domain:    example.com
FoundAt:   example.com
  0 issue "letsencrypt.org"
  0 iodef "mailto:security@example.com"
Policy:    wildcard gap — `issue` present but no `issuewild`
```

### CI gate — require specific CAs to be authorized

```sh
caa-lint --domain example.com \
  --expect-issue letsencrypt.org \
  --expect-issue sectigo.com
```

### Fail when no CAA exists anywhere up the tree

```sh
caa-lint --domain example.com --fail-on-missing
```

### Suggest zone records (BIND + Route53 UPSERT)

```sh
caa-lint --domain example.com --suggest \
  --expect-issue letsencrypt.org \
  --iodef mailto:security@example.com
```

### JSON output

```sh
caa-lint --domains-file list.txt --json | jq '.[] | select(.missingCAA)'
```

### Use a specific resolver

```sh
caa-lint --domain example.com --dns 1.1.1.1
```

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--domain D` | — | Domain to check |
| `--domains-file PATH` | — | File of domains (one per line, `#` comments) |
| `--expect-issue CA` | — | CA that must be authorized (repeatable) |
| `--require-iodef` | `false` | Fail if no `iodef` is published |
| `--fail-on-missing` | `false` | Fail if CAA is missing at domain *and* all parents |
| `--suggest` | `false` | Print BIND + Route53 zone snippets |
| `--iodef VAL` | `mailto:security@example.com` | `iodef` value used in `--suggest` output |
| `--dns HOST[:PORT]` | — | Override DNS server |
| `--timeout DUR` | `5s` | Per-domain DNS timeout |
| `--json` | `false` | Emit JSON array |

## Exit codes

| Code | Meaning |
|-----:|---------|
| `0` | All domains pass policy |
| `1` | CAA missing with `--fail-on-missing`, or `--expect-issue` not satisfied |
| `2` | Usage or DNS error |

## JSON schema

```json
[
  {
    "domain": "example.com",
    "foundAt": "example.com",
    "records": [{"flag":0,"tag":"issue","value":"letsencrypt.org"}],
    "issue": ["letsencrypt.org"],
    "issueWild": [],
    "iodef": ["mailto:sec@example.com"],
    "denyAll": false,
    "missingCAA": false,
    "wildcardGap": true,
    "unauthorized": [],
    "policy": ["issue present but no issuewild — ..."]
  }
]
```

## Use in GitHub Actions

```yaml
- uses: tigertrust/caa-lint@v0.1.0
  with:
    domain: api.example.com
    expect_issue: letsencrypt.org,sectigo.com
    fail_on_missing: 'true'
```

## Related

- [`47-day-readiness-score`](https://github.com/tigertrust/47-day-readiness-score) — CAA presence is one of its checks
- [`aia-chain-check`](https://github.com/tigertrust/aia-chain-check) — SC104 chain-completeness gate
- [`cert-expiry-action`](https://github.com/tigertrust/cert-expiry-action) — fail CI when a cert is close to expiry

## License

Apache-2.0. See [LICENSE](./LICENSE) and [SECURITY.md](./SECURITY.md).
