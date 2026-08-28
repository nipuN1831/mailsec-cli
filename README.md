# mailsec

A command-line tool that checks whether a domain's email authentication (SPF, DKIM, DMARC) is actually configured to stop spoofing — or just looks like it is.

Runs all three DNS checks concurrently, classifies each one against its real enforcement semantics (not just "record exists"), and gives a verdict. Works against a live domain or against a raw email you pipe in.

## Why

SPF, DKIM, and DMARC are three separate, easy-to-misconfigure DNS records that together decide whether a spoofed email claiming to be from your domain gets delivered. Most "SPF checker" tools stop at "a record exists." This one checks the parts that actually matter: does the SPF record end in a hard fail or a token that lets everything through, is the DKIM key still valid or revoked, is DMARC's policy actually `reject`/`quarantine` or just `none` (monitoring only, no enforcement).

## Install

Requires Go 1.22+.

```bash
git clone https://github.com/nipun/mailsec.git
cd mailsec
go build ./cmd/mailsec
```

This produces a `mailsec` binary in the current directory.

## Usage

### Check a domain directly

```bash
./mailsec --domain example.com
```

DKIM is checked at the `default` selector unless you specify one — most domains don't publish a key there, so pass the real selector if you know it (check a `DKIM-Signature` header from a real email, or your mail provider's docs):

```bash
./mailsec --domain google.com --selector 20230601
```

### Analyze a raw email

Pipe raw email headers (an `.eml` file, or anything starting with a `From:` line) in on stdin. The sender's domain and DKIM selector are extracted automatically from the headers:

```bash
cat suspicious-email.eml | ./mailsec
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--domain` | (none — reads stdin instead) | Domain to check |
| `--selector` | `default` | DKIM selector to look up |
| `--json` | `false` | Output machine-readable JSON instead of a table |
| `--timeout` | `5s` | Per-check DNS timeout |

## Sample output

```
$ ./mailsec --domain google.com --selector 20230601

Domain: google.com

SPF    ⚠ warning    v=spf1 include:_spf.google.com ~all — soft fail only, unauthorized senders are marked but delivered
DKIM   ✗ fail       key revoked (p= is empty)
DMARC  ✓ pass       policy=reject pct=100 rua=mailto:mailauth-reports@google.com

Verdict: VULNERABLE — authentication checks failed
```

```
$ ./mailsec --domain google.com --json
{
  "domain": "google.com",
  "checks": {
    "spf":   { "status": "warning", "detail": "v=spf1 include:_spf.google.com ~all — soft fail only, unauthorized senders are marked but delivered" },
    "dkim":  { "status": "fail", "detail": "key revoked (p= is empty)" },
    "dmarc": { "status": "pass", "detail": "policy=reject pct=100 rua=mailto:mailauth-reports@google.com" }
  },
  "verdict": "fail"
}
```

The verdict is only `SECURE` when SPF, DKIM, and DMARC all explicitly pass — a missing or unchecked record downgrades the verdict, it never gets silently treated as fine.

If a DNS lookup itself fails (timeout, resolver error) rather than genuinely returning "no record," the underlying cause is shown too:

```
SPF    ? none       DNS lookup failed
                    cause: spf: lookup example.com: read udp ...: i/o timeout
```

## Architecture

```
cmd/mailsec/main.go        CLI entry point: flags, mode dispatch, orchestration
internal/checker/          Checker interface + SPF/DKIM/DMARC implementations
internal/header/           Parses raw email text into domain + DKIM selector
internal/report/           Formats results as a table or JSON
```

All three checks implement a single interface:

```go
type Checker interface {
    Check(ctx context.Context, domain string) Result
}
```

`main.go` runs all three concurrently via goroutines, collecting results through a channel, each bounded by a context timeout so a slow or hanging DNS server can't hang the whole tool:

```
main.go
  ├── go spfChecker.Check(ctx, domain)   ──┐
  ├── go dkimChecker.Check(ctx, domain)  ──┤──► results channel ──► report
  └── go dmarcChecker.Check(ctx, domain) ──┘
```

DNS lookups are injected through an unexported function field on each checker (not a global, not an interface — just a func field defaulting to `net.DefaultResolver.LookupTXT`), so every classification rule — SPF's terminal-mechanism logic, DKIM's key-revocation and key-size math, DMARC's policy/pct parsing — has fast, deterministic unit tests that don't touch the network, alongside a smaller set of integration tests against real domains.

## Testing

```bash
go test ./...          # full suite
go test -race ./...    # concurrency check
go vet ./...
gofmt -l .              # should print nothing
```

Standard library only — no third-party dependencies.

## Known limitations

- SPF `include:` chains and `redirect=` targets are not recursively resolved — a policy that's only permissive through a delegated record won't be fully verified, though a `redirect=` is at least reported honestly rather than marked "insecure."
- DKIM key-size reporting is exact for RSA and Ed25519 keys; other key types fall back to an approximation.
