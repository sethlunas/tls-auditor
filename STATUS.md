# What Works / What's Next

## What Works

**Core Scanner**
The TLS Auditor successfully connects to any HTTPS server, performs a TLS
handshake, and extracts the protocol version, cipher suite, and certificate
details. Results are evaluated against known weak configurations and exported
as JSON and CSV reports to `artifacts/release/`.

**Weak Detection**
The scanner correctly identifies and flags:
- Weak cipher suites (AES128-SHA and other non-forward-secret ciphers)
- Deprecated protocol versions (TLS 1.0, TLS 1.1, SSLv2, SSLv3)
- Expired certificates

**Test Servers**
Two Docker-based test servers are fully operational:
- `nginx-weak` — serves TLS 1.2 with AES128-SHA cipher, correctly flagged as FAILED
- `nginx-hardened` — serves TLS 1.3 with AES-256-GCM, correctly passes as PASSED

**Automated Testing**
7 unit tests covering happy path, negative, and edge cases all pass locally
and in CI. GitHub Actions runs tests automatically on every push to main.

**Observability**
Structured logging records key processing steps during every scan. A summary
script generates a human-readable table and JSON summary of all scan results.

**Evidence**
PCAP captures of TLS handshake traffic are saved to `artifacts/release/`.
JSON and CSV scan reports are generated per scan run.

---

## What's Next

**Real-world evaluation**
Run the scanner against a broader set of public HTTPS servers to gather
real-world data on TLS configuration trends; what protocol versions and
cipher suites are most common, what percentage of servers are misconfigured.

**Certificate depth checking**
Currently the scanner checks expiry but does not verify the full certificate
chain. Adding chain validation would catch intermediate CA issues.

**Continuous monitoring mode**
Add a mode that scans a list of hosts on a schedule and alerts when
configurations change or weaken over time.

**HTML report output**
Generate a human-friendly HTML report in addition to JSON and CSV for
easier sharing with non-technical stakeholders.

**False positive tuning**
Some cipher suites flagged as weak may be acceptable in certain contexts.
Adding configurable allowlists would make the tool more flexible for
production use.