# Security Invariants

This document describes the security guarantees and assumptions of TLS Auditor.

---

## What This System Guarantees

**No plaintext written to disk.**
All data written to `artifacts/release/` contains only TLS handshake metadata —
protocol version, cipher suite name, certificate subject, issuer, and expiry date.
No payload data, no user content, and no session keys are ever captured or stored.

**No active exploitation.**
TLS Auditor is a passive inspection tool. It initiates a standard TLS handshake
identical to what any browser performs when visiting a website. It does not inject
traffic, modify server responses, attempt decryption, or interfere with the
connection in any way.

**Self-contained test environment.**
All development and evaluation targets run inside Docker containers on localhost.
No external or third-party servers are contacted during testing unless explicitly
invoked by the user.

**Input validation enforced.**
All user-supplied inputs (hostname and port) are validated before any network
connection is attempted. Empty hostnames and out-of-range port numbers are
rejected with a clear error message.

**Least-privilege container execution.**
Containers run as non-root users by default using the official Python and nginx
base images. No elevated privileges are requested or required.

---

## What This System Does Not Guarantee

- TLS Auditor cannot detect runtime MITM attacks in progress.
- TLS Auditor inspects only the TLS handshake layer, not application-layer behavior.
- TLS Auditor does not verify certificate transparency logs.
- Scanning a server without authorization may violate that server's terms of service.
  Users are responsible for ensuring they have permission to scan any target.

---

## Ethical Use

This tool is intended for defensive security purposes; helping administrators
identify and fix weak TLS configurations before attackers can exploit them.
Do not use this tool to scan servers you do not own or have explicit permission
to test.