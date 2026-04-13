# TLS Auditor

A lightweight, Dockerized security tool that inspects the TLS configuration of any HTTPS server and produces a plain-English security report.

Built for CECS 478 - Data Security & Privacy | Cal State Long Beach

---

## What It Does

- Connects to a target HTTPS server and inspects how it handles encrypted connections
- Flags weak protocol versions (modern standard is TLS 1.2 and TLS 1.3) 
- Identifies weak cipher suites (the encryption recipes both sides agree to use)
- Checks certificate health; expired, self-signed, or using weak key sizes
- Exports findings as a JSON/CSV report you can read and share

---

## Setup

### Requirements
- Docker Desktop
- Make

### Bootstrap
```bash
make bootstrap
```

### Run
```bash
make up && make demo
```

---

## Project Structure

tls-auditor/
    - src/ # Core auditor logic
    - tests/ # Unit and integration tests
    - artifacts/ # Evidence, logs, reports
    - Makefile # Command shortcuts
    - docker-compose.yml # Container definitions
    - README.md # This file
    - LICENSE # MIT License

---

## Status

> Proposal phase - skeleton only. System under active development.