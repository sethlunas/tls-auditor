# Runbook

## Prerequisites
- Docker desktop installed and running
- Make installed
- Git

## First Time Setup

Clone the repository:
```bash
git clone https://github.com/sethlunas/tls-auditor.git
cd tls-auditor
```

Pull the base Python image:
```bash
make bootstrap
```

## Running the System

Build and start all containers:
```bash
make up
```

Run the full demo scan against both test servers:
```bash
make demo
```

Or run both in sequence:
```bash
make up && make demo
```

## Viewing Results

Scan reports are saved automatically to `artifacts/release/` as JSON and CSV.

Generate a summary table of all scans:
```bash
make summarize
```

## Stopping the Environment
```bash
make down
```

## Full Reset
Tears down all containers, images, and volumes:
```bash
make clean
```

Clear generated scan reports:
```bash
make clean-artifacts
```

## Scanning a Real Server

To scan any public HTTPS server:
```bash
docker run --rm tls-auditor python src/auditor.py google.com
```