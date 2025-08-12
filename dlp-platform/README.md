# Data Loss Prevention (DLP) Platform - MVP

A minimal, runnable DLP service built with FastAPI. It supports:

- Policy-based scanning of text and files for sensitive data
- Built-in detectors (emails, credit cards, SSNs, phone numbers, API keys, IPv4, IBAN)
- REST endpoints to manage policies and run scans
- SQLite persistence for policies, scans, and findings
- Simple API-key auth

## Quickstart

### 1) Create and activate a virtualenv (optional)

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies

```bash
pip install -r requirements.txt
```

### 3) Run the API

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open the interactive docs at `http://localhost:8000/docs`.

Default API key: `dev-secret` (configurable).

## Configuration

Environment variables:
- `DLP_DB_URL` (default: `sqlite:///./dlp.db`)
- `DLP_API_KEY` (default: `dev-secret`)

## API Overview

- `POST /scan/text` — scan raw text
- `POST /scan/file` — multipart upload to scan a file
- `GET /findings` — list recent findings
- `POST /policies` — create/update a policy
- `GET /policies` — list policies

Policies define which detectors run and thresholds for severity/action.

## Example: Create Policy

```bash
curl -X POST http://localhost:8000/policies \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: dev-secret' \
  -d '{
    "name": "default",
    "enabled": true,
    "detectors": ["EMAIL", "CREDIT_CARD", "SSN", "PHONE", "API_KEY"],
    "min_severity": "low",
    "actions": ["log"]
  }'
```

## Example: Scan Text

```bash
curl -X POST http://localhost:8000/scan/text \
  -H 'Content-Type: application/json' \
  -H 'x-api-key: dev-secret' \
  -d '{
    "text": "Contact me at alice@example.com, cc: 4111111111111111",
    "policy_name": "default"
  }'
```

## Tests

```bash
pytest -q
```

## Notes

- This is an MVP. For production, add more robust detectors, streaming file scanning, tamper-proof audit logs, RBAC, and queue-based asynchronous processing.