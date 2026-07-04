# CapCut Account Creator

Full auto CapCut account registration with device spoofing, Email API integration, and parallel workers.

## Features

- ✅ **Full Device Spoofing** — unique fingerprint per account (device_id, verify_fp, ms_token, ttwid)
- ✅ **mix_mode Encoding** — XOR 0x05 hex encoding (CapCut/TikTok passport)
- ✅ **Email API Integration** — auto generate temp email + auto poll OTP
- ✅ **OTP Auto-Extract** — supports "code is XXXXX", "code: XXXXX", standalone digits
- ✅ **OTP Resend** — auto resend up to 2x if not received
- ✅ **Stabilize Phase** — waits for late-arriving OTP emails
- ✅ **Parallel Workers** — ThreadPoolExecutor for bulk creation
- ✅ **Account Storage** — saves to `accounts.json`

## Requirements

```bash
pip install requests
```

## Usage

### Single Account
```bash
python3 capcut_register.py
```

### Bulk Mode (Parallel)
```bash
# 5 akun, 5 worker (default)
python3 capcut_register.py bulk 5

# 10 akun, 3 worker
python3 capcut_register.py bulk 10 3

# 20 akun, 5 worker
python3 capcut_register.py bulk 20 5
```

## Performance

| Mode | Akun | Waktu | Rate |
|------|------|-------|------|
| Single | 1 | ~15s | - |
| Parallel 5w | 5 | ~15-20s | ~15/menit |
| Parallel 5w | 10 | ~20-30s | ~20/menit |
| Parallel 5w | 20 | ~40-60s | ~20/menit |

## Registration Flow

1. **Bootstrap** — GET capcut.com → ttwid cookie
2. **Region** — POST /passport/web/region/ → CSRF token + login domain
3. **Check Email** — POST /passport/web/user/check_email_registered
4. **Send OTP** — POST /passport/web/email/send_code/ (type=34)
5. **Poll OTP** — Email API Worker (Cloudflare Email Routing)
6. **Register** — POST /passport/web/email/register_verify_login/

## Architecture

```
capcut_register.py
├── mix_encode()           # XOR 0x05 encoding
├── DeviceSpoof            # Device fingerprint generator
├── CapCutClient           # Passport API client
├── EmailAPIProvider       # Email + OTP via CF Worker
├── _create_one_account()  # Single account worker
└── bulk_create()          # Parallel orchestrator
```

## Config

Edit in `capcut_register.py`:

```python
TBM_WORKER_API = "https://email-api.example.com"
TBM_DOMAINS = ["example.com", "example.org", "example.net"]
DEFAULT_REGION = "US"
```

## Output

Accounts saved to `accounts.json`:
```json
[
  {
    "email": "user1234@example.com",
    "password": "RandomPass123!@#",
    "user_id": 7653465574639666189,
    "user_id_str": "7653465574639666189",
    "screen_name": "user123456789",
    "session_cookies": {...},
    "device_id": "1234567890123456789",
    "created_at": "2026-06-20T12:00:00"
  }
]
```

## Email Provider

Uses [Email API](https://email-api.example.com) — Cloudflare Email Routing + Worker API.

> **Get an API key:** Contact sales to purchase access to the Email API endpoint.

Domains (configurable):
- `example.com`
- `example.org`
- `example.net`

## Disclaimer

For educational purposes only. Use at your own risk.
