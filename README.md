# Pingly MVP – Backend API

Phone Number & `@handle`-Based Non-Custodial USDC Payments on **Stellar Testnet**.

## Overview

Pingly maps verified phone numbers and unique `@handles` to user-owned Stellar wallets so users can send and receive **Stellar Testnet USDC** without manually copying 56-character Stellar public keys. The backend is strictly **non-custodial**—it never accepts or stores user private keys.

---

## Core Features & Production Hardening

1. **Interactive API Documentation (OpenAPI 3.0.3, Swagger UI & ReDoc)**
   - **Swagger UI**: `/api/docs/` (or `/swagger/`)
   - **ReDoc**: `/api/redoc/` (or `/redoc/`)
   - **OpenAPI 3.0.3 JSON Schema**: `/api/schema/` (or `/schema/`)

2. **Deliverable 1 – Phone Number & `@handle` Identity Layer**
   - E.164 phone registration and **Twilio SMS OTP** verification (`api/services/sms_service.py`) with hashed OTP storage, expiry (`OTP_EXPIRY_SECONDS`), resend cooldown (`OTP_RESEND_COOLDOWN_SECONDS`), hourly rate limits, retry attempt limits (`OTP_MAX_ATTEMPTS`), and automatic console/sandbox fallback when Twilio credentials are not set.
   - Case-insensitive unique `@handle` creation, reserved-handle protection (`@admin`, `@pingly`, etc.), and availability checks.
   - Cryptographic proof of Stellar wallet ownership supporting both **SEP-0010 sequence-0 transaction XDR signing** (`signed_xdr`) and **SEP-0053 / Ed25519 message signing** (`signature`).
   - Rate-limited recipient lookup by verified phone number or `@handle`, returning masked phone identity (`+141****0101`), display name, `@handle`, and verified Stellar public key.

3. **Deliverable 2 – Stellar Testnet USDC P2P Transfers**
   - Pre-flight Horizon validation of sender & recipient accounts, native XLM fee reserves, and Stellar Testnet USDC trustlines.
   - Unsigned Stellar `Payment` XDR builder (`POST /api/transfers/prepare/`) with idempotency key tracking and transfer preview.
   - Non-custodial signed transaction verification and submission (`POST /api/transfers/submit/`) with signature validation, payload hash verification, duplicate submission protection, and clear Horizon error code translation (`op_underfunded`, `op_no_trust`, `tx_insufficient_balance`, etc.).

4. **Deliverable 3 – Wallet Dashboard, Send/Receive & Transaction History**
   - Unified dashboard endpoint (`GET /api/dashboard/`) returning profile status, cached/live USDC & XLM balances, trustline status, and recent transactions.
   - Receive endpoint (`GET /api/wallet/receive/`) with `@handle`, verified phone identity, SEP-0007 `web+stellar:pay` URI, and QR payload.
   - Helper endpoints to prepare a Testnet USDC `ChangeTrust` transaction (`POST /api/wallet/trustline/prepare/`) and fund Testnet accounts via Friendbot (`POST /api/wallet/fund-testnet/`).
   - Paginated, filterable transaction history (`GET /api/transactions/`), transaction details (`GET /api/transactions/<id_or_hash>/`) with **Stellar Expert Testnet** links, and Horizon payment syncing (`POST /api/transactions/sync/`).

5. **Security, Validation, Rate Limiting, Caching & Logging**
   - **Input Validation & Sanitization (`api/validators.py`)**: Unicode NFKC normalization, control-character & null-byte stripping, HTML/XSS tag rejection, base64 XDR validation, 28-byte UTF-8 memo validation, and reserved handle blocking.
   - **Proxy-Aware Rate Limiting (`api/throttles.py`)**: Dedicated rate-limit scopes across every endpoint (`health`, `otp_send`, `otp_verify`, `handle_check`, `profile`, `recipient_lookup`, `wallet_action`, `wallet_read`, `transfer_prepare`, `transfer_submit`, `transaction_read`) respecting `X-Forwarded-For` / `X-Real-IP` behind Traefik.
   - **Structured Logging (`api/middleware.py` & `core/settings.py`)**: Propagates `X-Request-ID` on every request/response and emits structured logs across `api.request`, `api.security`, `api.stellar`, and `api`.
   - **Redis Caching & PostgreSQL**: Configured with `postgres:16-alpine` and `redis:7-alpine` in `docker-compose.yml` (with automatic fallback to SQLite & `LocMemCache` for standalone local tests).
   - **Twilio SMS Delivery**: Automatically activates live SMS OTP delivery when `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_PHONE_NUMBER` (or `TWILIO_MESSAGING_SERVICE_SID`) are set in environment variables (`SMS_PROVIDER=auto`).

---

## Deployment with Dokploy & Traefik

Both [Dockerfile](file:///Users/bossemma/Documents/Github/StellarProjects/Pingly/Dockerfile) and [docker-compose.yml](file:///Users/bossemma/Documents/Github/StellarProjects/Pingly/docker-compose.yml) are configured for **Dokploy + Traefik**:
- Services (`backend`, `db`, `redis`) use `expose` (`expose: ["8000"]` on `backend`) rather than host `ports` bindings so Traefik routes traffic directly to container port `8000`.
- Runs Gunicorn as a non-root `pingly` user via [entrypoint.sh](file:///Users/bossemma/Documents/Github/StellarProjects/Pingly/entrypoint.sh) (which runs `migrate --noinput` and `collectstatic --noinput` on startup).

```bash
docker compose up --build -d
```

---

## Local Development & Testing

```bash
# Activate virtual environment
source venv/bin/activate

# Apply database migrations
python manage.py migrate

# Run test suite
python manage.py test -v 2

# Start development server on http://127.0.0.1:8000
python manage.py runserver 8000
```
