import json

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

from api.throttles import HealthRateThrottle


def build_openapi_schema(server_url: str = "http://localhost:8000") -> dict:
    """Build the complete OpenAPI 3.0.3 specification for the Pingly MVP Backend API."""
    usdc_code = getattr(settings, "STELLAR_USDC_ASSET_CODE", "USDC")
    usdc_issuer = getattr(
        settings,
        "STELLAR_USDC_ISSUER",
        "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
    )

    clean_server_url = (server_url or "http://localhost:8000").rstrip("/")
    servers = [{"url": clean_server_url, "description": "Pingly API Server"}]

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Pingly MVP Backend API",
            "version": "1.0.0",
            "description": (
                "Phone Number & `@handle`-Based Non-Custodial USDC Payments on **Stellar Testnet**.\n\n"
                "### Authentication\n"
                "Obtain a token via `POST /api/auth/otp/verify/` and pass it in the `Authorization` header:\n"
                "`Authorization: Token <your_token>`"
            ),
            "contact": {"name": "Pingly Engineering"},
        },
        "servers": servers,
        "tags": [
            {"name": "System", "description": "Health check and Stellar Testnet configuration"},
            {"name": "Auth & Identity", "description": "Phone registration, SMS OTP verification, profile, and @handle management"},
            {"name": "Wallet", "description": "Non-custodial Stellar wallet ownership verification, balances, trustlines, and receive info"},
            {"name": "Recipients", "description": "Search and confirm verified Pingly recipients by phone number or @handle"},
            {"name": "Transfers", "description": "Prepare, authorize, submit, and verify Stellar Testnet USDC P2P payments"},
            {"name": "Transactions", "description": "Paginated transaction history, details, Stellar Expert links, and Horizon sync"},
        ],
        "components": {
            "securitySchemes": {
                "TokenAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "Authorization",
                    "description": "Format: `Token <token_key>`",
                }
            },
            "schemas": {
                "ErrorResponse": {
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "object",
                            "properties": {
                                "code": {"type": "string", "example": "validation_error"},
                                "message": {"type": "string", "example": "Request validation failed."},
                                "details": {"type": "object", "nullable": True},
                            },
                            "required": ["code", "message"],
                        }
                    },
                },
                "UserProfile": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "format": "uuid"},
                        "phone_number": {"type": "string", "example": "+14155550101"},
                        "masked_phone": {"type": "string", "example": "+141****0101"},
                        "handle": {"type": "string", "nullable": True, "example": "@alice"},
                        "raw_handle": {"type": "string", "nullable": True, "example": "alice"},
                        "display_name": {"type": "string", "example": "Alice Pingly"},
                        "is_phone_verified": {"type": "boolean", "example": True},
                        "phone_verified_at": {"type": "string", "format": "date-time", "nullable": True},
                        "stellar_public_key": {
                            "type": "string",
                            "nullable": True,
                            "example": "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
                        },
                        "wallet_verified_at": {"type": "string", "format": "date-time", "nullable": True},
                        "has_linked_wallet": {"type": "boolean", "example": True},
                        "onboarding_stage": {
                            "type": "string",
                            "enum": [
                                "PHONE_VERIFICATION_REQUIRED",
                                "HANDLE_REQUIRED",
                                "WALLET_REQUIRED",
                                "COMPLETED",
                            ],
                        },
                        "is_onboarding_complete": {"type": "boolean", "example": True},
                        "created_at": {"type": "string", "format": "date-time"},
                        "updated_at": {"type": "string", "format": "date-time"},
                    },
                },
                "HealthResponse": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "example": "ok"},
                        "service": {"type": "string", "example": "Pingly MVP Backend API"},
                        "docs": {
                            "type": "object",
                            "properties": {
                                "swagger": {"type": "string", "example": "/api/docs/"},
                                "redoc": {"type": "string", "example": "/api/redoc/"},
                                "openapi_schema": {"type": "string", "example": "/api/schema/"},
                            },
                        },
                        "sms": {
                            "type": "object",
                            "properties": {
                                "provider": {"type": "string", "enum": ["twilio", "console"], "example": "twilio"},
                                "twilio_configured": {"type": "boolean", "example": True},
                            },
                        },
                        "stellar": {
                            "type": "object",
                            "properties": {
                                "network": {"type": "string", "example": "TESTNET"},
                                "network_passphrase": {"type": "string", "example": "Test SDF Network ; September 2015"},
                                "horizon_url": {"type": "string", "example": "https://horizon-testnet.stellar.org"},
                                "usdc_asset_code": {"type": "string", "example": usdc_code},
                                "usdc_asset_issuer": {"type": "string", "example": usdc_issuer},
                                "explorer_base_url": {"type": "string", "example": "https://stellar.expert/explorer/testnet/tx"},
                            },
                        },
                    },
                },
                "OTPRequest": {
                    "type": "object",
                    "required": ["phone_number"],
                    "properties": {
                        "phone_number": {"type": "string", "example": "+14155550101"},
                        "display_name": {"type": "string", "example": "Alice Pingly"},
                    },
                },
                "OTPSendResponse": {
                    "type": "object",
                    "properties": {
                        "message": {"type": "string", "example": "Verification code sent."},
                        "phone_number": {"type": "string", "example": "+14155550101"},
                        "expires_in_seconds": {"type": "integer", "example": 300},
                        "resend_cooldown_seconds": {"type": "integer", "example": 60},
                        "is_new_user": {"type": "boolean", "example": True},
                        "sms_delivery": {
                            "type": "object",
                            "properties": {
                                "provider": {"type": "string", "enum": ["twilio", "console"], "example": "twilio"},
                                "delivered": {"type": "boolean", "example": True},
                            },
                        },
                        "debug_otp_code": {
                            "type": "string",
                            "nullable": True,
                            "description": "Present only when OTP_DEBUG_RETURN_CODE=True",
                            "example": "482910",
                        },
                    },
                },
                "OTPVerifyRequest": {
                    "type": "object",
                    "required": ["phone_number", "code"],
                    "properties": {
                        "phone_number": {"type": "string", "example": "+14155550101"},
                        "code": {"type": "string", "example": "123456"},
                        "display_name": {"type": "string", "example": "Alice Pingly"},
                    },
                },
                "OTPVerifyResponse": {
                    "type": "object",
                    "properties": {
                        "message": {"type": "string", "example": "Phone number verified successfully."},
                        "token": {"type": "string", "example": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"},
                        "user": {"$ref": "#/components/schemas/UserProfile"},
                    },
                },
                "HandleSetRequest": {
                    "type": "object",
                    "required": ["handle"],
                    "properties": {
                        "handle": {"type": "string", "example": "@alice_pay"},
                    },
                },
                "ProfileUpdateRequest": {
                    "type": "object",
                    "properties": {
                        "display_name": {"type": "string", "example": "Alice Pingly"},
                        "handle": {"type": "string", "example": "@alice_pay"},
                    },
                },
                "WalletChallengeRequest": {
                    "type": "object",
                    "required": ["public_key"],
                    "properties": {
                        "public_key": {
                            "type": "string",
                            "example": "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
                        }
                    },
                },
                "WalletChallengeResponse": {
                    "type": "object",
                    "properties": {
                        "challenge_id": {"type": "string", "format": "uuid"},
                        "public_key": {"type": "string"},
                        "nonce": {"type": "string"},
                        "challenge_message": {"type": "string"},
                        "challenge_xdr": {"type": "string"},
                        "expires_at": {"type": "string", "format": "date-time"},
                    },
                },
                "WalletVerifyRequest": {
                    "type": "object",
                    "properties": {
                        "challenge_id": {"type": "string", "format": "uuid"},
                        "public_key": {"type": "string"},
                        "signed_xdr": {
                            "type": "string",
                            "description": "Base64 SEP-0010 challenge XDR signed by the user's Stellar wallet",
                        },
                        "signature": {
                            "type": "string",
                            "description": "Base64 or hex 64-byte Ed25519 signature over `challenge_message`",
                        },
                    },
                },
                "RecipientConfirmation": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "format": "uuid"},
                        "display_name": {"type": "string", "example": "Bob Stellar"},
                        "handle": {"type": "string", "nullable": True, "example": "@bob"},
                        "masked_phone": {"type": "string", "example": "+141****0202"},
                        "stellar_public_key": {"type": "string", "nullable": True},
                        "has_linked_wallet": {"type": "boolean", "example": True},
                    },
                },
                "WalletNetworkDetails": {
                    "type": "object",
                    "properties": {
                        "public_key": {"type": "string"},
                        "network": {"type": "string", "example": "TESTNET"},
                        "account_exists": {"type": "boolean", "example": True},
                        "has_usdc_trustline": {"type": "boolean", "example": True},
                        "usdc_balance": {"type": "string", "example": "125.5000000"},
                        "xlm_balance": {"type": "string", "example": "99.9999000"},
                        "usdc_asset_code": {"type": "string", "example": usdc_code},
                        "usdc_asset_issuer": {"type": "string", "example": usdc_issuer},
                    },
                },
                "TransferPrepareRequest": {
                    "type": "object",
                    "required": ["recipient", "amount"],
                    "properties": {
                        "recipient": {
                            "type": "string",
                            "example": "@bob",
                            "description": "Verified recipient @handle or E.164 phone number",
                        },
                        "amount": {"type": "string", "example": "25.50"},
                        "memo": {"type": "string", "maxLength": 28, "example": "Lunch split"},
                        "idempotency_key": {"type": "string", "example": "idem_2026_001"},
                    },
                },
                "TransferSubmitRequest": {
                    "type": "object",
                    "required": ["signed_xdr"],
                    "properties": {
                        "transaction_id": {"type": "string", "format": "uuid"},
                        "idempotency_key": {"type": "string"},
                        "signed_xdr": {
                            "type": "string",
                            "description": "Base64 Stellar TransactionEnvelope XDR signed by the sender's wallet",
                        },
                    },
                },
                "TransferVerifyRequest": {
                    "type": "object",
                    "required": ["tx_hash"],
                    "properties": {
                        "tx_hash": {
                            "type": "string",
                            "example": "a" * 64,
                            "description": "64-character hex Stellar transaction hash",
                        },
                        "transaction_id": {"type": "string", "format": "uuid"},
                    },
                },
                "TransactionParty": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "nullable": True},
                        "display_name": {"type": "string"},
                        "handle": {"type": "string", "nullable": True},
                        "masked_phone": {"type": "string"},
                        "stellar_public_key": {"type": "string"},
                    },
                },
                "Transaction": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string", "format": "uuid"},
                        "transaction_id": {"type": "string", "format": "uuid"},
                        "idempotency_key": {"type": "string"},
                        "direction": {"type": "string", "enum": ["SENT", "RECEIVED", "UNKNOWN"]},
                        "amount": {"type": "string", "example": "25.5000000"},
                        "asset_code": {"type": "string", "example": usdc_code},
                        "asset_issuer": {"type": "string", "example": usdc_issuer},
                        "fee_stroops": {"type": "integer", "example": 100},
                        "fee_xlm": {"type": "string", "example": "0.0000100"},
                        "memo": {"type": "string"},
                        "status": {"type": "string", "enum": ["PENDING", "COMPLETED", "FAILED"]},
                        "tx_hash": {"type": "string", "nullable": True},
                        "ledger": {"type": "integer", "nullable": True},
                        "explorer_url": {
                            "type": "string",
                            "nullable": True,
                            "example": f"https://stellar.expert/explorer/testnet/tx/{'a' * 64}",
                        },
                        "error_code": {"type": "string"},
                        "failure_reason": {"type": "string"},
                        "sender": {"$ref": "#/components/schemas/TransactionParty"},
                        "recipient": {"$ref": "#/components/schemas/TransactionParty"},
                        "sender_wallet": {"type": "string"},
                        "recipient_wallet": {"type": "string"},
                        "unsigned_xdr": {"type": "string"},
                        "created_at": {"type": "string", "format": "date-time"},
                        "completed_at": {"type": "string", "format": "date-time", "nullable": True},
                    },
                },
            },
        },
        "paths": {
            "/api/health/": {
                "get": {
                    "tags": ["System"],
                    "summary": "Health check, SMS provider status & Stellar Testnet configuration",
                    "operationId": "getHealth",
                    "responses": {
                        "200": {
                            "description": "Service healthy",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/HealthResponse"}}},
                        }
                    },
                }
            },
            "/api/auth/register/": {
                "post": {
                    "tags": ["Auth & Identity"],
                    "summary": "Register phone number and send SMS OTP via Twilio",
                    "operationId": "registerAndSendOtp",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OTPRequest"}}},
                    },
                    "responses": {
                        "200": {
                            "description": "OTP generated and dispatched via Twilio SMS (or console fallback)",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OTPSendResponse"}}},
                        },
                        "400": {"description": "Invalid phone number", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}},
                        "429": {"description": "Cooldown or rate limit exceeded", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}},
                        "502": {"description": "Twilio SMS delivery failed (when SMS_FAIL_SILENTLY=False)", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}},
                    },
                }
            },
            "/api/auth/otp/send/": {
                "post": {
                    "tags": ["Auth & Identity"],
                    "summary": "Send or resend SMS OTP code via Twilio",
                    "operationId": "sendOtp",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OTPRequest"}}},
                    },
                    "responses": {
                        "200": {
                            "description": "OTP generated and dispatched via Twilio SMS (or console fallback)",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OTPSendResponse"}}},
                        },
                        "429": {"description": "Cooldown or rate limit exceeded", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}},
                        "502": {"description": "Twilio SMS delivery failed", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}},
                    },
                }
            },
            "/api/auth/otp/verify/": {
                "post": {
                    "tags": ["Auth & Identity"],
                    "summary": "Verify SMS OTP code and obtain authentication token",
                    "operationId": "verifyOtp",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OTPVerifyRequest"}}},
                    },
                    "responses": {
                        "200": {
                            "description": "Phone verified; returns auth token and user profile",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OTPVerifyResponse"}}},
                        },
                        "400": {"description": "Invalid or expired OTP", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}},
                        "429": {"description": "Max verification attempts exceeded", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}},
                    },
                }
            },
            "/api/auth/logout/": {
                "post": {
                    "tags": ["Auth & Identity"],
                    "summary": "Invalidate current authentication token",
                    "operationId": "logout",
                    "security": [{"TokenAuth": []}],
                    "responses": {"200": {"description": "Logged out"}},
                }
            },
            "/api/profile/": {
                "get": {
                    "tags": ["Auth & Identity"],
                    "summary": "Get authenticated user's profile",
                    "operationId": "getProfile",
                    "security": [{"TokenAuth": []}],
                    "responses": {
                        "200": {
                            "description": "User profile",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/UserProfile"}}},
                        }
                    },
                },
                "patch": {
                    "tags": ["Auth & Identity"],
                    "summary": "Update display name or @handle",
                    "operationId": "updateProfile",
                    "security": [{"TokenAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ProfileUpdateRequest"}}},
                    },
                    "responses": {
                        "200": {
                            "description": "Updated profile",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/UserProfile"}}},
                        }
                    },
                },
            },
            "/api/profile/handle/": {
                "post": {
                    "tags": ["Auth & Identity"],
                    "summary": "Create or update unique @handle",
                    "operationId": "setHandle",
                    "security": [{"TokenAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/HandleSetRequest"}}},
                    },
                    "responses": {"200": {"description": "Handle saved"}},
                }
            },
            "/api/handles/check/": {
                "get": {
                    "tags": ["Auth & Identity"],
                    "summary": "Check @handle format validity and case-insensitive availability",
                    "operationId": "checkHandleAvailability",
                    "parameters": [
                        {
                            "name": "handle",
                            "in": "query",
                            "required": True,
                            "schema": {"type": "string", "example": "@pinglyuser"},
                        }
                    ],
                    "responses": {"200": {"description": "Handle availability result"}},
                }
            },
            "/api/wallet/challenge/": {
                "post": {
                    "tags": ["Wallet"],
                    "summary": "Generate cryptographic challenge to verify Stellar wallet ownership",
                    "operationId": "createWalletChallenge",
                    "security": [{"TokenAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/WalletChallengeRequest"}}},
                    },
                    "responses": {
                        "200": {
                            "description": "Challenge issued",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/WalletChallengeResponse"}}},
                        }
                    },
                }
            },
            "/api/wallet/verify/": {
                "post": {
                    "tags": ["Wallet"],
                    "summary": "Verify signed challenge and link Stellar wallet to user identity",
                    "operationId": "verifyAndLinkWallet",
                    "security": [{"TokenAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/WalletVerifyRequest"}}},
                    },
                    "responses": {"200": {"description": "Wallet verified and linked"}},
                }
            },
            "/api/wallet/unlink/": {
                "delete": {
                    "tags": ["Wallet"],
                    "summary": "Unlink connected Stellar wallet",
                    "operationId": "unlinkWallet",
                    "security": [{"TokenAuth": []}],
                    "responses": {"200": {"description": "Wallet unlinked"}},
                }
            },
            "/api/recipients/lookup/": {
                "get": {
                    "tags": ["Recipients"],
                    "summary": "Resolve verified phone number or @handle to recipient confirmation details",
                    "operationId": "lookupRecipient",
                    "security": [{"TokenAuth": []}],
                    "parameters": [
                        {
                            "name": "q",
                            "in": "query",
                            "required": True,
                            "description": "Verified phone number (E.164) or @handle",
                            "schema": {"type": "string", "example": "@bob"},
                        }
                    ],
                    "responses": {
                        "200": {"description": "Recipient resolved"},
                        "404": {"description": "Recipient not found"},
                    },
                }
            },
            "/api/dashboard/": {
                "get": {
                    "tags": ["Wallet"],
                    "summary": "Fetch complete Wallet Dashboard (profile, live USDC/XLM balances, recent transactions)",
                    "operationId": "getDashboard",
                    "security": [{"TokenAuth": []}],
                    "responses": {"200": {"description": "Dashboard data"}},
                }
            },
            "/api/wallet/balance/": {
                "get": {
                    "tags": ["Wallet"],
                    "summary": "Query live Stellar Testnet USDC & XLM balances and trustline status",
                    "operationId": "getWalletBalance",
                    "security": [{"TokenAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Wallet balances",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/WalletNetworkDetails"}}},
                        }
                    },
                }
            },
            "/api/wallet/trustline/prepare/": {
                "post": {
                    "tags": ["Wallet"],
                    "summary": "Prepare unsigned Stellar ChangeTrust XDR to enable Testnet USDC",
                    "operationId": "prepareUsdcTrustline",
                    "security": [{"TokenAuth": []}],
                    "responses": {"200": {"description": "Unsigned ChangeTrust XDR"}},
                }
            },
            "/api/wallet/fund-testnet/": {
                "post": {
                    "tags": ["Wallet"],
                    "summary": "Fund connected Stellar wallet on Testnet via Friendbot",
                    "operationId": "fundTestnetWallet",
                    "security": [{"TokenAuth": []}],
                    "responses": {"200": {"description": "Account funded"}},
                }
            },
            "/api/wallet/receive/": {
                "get": {
                    "tags": ["Wallet"],
                    "summary": "Get Receive screen identity, wallet address, SEP-0007 URI, and QR payload",
                    "operationId": "getReceiveInfo",
                    "security": [{"TokenAuth": []}],
                    "parameters": [
                        {"name": "amount", "in": "query", "required": False, "schema": {"type": "string"}},
                        {"name": "memo", "in": "query", "required": False, "schema": {"type": "string"}},
                    ],
                    "responses": {"200": {"description": "Receive screen payload"}},
                }
            },
            "/api/transfers/prepare/": {
                "post": {
                    "tags": ["Transfers"],
                    "summary": "Resolve recipient, check balances/trustlines, and build unsigned Testnet USDC payment XDR",
                    "operationId": "prepareTransfer",
                    "security": [{"TokenAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/TransferPrepareRequest"}}},
                    },
                    "responses": {
                        "201": {"description": "Transfer prepared with unsigned_xdr and preview"},
                        "400": {"description": "Insufficient balance, missing trustline, or invalid recipient"},
                    },
                }
            },
            "/api/transfers/submit/": {
                "post": {
                    "tags": ["Transfers"],
                    "summary": "Validate wallet-signed XDR and submit USDC transfer to Stellar Testnet Horizon",
                    "operationId": "submitTransfer",
                    "security": [{"TokenAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/TransferSubmitRequest"}}},
                    },
                    "responses": {
                        "200": {"description": "Transfer completed"},
                        "400": {"description": "Invalid signature or Horizon transaction error"},
                        "409": {"description": "Duplicate submission"},
                    },
                }
            },
            "/api/transfers/verify/": {
                "post": {
                    "tags": ["Transfers"],
                    "summary": "Verify a submitted transaction hash on Stellar Testnet Horizon",
                    "operationId": "verifyTransfer",
                    "security": [{"TokenAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/TransferVerifyRequest"}}},
                    },
                    "responses": {"200": {"description": "Transaction verified"}},
                }
            },
            "/api/transactions/": {
                "get": {
                    "tags": ["Transactions"],
                    "summary": "Paginated sent & received transaction history",
                    "operationId": "listTransactions",
                    "security": [{"TokenAuth": []}],
                    "parameters": [
                        {
                            "name": "direction",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string", "enum": ["sent", "received"]},
                        },
                        {
                            "name": "status",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string", "enum": ["PENDING", "COMPLETED", "FAILED"]},
                        },
                        {"name": "search", "in": "query", "required": False, "schema": {"type": "string"}},
                        {"name": "page", "in": "query", "required": False, "schema": {"type": "integer"}},
                    ],
                    "responses": {"200": {"description": "Paginated transaction list"}},
                }
            },
            "/api/transactions/sync/": {
                "post": {
                    "tags": ["Transactions"],
                    "summary": "Sync incoming and outgoing Testnet USDC payments from Horizon",
                    "operationId": "syncTransactions",
                    "security": [{"TokenAuth": []}],
                    "responses": {"200": {"description": "Transactions synced"}},
                }
            },
            "/api/transactions/{id_or_hash}/": {
                "get": {
                    "tags": ["Transactions"],
                    "summary": "Get transaction details by internal UUID or Stellar tx_hash",
                    "operationId": "getTransactionDetail",
                    "security": [{"TokenAuth": []}],
                    "parameters": [
                        {
                            "name": "id_or_hash",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Transaction details",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Transaction"}}},
                        },
                        "404": {"description": "Transaction not found"},
                    },
                }
            },
        },
    }


class OpenAPISchemaView(APIView):
    """Serves the OpenAPI 3.0.3 specification for Pingly MVP Backend API."""

    permission_classes = [AllowAny]
    throttle_classes = [HealthRateThrottle]

    def get(self, request):
        server_url = request.build_absolute_uri("/").rstrip("/")
        schema = build_openapi_schema(server_url=server_url)
        return JsonResponse(
            schema,
            json_dumps_params={"indent": 2},
            content_type="application/json",
        )


class SwaggerUIView(APIView):
    """Serves interactive Swagger UI documentation for Pingly MVP Backend API."""

    permission_classes = [AllowAny]
    throttle_classes = [HealthRateThrottle]

    def get(self, request):
        server_url = request.build_absolute_uri("/").rstrip("/")
        spec_json = json.dumps(build_openapi_schema(server_url=server_url))
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Pingly API – Swagger UI</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    body {{ margin: 0; background: #fafafa; }}
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin></script>
  <script>
    window.onload = () => {{
      const embeddedSpec = {spec_json};
      embeddedSpec.servers = [{{ url: window.location.origin, description: "Current Server" }}];
      window.ui = SwaggerUIBundle({{
        spec: embeddedSpec,
        dom_id: "#swagger-ui",
        deepLinking: true,
        persistAuthorization: true,
        displayRequestDuration: true,
        filter: true
      }});
    }};
  </script>
</body>
</html>"""
        return HttpResponse(html, content_type="text/html; charset=utf-8")


class RedocUIView(APIView):
    """Serves ReDoc documentation for Pingly MVP Backend API."""

    permission_classes = [AllowAny]
    throttle_classes = [HealthRateThrottle]

    def get(self, request):
        server_url = request.build_absolute_uri("/").rstrip("/")
        spec_json = json.dumps(build_openapi_schema(server_url=server_url))
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Pingly API – ReDoc</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
  <style>
    body {{ margin: 0; padding: 0; background: #ffffff; }}
  </style>
</head>
<body>
  <div id="redoc-container"></div>
  <script>
    const embeddedSpec = {spec_json};
    embeddedSpec.servers = [{{ url: window.location.origin, description: "Current Server" }}];

    function initPinglyRedoc() {{
      if (window.Redoc && typeof window.Redoc.init === "function") {{
        window.Redoc.init(
          embeddedSpec,
          {{
            scrollYOffset: 0,
            hideDownloadButton: false,
            expandResponses: "200,201"
          }},
          document.getElementById("redoc-container")
        );
      }}
    }}
  </script>
  <script
    src="https://cdn.jsdelivr.net/npm/redoc@2.1.5/bundles/redoc.standalone.js"
    onload="initPinglyRedoc()"
    onerror="var s=document.createElement('script');s.src='https://unpkg.com/redoc@2.1.5/bundles/redoc.standalone.js';s.onload=initPinglyRedoc;document.body.appendChild(s);"
  ></script>
</body>
</html>"""
        return HttpResponse(html, content_type="text/html; charset=utf-8")
