import base64
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from stellar_sdk import Account, Keypair, Network, TransactionEnvelope
from stellar_sdk.exceptions import BadRequestError

from api.models import OTPVerification, Transaction, User


@override_settings(
    SMS_PROVIDER="console",
    OTP_DEBUG_RETURN_CODE=True,
    OTP_RESEND_COOLDOWN_SECONDS=60,
    OTP_MAX_ATTEMPTS=3,
)
class PinglyMVPBackendTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.alice_phone = "+14155550101"
        self.bob_phone = "+14155550202"
        self.alice_kp = Keypair.random()
        self.bob_kp = Keypair.random()
        self.usdc_issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"

    def _register_and_verify_user(
        self,
        phone: str,
        display_name: str,
        handle: str | None = None,
        keypair: Keypair | None = None,
        sign_mode: str = "xdr",
    ) -> tuple[User, str]:
        # 1. Request OTP
        reg_resp = self.client.post(
            "/api/auth/register/",
            {"phone_number": phone, "display_name": display_name},
            format="json",
        )
        self.assertEqual(reg_resp.status_code, status.HTTP_200_OK)
        otp_code = reg_resp.data["debug_otp_code"]

        # 2. Verify OTP
        verify_resp = self.client.post(
            "/api/auth/otp/verify/",
            {"phone_number": phone, "code": otp_code},
            format="json",
        )
        self.assertEqual(verify_resp.status_code, status.HTTP_200_OK)
        token = verify_resp.data["token"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")

        # 3. Set @handle if provided
        if handle:
            handle_resp = self.client.post(
                "/api/profile/handle/",
                {"handle": handle},
                format="json",
            )
            self.assertEqual(handle_resp.status_code, status.HTTP_200_OK)

        # 4. Link Stellar wallet if keypair provided
        if keypair:
            chal_resp = self.client.post(
                "/api/wallet/challenge/",
                {"public_key": keypair.public_key},
                format="json",
            )
            self.assertEqual(chal_resp.status_code, status.HTTP_200_OK)
            challenge_id = chal_resp.data["challenge_id"]

            if sign_mode == "xdr":
                envelope = TransactionEnvelope.from_xdr(
                    chal_resp.data["challenge_xdr"],
                    network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
                )
                envelope.sign(keypair)
                link_resp = self.client.post(
                    "/api/wallet/verify/",
                    {
                        "challenge_id": challenge_id,
                        "public_key": keypair.public_key,
                        "signed_xdr": envelope.to_xdr(),
                    },
                    format="json",
                )
            else:
                sig_bytes = keypair.sign(chal_resp.data["challenge_message"].encode("utf-8"))
                sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
                link_resp = self.client.post(
                    "/api/wallet/verify/",
                    {
                        "challenge_id": challenge_id,
                        "public_key": keypair.public_key,
                        "signature": sig_b64,
                    },
                    format="json",
                )
            self.assertEqual(link_resp.status_code, status.HTTP_200_OK)

        user = User.objects.get(phone_number=phone)
        return user, token

    def test_health_check_endpoint(self):
        resp = self.client.get("/api/health/")
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["status"], "ok")
        self.assertEqual(resp.data["stellar"]["usdc_asset_code"], "USDC")

    def test_otp_cooldown_expiry_and_retry_limits(self):
        # 1. Send OTP
        resp1 = self.client.post(
            "/api/auth/register/",
            {"phone_number": self.alice_phone},
            format="json",
        )
        self.assertEqual(resp1.status_code, status.HTTP_200_OK)

        # 2. Immediate resend should be blocked by cooldown
        resp_cooldown = self.client.post(
            "/api/auth/register/",
            {"phone_number": self.alice_phone},
            format="json",
        )
        self.assertEqual(resp_cooldown.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(resp_cooldown.data["error"]["code"], "otp_resend_cooldown")

        # 3. Exhaust retry attempts (max_attempts=3)
        for expected_remaining in (2, 1):
            bad_resp = self.client.post(
                "/api/auth/otp/verify/",
                {"phone_number": self.alice_phone, "code": "000000"},
                format="json",
            )
            self.assertEqual(bad_resp.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(bad_resp.data["error"]["code"], "otp_invalid_code")
            self.assertEqual(
                bad_resp.data["error"]["details"]["remaining_attempts"],
                expected_remaining,
            )

        exhausted_resp = self.client.post(
            "/api/auth/otp/verify/",
            {"phone_number": self.alice_phone, "code": "000000"},
            format="json",
        )
        self.assertEqual(exhausted_resp.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(exhausted_resp.data["error"]["code"], "otp_attempts_exceeded")

        # 4. Test expired OTP
        OTPVerification.objects.filter(phone_number=self.alice_phone).delete()
        resp2 = self.client.post(
            "/api/auth/register/",
            {"phone_number": self.alice_phone},
            format="json",
        )
        otp_code = resp2.data["debug_otp_code"]
        OTPVerification.objects.filter(phone_number=self.alice_phone).update(
            expires_at=timezone.now() - timedelta(seconds=10)
        )
        expired_resp = self.client.post(
            "/api/auth/otp/verify/",
            {"phone_number": self.alice_phone, "code": otp_code},
            format="json",
        )
        self.assertEqual(expired_resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(expired_resp.data["error"]["code"], "otp_expired")

    def test_deliverable_1_identity_handles_wallet_and_recipient_lookup(self):
        # Register Alice (signs XDR challenge) and Bob (signs message challenge)
        alice, alice_token = self._register_and_verify_user(
            phone=self.alice_phone,
            display_name="Alice Pingly",
            handle="@AlicePay",
            keypair=self.alice_kp,
            sign_mode="xdr",
        )
        bob, bob_token = self._register_and_verify_user(
            phone=self.bob_phone,
            display_name="Bob Stellar",
            handle="bob_stellar",
            keypair=self.bob_kp,
            sign_mode="message",
        )

        self.assertTrue(alice.is_onboarding_complete)
        self.assertEqual(alice.formatted_handle, "@alicepay")
        self.assertTrue(bob.is_onboarding_complete)
        self.assertEqual(bob.formatted_handle, "@bob_stellar")

        # Case-insensitive handle uniqueness check
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {bob_token}")
        dup_handle_resp = self.client.post(
            "/api/profile/handle/",
            {"handle": "@ALICEPAY"},
            format="json",
        )
        self.assertEqual(dup_handle_resp.status_code, status.HTTP_400_BAD_REQUEST)

        # Handle availability check endpoint
        avail_resp = self.client.get("/api/handles/check/?handle=@AlicePay")
        self.assertEqual(avail_resp.status_code, status.HTTP_200_OK)
        self.assertFalse(avail_resp.data["is_available"])

        free_resp = self.client.get("/api/handles/check/?handle=@charlie_99")
        self.assertEqual(free_resp.status_code, status.HTTP_200_OK)
        self.assertTrue(free_resp.data["is_available"])

        # Prevent linking Alice's wallet to Bob's account
        dup_wallet_resp = self.client.post(
            "/api/wallet/challenge/",
            {"public_key": self.alice_kp.public_key},
            format="json",
        )
        self.assertEqual(dup_wallet_resp.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(dup_wallet_resp.data["error"]["code"], "wallet_already_linked")

        # Alice looks up Bob by @handle (case-insensitive)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {alice_token}")
        lookup_by_handle = self.client.get("/api/recipients/lookup/?q=@BOB_STELLAR")
        self.assertEqual(lookup_by_handle.status_code, status.HTTP_200_OK)
        self.assertEqual(
            lookup_by_handle.data["recipient"]["stellar_public_key"],
            self.bob_kp.public_key,
        )
        self.assertEqual(lookup_by_handle.data["recipient"]["handle"], "@bob_stellar")
        self.assertEqual(lookup_by_handle.data["recipient"]["display_name"], "Bob Stellar")
        self.assertIn("****", lookup_by_handle.data["recipient"]["masked_phone"])
        self.assertTrue(lookup_by_handle.data["can_receive_payments"])

        # Alice looks up Bob by phone number
        lookup_by_phone = self.client.get(f"/api/recipients/lookup/?q={self.bob_phone}")
        self.assertEqual(lookup_by_phone.status_code, status.HTTP_200_OK)
        self.assertEqual(
            lookup_by_phone.data["recipient"]["stellar_public_key"],
            self.bob_kp.public_key,
        )

    @patch("api.services.stellar_service.get_horizon_server")
    @patch("api.services.stellar_service.get_wallet_network_details")
    def test_deliverable_2_and_3_end_to_end_usdc_transfer_dashboard_and_history(
        self,
        mock_network_details,
        mock_get_server,
    ):
        alice, alice_token = self._register_and_verify_user(
            phone=self.alice_phone,
            display_name="Alice Pingly",
            handle="@alice",
            keypair=self.alice_kp,
        )
        bob, bob_token = self._register_and_verify_user(
            phone=self.bob_phone,
            display_name="Bob Stellar",
            handle="@bob",
            keypair=self.bob_kp,
        )

        def network_details_side_effect(pub_key, **kwargs):
            return {
                "public_key": pub_key,
                "network": "TESTNET",
                "account_exists": True,
                "has_usdc_trustline": True,
                "usdc_trustline_authorized": True,
                "usdc_balance": "250.0000000" if pub_key == self.alice_kp.public_key else "10.0000000",
                "xlm_balance": "99.5000000",
                "usdc_asset_code": "USDC",
                "usdc_asset_issuer": self.usdc_issuer,
                "sequence": "1001",
                "subentry_count": 1,
            }

        mock_network_details.side_effect = network_details_side_effect

        mock_server = MagicMock()
        mock_server.load_account.side_effect = lambda pub_key: Account(
            account=pub_key, sequence=1001
        )
        expected_tx_hash = "a" * 64
        mock_server.submit_transaction.return_value = {
            "successful": True,
            "hash": expected_tx_hash,
            "ledger": 543210,
        }
        mock_get_server.return_value = mock_server

        # Authenticate as Alice
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {alice_token}")

        # 1. Prepare a 25.50 USDC transfer to @bob
        prep_resp = self.client.post(
            "/api/transfers/prepare/",
            {
                "recipient": "@bob",
                "amount": "25.50",
                "memo": "Lunch split",
                "idempotency_key": "idem_alice_bob_001",
            },
            format="json",
        )
        self.assertEqual(prep_resp.status_code, status.HTTP_201_CREATED)
        preview = prep_resp.data["preview"]
        self.assertEqual(preview["amount"], "25.5000000")
        self.assertEqual(preview["asset_code"], "USDC")
        self.assertEqual(preview["recipient"]["handle"], "@bob")
        unsigned_xdr = preview["unsigned_xdr"]
        tx_id = preview["transaction_id"]

        # 2. Attempting to submit with Bob's signature instead of Alice's should fail
        tampered_env = TransactionEnvelope.from_xdr(
            unsigned_xdr,
            network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
        )
        tampered_env.sign(self.bob_kp)
        bad_sig_resp = self.client.post(
            "/api/transfers/submit/",
            {
                "transaction_id": tx_id,
                "signed_xdr": tampered_env.to_xdr(),
            },
            format="json",
        )
        self.assertEqual(bad_sig_resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(bad_sig_resp.data["error"]["code"], "invalid_transaction_signature")

        # 3. Sign with Alice's wallet keypair and submit
        valid_env = TransactionEnvelope.from_xdr(
            unsigned_xdr,
            network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
        )
        valid_env.sign(self.alice_kp)
        submit_resp = self.client.post(
            "/api/transfers/submit/",
            {
                "transaction_id": tx_id,
                "signed_xdr": valid_env.to_xdr(),
            },
            format="json",
        )
        self.assertEqual(submit_resp.status_code, status.HTTP_200_OK)
        tx_data = submit_resp.data["transaction"]
        self.assertEqual(tx_data["status"], "COMPLETED")
        self.assertEqual(tx_data["tx_hash"], expected_tx_hash)
        self.assertEqual(tx_data["direction"], "SENT")
        self.assertIn(
            f"https://stellar.expert/explorer/testnet/tx/{expected_tx_hash}",
            tx_data["explorer_url"],
        )

        # 4. Verify Alice's dashboard & transaction history
        dash_resp = self.client.get("/api/dashboard/")
        self.assertEqual(dash_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(dash_resp.data["wallet"]["usdc_balance"], "250.0000000")
        self.assertEqual(len(dash_resp.data["recent_transactions"]), 1)

        # 5. Verify Bob sees the transaction as RECEIVED in his history and detail view
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {bob_token}")
        bob_tx_list = self.client.get("/api/transactions/?direction=received")
        self.assertEqual(bob_tx_list.status_code, status.HTTP_200_OK)
        self.assertEqual(bob_tx_list.data["count"], 1)
        self.assertEqual(bob_tx_list.data["results"][0]["direction"], "RECEIVED")
        self.assertEqual(bob_tx_list.data["results"][0]["sender"]["handle"], "@alice")

        # Detail lookup by tx_hash
        detail_resp = self.client.get(f"/api/transactions/{expected_tx_hash}/")
        self.assertEqual(detail_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(detail_resp.data["id"], str(tx_id))

        # Receive screen info
        receive_resp = self.client.get("/api/wallet/receive/?amount=15")
        self.assertEqual(receive_resp.status_code, status.HTTP_200_OK)
        self.assertIn("web+stellar:pay?", receive_resp.data["sep7_uri"])

    @patch("api.services.stellar_service.get_wallet_network_details")
    def test_transfer_error_handling_insufficient_balance_and_missing_trustline(
        self,
        mock_network_details,
    ):
        alice, alice_token = self._register_and_verify_user(
            phone=self.alice_phone,
            display_name="Alice",
            handle="@alice",
            keypair=self.alice_kp,
        )
        bob, _ = self._register_and_verify_user(
            phone=self.bob_phone,
            display_name="Bob",
            handle="@bob",
            keypair=self.bob_kp,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {alice_token}")

        # Case 1: Insufficient USDC balance
        mock_network_details.side_effect = lambda pub_key, **kwargs: {
            "public_key": pub_key,
            "network": "TESTNET",
            "account_exists": True,
            "has_usdc_trustline": True,
            "usdc_balance": "5.0000000",
            "xlm_balance": "20.0000000",
            "usdc_asset_code": "USDC",
            "usdc_asset_issuer": self.usdc_issuer,
        }
        insufficient_resp = self.client.post(
            "/api/transfers/prepare/",
            {"recipient": "@bob", "amount": "50.00"},
            format="json",
        )
        self.assertEqual(insufficient_resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            insufficient_resp.data["error"]["code"],
            "insufficient_usdc_balance",
        )

        # Case 2: Recipient missing USDC trustline
        mock_network_details.side_effect = lambda pub_key, **kwargs: {
            "public_key": pub_key,
            "network": "TESTNET",
            "account_exists": True,
            "has_usdc_trustline": pub_key == self.alice_kp.public_key,
            "usdc_balance": "100.0000000",
            "xlm_balance": "20.0000000",
            "usdc_asset_code": "USDC",
            "usdc_asset_issuer": self.usdc_issuer,
        }
        no_trust_resp = self.client.post(
            "/api/transfers/prepare/",
            {"recipient": "@bob", "amount": "10.00"},
            format="json",
        )
        self.assertEqual(no_trust_resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            no_trust_resp.data["error"]["code"],
            "recipient_missing_trustline",
        )

        # Case 3: Self-transfer blocked
        self_resp = self.client.post(
            "/api/transfers/prepare/",
            {"recipient": "@alice", "amount": "5.00"},
            format="json",
        )
        self.assertEqual(self_resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            self_resp.data["error"]["code"],
            "self_transfer_not_allowed",
        )

    @patch("api.services.stellar_service.get_horizon_server")
    @patch("api.services.stellar_service.get_wallet_network_details")
    def test_trustline_prepare_horizon_failure_and_network_sync(
        self,
        mock_network_details,
        mock_get_server,
    ):
        alice, alice_token = self._register_and_verify_user(
            phone=self.alice_phone,
            display_name="Alice",
            handle="@alice",
            keypair=self.alice_kp,
        )
        bob, _ = self._register_and_verify_user(
            phone=self.bob_phone,
            display_name="Bob",
            handle="@bob",
            keypair=self.bob_kp,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {alice_token}")

        mock_server = MagicMock()
        mock_server.load_account.side_effect = lambda pub_key: Account(
            account=pub_key, sequence=2001
        )
        mock_get_server.return_value = mock_server

        # 1. Prepare USDC trustline ChangeTrust XDR
        trust_resp = self.client.post("/api/wallet/trustline/prepare/")
        self.assertEqual(trust_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(trust_resp.data["asset_code"], "USDC")
        self.assertTrue(len(trust_resp.data["unsigned_xdr"]) > 20)

        # 2. Test Horizon BadRequestError (op_underfunded) persists FAILED status on Transaction
        mock_network_details.return_value = {
            "public_key": self.alice_kp.public_key,
            "network": "TESTNET",
            "account_exists": True,
            "has_usdc_trustline": True,
            "usdc_balance": "100.0000000",
            "xlm_balance": "20.0000000",
            "usdc_asset_code": "USDC",
            "usdc_asset_issuer": self.usdc_issuer,
        }
        prep_resp = self.client.post(
            "/api/transfers/prepare/",
            {"recipient": "@bob", "amount": "15.00"},
            format="json",
        )
        tx_id = prep_resp.data["preview"]["transaction_id"]
        env = TransactionEnvelope.from_xdr(
            prep_resp.data["preview"]["unsigned_xdr"],
            network_passphrase=Network.TESTNET_NETWORK_PASSPHRASE,
        )
        env.sign(self.alice_kp)

        mock_bad_req = BadRequestError(MagicMock(status_code=400, text="{}"))
        mock_bad_req.extras = {
            "result_codes": {
                "transaction": "tx_failed",
                "operations": ["op_underfunded"],
            }
        }
        mock_server.submit_transaction.side_effect = mock_bad_req

        fail_submit = self.client.post(
            "/api/transfers/submit/",
            {"transaction_id": tx_id, "signed_xdr": env.to_xdr()},
            format="json",
        )
        self.assertEqual(fail_submit.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(fail_submit.data["error"]["code"], "op_underfunded")

        tx_obj = Transaction.objects.get(id=tx_id)
        self.assertEqual(tx_obj.status, Transaction.Status.FAILED)
        self.assertEqual(tx_obj.error_code, "op_underfunded")

        # 3. Test syncing external USDC payments from Horizon
        synced_hash = "b" * 64
        mock_server.payments.return_value.for_account.return_value.order.return_value.limit.return_value.call.return_value = {
            "_embedded": {
                "records": [
                    {
                        "type": "payment",
                        "asset_code": "USDC",
                        "asset_issuer": self.usdc_issuer,
                        "from": self.bob_kp.public_key,
                        "to": self.alice_kp.public_key,
                        "amount": "42.0000000",
                        "transaction_hash": synced_hash,
                        "transaction_successful": True,
                    }
                ]
            }
        }
        sync_resp = self.client.post("/api/transactions/sync/")
        self.assertEqual(sync_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(sync_resp.data["synced_count"], 1)
        self.assertTrue(Transaction.objects.filter(tx_hash=synced_hash).exists())

    def test_openapi_schema_swagger_and_redoc_endpoints(self):
        schema_resp = self.client.get("/api/schema/")
        self.assertEqual(schema_resp.status_code, status.HTTP_200_OK)
        schema_json = schema_resp.json()
        self.assertEqual(schema_json["openapi"], "3.0.3")
        self.assertIn("/api/transfers/prepare/", schema_json["paths"])
        self.assertIn("/api/wallet/challenge/", schema_json["paths"])
        self.assertIn("TokenAuth", schema_json["components"]["securitySchemes"])

        swagger_resp = self.client.get("/api/docs/")
        self.assertEqual(swagger_resp.status_code, status.HTTP_200_OK)
        self.assertIn(b"SwaggerUIBundle", swagger_resp.content)

        redoc_resp = self.client.get("/api/redoc/")
        self.assertEqual(redoc_resp.status_code, status.HTTP_200_OK)
        self.assertIn(b"Redoc.init", redoc_resp.content)
        self.assertIn(b"redoc.standalone.js", redoc_resp.content)

    def test_input_sanitization_and_validation_controls(self):
        # 1. Reject HTML/script tags in display_name during registration
        xss_resp = self.client.post(
            "/api/auth/register/",
            {
                "phone_number": self.alice_phone,
                "display_name": "<script>alert('xss')</script>",
            },
            format="json",
            HTTP_X_REQUEST_ID="req_custom_123",
        )
        self.assertEqual(xss_resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(xss_resp["X-Request-ID"], "req_custom_123")

        # 2. Register Alice cleanly and test whitespace normalization & reserved handle rejection
        alice, alice_token = self._register_and_verify_user(
            phone=self.alice_phone,
            display_name="  Alice   \t\n  Pingly  ",
            handle="@alice_clean",
            keypair=self.alice_kp,
        )
        # Control chars / newlines stripped and extra spaces collapsed
        self.assertEqual(alice.display_name, "Alice Pingly")

        self.client.credentials(HTTP_AUTHORIZATION=f"Token {alice_token}")
        reserved_resp = self.client.post(
            "/api/profile/handle/",
            {"handle": "@admin"},
            format="json",
        )
        self.assertEqual(reserved_resp.status_code, status.HTTP_400_BAD_REQUEST)

        # 3. Reject HTML tags in memo and invalid Idempotency-Key on transfer prepare
        bad_memo_resp = self.client.post(
            "/api/transfers/prepare/",
            {
                "recipient": "@bob",
                "amount": "10.00",
                "memo": "<b>bad</b>",
            },
            format="json",
        )
        self.assertEqual(bad_memo_resp.status_code, status.HTTP_400_BAD_REQUEST)

        bad_idem_resp = self.client.post(
            "/api/transfers/prepare/",
            {
                "recipient": "@bob",
                "amount": "10.00",
                "idempotency_key": "bad key with spaces!",
            },
            format="json",
        )
        self.assertEqual(bad_idem_resp.status_code, status.HTTP_400_BAD_REQUEST)

        # 4. Reject non-base64 XDR on transfer submit
        bad_xdr_resp = self.client.post(
            "/api/transfers/submit/",
            {
                "idempotency_key": "valid_idem_123",
                "signed_xdr": "not-valid-base64!!!",
            },
            format="json",
        )
        self.assertEqual(bad_xdr_resp.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(
        SMS_PROVIDER="auto",
        TWILIO_ACCOUNT_SID="AC_TEST_ACCOUNT_SID_FOR_MOCKING",
        TWILIO_AUTH_TOKEN="test_auth_token_secret",
        TWILIO_PHONE_NUMBER="+15005550006",
        TWILIO_MESSAGING_SERVICE_SID="",
        OTP_DEBUG_RETURN_CODE=False,
        SMS_FAIL_SILENTLY=False,
    )
    @patch("api.services.sms_service.requests.post")
    def test_twilio_sms_delivery_and_strict_failure_rollback(self, mock_post):
        # 1. Successful Twilio 201 delivery
        ok_resp = MagicMock()
        ok_resp.status_code = 201
        ok_resp.content = b'{"sid": "SM1234567890"}'
        ok_resp.json.return_value = {"sid": "SM1234567890"}
        mock_post.return_value = ok_resp

        reg_resp = self.client.post(
            "/api/auth/register/",
            {"phone_number": self.alice_phone, "display_name": "Alice"},
            format="json",
        )
        self.assertEqual(reg_resp.status_code, status.HTTP_200_OK)
        self.assertEqual(reg_resp.data["sms_delivery"]["provider"], "twilio")
        self.assertTrue(reg_resp.data["sms_delivery"]["delivered"])
        self.assertNotIn("debug_otp_code", reg_resp.data)

        mock_post.assert_called_once()
        called_url = mock_post.call_args[0][0]
        called_data = mock_post.call_args[1]["data"]
        self.assertIn("AC_TEST_ACCOUNT_SID_FOR_MOCKING/Messages.json", called_url)
        self.assertEqual(called_data["To"], self.alice_phone)
        self.assertEqual(called_data["From"], "+15005550006")
        self.assertIn("Your Pingly verification code is ", called_data["Body"])

        # 2. Failed Twilio delivery in strict mode rolls back OTP so user is not blocked by cooldown
        fail_resp = MagicMock()
        fail_resp.status_code = 400
        fail_resp.content = b'{"code": 21608, "message": "Unverified number"}'
        fail_resp.json.return_value = {"code": 21608, "message": "Unverified number"}
        mock_post.return_value = fail_resp

        bob_resp = self.client.post(
            "/api/auth/register/",
            {"phone_number": self.bob_phone},
            format="json",
        )
        self.assertEqual(bob_resp.status_code, status.HTTP_502_BAD_GATEWAY)
        self.assertEqual(bob_resp.data["error"]["code"], "sms_delivery_failed")
        self.assertFalse(OTPVerification.objects.filter(phone_number=self.bob_phone).exists())



