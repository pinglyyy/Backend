import logging
import uuid
from urllib.parse import urlencode

from django.conf import settings
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db.models import Q
from rest_framework import generics, status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.exceptions import PinglyAPIError
from api.models import (
    Transaction,
    User,
)
from api.serializers import (
    HandleSetSerializer,
    OTPRequestSerializer,
    OTPVerifySerializer,
    ProfileUpdateSerializer,
    RecipientConfirmationSerializer,
    TransactionSerializer,
    TransferPrepareRequestSerializer,
    TransferSubmitRequestSerializer,
    TransferVerifyRequestSerializer,
    UserProfileSerializer,
    WalletChallengeRequestSerializer,
    WalletChallengeResponseSerializer,
    WalletVerifySerializer,
)
from api.services import otp_service, sms_service, stellar_service
from api.throttles import (
    HandleCheckRateThrottle,
    HealthRateThrottle,
    OTPSendRateThrottle,
    OTPVerifyRateThrottle,
    ProfileRateThrottle,
    RecipientLookupRateThrottle,
    TransactionReadRateThrottle,
    TransferPrepareRateThrottle,
    TransferSubmitRateThrottle,
    WalletActionRateThrottle,
    WalletReadRateThrottle,
)
from api.validators import (
    sanitize_text,
    validate_handle_format,
    validate_idempotency_key,
    validate_memo_text,
    validate_positive_usdc_amount,
    validate_search_query,
)

logger = logging.getLogger("api")


class HealthCheckView(APIView):
    """Public health check and Stellar Testnet configuration endpoint."""

    permission_classes = [AllowAny]
    throttle_classes = [HealthRateThrottle]

    def get(self, request):
        usdc_asset = stellar_service.get_usdc_asset()
        return Response(
            {
                "status": "ok",
                "service": "Pingly MVP Backend API",
                "docs": {
                    "swagger": "/api/docs/",
                    "redoc": "/api/redoc/",
                    "openapi_schema": "/api/schema/",
                },
                "sms": {
                    "provider": sms_service.get_active_sms_provider(),
                    "twilio_configured": sms_service.is_twilio_configured(),
                },
                "stellar": {
                    "network": getattr(settings, "STELLAR_NETWORK", "TESTNET"),
                    "network_passphrase": getattr(
                        settings,
                        "STELLAR_NETWORK_PASSPHRASE",
                        "Test SDF Network ; September 2015",
                    ),
                    "horizon_url": getattr(
                        settings,
                        "STELLAR_HORIZON_URL",
                        "https://horizon-testnet.stellar.org",
                    ),
                    "usdc_asset_code": usdc_asset.code,
                    "usdc_asset_issuer": usdc_asset.issuer,
                    "explorer_base_url": getattr(
                        settings,
                        "STELLAR_EXPLORER_BASE_URL",
                        "https://stellar.expert/explorer/testnet/tx",
                    ),
                },
            }
        )


class RegisterAndSendOTPView(APIView):
    """Register with a phone number or request a new SMS OTP code."""

    permission_classes = [AllowAny]
    throttle_classes = [OTPSendRateThrottle]

    def post(self, request):
        serializer = OTPRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        otp_info = otp_service.send_phone_otp(
            phone_number=serializer.validated_data["phone_number"],
            display_name=serializer.validated_data.get("display_name"),
        )
        return Response(
            {
                "message": "Verification code sent.",
                **otp_info,
            },
            status=status.HTTP_200_OK,
        )


class VerifyOTPView(APIView):
    """Verify SMS OTP code and issue an authentication token."""

    permission_classes = [AllowAny]
    throttle_classes = [OTPVerifyRateThrottle]

    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = otp_service.verify_phone_otp(
            phone_number=serializer.validated_data["phone_number"],
            code=serializer.validated_data["code"],
            display_name=serializer.validated_data.get("display_name"),
        )
        token, _ = Token.objects.get_or_create(user=user)
        return Response(
            {
                "message": "Phone number verified successfully.",
                "token": token.key,
                "user": UserProfileSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    """Invalidate the current user's authentication token."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [ProfileRateThrottle]

    def post(self, request):
        Token.objects.filter(user=request.user).delete()
        logger.info("user_logged_out user_id=%s", request.user.id)
        return Response(
            {"message": "Logged out successfully."},
            status=status.HTTP_200_OK,
        )


class ProfileView(APIView):
    """View or update the authenticated user's profile details and @handle."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [ProfileRateThrottle]

    def get(self, request):
        return Response(UserProfileSerializer(request.user).data)

    def patch(self, request):
        serializer = ProfileUpdateSerializer(
            data=request.data,
            context={"user": request.user},
        )
        serializer.is_valid(raise_exception=True)

        user: User = request.user
        update_fields = ["updated_at"]

        if "display_name" in serializer.validated_data:
            user.display_name = serializer.validated_data["display_name"]
            update_fields.append("display_name")

        if "handle" in serializer.validated_data:
            if not user.is_phone_verified:
                raise PinglyAPIError(
                    message="Verify your phone number before creating a @handle.",
                    code="phone_not_verified",
                    status_code=status.HTTP_403_FORBIDDEN,
                )
            user.handle = serializer.validated_data["handle"]
            update_fields.append("handle")

        user.save(update_fields=update_fields)
        logger.info("profile_updated user_id=%s fields=%s", user.id, update_fields)
        return Response(UserProfileSerializer(user).data)


class SetHandleView(APIView):
    """Create or update the authenticated user's unique @handle."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [ProfileRateThrottle]

    def post(self, request):
        user: User = request.user
        if not user.is_phone_verified:
            raise PinglyAPIError(
                message="Verify your phone number before creating a @handle.",
                code="phone_not_verified",
                status_code=status.HTTP_403_FORBIDDEN,
            )

        serializer = HandleSetSerializer(
            data=request.data,
            context={"user": user},
        )
        serializer.is_valid(raise_exception=True)
        user.handle = serializer.validated_data["handle"]
        user.save(update_fields=["handle", "updated_at"])
        logger.info("handle_updated user_id=%s handle=@%s", user.id, user.handle)

        return Response(
            {
                "message": f"Handle {user.formatted_handle} saved.",
                "user": UserProfileSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )


class HandleAvailabilityView(APIView):
    """Check whether a @handle is valid and available (case-insensitive)."""

    permission_classes = [AllowAny]
    throttle_classes = [HandleCheckRateThrottle]

    def get(self, request):
        raw_handle = request.query_params.get("handle", "")
        try:
            normalized = validate_handle_format(raw_handle)
        except DjangoValidationError as exc:
            return Response(
                {
                    "handle": sanitize_text(raw_handle, max_length=35, reject_html=False),
                    "normalized_handle": None,
                    "is_valid": False,
                    "is_available": False,
                    "reason": exc.messages[0],
                },
                status=status.HTTP_200_OK,
            )

        qs = User.objects.filter(handle__iexact=normalized)
        if request.user and request.user.is_authenticated:
            qs = qs.exclude(pk=request.user.pk)

        available = not qs.exists()
        return Response(
            {
                "handle": f"@{normalized}",
                "normalized_handle": normalized,
                "is_valid": True,
                "is_available": available,
                "reason": None if available else f"Handle '@{normalized}' is already taken.",
            },
            status=status.HTTP_200_OK,
        )


class WalletChallengeView(APIView):
    """Issue a cryptographic challenge to verify ownership of a Stellar public key."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [WalletActionRateThrottle]

    def post(self, request):
        serializer = WalletChallengeRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        challenge = stellar_service.create_wallet_challenge(
            user=request.user,
            public_key=serializer.validated_data["public_key"],
        )
        return Response(
            WalletChallengeResponseSerializer(challenge).data,
            status=status.HTTP_200_OK,
        )


class WalletVerifyView(APIView):
    """Verify signed challenge and link Stellar wallet to the user's Pingly identity."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [WalletActionRateThrottle]

    def post(self, request):
        serializer = WalletVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = stellar_service.verify_and_link_wallet(
            user=request.user,
            challenge_id=serializer.validated_data.get("challenge_id"),
            public_key=serializer.validated_data.get("public_key"),
            signed_xdr=serializer.validated_data.get("signed_xdr"),
            signature=serializer.validated_data.get("signature"),
        )

        if user.stellar_public_key:
            Transaction.objects.filter(
                sender__isnull=True,
                sender_wallet=user.stellar_public_key,
            ).update(sender=user)
            Transaction.objects.filter(
                recipient__isnull=True,
                recipient_wallet=user.stellar_public_key,
            ).update(recipient=user)

        return Response(
            {
                "message": "Stellar wallet verified and linked successfully.",
                "user": UserProfileSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )


class WalletUnlinkView(APIView):
    """Unlink the currently connected Stellar wallet from the user's profile."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [WalletActionRateThrottle]

    def delete(self, request):
        user: User = request.user
        old_key = user.stellar_public_key
        user.stellar_public_key = None
        user.wallet_verified_at = None
        user.save(update_fields=["stellar_public_key", "wallet_verified_at", "updated_at"])
        stellar_service.invalidate_wallet_cache(old_key)
        logger.info("wallet_unlinked user_id=%s old_public_key=%s", user.id, old_key)
        return Response(
            {
                "message": "Stellar wallet unlinked.",
                "user": UserProfileSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )


class RecipientLookupView(APIView):
    """
    Search for a recipient by verified phone number or @handle (case-insensitive).
    Returns recipient display name, @handle, masked phone identity, and Stellar public key.
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [RecipientLookupRateThrottle]

    def get(self, request):
        query = (
            request.query_params.get("q")
            or request.query_params.get("handle")
            or request.query_params.get("phone")
            or ""
        )
        recipient = stellar_service.resolve_recipient_user(query)
        return Response(
            {
                "recipient": RecipientConfirmationSerializer(recipient).data,
                "is_self": recipient.id == request.user.id,
                "can_receive_payments": recipient.has_linked_wallet and recipient.id != request.user.id,
            },
            status=status.HTTP_200_OK,
        )


class WalletBalanceView(APIView):
    """Query live Stellar Testnet USDC & XLM balances for the user's connected wallet."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [WalletReadRateThrottle]

    def get(self, request):
        user: User = request.user
        if not user.has_linked_wallet:
            raise PinglyAPIError(
                message="No Stellar wallet is linked to your account yet.",
                code="wallet_not_linked",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        details = stellar_service.get_wallet_network_details(user.stellar_public_key)
        return Response(details, status=status.HTTP_200_OK)


class WalletTrustlinePrepareView(APIView):
    """Prepare an unsigned Stellar ChangeTrust transaction to enable Testnet USDC."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [WalletActionRateThrottle]

    def post(self, request):
        user: User = request.user
        if not user.has_linked_wallet:
            raise PinglyAPIError(
                message="No Stellar wallet is linked to your account yet.",
                code="wallet_not_linked",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        payload = stellar_service.build_usdc_trustline_transaction(user.stellar_public_key)
        return Response(payload, status=status.HTTP_200_OK)


class WalletFundTestnetView(APIView):
    """Fund the user's linked Stellar wallet on Testnet using Friendbot."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [WalletActionRateThrottle]

    def post(self, request):
        user: User = request.user
        if not user.has_linked_wallet:
            raise PinglyAPIError(
                message="No Stellar wallet is linked to your account yet.",
                code="wallet_not_linked",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        payload = stellar_service.fund_testnet_account(user.stellar_public_key)
        return Response(payload, status=status.HTTP_200_OK)


class ReceiveInfoView(APIView):
    """Return Receive screen details: @handle, verified phone identity, wallet address, and QR payload."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [WalletReadRateThrottle]

    def get(self, request):
        user: User = request.user
        usdc_asset = stellar_service.get_usdc_asset()
        raw_amount = request.query_params.get("amount")
        raw_memo = request.query_params.get("memo")

        cleaned_amount = None
        if raw_amount is not None and str(raw_amount).strip():
            try:
                cleaned_amount = f"{validate_positive_usdc_amount(raw_amount):.7f}"
            except DjangoValidationError as exc:
                raise PinglyAPIError(
                    message=exc.messages[0],
                    code="invalid_amount",
                    status_code=status.HTTP_400_BAD_REQUEST,
                ) from exc

        cleaned_memo = None
        if raw_memo is not None and str(raw_memo).strip():
            try:
                cleaned_memo = validate_memo_text(raw_memo)
            except DjangoValidationError as exc:
                raise PinglyAPIError(
                    message=exc.messages[0],
                    code="invalid_memo",
                    status_code=status.HTTP_400_BAD_REQUEST,
                ) from exc

        sep7_uri = None
        if user.stellar_public_key:
            params = {
                "destination": user.stellar_public_key,
                "asset_code": usdc_asset.code,
                "asset_issuer": usdc_asset.issuer,
            }
            if cleaned_amount:
                params["amount"] = cleaned_amount
            if cleaned_memo:
                params["memo"] = cleaned_memo
            sep7_uri = f"web+stellar:pay?{urlencode(params)}"

        return Response(
            {
                "handle": user.formatted_handle,
                "display_name": user.display_name,
                "phone_number": user.phone_number,
                "masked_phone": user.masked_phone,
                "is_phone_verified": user.is_phone_verified,
                "stellar_public_key": user.stellar_public_key,
                "has_linked_wallet": user.has_linked_wallet,
                "asset_code": usdc_asset.code,
                "asset_issuer": usdc_asset.issuer,
                "sep7_uri": sep7_uri,
                "qr_payload": sep7_uri or user.formatted_handle or user.phone_number,
            },
            status=status.HTTP_200_OK,
        )


class DashboardView(APIView):
    """
    Aggregate Wallet Dashboard data:
    - User profile & onboarding status
    - Connected wallet & live USDC / XLM balances
    - Recent sent & received transactions
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [WalletReadRateThrottle]

    def get(self, request):
        user: User = request.user
        wallet_info = None
        wallet_error = None

        if user.has_linked_wallet:
            try:
                wallet_info = stellar_service.get_wallet_network_details(user.stellar_public_key)
            except PinglyAPIError as exc:
                wallet_error = {
                    "code": exc.code,
                    "message": exc.message,
                }
                usdc_asset = stellar_service.get_usdc_asset()
                wallet_info = {
                    "public_key": user.stellar_public_key,
                    "network": getattr(settings, "STELLAR_NETWORK", "TESTNET"),
                    "account_exists": None,
                    "has_usdc_trustline": None,
                    "usdc_balance": None,
                    "xlm_balance": None,
                    "usdc_asset_code": usdc_asset.code,
                    "usdc_asset_issuer": usdc_asset.issuer,
                }

        tx_filter = Q(sender=user) | Q(recipient=user)
        if user.stellar_public_key:
            tx_filter |= Q(sender_wallet=user.stellar_public_key) | Q(
                recipient_wallet=user.stellar_public_key
            )

        recent_txs = (
            Transaction.objects.select_related("sender", "recipient")
            .filter(tx_filter)
            .order_by("-created_at")[:10]
        )

        return Response(
            {
                "user": UserProfileSerializer(user).data,
                "wallet": wallet_info,
                "wallet_error": wallet_error,
                "recent_transactions": TransactionSerializer(
                    recent_txs,
                    many=True,
                    context={"request": request},
                ).data,
            },
            status=status.HTTP_200_OK,
        )


class TransferPrepareView(APIView):
    """
    Resolve recipient (@handle or phone number), verify balances & trustlines,
    and build an unsigned Stellar Testnet USDC payment transaction for wallet signing.
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [TransferPrepareRateThrottle]

    def post(self, request):
        serializer = TransferPrepareRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        header_idem_key = request.headers.get("Idempotency-Key")
        if header_idem_key:
            try:
                header_idem_key = validate_idempotency_key(header_idem_key)
            except DjangoValidationError as exc:
                raise PinglyAPIError(
                    message=exc.messages[0],
                    code="invalid_idempotency_key",
                    status_code=status.HTTP_400_BAD_REQUEST,
                ) from exc

        idempotency_key = serializer.validated_data.get("idempotency_key") or header_idem_key

        tx_record = stellar_service.prepare_usdc_transfer(
            sender=request.user,
            recipient_query=serializer.validated_data["recipient"],
            amount=serializer.validated_data["amount"],
            memo=serializer.validated_data.get("memo", ""),
            idempotency_key=idempotency_key,
        )

        tx_data = TransactionSerializer(tx_record, context={"request": request}).data
        return Response(
            {
                "message": "Transfer prepared. Sign 'unsigned_xdr' with your connected Stellar wallet to authorize payment.",
                "transfer": tx_data,
                "preview": {
                    "transaction_id": str(tx_record.id),
                    "idempotency_key": tx_record.idempotency_key,
                    "recipient": RecipientConfirmationSerializer(tx_record.recipient).data
                    if tx_record.recipient
                    else None,
                    "amount": f"{tx_record.amount:.7f}",
                    "asset_code": tx_record.asset_code,
                    "asset_issuer": tx_record.asset_issuer,
                    "fee_stroops": tx_record.fee_stroops,
                    "fee_xlm": tx_record.fee_xlm,
                    "memo": tx_record.memo,
                    "network_passphrase": getattr(
                        settings,
                        "STELLAR_NETWORK_PASSPHRASE",
                        "Test SDF Network ; September 2015",
                    ),
                    "unsigned_xdr": tx_record.unsigned_xdr,
                },
            },
            status=status.HTTP_201_CREATED,
        )


class TransferSubmitView(APIView):
    """Submit a wallet-signed Stellar Testnet USDC payment XDR to Horizon."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [TransferSubmitRateThrottle]

    def post(self, request):
        serializer = TransferSubmitRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        tx_record = stellar_service.submit_signed_transfer(
            user=request.user,
            signed_xdr=serializer.validated_data["signed_xdr"],
            transaction_id=serializer.validated_data.get("transaction_id"),
            idempotency_key=serializer.validated_data.get("idempotency_key"),
        )

        return Response(
            {
                "message": "Payment completed on Stellar Testnet.",
                "transaction": TransactionSerializer(
                    tx_record,
                    context={"request": request},
                ).data,
            },
            status=status.HTTP_200_OK,
        )


class TransferVerifyView(APIView):
    """Verify a submitted Stellar transaction hash directly against Stellar Testnet Horizon."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [TransferSubmitRateThrottle]

    def post(self, request):
        serializer = TransferVerifyRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        tx_record = stellar_service.verify_transaction_on_network(
            user=request.user,
            tx_hash=serializer.validated_data["tx_hash"],
            transaction_id=serializer.validated_data.get("transaction_id"),
        )

        return Response(
            {
                "message": "Transaction verified against Stellar Testnet.",
                "transaction": TransactionSerializer(
                    tx_record,
                    context={"request": request},
                ).data,
            },
            status=status.HTTP_200_OK,
        )


class TransactionListView(generics.ListAPIView):
    """
    Paginated transaction history for the authenticated user.
    Supports filtering by:
    - `direction`: `sent` | `received`
    - `status`: `PENDING` | `COMPLETED` | `FAILED`
    - `search`: query matching handle, display name, phone, wallet address, memo, or tx_hash
    """

    permission_classes = [IsAuthenticated]
    throttle_classes = [TransactionReadRateThrottle]
    serializer_class = TransactionSerializer

    def get_queryset(self):
        user: User = self.request.user
        sent_q = Q(sender=user)
        received_q = Q(recipient=user)
        if user.stellar_public_key:
            sent_q |= Q(sender_wallet=user.stellar_public_key)
            received_q |= Q(recipient_wallet=user.stellar_public_key)

        direction = (self.request.query_params.get("direction") or "").strip().lower()
        if direction == "sent":
            qs = Transaction.objects.filter(sent_q)
        elif direction == "received":
            qs = Transaction.objects.filter(received_q)
        else:
            qs = Transaction.objects.filter(sent_q | received_q)

        status_param = (self.request.query_params.get("status") or "").strip().upper()
        if status_param in Transaction.Status.values:
            qs = qs.filter(status=status_param)

        raw_search = self.request.query_params.get("search") or ""
        try:
            search = validate_search_query(raw_search, max_length=64)
        except DjangoValidationError as exc:
            raise PinglyAPIError(
                message=exc.messages[0],
                code="invalid_search_query",
                status_code=status.HTTP_400_BAD_REQUEST,
            ) from exc

        if search:
            clean_handle = search[1:] if search.startswith("@") else search
            qs = qs.filter(
                Q(tx_hash__icontains=search)
                | Q(memo__icontains=search)
                | Q(sender_wallet__icontains=search)
                | Q(recipient_wallet__icontains=search)
                | Q(sender__handle__icontains=clean_handle)
                | Q(recipient__handle__icontains=clean_handle)
                | Q(sender__display_name__icontains=search)
                | Q(recipient__display_name__icontains=search)
            )

        return qs.select_related("sender", "recipient").distinct().order_by("-created_at")


class TransactionDetailView(APIView):
    """Retrieve transaction details by internal UUID or Stellar transaction hash."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [TransactionReadRateThrottle]

    def get(self, request, id_or_hash: str):
        try:
            cleaned_lookup = validate_search_query(id_or_hash, max_length=64)
        except DjangoValidationError as exc:
            raise PinglyAPIError(
                message=exc.messages[0],
                code="invalid_transaction_reference",
                status_code=status.HTTP_400_BAD_REQUEST,
            ) from exc

        user: User = request.user
        user_filter = Q(sender=user) | Q(recipient=user)
        if user.stellar_public_key:
            user_filter |= Q(sender_wallet=user.stellar_public_key) | Q(
                recipient_wallet=user.stellar_public_key
            )

        lookup = Q(tx_hash__iexact=cleaned_lookup)
        try:
            parsed_uuid = uuid.UUID(cleaned_lookup)
            lookup |= Q(id=parsed_uuid)
        except ValueError:
            pass

        tx_record = (
            Transaction.objects.select_related("sender", "recipient")
            .filter(user_filter & lookup)
            .first()
        )
        if not tx_record:
            raise PinglyAPIError(
                message="Transaction not found.",
                code="transaction_not_found",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        return Response(
            TransactionSerializer(tx_record, context={"request": request}).data,
            status=status.HTTP_200_OK,
        )


class TransactionSyncView(APIView):
    """Sync incoming and outgoing Stellar Testnet USDC payments from Horizon."""

    permission_classes = [IsAuthenticated]
    throttle_classes = [TransactionReadRateThrottle]

    def post(self, request):
        synced_count = stellar_service.sync_wallet_transactions(user=request.user)
        return Response(
            {
                "message": f"Synced {synced_count} new transaction(s) from Stellar Testnet.",
                "synced_count": synced_count,
            },
            status=status.HTTP_200_OK,
        )
