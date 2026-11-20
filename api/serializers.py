from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from api.models import (
    Transaction,
    User,
    WalletChallenge,
    mask_phone_number,
)
from api.validators import (
    sanitize_text,
    validate_display_name,
    validate_handle_format,
    validate_idempotency_key,
    validate_memo_text,
    validate_phone_number,
    validate_positive_usdc_amount,
    validate_search_query,
    validate_stellar_public_key,
    validate_tx_hash,
    validate_xdr_string,
)


class UserProfileSerializer(serializers.ModelSerializer):
    handle = serializers.SerializerMethodField()
    raw_handle = serializers.CharField(source="handle", read_only=True)
    masked_phone = serializers.CharField(read_only=True)
    has_linked_wallet = serializers.BooleanField(read_only=True)
    onboarding_stage = serializers.CharField(read_only=True)
    is_onboarding_complete = serializers.BooleanField(read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "phone_number",
            "masked_phone",
            "handle",
            "raw_handle",
            "display_name",
            "is_phone_verified",
            "phone_verified_at",
            "stellar_public_key",
            "wallet_verified_at",
            "has_linked_wallet",
            "onboarding_stage",
            "is_onboarding_complete",
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields

    def get_handle(self, obj: User) -> str | None:
        return obj.formatted_handle


class ProfileUpdateSerializer(serializers.Serializer):
    display_name = serializers.CharField(max_length=100, required=False, allow_blank=True)
    handle = serializers.CharField(max_length=35, required=False)

    def validate_display_name(self, value: str) -> str:
        try:
            return validate_display_name(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc

    def validate_handle(self, value: str) -> str:
        try:
            normalized = validate_handle_format(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc

        user = self.context.get("user")
        qs = User.objects.filter(handle__iexact=normalized)
        if user:
            qs = qs.exclude(pk=user.pk)
        if qs.exists():
            raise serializers.ValidationError(f"Handle '@{normalized}' is already taken.")
        return normalized


class HandleSetSerializer(serializers.Serializer):
    handle = serializers.CharField(max_length=35, required=True)

    def validate_handle(self, value: str) -> str:
        try:
            normalized = validate_handle_format(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc

        user = self.context.get("user")
        qs = User.objects.filter(handle__iexact=normalized)
        if user:
            qs = qs.exclude(pk=user.pk)
        if qs.exists():
            raise serializers.ValidationError(f"Handle '@{normalized}' is already taken.")
        return normalized


class OTPRequestSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=30, required=True)
    display_name = serializers.CharField(max_length=100, required=False, allow_blank=True)

    def validate_phone_number(self, value: str) -> str:
        try:
            return validate_phone_number(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc

    def validate_display_name(self, value: str) -> str:
        try:
            return validate_display_name(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc


class OTPVerifySerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=30, required=True)
    code = serializers.CharField(max_length=10, required=True)
    display_name = serializers.CharField(max_length=100, required=False, allow_blank=True)

    def validate_phone_number(self, value: str) -> str:
        try:
            return validate_phone_number(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc

    def validate_code(self, value: str) -> str:
        try:
            return sanitize_text(value, max_length=10, field_name="OTP code")
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc

    def validate_display_name(self, value: str) -> str:
        try:
            return validate_display_name(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc


class WalletChallengeRequestSerializer(serializers.Serializer):
    public_key = serializers.CharField(max_length=64, required=True)

    def validate_public_key(self, value: str) -> str:
        try:
            return validate_stellar_public_key(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc


class WalletChallengeResponseSerializer(serializers.ModelSerializer):
    challenge_id = serializers.UUIDField(source="id", read_only=True)

    class Meta:
        model = WalletChallenge
        fields = [
            "challenge_id",
            "public_key",
            "nonce",
            "challenge_message",
            "challenge_xdr",
            "expires_at",
        ]


class WalletVerifySerializer(serializers.Serializer):
    challenge_id = serializers.UUIDField(required=False)
    public_key = serializers.CharField(max_length=64, required=False)
    signed_xdr = serializers.CharField(required=False, allow_blank=False, max_length=16384)
    signature = serializers.CharField(required=False, allow_blank=False, max_length=512)

    def validate_public_key(self, value: str) -> str:
        try:
            return validate_stellar_public_key(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc

    def validate_signed_xdr(self, value: str) -> str:
        try:
            return validate_xdr_string(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc

    def validate_signature(self, value: str) -> str:
        try:
            return sanitize_text(value, max_length=512, field_name="Signature")
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc


class RecipientConfirmationSerializer(serializers.ModelSerializer):
    handle = serializers.SerializerMethodField()
    masked_phone = serializers.CharField(read_only=True)
    has_linked_wallet = serializers.BooleanField(read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "display_name",
            "handle",
            "masked_phone",
            "stellar_public_key",
            "has_linked_wallet",
        ]

    def get_handle(self, obj: User) -> str | None:
        return obj.formatted_handle


class TransferPrepareRequestSerializer(serializers.Serializer):
    recipient = serializers.CharField(
        max_length=64,
        required=True,
        help_text="Recipient verified phone number (E.164) or @handle.",
    )
    amount = serializers.DecimalField(
        max_digits=20,
        decimal_places=7,
        required=True,
        help_text="Amount of USDC to send.",
    )
    memo = serializers.CharField(
        max_length=28,
        required=False,
        allow_blank=True,
        default="",
    )
    idempotency_key = serializers.CharField(
        max_length=128,
        required=False,
        allow_blank=True,
    )

    def validate_recipient(self, value: str) -> str:
        try:
            return validate_search_query(value, max_length=64)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc

    def validate_amount(self, value):
        try:
            return validate_positive_usdc_amount(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc

    def validate_memo(self, value: str) -> str:
        try:
            return validate_memo_text(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc

    def validate_idempotency_key(self, value: str) -> str | None:
        try:
            return validate_idempotency_key(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc


class TransferSubmitRequestSerializer(serializers.Serializer):
    transaction_id = serializers.UUIDField(required=False)
    idempotency_key = serializers.CharField(max_length=128, required=False)
    signed_xdr = serializers.CharField(required=True, max_length=16384)

    def validate_idempotency_key(self, value: str) -> str | None:
        try:
            return validate_idempotency_key(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc

    def validate_signed_xdr(self, value: str) -> str:
        try:
            return validate_xdr_string(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc


class TransferVerifyRequestSerializer(serializers.Serializer):
    tx_hash = serializers.CharField(max_length=64, required=True)
    transaction_id = serializers.UUIDField(required=False)

    def validate_tx_hash(self, value: str) -> str:
        try:
            return validate_tx_hash(value)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages[0]) from exc


class TransactionSerializer(serializers.ModelSerializer):
    transaction_id = serializers.UUIDField(source="id", read_only=True)
    direction = serializers.SerializerMethodField()
    fee_xlm = serializers.CharField(read_only=True)
    explorer_url = serializers.CharField(read_only=True)
    sender = serializers.SerializerMethodField()
    recipient = serializers.SerializerMethodField()
    amount = serializers.SerializerMethodField()

    class Meta:
        model = Transaction
        fields = [
            "id",
            "transaction_id",
            "idempotency_key",
            "direction",
            "amount",
            "asset_code",
            "asset_issuer",
            "fee_stroops",
            "fee_xlm",
            "memo",
            "status",
            "tx_hash",
            "ledger",
            "explorer_url",
            "error_code",
            "failure_reason",
            "sender",
            "recipient",
            "sender_wallet",
            "recipient_wallet",
            "recipient_query",
            "unsigned_xdr",
            "created_at",
            "updated_at",
            "completed_at",
        ]

    def get_amount(self, obj: Transaction) -> str:
        return f"{obj.amount:.7f}"

    def get_direction(self, obj: Transaction) -> str:
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return "UNKNOWN"
        if obj.sender_id == user.id or (
            user.stellar_public_key and obj.sender_wallet == user.stellar_public_key
        ):
            return "SENT"
        if obj.recipient_id == user.id or (
            user.stellar_public_key and obj.recipient_wallet == user.stellar_public_key
        ):
            return "RECEIVED"
        return "UNKNOWN"

    def get_sender(self, obj: Transaction) -> dict:
        if obj.sender:
            return {
                "id": str(obj.sender.id),
                "display_name": obj.sender.display_name,
                "handle": obj.sender.formatted_handle,
                "masked_phone": obj.sender.masked_phone,
                "stellar_public_key": obj.sender_wallet,
            }
        return {
            "id": None,
            "display_name": "",
            "handle": None,
            "masked_phone": "",
            "stellar_public_key": obj.sender_wallet,
        }

    def get_recipient(self, obj: Transaction) -> dict:
        if obj.recipient:
            return {
                "id": str(obj.recipient.id),
                "display_name": obj.recipient.display_name,
                "handle": obj.recipient.formatted_handle,
                "masked_phone": obj.recipient.masked_phone,
                "stellar_public_key": obj.recipient_wallet,
            }
        return {
            "id": None,
            "display_name": "",
            "handle": None,
            "masked_phone": mask_phone_number(obj.recipient_query)
            if obj.recipient_query.startswith("+")
            else "",
            "stellar_public_key": obj.recipient_wallet,
        }
