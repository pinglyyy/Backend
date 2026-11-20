import uuid
from decimal import Decimal

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone

from api.validators import (
    E164_PHONE_REGEX,
    HANDLE_REGEX,
    normalize_handle,
    normalize_phone_number,
    validate_display_name,
    validate_handle_format,
    validate_phone_number,
    validate_stellar_public_key,
)


def mask_phone_number(phone: str) -> str:
    """Mask a phone number for recipient confirmation (e.g., +14155552671 -> +141****2671)."""
    if not phone:
        return ""
    if len(phone) <= 6:
        return phone[:2] + "*" * max(0, len(phone) - 2)
    prefix = phone[:4]
    suffix = phone[-4:]
    middle_len = max(3, len(phone) - 8)
    return f"{prefix}{'*' * middle_len}{suffix}"


class UserManager(BaseUserManager):
    """Custom manager for phone-number-based User accounts."""

    def create_user(self, phone_number: str, password: str | None = None, **extra_fields):
        normalized_phone = validate_phone_number(phone_number)
        if "handle" in extra_fields and extra_fields["handle"]:
            extra_fields["handle"] = validate_handle_format(extra_fields["handle"])
        if "stellar_public_key" in extra_fields and extra_fields["stellar_public_key"]:
            extra_fields["stellar_public_key"] = validate_stellar_public_key(
                extra_fields["stellar_public_key"]
            )

        user = self.model(phone_number=normalized_phone, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, phone_number: str, password: str | None = None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_phone_verified", True)
        extra_fields.setdefault("phone_verified_at", timezone.now())

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(phone_number=phone_number, password=password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Pingly user identified by verified phone number, unique @handle, and linked Stellar wallet."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    phone_number = models.CharField(max_length=20, unique=True, db_index=True)
    handle = models.CharField(max_length=30, unique=True, null=True, blank=True, db_index=True)
    display_name = models.CharField(max_length=100, blank=True, default="")

    is_phone_verified = models.BooleanField(default=False, db_index=True)
    phone_verified_at = models.DateTimeField(null=True, blank=True)

    stellar_public_key = models.CharField(
        max_length=56,
        unique=True,
        null=True,
        blank=True,
        db_index=True,
    )
    wallet_verified_at = models.DateTimeField(null=True, blank=True)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = "phone_number"
    REQUIRED_FIELDS = []

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        if self.handle:
            return f"@{self.handle} ({self.phone_number})"
        return self.phone_number

    def clean(self):
        super().clean()
        if self.phone_number:
            self.phone_number = validate_phone_number(self.phone_number)
        if self.display_name:
            self.display_name = validate_display_name(self.display_name)
        if self.handle:
            self.handle = validate_handle_format(self.handle)
        else:
            self.handle = None
        if self.stellar_public_key:
            self.stellar_public_key = validate_stellar_public_key(self.stellar_public_key)
        else:
            self.stellar_public_key = None

    @property
    def formatted_handle(self) -> str | None:
        return f"@{self.handle}" if self.handle else None

    @property
    def masked_phone(self) -> str:
        return mask_phone_number(self.phone_number)

    @property
    def has_linked_wallet(self) -> bool:
        return bool(self.stellar_public_key and self.wallet_verified_at)

    @property
    def onboarding_stage(self) -> str:
        if not self.is_phone_verified:
            return "PHONE_VERIFICATION_REQUIRED"
        if not self.handle:
            return "HANDLE_REQUIRED"
        if not self.has_linked_wallet:
            return "WALLET_REQUIRED"
        return "COMPLETED"

    @property
    def is_onboarding_complete(self) -> bool:
        return self.onboarding_stage == "COMPLETED"


class OTPVerification(models.Model):
    """Stores time-limited, attempt-limited SMS OTP codes for phone verification."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    phone_number = models.CharField(max_length=20, db_index=True)
    code_hash = models.CharField(max_length=128)
    attempts = models.PositiveSmallIntegerField(default=0)
    max_attempts = models.PositiveSmallIntegerField(default=5)
    is_used = models.BooleanField(default=False, db_index=True)
    expires_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["phone_number", "is_used", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"OTP for {self.phone_number} (used={self.is_used})"

    @property
    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at

    @property
    def is_exhausted(self) -> bool:
        return self.attempts >= self.max_attempts

    def set_code(self, raw_code: str) -> None:
        self.code_hash = make_password(raw_code)

    def check_code(self, raw_code: str) -> bool:
        return check_password(raw_code, self.code_hash)


class WalletChallenge(models.Model):
    """Cryptographic challenge (XDR + message nonce) to verify ownership of a Stellar wallet."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="wallet_challenges",
    )
    public_key = models.CharField(max_length=56, db_index=True)
    nonce = models.CharField(max_length=128, unique=True)
    challenge_message = models.TextField()
    challenge_xdr = models.TextField()
    is_used = models.BooleanField(default=False, db_index=True)
    expires_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"WalletChallenge({self.user_id}, {self.public_key[:8]}...)"

    @property
    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at


class Transaction(models.Model):
    """Tracks Stellar Testnet USDC P2P payment preparation, submission, and status."""

    class Status(models.TextChoices):
        PENDING = "PENDING", "Pending"
        COMPLETED = "COMPLETED", "Completed"
        FAILED = "FAILED", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    idempotency_key = models.CharField(max_length=128, unique=True, db_index=True)

    sender = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="sent_transactions",
    )
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="received_transactions",
    )

    sender_wallet = models.CharField(max_length=56, db_index=True)
    recipient_wallet = models.CharField(max_length=56, db_index=True)
    recipient_query = models.CharField(max_length=64, blank=True, default="")

    amount = models.DecimalField(max_digits=20, decimal_places=7)
    asset_code = models.CharField(max_length=12, default="USDC")
    asset_issuer = models.CharField(max_length=56)
    fee_stroops = models.PositiveIntegerField(default=100)
    memo = models.CharField(max_length=28, blank=True, default="")

    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    unsigned_xdr = models.TextField(blank=True, default="")
    signed_xdr = models.TextField(blank=True, default="")
    tx_hash = models.CharField(max_length=64, unique=True, null=True, blank=True, db_index=True)
    ledger = models.PositiveBigIntegerField(null=True, blank=True)

    error_code = models.CharField(max_length=64, blank=True, default="")
    failure_reason = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["sender_wallet", "-created_at"]),
            models.Index(fields=["recipient_wallet", "-created_at"]),
            models.Index(fields=["status", "-created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.amount} {self.asset_code} ({self.sender_wallet[:6]} -> {self.recipient_wallet[:6]}) [{self.status}]"

    @property
    def fee_xlm(self) -> str:
        return f"{(Decimal(self.fee_stroops) / Decimal('10000000')):.7f}"

    @property
    def explorer_url(self) -> str | None:
        if not self.tx_hash:
            return None
        base_url = getattr(
            settings,
            "STELLAR_EXPLORER_BASE_URL",
            "https://stellar.expert/explorer/testnet/tx",
        ).rstrip("/")
        return f"{base_url}/{self.tx_hash}"
