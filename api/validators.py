import base64
import binascii
import re
import unicodedata
from decimal import Decimal, InvalidOperation

from django.core.exceptions import ValidationError
from stellar_sdk import StrKey

E164_PHONE_REGEX = re.compile(r"^\+[1-9]\d{6,14}$")
HANDLE_REGEX = re.compile(r"^[a-z0-9_]{3,30}$")
TX_HASH_REGEX = re.compile(r"^[0-9a-f]{64}$")
IDEMPOTENCY_KEY_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.:]{4,128}$")
CONTROL_CHARS_REGEX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
HTML_TAG_REGEX = re.compile(r"<[^>]*>")

RESERVED_HANDLES = frozenset(
    {
        "admin",
        "administrator",
        "api",
        "auth",
        "dashboard",
        "help",
        "login",
        "logout",
        "me",
        "official",
        "pingly",
        "profile",
        "redoc",
        "register",
        "root",
        "schema",
        "security",
        "settings",
        "stellar",
        "support",
        "swagger",
        "system",
        "testnet",
        "usdc",
        "wallet",
    }
)


def sanitize_text(
    value: str | None,
    *,
    max_length: int | None = None,
    allow_newlines: bool = False,
    reject_html: bool = True,
    field_name: str = "Input",
) -> str:
    """
    Normalize Unicode (NFKC), strip null bytes and control characters,
    and optionally reject or strip HTML/script tags.
    """
    if value is None:
        return ""

    normalized = unicodedata.normalize("NFKC", str(value))
    normalized = CONTROL_CHARS_REGEX.sub("", normalized)

    if not allow_newlines:
        normalized = normalized.replace("\r", " ").replace("\n", " ").replace("\t", " ")
        normalized = re.sub(r" {2,}", " ", normalized)

    cleaned = normalized.strip()

    if reject_html and HTML_TAG_REGEX.search(cleaned):
        raise ValidationError(f"{field_name} cannot contain HTML or script tags.")

    if max_length is not None and len(cleaned) > max_length:
        raise ValidationError(f"{field_name} cannot exceed {max_length} characters.")

    return cleaned


def normalize_phone_number(phone: str) -> str:
    """Sanitize and normalize a phone number string into E.164 format (+1234567890)."""
    cleaned = sanitize_text(phone, max_length=30, field_name="Phone number")
    if not cleaned:
        return ""
    cleaned = re.sub(r"[\s\-\(\)\.]", "", cleaned)
    if cleaned and not cleaned.startswith("+") and cleaned.isdigit():
        cleaned = f"+{cleaned}"
    return cleaned


def validate_phone_number(phone: str) -> str:
    normalized = normalize_phone_number(phone)
    if not E164_PHONE_REGEX.match(normalized):
        raise ValidationError(
            "Enter a valid phone number in international E.164 format (e.g., +14155552671)."
        )
    return normalized


def normalize_handle(handle: str | None) -> str | None:
    """Sanitize and normalize a @handle to lowercase without leading '@'."""
    if handle is None:
        return None
    cleaned = sanitize_text(handle, max_length=35, field_name="Handle").lower()
    if cleaned.startswith("@"):
        cleaned = cleaned[1:]
    return cleaned or None


def validate_handle_format(handle: str) -> str:
    normalized = normalize_handle(handle)
    if not normalized or not HANDLE_REGEX.match(normalized):
        raise ValidationError(
            "Handle must be 3-30 characters long and contain only lowercase letters, numbers, and underscores."
        )
    if normalized in RESERVED_HANDLES:
        raise ValidationError(f"Handle '@{normalized}' is reserved and cannot be registered.")
    return normalized


def validate_display_name(display_name: str | None) -> str:
    return sanitize_text(
        display_name,
        max_length=100,
        allow_newlines=False,
        reject_html=True,
        field_name="Display name",
    )


def validate_stellar_public_key(public_key: str) -> str:
    cleaned = sanitize_text(public_key, max_length=64, field_name="Stellar public key").upper()
    if not StrKey.is_valid_ed25519_public_key(cleaned):
        raise ValidationError(
            "Invalid Stellar Ed25519 public key (must start with 'G' and be 56 characters)."
        )
    return cleaned


def validate_memo_text(memo: str | None) -> str:
    cleaned = sanitize_text(
        memo,
        max_length=28,
        allow_newlines=False,
        reject_html=True,
        field_name="Memo",
    )
    if len(cleaned.encode("utf-8")) > 28:
        raise ValidationError("Memo cannot exceed 28 UTF-8 bytes.")
    return cleaned


def validate_idempotency_key(key: str | None) -> str | None:
    if not key:
        return None
    cleaned = sanitize_text(key, max_length=128, field_name="Idempotency key")
    if not cleaned:
        return None
    if not IDEMPOTENCY_KEY_REGEX.match(cleaned):
        raise ValidationError(
            "Idempotency key must be 4-128 characters and contain only letters, numbers, '_', '-', '.', or ':'."
        )
    return cleaned


def validate_xdr_string(xdr_value: str, max_length: int = 16384) -> str:
    cleaned = sanitize_text(
        xdr_value,
        max_length=max_length,
        allow_newlines=False,
        reject_html=True,
        field_name="Transaction XDR",
    )
    if not cleaned:
        raise ValidationError("Transaction XDR cannot be empty.")
    try:
        decoded = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("Transaction XDR must be a valid base64-encoded string.") from exc
    if len(decoded) < 16:
        raise ValidationError("Transaction XDR is too short to be a valid Stellar envelope.")
    return cleaned


def validate_tx_hash(tx_hash: str) -> str:
    cleaned = sanitize_text(tx_hash, max_length=64, field_name="Transaction hash").lower()
    if not TX_HASH_REGEX.match(cleaned):
        raise ValidationError(
            "Invalid Stellar transaction hash (expected 64-character lowercase hexadecimal string)."
        )
    return cleaned


def validate_search_query(query: str | None, max_length: int = 64) -> str:
    return sanitize_text(
        query,
        max_length=max_length,
        allow_newlines=False,
        reject_html=True,
        field_name="Search query",
    )


def validate_positive_usdc_amount(amount: Decimal | str | float | int) -> Decimal:
    try:
        dec = Decimal(str(amount).strip())
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValidationError("Enter a valid numeric USDC amount.") from exc

    if not dec.is_finite() or dec <= Decimal("0"):
        raise ValidationError("Transfer amount must be greater than zero.")

    if dec > Decimal("1000000000"):
        raise ValidationError("Transfer amount exceeds maximum allowed limit.")

    quantized = dec.quantize(Decimal("0.0000001"))
    if quantized != dec:
        raise ValidationError("Stellar amounts support at most 7 decimal places.")
    return quantized
