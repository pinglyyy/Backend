import logging
import secrets
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from rest_framework import status

from api.exceptions import PinglyAPIError
from api.models import OTPVerification, User, mask_phone_number
from api.services import sms_service
from api.validators import sanitize_text, validate_display_name, validate_phone_number

logger = logging.getLogger("api.security")


def generate_otp_code(length: int = 6) -> str:
    """Generate a cryptographically random numeric OTP code."""
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


@transaction.atomic
def send_phone_otp(phone_number: str, display_name: str | None = None) -> dict:
    """
    Validate phone number, enforce resend cooldown and hourly send limits,
    generate and persist a new OTP, and create/fetch the User record.
    """
    try:
        normalized_phone = validate_phone_number(phone_number)
        sanitized_name = validate_display_name(display_name) if display_name else ""
    except ValidationError as exc:
        raise PinglyAPIError(
            message=exc.messages[0],
            code="invalid_phone_number",
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from exc

    now = timezone.now()
    cooldown_seconds = getattr(settings, "OTP_RESEND_COOLDOWN_SECONDS", 60)
    max_sends_per_hour = getattr(settings, "OTP_MAX_SENDS_PER_HOUR", 5)
    expiry_seconds = getattr(settings, "OTP_EXPIRY_SECONDS", 300)
    max_attempts = getattr(settings, "OTP_MAX_ATTEMPTS", 5)

    # 1. Check resend cooldown
    latest_otp = (
        OTPVerification.objects.filter(phone_number=normalized_phone)
        .order_by("-created_at")
        .first()
    )
    if latest_otp and not latest_otp.is_used:
        elapsed = (now - latest_otp.created_at).total_seconds()
        if elapsed < cooldown_seconds:
            retry_after = max(1, int(cooldown_seconds - elapsed))
            logger.warning(
                "otp_send_cooldown_blocked phone=%s retry_after_s=%s",
                mask_phone_number(normalized_phone),
                retry_after,
            )
            raise PinglyAPIError(
                message=f"Please wait {retry_after} seconds before requesting another OTP.",
                code="otp_resend_cooldown",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                details={"retry_after_seconds": retry_after},
            )

    # 2. Check hourly rate limit per phone number
    one_hour_ago = now - timedelta(hours=1)
    recent_count = OTPVerification.objects.filter(
        phone_number=normalized_phone,
        created_at__gte=one_hour_ago,
    ).count()
    if recent_count >= max_sends_per_hour:
        logger.warning(
            "otp_hourly_limit_exceeded phone=%s count=%s",
            mask_phone_number(normalized_phone),
            recent_count,
        )
        raise PinglyAPIError(
            message="Maximum OTP requests reached for this phone number. Please try again later.",
            code="otp_rate_limit_exceeded",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            details={"max_sends_per_hour": max_sends_per_hour},
        )

    # 3. Invalidate previous unused OTPs for this phone number
    OTPVerification.objects.filter(
        phone_number=normalized_phone,
        is_used=False,
    ).update(is_used=True)

    # 4. Ensure User record exists
    user, created = User.objects.get_or_create(
        phone_number=normalized_phone,
        defaults={"display_name": sanitized_name},
    )
    if not created and sanitized_name and not user.display_name:
        user.display_name = sanitized_name
        user.save(update_fields=["display_name", "updated_at"])

    # 5. Create new OTPVerification record
    raw_code = generate_otp_code(6)
    otp = OTPVerification(
        phone_number=normalized_phone,
        max_attempts=max_attempts,
        expires_at=now + timedelta(seconds=expiry_seconds),
    )
    otp.set_code(raw_code)
    otp.save()

    # 6. Dispatch SMS via Twilio (if configured) or console mode
    expiry_minutes = max(1, expiry_seconds // 60)
    sms_result = sms_service.send_otp_sms(
        phone_number=normalized_phone,
        code=raw_code,
        expiry_minutes=expiry_minutes,
    )

    logger.info(
        "otp_generated phone=%s user_id=%s is_new_user=%s sms_provider=%s delivered=%s expires_at=%s",
        mask_phone_number(normalized_phone),
        user.id,
        created,
        sms_result.get("provider"),
        sms_result.get("delivered"),
        otp.expires_at.isoformat(),
    )

    result = {
        "phone_number": normalized_phone,
        "expires_in_seconds": expiry_seconds,
        "resend_cooldown_seconds": cooldown_seconds,
        "is_new_user": created,
        "sms_delivery": {
            "provider": sms_result.get("provider"),
            "delivered": bool(sms_result.get("delivered")),
        },
    }
    if getattr(settings, "OTP_DEBUG_RETURN_CODE", False):
        result["debug_otp_code"] = raw_code

    return result


def verify_phone_otp(
    phone_number: str,
    code: str,
    display_name: str | None = None,
) -> User:
    """Verify an SMS OTP code with expiry and retry controls, then mark User phone verified."""
    try:
        normalized_phone = validate_phone_number(phone_number)
        sanitized_name = validate_display_name(display_name) if display_name else ""
        cleaned_code = sanitize_text(code, max_length=10, field_name="OTP code")
    except ValidationError as exc:
        raise PinglyAPIError(
            message=exc.messages[0],
            code="invalid_phone_number",
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from exc

    if not cleaned_code.isdigit() or len(cleaned_code) != 6:
        raise PinglyAPIError(
            message="OTP code must be a 6-digit number.",
            code="invalid_otp_format",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    otp = (
        OTPVerification.objects.filter(phone_number=normalized_phone, is_used=False)
        .order_by("-created_at")
        .first()
    )

    if not otp:
        logger.warning("otp_verify_not_found phone=%s", mask_phone_number(normalized_phone))
        raise PinglyAPIError(
            message="No active verification code found. Please request a new OTP.",
            code="otp_not_found",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if otp.is_expired:
        otp.is_used = True
        otp.save(update_fields=["is_used"])
        logger.warning("otp_verify_expired phone=%s", mask_phone_number(normalized_phone))
        raise PinglyAPIError(
            message="Verification code has expired. Please request a new OTP.",
            code="otp_expired",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if otp.is_exhausted:
        otp.is_used = True
        otp.save(update_fields=["is_used"])
        logger.warning("otp_verify_exhausted phone=%s", mask_phone_number(normalized_phone))
        raise PinglyAPIError(
            message="Too many failed verification attempts. Please request a new OTP.",
            code="otp_attempts_exceeded",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    code_valid = otp.check_code(cleaned_code)
    if not code_valid and sms_service.is_twilio_configured():
        code_valid = sms_service.check_twilio_verify_code(normalized_phone, cleaned_code)

    if not code_valid:
        otp.attempts += 1
        if otp.attempts >= otp.max_attempts:
            otp.is_used = True
        otp.save(update_fields=["attempts", "is_used"])
        remaining = max(0, otp.max_attempts - otp.attempts)
        logger.warning(
            "otp_verify_invalid_code phone=%s attempts=%s remaining=%s",
            mask_phone_number(normalized_phone),
            otp.attempts,
            remaining,
        )
        if remaining == 0:
            raise PinglyAPIError(
                message="Too many failed verification attempts. Please request a new OTP.",
                code="otp_attempts_exceeded",
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                details={"remaining_attempts": 0},
            )
        raise PinglyAPIError(
            message=f"Invalid verification code. {remaining} attempt(s) remaining.",
            code="otp_invalid_code",
            status_code=status.HTTP_400_BAD_REQUEST,
            details={"remaining_attempts": remaining},
        )

    with transaction.atomic():
        otp.is_used = True
        otp.save(update_fields=["is_used"])

        now = timezone.now()
        user, _ = User.objects.get_or_create(phone_number=normalized_phone)
        user.is_phone_verified = True
        if not user.phone_verified_at:
            user.phone_verified_at = now
        if sanitized_name:
            user.display_name = sanitized_name
        user.save()

    logger.info(
        "otp_verified_success user_id=%s phone=%s",
        user.id,
        mask_phone_number(normalized_phone),
    )
    return user
