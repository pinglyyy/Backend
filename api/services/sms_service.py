import logging

import requests
from django.conf import settings
from django.core.cache import cache
from rest_framework import status

from api.exceptions import PinglyAPIError
from api.models import mask_phone_number

logger = logging.getLogger("api.security")

TWILIO_API_BASE = "https://api.twilio.com/2010-04-01"
TWILIO_VERIFY_BASE = "https://verify.twilio.com/v2"
VERIFY_SID_CACHE_KEY = "pingly:twilio_verify_service_sid"


def is_twilio_configured() -> bool:
    account_sid = getattr(settings, "TWILIO_ACCOUNT_SID", "").strip()
    auth_token = getattr(settings, "TWILIO_AUTH_TOKEN", "").strip()
    from_number = getattr(settings, "TWILIO_PHONE_NUMBER", "").strip()
    messaging_service_sid = getattr(settings, "TWILIO_MESSAGING_SERVICE_SID", "").strip()
    verify_service_sid = getattr(settings, "TWILIO_VERIFY_SERVICE_SID", "").strip()
    return bool(
        account_sid
        and auth_token
        and (from_number or messaging_service_sid or verify_service_sid)
    )


def get_active_sms_provider() -> str:
    configured = getattr(settings, "SMS_PROVIDER", "auto").strip().lower()
    if configured == "console":
        return "console"
    if configured in ("twilio", "twilio_verify"):
        return configured
    return "twilio" if is_twilio_configured() else "console"


def _resolve_verify_service_sid(account_sid: str, auth_token: str) -> str | None:
    """
    Resolve or auto-provision a Twilio Verify V2 Service SID (VA...) for OTP delivery.
    Twilio Trial accounts require Verify V2 (or predefined templates) due to error 572006.
    """
    explicit_sid = getattr(settings, "TWILIO_VERIFY_SERVICE_SID", "").strip()
    if explicit_sid:
        return explicit_sid

    cached_sid = cache.get(VERIFY_SID_CACHE_KEY)
    if cached_sid:
        return cached_sid

    try:
        list_resp = requests.get(
            f"{TWILIO_VERIFY_BASE}/Services",
            auth=(account_sid, auth_token),
            timeout=10,
        )
        if list_resp.status_code == 200:
            services = list_resp.json().get("services", [])
            for svc in services:
                if svc.get("sid"):
                    sid = svc["sid"]
                    cache.set(VERIFY_SID_CACHE_KEY, sid, timeout=3600)
                    return sid

        create_resp = requests.post(
            f"{TWILIO_VERIFY_BASE}/Services",
            data={"FriendlyName": "Pingly", "CodeLength": 6},
            auth=(account_sid, auth_token),
            timeout=10,
        )
        if create_resp.status_code in (200, 201):
            sid = create_resp.json().get("sid")
            if sid:
                cache.set(VERIFY_SID_CACHE_KEY, sid, timeout=3600)
                return sid
    except requests.RequestException as exc:
        logger.warning("twilio_verify_service_discovery_error error=%s", exc)

    return None


def _send_via_twilio_verify(
    account_sid: str,
    auth_token: str,
    verify_sid: str,
    phone_number: str,
    fail_silently: bool,
) -> dict:
    masked_phone = mask_phone_number(phone_number)
    url = f"{TWILIO_VERIFY_BASE}/Services/{verify_sid}/Verifications"
    try:
        response = requests.post(
            url,
            data={"To": phone_number, "Channel": "sms"},
            auth=(account_sid, auth_token),
            timeout=10,
        )
    except requests.RequestException as exc:
        logger.error("twilio_verify_network_error phone=%s error=%s", masked_phone, exc)
        if fail_silently:
            return {
                "provider": "twilio_verify",
                "delivered": False,
                "fallback_used": True,
            }
        raise PinglyAPIError(
            message="Failed to reach SMS verification provider. Please try again shortly.",
            code="sms_delivery_failed",
            status_code=status.HTTP_502_BAD_GATEWAY,
        ) from exc

    try:
        resp_json = response.json() if response.content else {}
    except ValueError:
        resp_json = {}

    if response.status_code in (200, 201):
        sid = resp_json.get("sid")
        logger.info(
            "sms_otp_delivered provider=twilio_verify phone=%s verification_sid=%s",
            masked_phone,
            sid,
        )
        return {
            "provider": "twilio_verify",
            "delivered": True,
            "message_sid": sid,
        }

    twilio_code = resp_json.get("code")
    twilio_msg = resp_json.get("message") or f"Twilio Verify returned HTTP {response.status_code}"
    logger.warning(
        "twilio_verify_delivery_failed phone=%s http_status=%s twilio_code=%s message=%s",
        masked_phone,
        response.status_code,
        twilio_code,
        twilio_msg,
    )
    if fail_silently:
        return {
            "provider": "twilio_verify",
            "delivered": False,
            "fallback_used": True,
            "twilio_error_code": twilio_code,
        }

    raise PinglyAPIError(
        message="Unable to deliver SMS verification code to this phone number.",
        code="sms_delivery_failed",
        status_code=status.HTTP_502_BAD_GATEWAY,
        details={"twilio_code": twilio_code, "twilio_message": twilio_msg} if twilio_code else None,
    )


def send_otp_sms(phone_number: str, code: str, expiry_minutes: int = 5) -> dict:
    """
    Send a 6-digit OTP SMS to `phone_number` using Twilio Programmable SMS or Twilio Verify V2
    (automatically falling back to Twilio Verify V2 on Trial account template error 572006).
    """
    provider = get_active_sms_provider()
    masked_phone = mask_phone_number(phone_number)

    if provider == "console":
        logger.info("sms_otp_console_mode phone=%s", masked_phone)
        return {
            "provider": "console",
            "delivered": False,
            "simulated": True,
        }

    account_sid = getattr(settings, "TWILIO_ACCOUNT_SID", "").strip()
    auth_token = getattr(settings, "TWILIO_AUTH_TOKEN", "").strip()
    from_number = getattr(settings, "TWILIO_PHONE_NUMBER", "").strip()
    messaging_service_sid = getattr(settings, "TWILIO_MESSAGING_SERVICE_SID", "").strip()
    explicit_verify_sid = getattr(settings, "TWILIO_VERIFY_SERVICE_SID", "").strip()
    fail_silently = bool(
        getattr(settings, "SMS_FAIL_SILENTLY", False)
        or getattr(settings, "OTP_DEBUG_RETURN_CODE", False)
    )

    if not (account_sid and auth_token and (from_number or messaging_service_sid or explicit_verify_sid)):
        logger.error("twilio_misconfigured missing required credentials")
        if fail_silently:
            return {
                "provider": "twilio",
                "delivered": False,
                "fallback_used": True,
                "reason": "Twilio credentials are incomplete.",
            }
        raise PinglyAPIError(
            message="SMS service is not configured properly on the server.",
            code="sms_service_misconfigured",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    # If TWILIO_VERIFY_SERVICE_SID is explicitly configured or provider=="twilio_verify", use Verify V2 directly
    if explicit_verify_sid or provider == "twilio_verify":
        verify_sid = explicit_verify_sid or _resolve_verify_service_sid(account_sid, auth_token)
        if verify_sid:
            return _send_via_twilio_verify(
                account_sid=account_sid,
                auth_token=auth_token,
                verify_sid=verify_sid,
                phone_number=phone_number,
                fail_silently=fail_silently,
            )

    body_text = (
        f"Your Pingly verification code is {code}. "
        f"It expires in {expiry_minutes} minute(s). Do not share this code with anyone."
    )
    url = f"{TWILIO_API_BASE}/Accounts/{account_sid}/Messages.json"
    payload = {
        "To": phone_number,
        "Body": body_text,
    }
    if messaging_service_sid:
        payload["MessagingServiceSid"] = messaging_service_sid
    else:
        payload["From"] = from_number

    try:
        response = requests.post(
            url,
            data=payload,
            auth=(account_sid, auth_token),
            timeout=10,
        )
    except requests.RequestException as exc:
        logger.error("twilio_network_error phone=%s error=%s", masked_phone, exc)
        if fail_silently:
            return {
                "provider": "twilio",
                "delivered": False,
                "fallback_used": True,
                "reason": "Unable to reach Twilio SMS API.",
            }
        raise PinglyAPIError(
            message="Failed to reach SMS provider. Please try again shortly.",
            code="sms_delivery_failed",
            status_code=status.HTTP_502_BAD_GATEWAY,
        ) from exc

    try:
        resp_json = response.json() if response.content else {}
    except ValueError:
        resp_json = {}

    if response.status_code in (200, 201):
        sid = resp_json.get("sid")
        logger.info(
            "sms_otp_delivered provider=twilio phone=%s message_sid=%s",
            masked_phone,
            sid,
        )
        return {
            "provider": "twilio",
            "delivered": True,
            "message_sid": sid,
        }

    twilio_code = resp_json.get("code")
    twilio_msg = resp_json.get("message") or f"Twilio returned HTTP {response.status_code}"

    # Automatic fallback to Twilio Verify V2 when Twilio Trial account rejects custom SMS template (572006)
    if twilio_code == 572006:
        logger.info(
            "twilio_trial_template_restriction_572006 falling_back_to_twilio_verify phone=%s",
            masked_phone,
        )
        verify_sid = _resolve_verify_service_sid(account_sid, auth_token)
        if verify_sid:
            return _send_via_twilio_verify(
                account_sid=account_sid,
                auth_token=auth_token,
                verify_sid=verify_sid,
                phone_number=phone_number,
                fail_silently=fail_silently,
            )

    logger.warning(
        "twilio_delivery_failed phone=%s http_status=%s twilio_code=%s message=%s",
        masked_phone,
        response.status_code,
        twilio_code,
        twilio_msg,
    )

    if fail_silently:
        return {
            "provider": "twilio",
            "delivered": False,
            "fallback_used": True,
            "twilio_error_code": twilio_code,
        }

    raise PinglyAPIError(
        message="Unable to deliver SMS verification code to this phone number.",
        code="sms_delivery_failed",
        status_code=status.HTTP_502_BAD_GATEWAY,
        details={"twilio_code": twilio_code} if twilio_code else None,
    )


def check_twilio_verify_code(phone_number: str, code: str) -> bool:
    """
    Check an OTP code against Twilio Verify V2 VerificationCheck endpoint
    (used when OTP was dispatched via Twilio Verify V2).
    """
    if not is_twilio_configured():
        return False

    account_sid = getattr(settings, "TWILIO_ACCOUNT_SID", "").strip()
    auth_token = getattr(settings, "TWILIO_AUTH_TOKEN", "").strip()
    verify_sid = _resolve_verify_service_sid(account_sid, auth_token)
    if not verify_sid:
        return False

    try:
        resp = requests.post(
            f"{TWILIO_VERIFY_BASE}/Services/{verify_sid}/VerificationCheck",
            data={"To": phone_number, "Code": code},
            auth=(account_sid, auth_token),
            timeout=10,
        )
        if resp.status_code in (200, 201):
            data = resp.json() if resp.content else {}
            if data.get("status") == "approved" or data.get("valid") is True:
                logger.info(
                    "twilio_verify_code_approved phone=%s",
                    mask_phone_number(phone_number),
                )
                return True
    except requests.RequestException as exc:
        logger.warning("twilio_verify_check_error error=%s", exc)

    return False
