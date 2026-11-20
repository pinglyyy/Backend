from rest_framework.throttling import SimpleRateThrottle


class PinglyBaseThrottle(SimpleRateThrottle):
    """
    Proxy-aware rate throttle that respects X-Forwarded-For / X-Real-IP headers
    when deployed behind Traefik / Dokploy.
    """

    def get_client_ip(self, request) -> str:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        x_real_ip = request.META.get("HTTP_X_REAL_IP")
        if x_real_ip:
            return x_real_ip.strip()
        return self.get_ident(request)

    def get_cache_key(self, request, view):
        if request.user and request.user.is_authenticated:
            ident = f"user_{request.user.pk}"
        else:
            ident = f"ip_{self.get_client_ip(request)}"
        return self.cache_format % {"scope": self.scope, "ident": ident}


class HealthRateThrottle(PinglyBaseThrottle):
    scope = "health"


class OTPSendRateThrottle(PinglyBaseThrottle):
    scope = "otp_send"

    def get_cache_key(self, request, view):
        ident = f"ip_{self.get_client_ip(request)}"
        return self.cache_format % {"scope": self.scope, "ident": ident}


class OTPVerifyRateThrottle(PinglyBaseThrottle):
    scope = "otp_verify"

    def get_cache_key(self, request, view):
        ident = f"ip_{self.get_client_ip(request)}"
        return self.cache_format % {"scope": self.scope, "ident": ident}


class HandleCheckRateThrottle(PinglyBaseThrottle):
    scope = "handle_check"


class ProfileRateThrottle(PinglyBaseThrottle):
    scope = "profile"


class RecipientLookupRateThrottle(PinglyBaseThrottle):
    """Rate limit recipient lookups to prevent bulk phone-number or handle enumeration."""

    scope = "recipient_lookup"


class WalletActionRateThrottle(PinglyBaseThrottle):
    """Rate limit state-changing or network-heavy wallet operations."""

    scope = "wallet_action"


class WalletReadRateThrottle(PinglyBaseThrottle):
    """Rate limit wallet balance, dashboard, and receive read operations."""

    scope = "wallet_read"


class TransferPrepareRateThrottle(PinglyBaseThrottle):
    """Rate limit Stellar USDC transfer preparation requests."""

    scope = "transfer_prepare"


class TransferSubmitRateThrottle(PinglyBaseThrottle):
    """Rate limit Stellar USDC transaction submission and network verification requests."""

    scope = "transfer_submit"


class TransactionReadRateThrottle(PinglyBaseThrottle):
    """Rate limit transaction history, detail, and sync endpoints."""

    scope = "transaction_read"
