import logging
import time
import uuid

from django.conf import settings
from django.http import HttpResponse

request_logger = logging.getLogger("api.request")


class CorsMiddleware:
    """CORS and security header middleware for frontend integration."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == "OPTIONS":
            response = HttpResponse(status=204)
        else:
            response = self.get_response(request)

        origin = request.headers.get("Origin")
        if getattr(settings, "CORS_ALLOW_ALL_ORIGINS", False):
            response["Access-Control-Allow-Origin"] = origin or "*"
        elif origin and origin in getattr(settings, "CORS_ALLOWED_ORIGINS", []):
            response["Access-Control-Allow-Origin"] = origin

        response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response["Access-Control-Allow-Headers"] = (
            "Accept, Authorization, Content-Type, X-CSRFToken, Idempotency-Key, X-Request-ID"
        )
        response["Access-Control-Expose-Headers"] = "X-Request-ID, Retry-After"
        response["Access-Control-Allow-Credentials"] = "true"
        response["Vary"] = "Origin"
        response.setdefault("X-Content-Type-Options", "nosniff")
        response.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response


class RequestLoggingMiddleware:
    """
    Assigns a unique X-Request-ID to every request and logs method, path,
    status code, latency, client IP, and authenticated user ID.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    @staticmethod
    def _get_client_ip(request) -> str:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        x_real_ip = request.META.get("HTTP_X_REAL_IP")
        if x_real_ip:
            return x_real_ip.strip()
        return request.META.get("REMOTE_ADDR", "unknown")

    def __call__(self, request):
        start_time = time.monotonic()
        incoming_req_id = request.headers.get("X-Request-ID", "").strip()
        request_id = incoming_req_id[:64] if incoming_req_id else uuid.uuid4().hex
        request.request_id = request_id

        response = self.get_response(request)
        duration_ms = round((time.monotonic() - start_time) * 1000, 2)

        response["X-Request-ID"] = request_id
        user = getattr(request, "user", None)
        user_id = str(user.id) if (user and getattr(user, "is_authenticated", False)) else "anon"
        client_ip = self._get_client_ip(request)
        status_code = getattr(response, "status_code", 0)

        log_msg = (
            "request_id=%s method=%s path=%s status=%s duration_ms=%s ip=%s user=%s"
        )
        log_args = (
            request_id,
            request.method,
            request.path,
            status_code,
            duration_ms,
            client_ip,
            user_id,
        )

        if status_code >= 500:
            request_logger.error(log_msg, *log_args)
        elif status_code >= 400:
            request_logger.warning(log_msg, *log_args)
        else:
            request_logger.info(log_msg, *log_args)

        return response
