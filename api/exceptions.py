import logging

from rest_framework import status
from rest_framework.exceptions import Throttled
from rest_framework.response import Response
from rest_framework.views import exception_handler

security_logger = logging.getLogger("api.security")
api_logger = logging.getLogger("api")


class PinglyAPIError(Exception):
    """Structured domain exception for Pingly API endpoints."""

    def __init__(
        self,
        message: str,
        code: str = "bad_request",
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: dict | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


def custom_exception_handler(exc, context):
    request = context.get("request")
    request_id = getattr(request, "request_id", None)
    path = getattr(request, "path", "unknown")

    if isinstance(exc, PinglyAPIError):
        if exc.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN, status.HTTP_429_TOO_MANY_REQUESTS):
            security_logger.warning(
                "security_event code=%s status=%s path=%s request_id=%s msg=%s",
                exc.code,
                exc.status_code,
                path,
                request_id,
                exc.message,
            )
        else:
            api_logger.info(
                "domain_error code=%s status=%s path=%s request_id=%s msg=%s",
                exc.code,
                exc.status_code,
                path,
                request_id,
                exc.message,
            )
        payload = {
            "error": {
                "code": exc.code,
                "message": exc.message,
            }
        }
        if exc.details:
            payload["error"]["details"] = exc.details
        return Response(payload, status=exc.status_code)

    response = exception_handler(exc, context)
    if response is not None:
        if isinstance(response.data, dict) and "error" in response.data:
            return response

        error_code = getattr(exc, "default_code", "validation_error")
        if response.status_code == status.HTTP_401_UNAUTHORIZED:
            error_code = "not_authenticated"
        elif response.status_code == status.HTTP_403_FORBIDDEN:
            error_code = "permission_denied"
        elif response.status_code == status.HTTP_404_NOT_FOUND:
            error_code = "not_found"
        elif response.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            error_code = "rate_limit_exceeded"
            wait_seconds = int(getattr(exc, "wait", 0) or 0) if isinstance(exc, Throttled) else 0
            security_logger.warning(
                "rate_limit_exceeded path=%s request_id=%s retry_after=%s",
                path,
                request_id,
                wait_seconds,
            )

        detail_msg = "Request validation failed."
        if isinstance(response.data, dict) and "detail" in response.data:
            detail_msg = str(response.data["detail"])
        elif isinstance(response.data, list) and response.data:
            detail_msg = str(response.data[0])

        details = response.data
        if isinstance(exc, Throttled) and getattr(exc, "wait", None):
            details = {
                "detail": detail_msg,
                "retry_after_seconds": int(exc.wait),
            }

        response.data = {
            "error": {
                "code": str(error_code),
                "message": detail_msg,
                "details": details,
            }
        }
    return response
