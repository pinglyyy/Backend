"""
Django settings for Pingly MVP Backend API.
"""

import os
from pathlib import Path
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(env_path: Path) -> None:
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key:
            os.environ.setdefault(key, value)


_load_dotenv(BASE_DIR / ".env")

SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "django-insecure-m!pu)e(+w4%b!i4mulhwzm8(3l^*!t#6*@08^z^-h2ohz89_vu",
)

DEBUG = os.environ.get("DJANGO_DEBUG", "True").lower() in ("1", "true", "yes")

ALLOWED_HOSTS = [
    host.strip()
    for host in os.environ.get(
        "DJANGO_ALLOWED_HOSTS",
        "localhost,127.0.0.1,0.0.0.0,testserver",
    ).split(",")
    if host.strip()
]

# Reverse Proxy / Traefik / Dokploy Support
USE_X_FORWARDED_HOST = os.environ.get("USE_X_FORWARDED_HOST", "True").lower() in ("1", "true", "yes")
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "CSRF_TRUSTED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000,http://127.0.0.1:8000",
    ).split(",")
    if origin.strip()
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework.authtoken",
    "django_filters",
    "api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "api.middleware.RequestLoggingMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "api.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "core.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "core.wsgi.application"


# Database Configuration (PostgreSQL in Docker/Production, SQLite fallback for local dev/tests)
def _build_database_config() -> dict:
    database_url = os.environ.get("DATABASE_URL", "").strip()
    postgres_host = os.environ.get("POSTGRES_HOST", "").strip()

    if database_url.startswith(("postgres://", "postgresql://")):
        parsed = urlparse(database_url)
        return {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": (parsed.path or "/pingly").lstrip("/"),
            "USER": parsed.username or "pingly",
            "PASSWORD": parsed.password or "",
            "HOST": parsed.hostname or "db",
            "PORT": str(parsed.port or 5432),
            "CONN_MAX_AGE": int(os.environ.get("DB_CONN_MAX_AGE", "60")),
            "CONN_HEALTH_CHECKS": True,
        }

    if postgres_host:
        return {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("POSTGRES_DB", "pingly"),
            "USER": os.environ.get("POSTGRES_USER", "pingly"),
            "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "pingly_secret"),
            "HOST": postgres_host,
            "PORT": os.environ.get("POSTGRES_PORT", "5432"),
            "CONN_MAX_AGE": int(os.environ.get("DB_CONN_MAX_AGE", "60")),
            "CONN_HEALTH_CHECKS": True,
        }

    return {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / os.environ.get("SQLITE_DB_NAME", "db.sqlite3"),
    }


DATABASES = {"default": _build_database_config()}


# Cache Configuration (Redis in Docker/Production, LocMemCache fallback for local dev/tests)
REDIS_URL = os.environ.get("REDIS_URL", "").strip()
if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": REDIS_URL,
            "KEY_PREFIX": os.environ.get("CACHE_KEY_PREFIX", "pingly"),
            "TIMEOUT": int(os.environ.get("CACHE_DEFAULT_TIMEOUT", "300")),
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "pingly-local-cache",
            "TIMEOUT": int(os.environ.get("CACHE_DEFAULT_TIMEOUT", "300")),
        }
    }

WALLET_BALANCE_CACHE_TTL_SECONDS = int(os.environ.get("WALLET_BALANCE_CACHE_TTL_SECONDS", "15"))

AUTH_USER_MODEL = "api.User"

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

MAILERS = {
    "default": {
        "BACKEND": "django.core.mail.backends.console.EmailBackend",
    },
}

# Django REST Framework Configuration
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.TokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": os.environ.get("THROTTLE_RATE_ANON", "60/minute"),
        "user": os.environ.get("THROTTLE_RATE_USER", "120/minute"),
        "health": os.environ.get("THROTTLE_RATE_HEALTH", "120/minute"),
        "otp_send": os.environ.get("THROTTLE_RATE_OTP_SEND", "10/hour"),
        "otp_verify": os.environ.get("THROTTLE_RATE_OTP_VERIFY", "20/hour"),
        "handle_check": os.environ.get("THROTTLE_RATE_HANDLE_CHECK", "60/minute"),
        "profile": os.environ.get("THROTTLE_RATE_PROFILE", "60/minute"),
        "recipient_lookup": os.environ.get("THROTTLE_RATE_RECIPIENT_LOOKUP", "30/minute"),
        "wallet_action": os.environ.get("THROTTLE_RATE_WALLET_ACTION", "20/minute"),
        "wallet_read": os.environ.get("THROTTLE_RATE_WALLET_READ", "60/minute"),
        "transfer_prepare": os.environ.get("THROTTLE_RATE_TRANSFER_PREPARE", "30/minute"),
        "transfer_submit": os.environ.get("THROTTLE_RATE_TRANSFER_SUBMIT", "20/minute"),
        "transaction_read": os.environ.get("THROTTLE_RATE_TRANSACTION_READ", "60/minute"),
    },
    "EXCEPTION_HANDLER": "api.exceptions.custom_exception_handler",
}

# CORS Configuration
CORS_ALLOW_ALL_ORIGINS = os.environ.get("CORS_ALLOW_ALL_ORIGINS", "True").lower() in ("1", "true", "yes")
CORS_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

# OTP & Identity Settings
OTP_EXPIRY_SECONDS = int(os.environ.get("OTP_EXPIRY_SECONDS", "300"))
OTP_RESEND_COOLDOWN_SECONDS = int(os.environ.get("OTP_RESEND_COOLDOWN_SECONDS", "60"))
OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))
OTP_MAX_SENDS_PER_HOUR = int(os.environ.get("OTP_MAX_SENDS_PER_HOUR", "5"))
OTP_DEBUG_RETURN_CODE = os.environ.get("OTP_DEBUG_RETURN_CODE", str(DEBUG)).lower() in ("1", "true", "yes")

# Twilio SMS Settings (auto-enabled when TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and sender are set)
SMS_PROVIDER = os.environ.get("SMS_PROVIDER", "auto")
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_PHONE_NUMBER = os.environ.get("TWILIO_PHONE_NUMBER", "")
TWILIO_MESSAGING_SERVICE_SID = os.environ.get("TWILIO_MESSAGING_SERVICE_SID", "")
TWILIO_VERIFY_SERVICE_SID = os.environ.get("TWILIO_VERIFY_SERVICE_SID", "")
SMS_FAIL_SILENTLY = os.environ.get("SMS_FAIL_SILENTLY", "False").lower() in ("1", "true", "yes")

# Wallet Challenge Settings
WALLET_CHALLENGE_EXPIRY_SECONDS = int(os.environ.get("WALLET_CHALLENGE_EXPIRY_SECONDS", "300"))
PINGLY_CHALLENGE_DOMAIN = os.environ.get("PINGLY_CHALLENGE_DOMAIN", "pingly.app")

# Stellar Testnet Settings
STELLAR_NETWORK = os.environ.get("STELLAR_NETWORK", "TESTNET")
STELLAR_NETWORK_PASSPHRASE = os.environ.get(
    "STELLAR_NETWORK_PASSPHRASE",
    "Test SDF Network ; September 2015",
)
STELLAR_HORIZON_URL = os.environ.get(
    "STELLAR_HORIZON_URL",
    "https://horizon-testnet.stellar.org",
)
STELLAR_FRIENDBOT_URL = os.environ.get(
    "STELLAR_FRIENDBOT_URL",
    "https://friendbot.stellar.org",
)
STELLAR_USDC_ASSET_CODE = os.environ.get("STELLAR_USDC_ASSET_CODE", "USDC")
STELLAR_USDC_ISSUER = os.environ.get(
    "STELLAR_USDC_ISSUER",
    "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
)
STELLAR_BASE_FEE = int(os.environ.get("STELLAR_BASE_FEE", "100"))
STELLAR_TX_TIMEOUT_SECONDS = int(os.environ.get("STELLAR_TX_TIMEOUT_SECONDS", "300"))
STELLAR_EXPLORER_BASE_URL = os.environ.get(
    "STELLAR_EXPLORER_BASE_URL",
    "https://stellar.expert/explorer/testnet/tx",
)

# Structured Logging Configuration
LOG_LEVEL = os.environ.get("DJANGO_LOG_LEVEL", "INFO").upper()

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "structured": {
            "format": "{asctime} [{levelname}] {name}: {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "structured",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": LOG_LEVEL,
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
        "api": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
        "api.request": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
        "api.security": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
        "api.stellar": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
    },
}
