from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from api.models import OTPVerification, Transaction, User, WalletChallenge


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    ordering = ["-created_at"]
    list_display = [
        "phone_number",
        "handle",
        "display_name",
        "is_phone_verified",
        "stellar_public_key",
        "created_at",
    ]
    list_filter = ["is_phone_verified", "is_active", "is_staff"]
    search_fields = ["phone_number", "handle", "display_name", "stellar_public_key"]
    readonly_fields = ["id", "created_at", "updated_at", "phone_verified_at", "wallet_verified_at"]
    fieldsets = (
        (None, {"fields": ("id", "phone_number", "password")}),
        ("Identity", {"fields": ("handle", "display_name", "is_phone_verified", "phone_verified_at")}),
        ("Stellar Wallet", {"fields": ("stellar_public_key", "wallet_verified_at")}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Timestamps", {"fields": ("created_at", "updated_at", "last_login")}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("phone_number", "handle", "display_name", "is_phone_verified"),
            },
        ),
    )


@admin.register(OTPVerification)
class OTPVerificationAdmin(admin.ModelAdmin):
    list_display = ["phone_number", "attempts", "max_attempts", "is_used", "expires_at", "created_at"]
    list_filter = ["is_used"]
    search_fields = ["phone_number"]
    readonly_fields = ["id", "code_hash", "created_at"]


@admin.register(WalletChallenge)
class WalletChallengeAdmin(admin.ModelAdmin):
    list_display = ["user", "public_key", "is_used", "expires_at", "created_at"]
    list_filter = ["is_used"]
    search_fields = ["public_key", "user__phone_number", "user__handle"]
    readonly_fields = ["id", "nonce", "challenge_message", "challenge_xdr", "created_at"]


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "amount",
        "asset_code",
        "sender_wallet",
        "recipient_wallet",
        "status",
        "tx_hash",
        "created_at",
    ]
    list_filter = ["status", "asset_code"]
    search_fields = ["tx_hash", "idempotency_key", "sender_wallet", "recipient_wallet", "memo"]
    readonly_fields = ["id", "created_at", "updated_at", "completed_at"]
