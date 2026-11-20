from django.urls import path

from api.openapi import OpenAPISchemaView, RedocUIView, SwaggerUIView
from api.views import (
    DashboardView,
    HandleAvailabilityView,
    HealthCheckView,
    LogoutView,
    ProfileView,
    ReceiveInfoView,
    RecipientLookupView,
    RegisterAndSendOTPView,
    SetHandleView,
    TransactionDetailView,
    TransactionListView,
    TransactionSyncView,
    TransferPrepareView,
    TransferSubmitView,
    TransferVerifyView,
    VerifyOTPView,
    WalletBalanceView,
    WalletChallengeView,
    WalletFundTestnetView,
    WalletTrustlinePrepareView,
    WalletUnlinkView,
    WalletVerifyView,
)

app_name = "api"

urlpatterns = [
    # Health & Network Config
    path("health/", HealthCheckView.as_view(), name="health"),
    # OpenAPI Schema, Swagger UI & ReDoc
    path("schema/", OpenAPISchemaView.as_view(), name="openapi-schema"),
    path("docs/", SwaggerUIView.as_view(), name="swagger-docs"),
    path("swagger/", SwaggerUIView.as_view(), name="swagger-ui"),
    path("redoc/", RedocUIView.as_view(), name="redoc"),
    # Deliverable 1: Phone Number & @Handle Identity Layer
    path("auth/register/", RegisterAndSendOTPView.as_view(), name="auth-register"),
    path("auth/otp/send/", RegisterAndSendOTPView.as_view(), name="auth-otp-send"),
    path("auth/otp/verify/", VerifyOTPView.as_view(), name="auth-otp-verify"),
    path("auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("auth/me/", ProfileView.as_view(), name="auth-me"),
    path("profile/", ProfileView.as_view(), name="profile"),
    path("profile/handle/", SetHandleView.as_view(), name="profile-handle"),
    path("handles/check/", HandleAvailabilityView.as_view(), name="handle-check"),
    # Wallet Ownership Verification & Linking
    path("wallet/challenge/", WalletChallengeView.as_view(), name="wallet-challenge"),
    path("wallet/verify/", WalletVerifyView.as_view(), name="wallet-verify"),
    path("wallet/link/", WalletVerifyView.as_view(), name="wallet-link"),
    path("wallet/unlink/", WalletUnlinkView.as_view(), name="wallet-unlink"),
    # Recipient Resolution
    path("recipients/lookup/", RecipientLookupView.as_view(), name="recipient-lookup"),
    # Deliverable 2 & 3: Wallet Dashboard, Balance, Trustline & Receive
    path("dashboard/", DashboardView.as_view(), name="dashboard"),
    path("wallet/balance/", WalletBalanceView.as_view(), name="wallet-balance"),
    path("wallet/trustline/prepare/", WalletTrustlinePrepareView.as_view(), name="wallet-trustline-prepare"),
    path("wallet/fund-testnet/", WalletFundTestnetView.as_view(), name="wallet-fund-testnet"),
    path("wallet/receive/", ReceiveInfoView.as_view(), name="wallet-receive"),
    # Deliverable 2: Stellar Testnet USDC P2P Transfers
    path("transfers/prepare/", TransferPrepareView.as_view(), name="transfer-prepare"),
    path("transfers/submit/", TransferSubmitView.as_view(), name="transfer-submit"),
    path("transfers/verify/", TransferVerifyView.as_view(), name="transfer-verify"),
    path("payments/prepare/", TransferPrepareView.as_view(), name="payment-prepare"),
    path("payments/submit/", TransferSubmitView.as_view(), name="payment-submit"),
    path("payments/verify/", TransferVerifyView.as_view(), name="payment-verify"),
    # Deliverable 3: Transaction History & Details
    path("transactions/", TransactionListView.as_view(), name="transaction-list"),
    path("transactions/sync/", TransactionSyncView.as_view(), name="transaction-sync"),
    path("transactions/<str:id_or_hash>/", TransactionDetailView.as_view(), name="transaction-detail"),
]
