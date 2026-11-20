import base64
import binascii
import logging
import secrets
import uuid
from datetime import timedelta
from decimal import Decimal

import requests
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework import status
from stellar_sdk import (
    Account,
    Asset,
    Keypair,
    Server,
    TransactionBuilder,
    TransactionEnvelope,
)
from stellar_sdk.exceptions import (
    BadRequestError,
    BadSignatureError,
    BaseHorizonError,
    NotFoundError,
)

from api.exceptions import PinglyAPIError
from api.models import (
    Transaction,
    User,
    WalletChallenge,
)
from api.validators import (
    normalize_handle,
    normalize_phone_number,
    validate_idempotency_key,
    validate_memo_text,
    validate_positive_usdc_amount,
    validate_search_query,
    validate_stellar_public_key,
    validate_tx_hash,
    validate_xdr_string,
)

logger = logging.getLogger("api.stellar")

STROOPS_PER_XLM = Decimal("10000000")
HORIZON_ERROR_MESSAGES = {
    "tx_insufficient_balance": "Insufficient XLM balance to cover the Stellar network fee.",
    "tx_bad_seq": "Transaction sequence number is outdated. Please prepare the transfer again.",
    "tx_bad_auth": "Transaction signature is invalid or does not match the sender wallet.",
    "tx_too_late": "Transaction expired before submission. Please prepare a new transfer.",
    "op_underfunded": "Insufficient USDC balance to complete this transfer.",
    "op_no_trust": "Recipient or sender wallet does not have a Stellar Testnet USDC trustline enabled.",
    "op_no_destination": "Recipient Stellar account does not exist on Stellar Testnet.",
    "op_line_full": "Recipient wallet has reached its USDC trustline limit.",
    "op_not_authorized": "USDC trustline is not authorized for this transfer.",
}


def get_horizon_server() -> Server:
    horizon_url = getattr(
        settings,
        "STELLAR_HORIZON_URL",
        "https://horizon-testnet.stellar.org",
    )
    return Server(horizon_url=horizon_url)


def get_network_passphrase() -> str:
    return getattr(
        settings,
        "STELLAR_NETWORK_PASSPHRASE",
        "Test SDF Network ; September 2015",
    )


def get_usdc_asset() -> Asset:
    code = getattr(settings, "STELLAR_USDC_ASSET_CODE", "USDC")
    issuer = getattr(
        settings,
        "STELLAR_USDC_ISSUER",
        "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
    )
    return Asset(code, issuer)


def _wallet_cache_key(public_key: str) -> str:
    return f"pingly:wallet_net:{public_key}"


def invalidate_wallet_cache(*public_keys: str | None) -> None:
    keys = [_wallet_cache_key(pk) for pk in public_keys if pk]
    if keys:
        cache.delete_many(keys)


def quantize_stellar_amount(amount: Decimal | str | float | int) -> Decimal:
    try:
        return validate_positive_usdc_amount(amount)
    except ValidationError as exc:
        msg = exc.messages[0]
        code = "invalid_amount_precision" if "decimal" in msg.lower() else "invalid_amount"
        raise PinglyAPIError(
            message=msg,
            code=code,
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from exc


@transaction.atomic
def create_wallet_challenge(user: User, public_key: str) -> WalletChallenge:
    """
    Create a cryptographic challenge for proving ownership of a Stellar public key.
    Generates both:
    - `challenge_xdr`: A sequence-0 SEP-0010 style Stellar Testnet transaction XDR
    - `challenge_message`: A human-readable message string for SEP-0053 / message signing
    """
    if not user.is_phone_verified:
        raise PinglyAPIError(
            message="Phone number must be verified before linking a Stellar wallet.",
            code="phone_not_verified",
            status_code=status.HTTP_403_FORBIDDEN,
        )

    try:
        cleaned_key = validate_stellar_public_key(public_key)
    except ValidationError as exc:
        raise PinglyAPIError(
            message=exc.messages[0],
            code="invalid_stellar_public_key",
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from exc

    # Ensure no other user has already verified this wallet
    existing_owner = (
        User.objects.filter(stellar_public_key=cleaned_key)
        .exclude(id=user.id)
        .first()
    )
    if existing_owner:
        logger.warning(
            "wallet_challenge_conflict user_id=%s public_key=%s",
            user.id,
            cleaned_key,
        )
        raise PinglyAPIError(
            message="This Stellar wallet is already linked to another Pingly account.",
            code="wallet_already_linked",
            status_code=status.HTTP_409_CONFLICT,
        )

    # Invalidate previous unused challenges for this user
    WalletChallenge.objects.filter(user=user, is_used=False).update(is_used=True)

    nonce = secrets.token_hex(24)
    now = timezone.now()
    expiry_seconds = getattr(settings, "WALLET_CHALLENGE_EXPIRY_SECONDS", 300)
    expires_at = now + timedelta(seconds=expiry_seconds)
    domain = getattr(settings, "PINGLY_CHALLENGE_DOMAIN", "pingly.app")

    challenge_message = (
        f"Pingly Wallet Ownership Verification\n"
        f"Domain: {domain}\n"
        f"Account: {cleaned_key}\n"
        f"User ID: {user.id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {now.isoformat()}\n"
        f"Expires At: {expires_at.isoformat()}"
    )

    # Build a sequence-0 transaction so it can never be executed on-chain
    source_account = Account(account=cleaned_key, sequence=-1)
    challenge_tx = (
        TransactionBuilder(
            source_account=source_account,
            network_passphrase=get_network_passphrase(),
            base_fee=getattr(settings, "STELLAR_BASE_FEE", 100),
        )
        .append_manage_data_op(
            data_name=f"{domain} auth",
            data_value=nonce.encode("utf-8"),
            source=cleaned_key,
        )
        .set_timeout(expiry_seconds)
        .build()
    )

    challenge = WalletChallenge.objects.create(
        user=user,
        public_key=cleaned_key,
        nonce=nonce,
        challenge_message=challenge_message,
        challenge_xdr=challenge_tx.to_xdr(),
        expires_at=expires_at,
    )
    logger.info(
        "wallet_challenge_created user_id=%s challenge_id=%s public_key=%s",
        user.id,
        challenge.id,
        cleaned_key,
    )
    return challenge


def _decode_signature_bytes(signature_str: str) -> bytes:
    cleaned = signature_str.strip()
    try:
        raw = base64.b64decode(cleaned, validate=True)
        if len(raw) == 64:
            return raw
    except (binascii.Error, ValueError):
        pass

    try:
        raw = bytes.fromhex(cleaned)
        if len(raw) == 64:
            return raw
    except ValueError:
        pass

    raise PinglyAPIError(
        message="Invalid signature encoding. Expected 64-byte Ed25519 signature in base64 or hex format.",
        code="invalid_signature_encoding",
        status_code=status.HTTP_400_BAD_REQUEST,
    )


def _verify_challenge_xdr_signature(
    challenge: WalletChallenge,
    signed_xdr: str,
) -> bool:
    network_passphrase = get_network_passphrase()
    try:
        cleaned_xdr = validate_xdr_string(signed_xdr)
        envelope = TransactionEnvelope.from_xdr(
            cleaned_xdr,
            network_passphrase=network_passphrase,
        )
        expected_envelope = TransactionEnvelope.from_xdr(
            challenge.challenge_xdr,
            network_passphrase=network_passphrase,
        )
    except Exception as exc:
        raise PinglyAPIError(
            message="Invalid Stellar transaction XDR provided for wallet verification.",
            code="invalid_challenge_xdr",
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from exc

    if envelope.hash() != expected_envelope.hash():
        raise PinglyAPIError(
            message="Signed challenge XDR does not match the issued challenge transaction.",
            code="challenge_xdr_mismatch",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if not envelope.signatures:
        return False

    keypair = Keypair.from_public_key(challenge.public_key)
    tx_hash = envelope.hash()
    for decorated_sig in envelope.signatures:
        try:
            keypair.verify(tx_hash, decorated_sig.signature)
            return True
        except BadSignatureError:
            continue
    return False


def _verify_challenge_message_signature(
    challenge: WalletChallenge,
    signature_str: str,
) -> bool:
    sig_bytes = _decode_signature_bytes(signature_str)
    keypair = Keypair.from_public_key(challenge.public_key)

    candidates = [
        challenge.challenge_message.encode("utf-8"),
        challenge.nonce.encode("utf-8"),
    ]

    for payload in candidates:
        try:
            keypair.verify_message(payload, sig_bytes)
            return True
        except BadSignatureError:
            pass
        try:
            keypair.verify(payload, sig_bytes)
            return True
        except BadSignatureError:
            pass

    return False


def verify_and_link_wallet(
    user: User,
    challenge_id: str | None = None,
    public_key: str | None = None,
    signed_xdr: str | None = None,
    signature: str | None = None,
) -> User:
    """
    Verify proof of Stellar wallet ownership via signed challenge XDR or signed message,
    then associate the verified Stellar public key with the user's Pingly identity.
    """
    if not user.is_phone_verified:
        raise PinglyAPIError(
            message="Phone number must be verified before linking a Stellar wallet.",
            code="phone_not_verified",
            status_code=status.HTTP_403_FORBIDDEN,
        )

    if not signed_xdr and not signature:
        raise PinglyAPIError(
            message="Provide either 'signed_xdr' or 'signature' to verify wallet ownership.",
            code="missing_signature",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    qs = WalletChallenge.objects.filter(user=user, is_used=False)
    if challenge_id:
        qs = qs.filter(id=challenge_id)
    if public_key:
        try:
            cleaned_key = validate_stellar_public_key(public_key)
        except ValidationError as exc:
            raise PinglyAPIError(
                message=exc.messages[0],
                code="invalid_stellar_public_key",
                status_code=status.HTTP_400_BAD_REQUEST,
            ) from exc
        qs = qs.filter(public_key=cleaned_key)

    challenge = qs.order_by("-created_at").first()
    if not challenge:
        raise PinglyAPIError(
            message="No active wallet challenge found. Please request a new challenge.",
            code="challenge_not_found",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if challenge.is_expired:
        challenge.is_used = True
        challenge.save(update_fields=["is_used"])
        raise PinglyAPIError(
            message="Wallet verification challenge has expired. Please request a new challenge.",
            code="challenge_expired",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    verified = False
    if signed_xdr:
        verified = _verify_challenge_xdr_signature(challenge, signed_xdr)
    elif signature:
        verified = _verify_challenge_message_signature(challenge, signature)

    if not verified:
        logger.warning(
            "wallet_verification_failed user_id=%s challenge_id=%s public_key=%s",
            user.id,
            challenge.id,
            challenge.public_key,
        )
        raise PinglyAPIError(
            message="Wallet signature verification failed. Ensure you signed with the matching Stellar keypair.",
            code="invalid_wallet_signature",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    with transaction.atomic():
        existing_owner = (
            User.objects.filter(stellar_public_key=challenge.public_key)
            .exclude(id=user.id)
            .first()
        )
        if existing_owner:
            raise PinglyAPIError(
                message="This Stellar wallet is already linked to another Pingly account.",
                code="wallet_already_linked",
                status_code=status.HTTP_409_CONFLICT,
            )

        challenge.is_used = True
        challenge.save(update_fields=["is_used"])

        user.stellar_public_key = challenge.public_key
        user.wallet_verified_at = timezone.now()
        user.save(update_fields=["stellar_public_key", "wallet_verified_at", "updated_at"])

    invalidate_wallet_cache(challenge.public_key)
    logger.info(
        "wallet_linked user_id=%s public_key=%s",
        user.id,
        challenge.public_key,
    )
    return user


def get_wallet_network_details(public_key: str, *, use_cache: bool = True) -> dict:
    """
    Query Stellar Testnet Horizon for an account's existence, XLM balance,
    USDC balance, and USDC trustline status. Supports short-lived Redis/LocMem caching.
    """
    cleaned_key = validate_stellar_public_key(public_key)
    cache_ttl = getattr(settings, "WALLET_BALANCE_CACHE_TTL_SECONDS", 15)
    cache_key = _wallet_cache_key(cleaned_key)

    if use_cache and cache_ttl > 0:
        cached = cache.get(cache_key)
        if isinstance(cached, dict):
            return cached

    usdc_asset = get_usdc_asset()
    server = get_horizon_server()

    try:
        account_data = server.accounts().account_id(cleaned_key).call()
    except NotFoundError:
        result = {
            "public_key": cleaned_key,
            "network": getattr(settings, "STELLAR_NETWORK", "TESTNET"),
            "account_exists": False,
            "has_usdc_trustline": False,
            "usdc_balance": "0.0000000",
            "xlm_balance": "0.0000000",
            "usdc_asset_code": usdc_asset.code,
            "usdc_asset_issuer": usdc_asset.issuer,
            "sequence": None,
            "subentry_count": 0,
        }
        if use_cache and cache_ttl > 0:
            cache.set(cache_key, result, timeout=cache_ttl)
        return result
    except BaseHorizonError as exc:
        logger.warning("horizon_account_error public_key=%s error=%s", cleaned_key, exc)
        raise PinglyAPIError(
            message="Unable to fetch account balances from Stellar Testnet Horizon.",
            code="horizon_unavailable",
            status_code=status.HTTP_502_BAD_GATEWAY,
            details={"horizon_error": str(exc)},
        ) from exc
    except requests.RequestException as exc:
        logger.warning("horizon_connection_error public_key=%s error=%s", cleaned_key, exc)
        raise PinglyAPIError(
            message="Unable to connect to Stellar Testnet Horizon.",
            code="horizon_connection_error",
            status_code=status.HTTP_502_BAD_GATEWAY,
        ) from exc

    xlm_balance = "0.0000000"
    usdc_balance = "0.0000000"
    has_usdc_trustline = False
    usdc_authorized = True

    for bal in account_data.get("balances", []):
        asset_type = bal.get("asset_type")
        if asset_type == "native":
            xlm_balance = bal.get("balance", "0.0000000")
        elif (
            bal.get("asset_code") == usdc_asset.code
            and bal.get("asset_issuer") == usdc_asset.issuer
        ):
            has_usdc_trustline = True
            usdc_balance = bal.get("balance", "0.0000000")
            usdc_authorized = bal.get("is_authorized", True)

    result = {
        "public_key": cleaned_key,
        "network": getattr(settings, "STELLAR_NETWORK", "TESTNET"),
        "account_exists": True,
        "has_usdc_trustline": has_usdc_trustline,
        "usdc_trustline_authorized": usdc_authorized,
        "usdc_balance": usdc_balance,
        "xlm_balance": xlm_balance,
        "usdc_asset_code": usdc_asset.code,
        "usdc_asset_issuer": usdc_asset.issuer,
        "sequence": str(account_data.get("sequence", "")),
        "subentry_count": int(account_data.get("subentry_count", 0)),
    }
    if use_cache and cache_ttl > 0:
        cache.set(cache_key, result, timeout=cache_ttl)
    return result


def build_usdc_trustline_transaction(public_key: str) -> dict:
    """
    Build an unsigned Stellar ChangeTrust transaction XDR so a user can establish
    the Stellar Testnet USDC trustline from their connected non-custodial wallet.
    """
    cleaned_key = validate_stellar_public_key(public_key)
    server = get_horizon_server()
    usdc_asset = get_usdc_asset()
    base_fee = getattr(settings, "STELLAR_BASE_FEE", 100)
    timeout = getattr(settings, "STELLAR_TX_TIMEOUT_SECONDS", 300)

    try:
        source_account = server.load_account(cleaned_key)
    except NotFoundError as exc:
        raise PinglyAPIError(
            message="Stellar account is not funded on Testnet yet. Fund the account with Testnet XLM first.",
            code="account_not_funded",
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from exc
    except (BaseHorizonError, requests.RequestException) as exc:
        raise PinglyAPIError(
            message="Unable to load Stellar account from Testnet Horizon.",
            code="horizon_unavailable",
            status_code=status.HTTP_502_BAD_GATEWAY,
        ) from exc

    tx = (
        TransactionBuilder(
            source_account=source_account,
            network_passphrase=get_network_passphrase(),
            base_fee=base_fee,
        )
        .append_change_trust_op(asset=usdc_asset)
        .set_timeout(timeout)
        .build()
    )

    invalidate_wallet_cache(cleaned_key)
    return {
        "public_key": cleaned_key,
        "asset_code": usdc_asset.code,
        "asset_issuer": usdc_asset.issuer,
        "fee_stroops": base_fee,
        "fee_xlm": f"{(Decimal(base_fee) / STROOPS_PER_XLM):.7f}",
        "unsigned_xdr": tx.to_xdr(),
        "network_passphrase": get_network_passphrase(),
    }


def fund_testnet_account(public_key: str) -> dict:
    """Fund an account on Stellar Testnet using Friendbot."""
    cleaned_key = validate_stellar_public_key(public_key)
    friendbot_url = getattr(settings, "STELLAR_FRIENDBOT_URL", "https://friendbot.stellar.org")
    try:
        resp = requests.get(friendbot_url, params={"addr": cleaned_key}, timeout=15)
    except requests.RequestException as exc:
        raise PinglyAPIError(
            message="Failed to reach Stellar Testnet Friendbot.",
            code="friendbot_unavailable",
            status_code=status.HTTP_502_BAD_GATEWAY,
        ) from exc

    if resp.status_code not in (200, 201):
        raise PinglyAPIError(
            message="Friendbot could not fund this account (it may already be funded).",
            code="friendbot_error",
            status_code=status.HTTP_400_BAD_REQUEST,
            details={"friendbot_response": resp.text[:500]},
        )

    invalidate_wallet_cache(cleaned_key)
    data = resp.json() if resp.content else {}
    logger.info("friendbot_funded public_key=%s tx_hash=%s", cleaned_key, data.get("hash"))
    return {
        "public_key": cleaned_key,
        "funded": True,
        "tx_hash": data.get("hash"),
    }


def resolve_recipient_user(query: str) -> User:
    """
    Resolve a phone number or @handle to a verified Pingly user.
    Case-insensitive for @handles, normalized E.164 for phone numbers.
    """
    try:
        raw = validate_search_query(query, max_length=64)
    except ValidationError as exc:
        raise PinglyAPIError(
            message=exc.messages[0],
            code="invalid_recipient_query",
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from exc

    if not raw:
        raise PinglyAPIError(
            message="Enter a recipient @handle or phone number.",
            code="invalid_recipient_query",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    user = None
    cleaned_phone_candidate = raw.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if raw.startswith("+") or cleaned_phone_candidate.isdigit():
        normalized_phone = normalize_phone_number(raw)
        user = User.objects.filter(
            phone_number=normalized_phone,
            is_phone_verified=True,
            is_active=True,
        ).first()
    else:
        normalized_handle = normalize_handle(raw)
        if normalized_handle:
            user = User.objects.filter(
                handle__iexact=normalized_handle,
                is_phone_verified=True,
                is_active=True,
            ).first()

    if not user:
        raise PinglyAPIError(
            message="Recipient not found or has not verified their phone number.",
            code="recipient_not_found",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    return user


@transaction.atomic
def prepare_usdc_transfer(
    sender: User,
    recipient_query: str,
    amount: Decimal | str | float,
    memo: str = "",
    idempotency_key: str | None = None,
) -> Transaction:
    """
    Validate sender & recipient identities, check Stellar Testnet balances and USDC trustlines,
    build an unsigned Stellar Payment transaction XDR, and persist a PENDING Transaction record.
    """
    if not sender.is_phone_verified:
        raise PinglyAPIError(
            message="Verify your phone number before sending payments.",
            code="sender_phone_not_verified",
            status_code=status.HTTP_403_FORBIDDEN,
        )

    if not sender.has_linked_wallet:
        raise PinglyAPIError(
            message="Connect and verify your Stellar wallet before sending USDC.",
            code="sender_wallet_not_linked",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    quantized_amount = quantize_stellar_amount(amount)
    try:
        cleaned_memo = validate_memo_text(memo)
        cleaned_idem_key = validate_idempotency_key(idempotency_key)
    except ValidationError as exc:
        raise PinglyAPIError(
            message=exc.messages[0],
            code="validation_error",
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from exc

    if cleaned_idem_key:
        existing_tx = Transaction.objects.filter(idempotency_key=cleaned_idem_key).first()
        if existing_tx:
            if existing_tx.sender_id != sender.id:
                raise PinglyAPIError(
                    message="Idempotency key is already in use.",
                    code="duplicate_idempotency_key",
                    status_code=status.HTTP_409_CONFLICT,
                )
            return existing_tx
    else:
        cleaned_idem_key = f"prep_{uuid.uuid4().hex}"

    recipient = resolve_recipient_user(recipient_query)
    if recipient.id == sender.id:
        raise PinglyAPIError(
            message="You cannot send a payment to yourself.",
            code="self_transfer_not_allowed",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if not recipient.has_linked_wallet:
        raise PinglyAPIError(
            message=f"Recipient {recipient.formatted_handle or recipient.masked_phone} has not connected a Stellar wallet yet.",
            code="recipient_wallet_not_linked",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if recipient.stellar_public_key == sender.stellar_public_key:
        raise PinglyAPIError(
            message="Sender and recipient wallets cannot be identical.",
            code="self_transfer_not_allowed",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # 1. Inspect sender wallet on Stellar Testnet (bypass cache for pre-flight transfer check)
    sender_net = get_wallet_network_details(sender.stellar_public_key, use_cache=False)
    if not sender_net["account_exists"]:
        raise PinglyAPIError(
            message="Your Stellar wallet is not funded on Stellar Testnet yet.",
            code="sender_account_not_funded",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if not sender_net["has_usdc_trustline"]:
        raise PinglyAPIError(
            message="Your Stellar wallet does not have a USDC trustline enabled.",
            code="sender_missing_trustline",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    base_fee = getattr(settings, "STELLAR_BASE_FEE", 100)
    fee_xlm_dec = Decimal(base_fee) / STROOPS_PER_XLM
    sender_xlm_dec = Decimal(sender_net["xlm_balance"])
    if sender_xlm_dec < fee_xlm_dec:
        raise PinglyAPIError(
            message="Insufficient XLM balance to cover the Stellar network fee.",
            code="insufficient_xlm_for_fee",
            status_code=status.HTTP_400_BAD_REQUEST,
            details={
                "available_xlm": str(sender_xlm_dec),
                "required_fee_xlm": f"{fee_xlm_dec:.7f}",
            },
        )

    sender_usdc_dec = Decimal(sender_net["usdc_balance"])
    if sender_usdc_dec < quantized_amount:
        raise PinglyAPIError(
            message="Insufficient USDC balance for this transfer.",
            code="insufficient_usdc_balance",
            status_code=status.HTTP_400_BAD_REQUEST,
            details={
                "available_usdc": str(sender_usdc_dec),
                "requested_usdc": str(quantized_amount),
            },
        )

    # 2. Inspect recipient wallet on Stellar Testnet
    recipient_net = get_wallet_network_details(recipient.stellar_public_key, use_cache=False)
    if not recipient_net["account_exists"]:
        raise PinglyAPIError(
            message="Recipient's Stellar wallet is not activated on Stellar Testnet.",
            code="recipient_account_not_funded",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if not recipient_net["has_usdc_trustline"]:
        raise PinglyAPIError(
            message="Recipient's Stellar wallet does not have a USDC trustline enabled.",
            code="recipient_missing_trustline",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # 3. Build unsigned Stellar Payment transaction
    server = get_horizon_server()
    usdc_asset = get_usdc_asset()
    timeout = getattr(settings, "STELLAR_TX_TIMEOUT_SECONDS", 300)

    try:
        source_account = server.load_account(sender.stellar_public_key)
    except (BaseHorizonError, requests.RequestException) as exc:
        raise PinglyAPIError(
            message="Unable to load sender account sequence from Stellar Testnet Horizon.",
            code="horizon_unavailable",
            status_code=status.HTTP_502_BAD_GATEWAY,
        ) from exc

    builder = (
        TransactionBuilder(
            source_account=source_account,
            network_passphrase=get_network_passphrase(),
            base_fee=base_fee,
        )
        .append_payment_op(
            destination=recipient.stellar_public_key,
            asset=usdc_asset,
            amount=f"{quantized_amount:.7f}",
        )
        .set_timeout(timeout)
    )
    if cleaned_memo:
        builder.add_text_memo(cleaned_memo)

    unsigned_tx = builder.build()

    tx_record = Transaction.objects.create(
        idempotency_key=cleaned_idem_key,
        sender=sender,
        recipient=recipient,
        sender_wallet=sender.stellar_public_key,
        recipient_wallet=recipient.stellar_public_key,
        recipient_query=validate_search_query(recipient_query, max_length=64),
        amount=quantized_amount,
        asset_code=usdc_asset.code,
        asset_issuer=usdc_asset.issuer,
        fee_stroops=base_fee,
        memo=cleaned_memo,
        status=Transaction.Status.PENDING,
        unsigned_xdr=unsigned_tx.to_xdr(),
    )
    logger.info(
        "transfer_prepared tx_id=%s sender_id=%s recipient_id=%s amount=%s",
        tx_record.id,
        sender.id,
        recipient.id,
        quantized_amount,
    )
    return tx_record


def _extract_horizon_error(exc: BadRequestError) -> tuple[str, str]:
    """Extract specific Horizon transaction/operation result code and readable message."""
    extras = getattr(exc, "extras", None) or {}
    result_codes = extras.get("result_codes") or {}
    op_codes = result_codes.get("operations") or []
    tx_code = result_codes.get("transaction") or "tx_failed"

    for op_code in op_codes:
        if op_code and op_code != "op_success":
            msg = HORIZON_ERROR_MESSAGES.get(
                op_code,
                f"Stellar payment operation failed with code '{op_code}'.",
            )
            return op_code, msg

    msg = HORIZON_ERROR_MESSAGES.get(
        tx_code,
        f"Stellar transaction failed with code '{tx_code}'.",
    )
    return tx_code, msg


def _validate_signed_payment_envelope(
    signed_xdr: str,
    sender_wallet: str,
    expected_unsigned_xdr: str = "",
) -> TransactionEnvelope:
    network_passphrase = get_network_passphrase()
    try:
        cleaned_xdr = validate_xdr_string(signed_xdr)
        envelope = TransactionEnvelope.from_xdr(
            cleaned_xdr,
            network_passphrase=network_passphrase,
        )
    except Exception as exc:
        raise PinglyAPIError(
            message="Invalid signed Stellar transaction XDR.",
            code="invalid_signed_xdr",
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from exc

    if expected_unsigned_xdr:
        try:
            expected_envelope = TransactionEnvelope.from_xdr(
                expected_unsigned_xdr.strip(),
                network_passphrase=network_passphrase,
            )
        except Exception:
            expected_envelope = None

        if expected_envelope and envelope.hash() != expected_envelope.hash():
            raise PinglyAPIError(
                message="Signed transaction does not match the prepared transfer details.",
                code="transaction_payload_mismatch",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    if not envelope.signatures:
        raise PinglyAPIError(
            message="Transaction XDR has not been signed by the wallet.",
            code="unsigned_transaction",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    keypair = Keypair.from_public_key(sender_wallet)
    tx_hash = envelope.hash()
    signature_valid = False
    for decorated_sig in envelope.signatures:
        try:
            keypair.verify(tx_hash, decorated_sig.signature)
            signature_valid = True
            break
        except BadSignatureError:
            continue

    if not signature_valid:
        raise PinglyAPIError(
            message="Transaction signature does not match the sender's connected Stellar wallet.",
            code="invalid_transaction_signature",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    return envelope


def submit_signed_transfer(
    user: User,
    signed_xdr: str,
    transaction_id: str | None = None,
    idempotency_key: str | None = None,
) -> Transaction:
    """
    Validate a user-signed Stellar USDC transfer XDR, prevent duplicate submissions,
    submit to Stellar Testnet Horizon, and update the Transaction record.
    """
    if not user.has_linked_wallet:
        raise PinglyAPIError(
            message="Connect and verify your Stellar wallet before submitting a payment.",
            code="sender_wallet_not_linked",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    qs = Transaction.objects.filter(sender=user)
    if transaction_id:
        qs = qs.filter(id=transaction_id)
    elif idempotency_key:
        qs = qs.filter(idempotency_key=idempotency_key)
    else:
        raise PinglyAPIError(
            message="Provide either 'transaction_id' or 'idempotency_key' for the prepared transfer.",
            code="missing_transaction_reference",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    tx_record = qs.first()
    if not tx_record:
        raise PinglyAPIError(
            message="Prepared transfer not found.",
            code="transaction_not_found",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    if tx_record.status == Transaction.Status.COMPLETED and tx_record.tx_hash:
        return tx_record

    envelope = _validate_signed_payment_envelope(
        signed_xdr=signed_xdr,
        sender_wallet=tx_record.sender_wallet,
        expected_unsigned_xdr=tx_record.unsigned_xdr,
    )
    computed_hash = envelope.hash_hex()

    duplicate_hash_tx = (
        Transaction.objects.filter(tx_hash=computed_hash)
        .exclude(id=tx_record.id)
        .first()
    )
    if duplicate_hash_tx:
        raise PinglyAPIError(
            message="This Stellar transaction has already been submitted.",
            code="duplicate_transaction_submission",
            status_code=status.HTTP_409_CONFLICT,
            details={"tx_hash": computed_hash, "transaction_id": str(duplicate_hash_tx.id)},
        )

    tx_record.signed_xdr = signed_xdr.strip()
    server = get_horizon_server()

    try:
        horizon_response = server.submit_transaction(envelope)
    except BadRequestError as exc:
        err_code, err_msg = _extract_horizon_error(exc)
        tx_record.status = Transaction.Status.FAILED
        tx_record.tx_hash = computed_hash
        tx_record.error_code = err_code
        tx_record.failure_reason = err_msg
        tx_record.save(
            update_fields=[
                "signed_xdr",
                "status",
                "tx_hash",
                "error_code",
                "failure_reason",
                "updated_at",
            ]
        )
        invalidate_wallet_cache(tx_record.sender_wallet, tx_record.recipient_wallet)
        logger.warning(
            "transfer_submission_failed tx_id=%s tx_hash=%s error_code=%s",
            tx_record.id,
            computed_hash,
            err_code,
        )
        raise PinglyAPIError(
            message=err_msg,
            code=err_code,
            status_code=status.HTTP_400_BAD_REQUEST,
            details={
                "transaction_id": str(tx_record.id),
                "tx_hash": computed_hash,
                "status": tx_record.status,
            },
        ) from exc
    except (BaseHorizonError, requests.RequestException) as exc:
        logger.warning("horizon_submission_error tx_id=%s error=%s", tx_record.id, exc)
        raise PinglyAPIError(
            message="Unable to submit transaction to Stellar Testnet Horizon. Please check transaction status before retrying.",
            code="horizon_submission_error",
            status_code=status.HTTP_502_BAD_GATEWAY,
            details={"transaction_id": str(tx_record.id), "tx_hash": computed_hash},
        ) from exc

    successful = horizon_response.get("successful", True)
    tx_record.tx_hash = horizon_response.get("hash") or computed_hash
    tx_record.ledger = horizon_response.get("ledger")
    if successful:
        tx_record.status = Transaction.Status.COMPLETED
        tx_record.completed_at = timezone.now()
        tx_record.error_code = ""
        tx_record.failure_reason = ""
    else:
        tx_record.status = Transaction.Status.FAILED
        tx_record.error_code = "tx_failed"
        tx_record.failure_reason = "Transaction was rejected by the Stellar network."

    tx_record.save()
    invalidate_wallet_cache(tx_record.sender_wallet, tx_record.recipient_wallet)
    logger.info(
        "transfer_submitted tx_id=%s tx_hash=%s status=%s ledger=%s",
        tx_record.id,
        tx_record.tx_hash,
        tx_record.status,
        tx_record.ledger,
    )
    return tx_record


@transaction.atomic
def verify_transaction_on_network(
    user: User,
    tx_hash: str,
    transaction_id: str | None = None,
) -> Transaction:
    """
    Verify a transaction hash directly against Stellar Testnet Horizon and update/create
    the corresponding Pingly Transaction record.
    """
    try:
        cleaned_hash = validate_tx_hash(tx_hash)
    except ValidationError as exc:
        raise PinglyAPIError(
            message=exc.messages[0],
            code="invalid_tx_hash",
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from exc

    server = get_horizon_server()
    try:
        tx_data = server.transactions().transaction(cleaned_hash).call()
        ops_data = server.operations().for_transaction(cleaned_hash).call()
    except NotFoundError as exc:
        raise PinglyAPIError(
            message="Transaction hash was not found on Stellar Testnet.",
            code="transaction_not_found_on_network",
            status_code=status.HTTP_404_NOT_FOUND,
        ) from exc
    except (BaseHorizonError, requests.RequestException) as exc:
        raise PinglyAPIError(
            message="Unable to verify transaction on Stellar Testnet Horizon.",
            code="horizon_unavailable",
            status_code=status.HTTP_502_BAD_GATEWAY,
        ) from exc

    records = ops_data.get("_embedded", {}).get("records", [])
    usdc_asset = get_usdc_asset()
    payment_op = None
    for op in records:
        if (
            op.get("type") == "payment"
            and op.get("asset_code") == usdc_asset.code
            and op.get("asset_issuer") == usdc_asset.issuer
        ):
            payment_op = op
            break

    if not payment_op:
        raise PinglyAPIError(
            message="Transaction does not contain a Stellar Testnet USDC payment operation.",
            code="not_a_usdc_payment",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    from_wallet = payment_op.get("from", "")
    to_wallet = payment_op.get("to", "")
    amount_dec = Decimal(payment_op.get("amount", "0.0000000"))
    successful = bool(tx_data.get("successful", False))
    ledger = tx_data.get("ledger")
    memo = tx_data.get("memo", "") or ""
    fee_charged = int(tx_data.get("fee_charged") or tx_data.get("max_fee") or 100)

    tx_record = None
    if transaction_id:
        tx_record = Transaction.objects.select_for_update().filter(id=transaction_id).first()
    if not tx_record:
        tx_record = Transaction.objects.select_for_update().filter(tx_hash=cleaned_hash).first()

    sender_user = User.objects.filter(stellar_public_key=from_wallet).first()
    recipient_user = User.objects.filter(stellar_public_key=to_wallet).first()

    invalidate_wallet_cache(from_wallet, to_wallet)

    if tx_record:
        tx_record.tx_hash = cleaned_hash
        tx_record.ledger = ledger
        tx_record.fee_stroops = fee_charged
        tx_record.status = (
            Transaction.Status.COMPLETED if successful else Transaction.Status.FAILED
        )
        if successful and not tx_record.completed_at:
            tx_record.completed_at = timezone.now()
        if not tx_record.sender and sender_user:
            tx_record.sender = sender_user
        if not tx_record.recipient and recipient_user:
            tx_record.recipient = recipient_user
        tx_record.save()
        return tx_record

    try:
        tx_record = Transaction.objects.create(
            idempotency_key=f"net_{cleaned_hash}",
            sender=sender_user,
            recipient=recipient_user,
            sender_wallet=from_wallet,
            recipient_wallet=to_wallet,
            amount=amount_dec,
            asset_code=usdc_asset.code,
            asset_issuer=usdc_asset.issuer,
            fee_stroops=fee_charged,
            memo=str(memo)[:28],
            status=Transaction.Status.COMPLETED if successful else Transaction.Status.FAILED,
            tx_hash=cleaned_hash,
            ledger=ledger,
            completed_at=timezone.now() if successful else None,
        )
    except IntegrityError:
        tx_record = Transaction.objects.get(tx_hash=cleaned_hash)

    return tx_record


def sync_wallet_transactions(user: User, limit: int = 20) -> int:
    """
    Fetch recent USDC payment operations for the user's connected wallet from Stellar Testnet
    Horizon and index any missing transactions into the local database.
    """
    if not user.has_linked_wallet:
        raise PinglyAPIError(
            message="Connect a Stellar wallet before syncing transactions.",
            code="wallet_not_linked",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    server = get_horizon_server()
    usdc_asset = get_usdc_asset()

    try:
        payments_page = (
            server.payments()
            .for_account(user.stellar_public_key)
            .order(desc=True)
            .limit(min(max(1, limit), 50))
            .call()
        )
    except NotFoundError:
        return 0
    except (BaseHorizonError, requests.RequestException) as exc:
        raise PinglyAPIError(
            message="Unable to sync transactions from Stellar Testnet Horizon.",
            code="horizon_unavailable",
            status_code=status.HTTP_502_BAD_GATEWAY,
        ) from exc

    records = payments_page.get("_embedded", {}).get("records", [])
    synced_count = 0

    for op in records:
        if (
            op.get("type") != "payment"
            or op.get("asset_code") != usdc_asset.code
            or op.get("asset_issuer") != usdc_asset.issuer
        ):
            continue

        tx_hash = (op.get("transaction_hash") or "").lower()
        if not tx_hash or Transaction.objects.filter(tx_hash=tx_hash).exists():
            continue

        from_wallet = op.get("from", "")
        to_wallet = op.get("to", "")
        amount_dec = Decimal(op.get("amount", "0.0000000"))
        successful = bool(op.get("transaction_successful", True))

        sender_user = User.objects.filter(stellar_public_key=from_wallet).first()
        recipient_user = User.objects.filter(stellar_public_key=to_wallet).first()

        try:
            Transaction.objects.create(
                idempotency_key=f"sync_{tx_hash}",
                sender=sender_user,
                recipient=recipient_user,
                sender_wallet=from_wallet,
                recipient_wallet=to_wallet,
                amount=amount_dec,
                asset_code=usdc_asset.code,
                asset_issuer=usdc_asset.issuer,
                status=Transaction.Status.COMPLETED if successful else Transaction.Status.FAILED,
                tx_hash=tx_hash,
                completed_at=timezone.now() if successful else None,
            )
            synced_count += 1
        except IntegrityError:
            continue

    invalidate_wallet_cache(user.stellar_public_key)
    logger.info("wallet_transactions_synced user_id=%s count=%s", user.id, synced_count)
    return synced_count
