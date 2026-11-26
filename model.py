import sys
from curl_cffi import requests as _curl_requests

# Ép toàn bộ project dùng curl_cffi giả lập Chrome thay cho requests mặc định
_orig_session = _curl_requests.Session
_curl_requests.Session = lambda *a, **kw: _orig_session(*a, impersonate="chrome120", **kw)
sys.modules["requests"] = _curl_requests
import requests

import base64
import hashlib
import json
import math
import os
import secrets
import time
import uuid
from typing import Any, Callable, Mapping, MutableMapping, Optional, Sequence, Union
from urllib.parse import quote, urlparse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- Crypto schemes (JS_24_7 index bundle) ---
# Gateway g-auth (hA / tm):
SALT = "glk-gauth-v3-2026q3"
HKDF_INFO = "aes-gcm-key"
# Sectoken mint g-auth (xA / dA) → server tra header sig:
SECTOKEN_SALT = "glk-sectoken-v31-2026q3"
SECTOKEN_HKDF_INFO = "aes-gcm-key-v31"

# Current security/token scheme (bundle 26.08.01.1 / gweb-v3).
GWEB_SCHEME = "gweb-v3"
GWEB_SIGNING_SALT = "glk-gweb-sig-v3-2026q3"
GWEB_HKDF_INFO = "aes-gcm-key-gweb-v3"
# gweb-v2 / gweb-v3 XORs the 32-byte session key with this bundle constant before HKDF.
GWEB_V2_KEY_MASK = bytes.fromhex(
    "b73a158cf39f8825a2ab95c5c90e54b4"
    "75a900271d5ab4c23fa82dabbccbfd8a"
)
GWEB_V3_KEY_MASK = bytes.fromhex(
    "ad51dd3affdce8070210c36571decebdd5a37dd47396c31bf5b4adb711ab6713"
)
GWEB_SCHEME_CONFIG = {
    "gweb-v1": {
        "version": 1,
        "salt": "glk-gweb-sig-v1-2026q3",
        "info": "aes-gcm-key-gweb-v1",
        "key_mask": None,
    },
    "gweb-v2": {
        "version": 2,
        "salt": "glk-gweb-sig-v2-2026q3",
        "info": "aes-gcm-key-gweb-v2",
        "key_mask": GWEB_V2_KEY_MASK,
    },
    "gweb-v3": {
        "version": 3,
        "salt": GWEB_SIGNING_SALT,
        "info": GWEB_HKDF_INFO,
        "key_mask": GWEB_V3_KEY_MASK,
    },
}

APP_VERSION = "26.08.01.1"
APP_CLIENT = "109096667105508"
# Gateway data API moved to /api-v2 (2026). The security/token signer still
# signs the legacy /api/<path> form (e.g. /api/advertising/publishers/...).
BASE_API = "https://gateway.golike.net/api-v2"
LEGACY_API = "https://gateway.golike.net/api"
SECURITY_API = "https://api.golike.net"
SECURITY_SESSION_PATH = "/api/v1/security/session"
SECURITY_TOKEN_PATH = "/api/v1/security/token"
SECURITY_CAPTCHA_CHALLENGE_PATH = "/api/v1/security/captcha/challenge"
SECURITY_CAPTCHA_VERIFY_PATH = "/api/v1/security/captcha/verify"
# Mobile UA — app web gen g-version/g-client/header theo client mobile
MOBILE_UA = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1"
)

JsonBody = Union[None, str, bytes, Mapping[str, Any], list]
CaptchaSolver = Callable[
    [Mapping[str, Any], str], Optional[Sequence[Sequence[Union[int, float]]]]
]
TurnstileSolver = Callable[[str], Optional[str]]

# Client Headers (captured from official client in ga.py)
SEC_CH_UA = '"Google Chrome";v="155", "Chromium";v="155", "Not(A:Brand";v="24"'
SEC_CH_UA_MOBILE = "?1"
SEC_CH_UA_PLATFORM = '"iOS"'
PRIORITY_HEADER = "u=1, i"
ACCEPT_LANGUAGE = "vi,en;q=0.9,en-GB;q=0.8,en-US;q=0.7"


def jwt_payload(token: str) -> dict:
    """Decode JWT payload (no verify)."""
    parts = (token or "").strip().split(".")
    if len(parts) != 3:
        raise ValueError("token must be a JWT with three segments")
    raw = b64url_decode(parts[1])
    return json.loads(raw.decode("utf-8"))


def normalize_user_id(user_id: Any) -> Union[int, str]:
    """Normalize user id to int (legacy numeric) or str (new ULID)."""
    if user_id is None:
        return 0
    if isinstance(user_id, int) and not isinstance(user_id, bool):
        return user_id
    s = str(user_id).strip()
    if not s:
        return 0
    return int(s) if s.isdigit() else s


def jwt_user_id(token: str) -> Union[int, str]:
    """user_id = JWT sub: int for legacy numeric ids, str for new ULID ids."""
    payload = jwt_payload(token)
    sub = payload.get("sub")
    if sub is None:
        raise ValueError("JWT payload is missing required claim: sub")
    return normalize_user_id(sub)


def mobile_bearer_headers(token: str, device_id: Optional[str] = None) -> dict:
    """Header mobile khi goi API chi can Bearer (vd /users/me)."""
    did = generate_device_id(device_id)
    return {
        "accept": "application/json, text/plain, */*",
        "accept-language": ACCEPT_LANGUAGE,
        "authorization": f"Bearer {token}",
        "content-type": "application/json;charset=utf-8",
        "origin": "https://app.golike.net",
        "referer": "https://app.golike.net/",
        "user-agent": MOBILE_UA,
        "g-device-id": did,
        "g-version": APP_VERSION,
        "g-client": APP_CLIENT,
        "priority": PRIORITY_HEADER,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "t": make_t_header(),
    }


def fetch_user_me(
    token: str,
    *,
    device_id: Optional[str] = None,
    timeout: float = 30,
    session=None,
) -> dict:
    """
    GET /users/me — chi can token (khong bat g-auth).
    Tra ve dict user (data) + raw response.
    """
    import requests

    did = generate_device_id(device_id)
    headers = mobile_bearer_headers(token, did)
    http = session or requests
    resp = http.get(f"{BASE_API}/users/me", headers=headers, timeout=timeout)
    try:
        body = resp.json()
    except Exception:
        raise ValueError(
            f"GET /users/me returned non-JSON response: HTTP {resp.status_code}"
        )
    if resp.status_code != 200 or not (body.get("success") or body.get("status") == 200):
        detail = body.get("message") or body.get("error") or body
        raise ValueError(f"GET /users/me failed: HTTP {resp.status_code}: {detail}")
    data = body.get("data") or {}
    if not isinstance(data, dict):
        raise ValueError("GET /users/me returned an invalid data payload")
    return data


def security_session_headers(
    token: str, *, scheme: str = GWEB_SCHEME
) -> dict:
    """Headers for the scheme-specific security/session handshake."""
    jwt = (token or "").strip()
    if jwt.lower().startswith("bearer "):
        jwt = jwt[7:].strip()
    return {
        "accept": "application/json, text/plain, */*",
        "accept-language": ACCEPT_LANGUAGE,
        "authorization": f"Bearer {jwt}",
        "content-type": "application/json;charset=UTF-8",
        "g-scheme": scheme,
        "origin": "https://app.golike.net",
        "priority": PRIORITY_HEADER,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": MOBILE_UA,
    }


def fetch_security_session(
    token: str,
    *,
    timeout: float = 30,
    session=None,
    scheme: str = GWEB_SCHEME,
) -> dict:
    """
    POST https://api.golike.net/api/v1/security/session

    App goi API nay TRUOC khi get job TikTok. Response:
      {
        "signing_key": "<b64 32B>",
        "exp": 1784887743,
        "epoch": "0",
        "schemeVersion": "gweb-v1"
      }

    Raise ValueError neu rejected / thieu key.
    """
    import requests

    scheme = str(scheme or GWEB_SCHEME).strip().lower()
    _gweb_config(scheme)
    token = (token or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    http = session or requests
    url = f"{SECURITY_API}{SECURITY_SESSION_PATH}"
    resp = http.post(
        url,
        headers=security_session_headers(token, scheme=scheme),
        json={},
        timeout=timeout,
    )
    try:
        body = resp.json()
    except Exception:
        raise ValueError(
            f"POST /security/session returned non-JSON response: HTTP {resp.status_code}"
        )
    if not isinstance(body, dict):
        raise ValueError(
            f"POST /security/session returned an invalid payload: {type(body).__name__}"
        )

    payload = body.get("data") if isinstance(body.get("data"), dict) else body
    sk = payload.get("signing_key")
    if not sk or not isinstance(sk, str) or not sk.strip():
        reason = (
            payload.get("reason")
            or payload.get("message")
            or body.get("reason")
            or body.get("message")
            or "unknown"
        )
        raise ValueError(
            f"POST /security/session did not return a signing_key: {reason}"
        )
    sk = sk.strip()
    parse_signing_key(sk)  # validate 32 bytes
    return {
        "signing_key": sk,
        "exp": payload.get("exp"),
        "epoch": payload.get("epoch"),
        "schemeVersion": (
            payload.get("schemeVersion")
            or payload.get("scheme_version")
            or scheme
        ),
        # The current bundle keeps using the requested signer even when this
        # response metadata reports an older schemeVersion.
        "requestedScheme": scheme,
        "raw": body,
    }


def resolve_signing_key(
    profile: Optional[Mapping[str, Any]] = None,
    *,
    signing_key: Optional[str] = None,
) -> Optional[str]:
    """
    Lay signing_key / firebase_id tu profile /users/me.

    App web: store.signing_key = data.firebase_id (khi co).
    Thu nhieu field vi API doi ten theo thoi ky.
    """
    if signing_key and str(signing_key).strip():
        cand = str(signing_key).strip()
        try:
            parse_signing_key(cand)
            return cand
        except ValueError:
            pass

    if not isinstance(profile, Mapping):
        return None

    # uu tien cac key thuong gap
    keys = (
        "firebase_id",
        "signing_key",
        "gauth_key",
        "g_auth_key",
        "store_signing_key",
        "firebaseId",
        "signingKey",
    )
    for key in keys:
        val = profile.get(key)
        if isinstance(val, str) and val.strip():
            try:
                parse_signing_key(val.strip())
                return val.strip()
            except ValueError:
                continue

    # nested: data.security / data.gauth
    for nest_key in ("security", "gauth", "auth", "meta"):
        nest = profile.get(nest_key)
        if not isinstance(nest, Mapping):
            continue
        for key in keys:
            val = nest.get(key)
            if isinstance(val, str) and val.strip():
                try:
                    parse_signing_key(val.strip())
                    return val.strip()
                except ValueError:
                    continue
    return None


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data.replace("-", "+").replace("_", "/") + pad)


def parse_signing_key(signing_key: str) -> bytes:
    """Decode 32-byte signing key from hex or base64/base64url."""
    if not signing_key or not isinstance(signing_key, str):
        raise ValueError("signing_key must be a non-empty string")

    attempts = []
    s = signing_key.strip()

    if len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
        try:
            raw = bytes.fromhex(s)
            attempts.append(("hex", len(raw)))
            if len(raw) == 32:
                return raw
        except Exception as ex:
            attempts.append(("hex", str(ex)))

    for label, decoder in (
        ("b64", base64.b64decode),
        ("b64url", b64url_decode),
    ):
        try:
            raw = decoder(s)
            attempts.append((label, len(raw)))
            if len(raw) == 32:
                return raw
        except Exception as ex:
            attempts.append((label, str(ex)))

    raise ValueError(
        f"signing_key must decode to exactly 32 bytes for AES-256; attempts={attempts}"
    )


def derive_aes_key(
    signing_key: str,
    *,
    salt: str = SALT,
    info: str = HKDF_INFO,
) -> bytes:
    """HKDF-SHA256(signing_key, salt, info) -> 32 bytes."""
    ikm = parse_signing_key(signing_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode("utf-8"),
        info=info.encode("utf-8"),
    ).derive(ikm)


def derive_sectoken_aes_key(signing_key: str) -> bytes:
    """Key cho mint sig (xA): salt glk-sectoken-v31-2026q3."""
    return derive_aes_key(
        signing_key, salt=SECTOKEN_SALT, info=SECTOKEN_HKDF_INFO
    )


def _gweb_config(scheme: str = GWEB_SCHEME) -> Mapping[str, Any]:
    name = str(scheme or "").strip().lower()
    try:
        return GWEB_SCHEME_CONFIG[name]
    except KeyError:
        supported = ", ".join(sorted(GWEB_SCHEME_CONFIG))
        raise ValueError(
            f"unsupported gweb scheme {scheme!r}; expected one of: {supported}"
        )


def derive_gweb_aes_key(
    signing_key: str, *, scheme: str = GWEB_SCHEME
) -> bytes:
    """Derive the AES key used by a gweb security/token signer."""
    config = _gweb_config(scheme)
    ikm = parse_signing_key(signing_key)
    key_mask = config.get("key_mask")
    if key_mask is not None:
        ikm = bytes(a ^ b for a, b in zip(ikm, key_mask))
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=str(config["salt"]).encode("utf-8"),
        info=str(config["info"]).encode("utf-8"),
    ).derive(ikm)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def body_hash(body: JsonBody = None) -> str:
    """SHA256 hex of request body string (GET uses empty string)."""
    if body is None:
        s = ""
    elif isinstance(body, bytes):
        s = body.decode("utf-8")
    elif isinstance(body, str):
        s = body
    else:
        s = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return sha256_hex(s)


def request_digest(ts_ms: int, device_id: str, q: str) -> str:
    """r field for gateway g-auth (uA)."""
    return sha256_hex(f"{ts_ms}:{device_id}:{q}:{SALT}")[:16]


def sectoken_digest_r(ts_ms: int, user_id: Union[int, str], q: str) -> str:
    """r field for sectoken g-auth (cA): sha256(sh:t:userId:q)[:16]."""
    return sha256_hex(
        f"{SECTOKEN_SALT}:{ts_ms}:{normalize_user_id(user_id)}:{q}"
    )[:16]


def sectoken_digest_r2(device_id: str, method: str, path: str) -> str:
    """r2 field (fA): sha256hex(device|method|path|sh)[16:40]."""
    return sha256_hex(
        f"{device_id}|{method.upper()}|{path}|{SECTOKEN_SALT}"
    )[16:40]


def generate_device_id(existing: Optional[str] = None) -> str:
    if existing:
        return existing
    return str(uuid.uuid4())


def generate_nonce_x() -> str:
    return b64url_encode(secrets.token_bytes(16))


def triple_btoa(value: str) -> str:
    x = value.encode("utf-8")
    for _ in range(3):
        x = base64.b64encode(x)
    return x.decode("ascii")


def make_t_header(ts: Optional[int] = None) -> str:
    if ts is None:
        ts = int(time.time())
    return triple_btoa(str(ts))


def normalize_path(path: str, base_url: str = LEGACY_API) -> str:
    """Pathname used in g-auth payload (no query/hash)."""
    p = (path or "").split("?")[0].split("#")[0]
    if not p.startswith("/"):
        p = "/" + p
    base = (base_url or "").rstrip("/")
    if p.startswith("/api/"):
        return p
    if base.endswith("/api"):
        return "/api" + p
    return urlparse(base + p).path


def _aes_gcm_b64url(aes_key: bytes, payload: dict) -> str:
    """AES-GCM encrypt JSON payload -> b64url(iv12 || ct+tag)."""
    iv = secrets.token_bytes(12)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    ct = AESGCM(aes_key).encrypt(iv, plaintext, None)
    return b64url_encode(iv + ct)


def generate_g_auth(
    *,
    method: str,
    path: str,
    signing_key: str,
    device_id: str,
    user_id: Union[int, str],
    body: JsonBody = None,
    base_url: str = LEGACY_API,
    ts_ms: Optional[int] = None,
) -> str:
    """
    Gateway g-auth (hA) — salt glk-gauth-v3-2026q3.
    Payload: {t,x,d,u,n,k,q,r}
    """
    t = int(ts_ms if ts_ms is not None else time.time() * 1000)
    k = normalize_path(path, base_url)
    q = body_hash("" if body is None else body)
    payload = {
        "t": t,
        "x": generate_nonce_x(),
        "d": device_id,
        "u": normalize_user_id(user_id),
        "n": method.upper(),
        "k": k,
        "q": q,
        "r": request_digest(t, device_id, q),
    }
    return _aes_gcm_b64url(derive_aes_key(signing_key), payload)


def generate_sectoken_g_auth(
    *,
    method: str,
    path: str,
    signing_key: str,
    device_id: str,
    user_id: Union[int, str],
    body: JsonBody = None,
    ts_ms: Optional[int] = None,
) -> str:
    """
    Sectoken g-auth (xA) de POST /api/v1/security/token.
    salt glk-sectoken-v31-2026q3 + field r2.
    path: dung raw path API security, vd /api/v1/security/token
    """
    t = int(ts_ms if ts_ms is not None else time.time() * 1000)
    method_u = method.upper()
    # JS: k = path as passed (dx = "/api/v1/security/token")
    k = path if path.startswith("/") else "/" + path
    q = body_hash("" if body is None else body)
    payload = {
        "t": t,
        "x": generate_nonce_x(),
        "d": device_id,
        "u": normalize_user_id(user_id),
        "n": method_u,
        "k": k,
        "q": q,
        "r": sectoken_digest_r(t, user_id, q),
        "r2": sectoken_digest_r2(device_id, method_u, k),
    }
    return _aes_gcm_b64url(derive_sectoken_aes_key(signing_key), payload)


def generate_gweb_g_auth(
    *,
    method: str,
    path: str,
    signing_key: str,
    device_id: str,
    user_id: Union[int, str],
    body: JsonBody = None,
    ts_ms: Optional[int] = None,
    nonce: Optional[str] = None,
    iv: Optional[bytes] = None,
    scheme: str = GWEB_SCHEME,
) -> str:
    """
    Build the ``g-auth`` used by ``POST /api/v1/security/token``.

    This is the pure-Python equivalent of the gweb WASM signer embedded in the
    Golike web bundle. Its wire format is:

      base64url(version_byte || iv12 || tag16 || ciphertext)

    ``iv`` is exposed only for deterministic tests/diagnostics. Never reuse an
    AES-GCM IV with the same signing key in production.
    """
    scheme_name = str(scheme or "").strip().lower()
    config = _gweb_config(scheme_name)
    t = int(ts_ms if ts_ms is not None else time.time() * 1000)
    method_u = method.upper()
    if not path.startswith("/"):
        raise ValueError(
            f"{scheme_name} path must be the raw absolute API path"
        )
    k = path
    q = body_hash("" if body is None else body)
    x = nonce if nonce is not None else generate_nonce_x()
    proof_input = (
        f"{scheme_name}:{config['salt']}:"
        f"{t}:{normalize_user_id(user_id)}:{method_u}:{k}:{q}"
    )
    proof = sha256_hex(proof_input)[8:32]
    payload = {
        "t": t,
        "x": x,
        "d": device_id,
        "u": normalize_user_id(user_id),
        "n": method_u,
        "k": k,
        "q": q,
        "w": proof,
    }
    plaintext = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    iv12 = secrets.token_bytes(12) if iv is None else bytes(iv)
    if len(iv12) != 12:
        raise ValueError(f"{scheme_name} iv must be exactly 12 bytes")
    ciphertext_and_tag = AESGCM(
        derive_gweb_aes_key(signing_key, scheme=scheme_name)
    ).encrypt(
        iv12,
        plaintext,
        scheme_name.encode("ascii"),
    )
    ciphertext, tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]
    version_byte = bytes([int(config["version"])])
    return b64url_encode(version_byte + iv12 + tag + ciphertext)


def resolve_sig_act(path: str) -> Optional[tuple]:
    """
    Map gateway path → (plt, act) for security/token mint.

    Golike 1.9 / 2.0 publisher jobs require sig + optional captcha:
      tiktok, facebook, instagram, threads, twitter, youtube,
      bluesky, lazada, pinterest, soundcloud, tumblr, shopee, ...

    Pattern:
      /advertising/publishers/<plt>/jobs            → (plt, get_job)
      /advertising/publishers/<plt>/complete-jobs   → (plt, complete_job)
      /advertising/publishers/get-jobs-2026         → (facebook, get_job)
      /advertising/publishers/complete-jobs-2026    → (facebook, complete_job)
      /traffic/publishers/...                       → (traffic, get_job|complete_job)
      /review-jobs/publishers/complete              → (review, complete_job)

    Skip-jobs / logs paths are ignored (no sig).
    Returns None when the path does not need a sig header.
    """
    import re

    s = (path or "").lower()
    if "/skip" in s or "/logs" in s:
        return None

    # Facebook special endpoints (no /facebook/ segment in path)
    if "complete-jobs-2026" in s:
        return ("facebook", "complete_job")
    if "get-jobs-2026" in s or "publishers/get-jobs" in s:
        return ("facebook", "get_job")

    # Golike 2.0 traffic jobs
    if "/traffic/publishers/complete" in s:
        return ("traffic", "complete_job")
    if "/traffic/publishers/" in s:
        return ("traffic", "get_job")

    # Golike 2.0 review jobs
    if "/review-jobs/publishers/complete" in s:
        return ("review", "complete_job")
    if "/review-jobs/publishers/" in s:
        return ("review", "get_job")

    # Generic: publishers/<plt>/complete-jobs
    m = re.search(r"publishers/([a-z0-9_]+)/complete[-_]jobs", s)
    if m:
        return (m.group(1), "complete_job")

    # Generic: publishers/<plt>/jobs
    m = re.search(r"publishers/([a-z0-9_]+)/jobs", s)
    if m:
        return (m.group(1), "get_job")

    return None


def resolve_tiktok_sig_act(path: str) -> Optional[str]:
    """
    Backward-compatible alias.

    Old code expected only an act string for TikTok paths.
    Prefer resolve_sig_act() for multi-platform support.
    """
    result = resolve_sig_act(path)
    return result[1] if result else None


def split_path_query(path: str) -> tuple:
    """Return (path_no_query, query_string)."""
    s = path or ""
    if "?" in s:
        p, q = s.split("?", 1)
        return p, q
    return s, ""


def generate_sig(
    *,
    method: str,
    path: str,
    signing_key: str,
    device_id: str,
    user_id: Union[int, str],
    token: str,
    body: JsonBody = None,
    base_url: str = LEGACY_API,
    plt: str = "tiktok",
    act: Optional[str] = None,
    timeout: float = 30,
    telemetry: Optional[Mapping[str, Any]] = None,
    scheme: str = GWEB_SCHEME,
    captcha_solver: Optional[CaptchaSolver] = None,
    captcha_max_attempts: int = 3,
    session=None,
) -> Optional[str]:
    """
    Mint header ``sig`` cho TikTok (JS_24_7: _A / xx).

    Flow:
      1. body = {plt, act, req:{method,path,query,body}}
      2. g-auth = generate_gweb_g_auth(POST, /api/v1/security/token, body)
      3. POST https://api.golike.net/api/v1/security/token
      4. return response.data.token  (hoac response.token)
    """
    return mint_security_token(
        method=method,
        path=path,
        signing_key=signing_key,
        device_id=device_id,
        user_id=user_id,
        token=token,
        body=body,
        base_url=base_url,
        plt=plt,
        act=act,
        timeout=timeout,
        telemetry=telemetry,
        scheme=scheme,
        captcha_solver=captcha_solver,
        captcha_max_attempts=captcha_max_attempts,
        session=session,
    )


class SecurityTokenMintError(ValueError):
    """The security/token endpoint did not return a usable token."""

    def __init__(
        self,
        message: str,
        *,
        action: Optional[str] = None,
        reason: Optional[str] = None,
        response: Optional[Mapping[str, Any]] = None,
        retryable: bool = True,
    ) -> None:
        super().__init__(message)
        self.action = action
        self.reason = reason
        self.response = dict(response or {})
        self.retryable = bool(retryable)


class SecurityCaptchaRequired(SecurityTokenMintError):
    """The security/token endpoint requires the interactive drag challenge."""

    def __init__(
        self,
        message: str,
        *,
        reason: Optional[str] = "captcha",
        response: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(
            message,
            action="captcha",
            reason=reason,
            response=response,
            retryable=False,
        )


class SecurityCaptchaError(ValueError):
    """Fetching or verifying the interactive security challenge failed."""


def _strip_bearer(token: str) -> str:
    jwt = (token or "").strip()
    if jwt.lower().startswith("bearer "):
        jwt = jwt[7:].strip()
    return jwt


def _security_response_payload(data: Any) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        return {}
    inner = data.get("data")
    return inner if isinstance(inner, Mapping) else data


def _signed_security_post(
    *,
    path: str,
    payload: Mapping[str, Any],
    signing_key: str,
    device_id: str,
    user_id: Union[int, str],
    token: str,
    timeout: float,
    scheme: str,
    session=None,
) -> Mapping[str, Any]:
    import requests

    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    g_auth = generate_gweb_g_auth(
        method="POST",
        path=path,
        body=body,
        signing_key=signing_key,
        device_id=device_id,
        user_id=normalize_user_id(user_id),
        scheme=scheme,
    )
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": ACCEPT_LANGUAGE,
        "Authorization": f"Bearer {_strip_bearer(token)}",
        "Content-Type": "application/json;charset=UTF-8",
        "g-auth": g_auth,
        "Origin": "https://app.golike.net",
        "Priority": PRIORITY_HEADER,
        "User-Agent": MOBILE_UA,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
    }
    http = session or requests
    response = http.post(
        f"{SECURITY_API}{path}",
        headers=headers,
        data=body.encode("utf-8"),
        timeout=timeout,
    )
    try:
        data = response.json()
    except Exception:
        raise SecurityCaptchaError(
            f"POST {path} returned non-JSON response: "
            f"HTTP {getattr(response, 'status_code', '?')}"
        )
    if getattr(response, "status_code", 200) >= 400:
        raise SecurityCaptchaError(
            f"POST {path} failed: HTTP {response.status_code}: {data!r}"
        )
    if not isinstance(data, Mapping):
        raise SecurityCaptchaError(
            f"POST {path} returned an invalid payload: {type(data).__name__}"
        )
    return data


def fetch_captcha_challenge(
    *,
    signing_key: str,
    device_id: str,
    user_id: Union[int, str],
    token: str,
    timeout: float = 10,
    scheme: str = GWEB_SCHEME,
    session=None,
) -> Mapping[str, Any]:
    """Fetch one Golike drag-puzzle challenge using a signed request."""
    data = _signed_security_post(
        path=SECURITY_CAPTCHA_CHALLENGE_PATH,
        payload={},
        signing_key=signing_key,
        device_id=device_id,
        user_id=user_id,
        token=token,
        timeout=timeout,
        scheme=scheme,
        session=session,
    )
    payload = _security_response_payload(data)

    # Check if server returned an error or message
    msg = None
    if isinstance(data, Mapping):
        msg = data.get("message") or data.get("error")
    if isinstance(payload, Mapping) and not msg:
        msg = payload.get("message") or payload.get("error")

    # Locate challenge object (under "challenge" or flattened in payload/data)
    challenge = None
    if isinstance(payload, Mapping):
        challenge = payload.get("challenge")
        if not isinstance(challenge, Mapping) and (
            payload.get("challengeId") or payload.get("challenge_id") or payload.get("geometry")
        ):
            challenge = payload
    if not isinstance(challenge, Mapping) and isinstance(data, Mapping):
        challenge = data.get("challenge")

    if not isinstance(challenge, Mapping):
        error_detail = f": {msg}" if msg else f": {data!r}"
        raise SecurityCaptchaError(f"captcha challenge response is missing challenge{error_detail}")

    cid = challenge.get("challengeId") or challenge.get("challenge_id") or challenge.get("id")
    kind = str(challenge.get("kind") or "").lower()
    geo = challenge.get("geometry")
    site_key = challenge.get("siteKey") or challenge.get("site_key")
    if not cid:
        error_detail = f": {msg}" if msg else f": {data!r}"
        raise SecurityCaptchaError(f"captcha challenge is missing challengeId{error_detail}")
    if kind != "turnstile" and not isinstance(geo, Mapping):
        error_detail = f": {msg}" if msg else f": {data!r}"
        raise SecurityCaptchaError(f"captcha challenge is missing geometry{error_detail}")
    if kind == "turnstile" and not site_key:
        error_detail = f": {msg}" if msg else f": {data!r}"
        raise SecurityCaptchaError(f"turnstile challenge is missing siteKey{error_detail}")
    return dict(challenge)



def _normalize_captcha_points(
    points: Sequence[Sequence[Union[int, float]]],
) -> list:
    if isinstance(points, (str, bytes)) or not isinstance(points, Sequence):
        raise SecurityCaptchaError(
            "captcha solver must return a sequence of [elapsed_ms, x, y] points"
        )
    normalized = []
    for point in points:
        if (
            isinstance(point, (str, bytes))
            or not isinstance(point, Sequence)
            or len(point) != 3
        ):
            raise SecurityCaptchaError(
                "each captcha point must contain [elapsed_ms, x, y]"
            )
        values = []
        for value in point:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise SecurityCaptchaError("captcha point values must be numeric")
            if not math.isfinite(float(value)):
                raise SecurityCaptchaError("captcha point values must be finite")
            values.append(value)
        normalized.append(values)
    if len(normalized) < 2:
        raise SecurityCaptchaError("captcha solver must return at least two points")
    return normalized


def verify_captcha_challenge(
    *,
    challenge_id: str,
    points: Sequence[Sequence[Union[int, float]]],
    signing_key: str,
    device_id: str,
    user_id: Union[int, str],
    token: str,
    timeout: float = 10,
    scheme: str = GWEB_SCHEME,
    session=None,
) -> bool:
    """Submit human-collected pointer samples for one drag challenge."""
    normalized = _normalize_captcha_points(points)
    data = _signed_security_post(
        path=SECURITY_CAPTCHA_VERIFY_PATH,
        payload={"challengeId": str(challenge_id), "points": normalized},
        signing_key=signing_key,
        device_id=device_id,
        user_id=user_id,
        token=token,
        timeout=timeout,
        scheme=scheme,
        session=session,
    )
    return bool(_security_response_payload(data).get("ok"))


def verify_turnstile_challenge(
    *,
    challenge_id: str,
    turnstile_token: str,
    signing_key: str,
    device_id: str,
    user_id: Union[int, str],
    token: str,
    timeout: float = 10,
    scheme: str = GWEB_SCHEME,
    session=None,
) -> bool:
    """Submit a Cloudflare Turnstile token for one challenge."""
    data = _signed_security_post(
        path=SECURITY_CAPTCHA_VERIFY_PATH,
        payload={"challengeId": str(challenge_id), "token": str(turnstile_token)},
        signing_key=signing_key,
        device_id=device_id,
        user_id=user_id,
        token=token,
        timeout=timeout,
        scheme=scheme,
        session=session,
    )
    return bool(_security_response_payload(data).get("ok"))


def auto_solve_captcha(
    challenge: Mapping[str, Any],
    message: str = "",
) -> Optional[Sequence[Sequence[Union[int, float]]]]:
    """
    Automatic captcha solver for Golike drag challenge mimicking real human behavior.
    Matches human kinematics captured from browser session in ga.py:
    - Initial touch-down hesitation hold (~380-450ms)
    - Smooth cubic Bezier trajectory with micro-jitter (human tremor)
    - Passes within the dashed circle (waypoint)
    - Lands safely inside target circle
    - Final hold/settle on target (~300-500ms) before finger lift
    - Total duration: ~2.0 - 2.8s, matching '~5 giay' prompt
    """
    try:
        geo = challenge.get("geometry")
        if not isinstance(geo, Mapping):
            return None

        start = geo.get("start")
        waypoint = geo.get("waypoint")
        if not waypoint and isinstance(geo.get("waypoints"), list) and geo["waypoints"]:
            waypoint = geo["waypoints"][-1]
        target = geo.get("target")
        if not all(isinstance(p, Mapping) for p in (start, waypoint, target)):
            return None

        sx = float(start["x"])
        sy = float(start["y"])
        wx = float(waypoint["x"])
        wy = float(waypoint["y"])
        wr = float(waypoint.get("r", 34))
        tx = float(target["x"])
        ty = float(target["y"])
        tr = float(target.get("r", 22))

        # Initial touch offset (inside the blue box)
        touch_x = sx + (secrets.randbelow(800) - 400) / 100.0
        touch_y = sy + (secrets.randbelow(800) - 400) / 100.0

        points: list[list[Union[int, float]]] = []
        t = 0.0

        # 1. Touch start at t = 0
        points.append([0, round(touch_x, 2), round(touch_y, 2)])

        # 2. Hesitation / touch-down hold before movement (~380 - 450 ms)
        t = float(secrets.randbelow(70) + 380) + round(secrets.randbelow(10) / 10.0, 1)
        touch_x += (secrets.randbelow(40) - 20) / 100.0
        touch_y += (secrets.randbelow(40) - 20) / 100.0
        points.append([round(t, 1), round(touch_x, 2), round(touch_y, 2)])

        # Intermediate waypoint target (safely inside dashed circle)
        wp_target_x = wx + (secrets.randbelow(int(wr * 40)) - int(wr * 20)) / 100.0
        wp_target_y = wy + (secrets.randbelow(int(wr * 40)) - int(wr * 20)) / 100.0

        # Final target (safely inside green circle)
        final_x = tx + (secrets.randbelow(int(tr * 40)) - int(tr * 20)) / 100.0
        final_y = ty + (secrets.randbelow(int(tr * 40)) - int(tr * 20)) / 100.0

        def generate_bezier_segment(
            p0: tuple[float, float],
            p1: tuple[float, float],
            p2: tuple[float, float],
            p3: tuple[float, float],
            steps: int,
            dt_min: float = 8.0,
            dt_max: float = 16.0,
        ):
            nonlocal t
            for i in range(1, steps + 1):
                u = i / steps
                inv_u = 1.0 - u
                x = (
                    inv_u**3 * p0[0]
                    + 3 * inv_u**2 * u * p1[0]
                    + 3 * inv_u * u**2 * p2[0]
                    + u**3 * p3[0]
                )
                y = (
                    inv_u**3 * p0[1]
                    + 3 * inv_u**2 * u * p1[1]
                    + 3 * inv_u * u**2 * p2[1]
                    + u**3 * p3[1]
                )
                jitter_x = (secrets.randbelow(60) - 30) / 100.0
                jitter_y = (secrets.randbelow(60) - 30) / 100.0
                dt = (secrets.randbelow(int((dt_max - dt_min) * 10)) / 10.0) + dt_min
                t += dt
                points.append([round(t, 1), round(x + jitter_x, 2), round(y + jitter_y, 2)])

        # Phase 1: From start to waypoint
        ctrl1_x = touch_x + (wp_target_x - touch_x) * 0.3 + (secrets.randbelow(16) - 8)
        ctrl1_y = touch_y + (wp_target_y - touch_y) * 0.3 + (secrets.randbelow(16) - 8)
        ctrl2_x = touch_x + (wp_target_x - touch_x) * 0.7 + (secrets.randbelow(12) - 6)
        ctrl2_y = touch_y + (wp_target_y - touch_y) * 0.7 + (secrets.randbelow(12) - 6)
        steps1 = secrets.randbelow(8) + 40
        generate_bezier_segment(
            (touch_x, touch_y),
            (ctrl1_x, ctrl1_y),
            (ctrl2_x, ctrl2_y),
            (wp_target_x, wp_target_y),
            steps=steps1,
            dt_min=9.0,
            dt_max=16.0,
        )

        # Phase 2: From waypoint to target
        ctrl3_x = wp_target_x + (final_x - wp_target_x) * 0.35 + (secrets.randbelow(12) - 6)
        ctrl3_y = wp_target_y + (final_y - wp_target_y) * 0.35 + (secrets.randbelow(12) - 6)
        ctrl4_x = wp_target_x + (final_x - wp_target_x) * 0.75 + (secrets.randbelow(10) - 5)
        ctrl4_y = wp_target_y + (final_y - wp_target_y) * 0.75 + (secrets.randbelow(10) - 5)
        steps2 = secrets.randbelow(8) + 42
        generate_bezier_segment(
            (wp_target_x, wp_target_y),
            (ctrl3_x, ctrl3_y),
            (ctrl4_x, ctrl4_y),
            (final_x, final_y),
            steps=steps2,
            dt_min=8.0,
            dt_max=15.0,
        )

        # Phase 3: Hold / settle at target before lifting finger
        settle_points = secrets.randbelow(3) + 3
        for _ in range(settle_points):
            t += secrets.randbelow(120) + 80
            jx = (secrets.randbelow(20) - 10) / 100.0
            jy = (secrets.randbelow(20) - 10) / 100.0
            points.append([round(t, 1), round(final_x + jx, 2), round(final_y + jy, 2)])

        if len(points) < 10:
            return None
        return points
    except Exception:
        return None


SOLVECAPTCHA_API = "https://api.solvecaptcha.com"


def solve_turnstile_via_service(
    site_key: str,
    *,
    page_url: str = "https://app.golike.net/",
    api_key: Optional[str] = None,
    action: Optional[str] = None,
    data: Optional[str] = None,
    pagedata: Optional[str] = None,
    timeout: float = 120,
    poll_interval: float = 5,
    session=None,
) -> Optional[str]:
    """Solve a Cloudflare Turnstile via the SolveCaptcha API (2captcha-compatible).

    This is the recommended path for ``kind == "turnstile"``: SolveCaptcha's own
    infrastructure solves the widget and returns a valid token, which we then
    submit to GoLike's ``/api/v1/security/captcha/verify``.

    Requires an API key: pass ``api_key`` or set ``GOLIKE_SOLVECAPTCHA_API_KEY``.
    Returns ``None`` if the service did not produce a token in time.
    """
    import requests  # curl_cffi is swapped in at import time

    key = (api_key or os.environ.get("GOLIKE_SOLVECAPTCHA_API_KEY") or "").strip()
    if not site_key:
        return None
    if not key:
        raise SecurityCaptchaError(
            "SolveCaptcha API key is required (set GOLIKE_SOLVECAPTCHA_API_KEY)"
        )

    http = session or requests
    form: dict = {
        "key": key,
        "method": "turnstile",
        "sitekey": site_key,
        "pageurl": page_url,
        "json": "1",
    }
    if action:
        form["action"] = action
    if data:
        form["data"] = data
    if pagedata:
        form["pagedata"] = pagedata
    submit = http.post(
        f"{SOLVECAPTCHA_API}/in.php",
        data=form,
        timeout=timeout,
    )

    task_id: Optional[str] = None
    try:
        body = submit.json()
    except Exception:
        body = None
    if isinstance(body, Mapping) and body.get("status") == 1:
        task_id = (str(body.get("request") or "").strip() or None)
    elif isinstance(body, Mapping):
        raise SecurityCaptchaError(
            f"SolveCaptcha in.php error: {body.get('request') or body}"
        )
    else:
        text = (submit.text or "").strip()
        if text.startswith("OK|"):
            task_id = text.split("|", 1)[1].strip() or None
        else:
            raise SecurityCaptchaError(f"SolveCaptcha in.php failed: {text!r}")

    if not task_id:
        raise SecurityCaptchaError("SolveCaptcha in.php did not return a task id")

    deadline = time.time() + (timeout if timeout and timeout > 0 else 120)
    interval = poll_interval if poll_interval and poll_interval > 0 else 5
    while time.time() < deadline:
        res = http.get(
            f"{SOLVECAPTCHA_API}/res.php",
            params={"key": key, "action": "get", "id": task_id, "json": "1"},
            timeout=max(float(timeout), 30.0),
        )
        try:
            rbody = res.json()
        except Exception:
            rbody = None
        if isinstance(rbody, Mapping) and rbody.get("status") == 1:
            token_value = (str(rbody.get("request") or "").strip() or None)
            return token_value
        if isinstance(rbody, Mapping):
            req = str(rbody.get("request") or "")
            if req and req != "CAPCHA_NOT_READY":
                raise SecurityCaptchaError(f"SolveCaptcha res.php error: {rbody}")
        else:
            text = (res.text or "").strip()
            if text.startswith("OK|"):
                return text.split("|", 1)[1].strip() or None
            if text and text != "CAPCHA_NOT_READY":
                raise SecurityCaptchaError(f"SolveCaptcha res.php error: {text!r}")
        time.sleep(interval)

    return None


def solve_turnstile_via_playwright(
    site_key: str,
    *,
    url: str = "https://app.golike.net/",
    timeout: float = 45,
    headless: Optional[bool] = None,
    executable_path: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Optional[str]:
    """Solve a Cloudflare Turnstile challenge with Playwright and return the token.

    GoLike binds the Turnstile ``siteKey`` to the ``app.golike.net`` origin, so we
    open that origin, inject an explicit (hidden) Turnstile render and read the
    token from its ``callback``. Invisible (non-interactive) Turnstile emits the
    token by itself; for interactive (checkbox) Turnstile we also click the
    challenge frame once as a best-effort.

    Set ``GOLIKE_TURNSTILE_HEADLESS=0`` (or pass ``headless=False``) if Cloudflare
    keeps rejecting the headless browser.
    """
    if not site_key:
        return None
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        raise SecurityCaptchaError(
            f"playwright is required to solve a Turnstile challenge: {exc}"
        ) from exc

    if headless is None:
        env = (os.environ.get("GOLIKE_TURNSTILE_HEADLESS") or "").strip().lower()
        headless = False if env in ("0", "false", "no", "off") else True

    injected = site_key.replace("\\", "\\\\").replace("`", "\\`")
    render_js = (
        "(() => {"
        "window.__glk_turnstile_token = null;"
        "window.__glk_turnstile_error = null;"
        "const el = document.createElement('div');"
        "el.id = 'glk-turnstile';"
        "el.style.cssText = 'position:fixed;top:8px;left:8px;width:300px;height:66px;z-index:2147483647;';"
        "document.body.appendChild(el);"
        "try {"
        "window.turnstile.render('#glk-turnstile', {"
        "sitekey: `" + injected + "`,"
        "callback: (t) => { window.__glk_turnstile_token = t; },"
        "'error-callback': () => { window.__glk_turnstile_error = 'error'; },"
        "'expired-callback': () => { window.__glk_turnstile_error = 'expired'; },"
        "'timeout-callback': () => { window.__glk_turnstile_error = 'timeout'; },"
        "});"
        "} catch (e) { window.__glk_turnstile_error = String(e && e.message ? e.message : e); }"
        "})()"
    )

    ms = int((timeout if timeout and timeout > 0 else 45) * 1000)
    state: dict = {"token": None, "error": None}

    with sync_playwright() as p:
        browser = None
        try:
            launch_kwargs: dict = {"args": ["--disable-blink-features=AutomationControlled"]}
            if executable_path:
                launch_kwargs["executable_path"] = executable_path
            browser = p.chromium.launch(headless=headless, **launch_kwargs)
            context = browser.new_context(
                user_agent=user_agent, locale="vi-VN", viewport={"width": 1280, "height": 720}
            )
            context.add_init_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
            )
            page = context.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=ms)
            page.wait_for_selector("body", timeout=ms)
            page.add_script_tag(
                url="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"
            )
            page.wait_for_function(
                "() => window.turnstile && typeof window.turnstile.render === 'function'",
                timeout=ms,
            )
            page.evaluate(render_js)

            clicked = False
            deadline = time.time() + (ms / 1000.0)
            while time.time() < deadline:
                state = page.evaluate(
                    "() => ({token: window.__glk_turnstile_token, "
                    "error: window.__glk_turnstile_error})"
                )
                if state.get("token") or state.get("error"):
                    break
                if not clicked:
                    for frame in page.frames:
                        if "challenges.cloudflare.com" in (frame.url or ""):
                            try:
                                frame.click("body", timeout=2000)
                            except Exception:
                                pass
                            clicked = True
                            break
                time.sleep(1.0)
        except Exception as exc:
            state["error"] = str(exc)
        finally:
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass

    token_value = state.get("token") if isinstance(state, Mapping) else None
    return str(token_value) if token_value else None


def solve_security_captcha(
    *,
    turnstile_solver: Optional[TurnstileSolver] = None,
    solver: Optional[CaptchaSolver] = None,
    signing_key: str,
    device_id: str,
    user_id: Union[int, str],
    token: str,
    message: str = "",
    max_attempts: int = 3,
    timeout: float = 15,
    scheme: str = GWEB_SCHEME,
    session=None,
) -> bool:
    """
    Run the bundle's challenge/verify loop for both challenge kinds.

    * ``drag`` (Golike puzzle) — ``solver`` (default ``auto_solve_captcha``)
      returns ``[elapsed_ms, x, y]`` pointer samples.
    * ``turnstile`` (Cloudflare) — solved via ``turnstile_solver`` (default is
      ``solve_turnstile_via_service`` when ``GOLIKE_SOLVECAPTCHA_API_KEY`` is set,
      otherwise ``solve_turnstile_via_playwright``), returning a Cloudflare token.

    Returning ``None`` / an empty token cancels the challenge.
    """
    active_solver = solver or auto_solve_captcha
    if turnstile_solver is not None:
        active_turnstile = turnstile_solver
    elif (os.environ.get("GOLIKE_SOLVECAPTCHA_API_KEY") or "").strip():
        active_turnstile = solve_turnstile_via_service
    else:
        active_turnstile = solve_turnstile_via_playwright
    if not callable(active_solver):
        raise TypeError("captcha solver must be callable")
    if not callable(active_turnstile):
        raise TypeError("turnstile solver must be callable")
    attempts = int(max_attempts)
    if attempts < 1:
        raise ValueError("captcha max_attempts must be at least 1")
    for _ in range(attempts):
        challenge = fetch_captcha_challenge(
            signing_key=signing_key,
            device_id=device_id,
            user_id=user_id,
            token=token,
            timeout=max(float(timeout), 15.0),
            scheme=scheme,
            session=session,
        )
        cid = str(challenge.get("challengeId") or challenge.get("challenge_id") or challenge.get("id"))
        kind = str(challenge.get("kind") or "").lower()

        if kind == "turnstile":
            site_key = str(challenge.get("siteKey") or challenge.get("site_key") or "")
            turnstile_token = active_turnstile(site_key)
            if not turnstile_token:
                return False
            if verify_turnstile_challenge(
                challenge_id=cid,
                turnstile_token=turnstile_token,
                signing_key=signing_key,
                device_id=device_id,
                user_id=user_id,
                token=token,
                timeout=max(float(timeout), 15.0),
                scheme=scheme,
                session=session,
            ):
                return True
            continue

        points = active_solver(challenge, message)
        if points is None:
            return False
        if verify_captcha_challenge(
            challenge_id=cid,
            points=points,
            signing_key=signing_key,
            device_id=device_id,
            user_id=user_id,
            token=token,
            timeout=max(float(timeout), 15.0),
            scheme=scheme,
            session=session,
        ):
            return True
    return False



def mint_security_token(
    *,
    method: str,
    path: str,
    signing_key: str,
    device_id: str,
    user_id: Union[int, str],
    token: str,
    body: JsonBody = None,
    base_url: str = LEGACY_API,
    plt: str = "tiktok",
    act: Optional[str] = None,
    timeout: float = 30,
    telemetry: Optional[Mapping[str, Any]] = None,
    scheme: str = GWEB_SCHEME,
    captcha_solver: Optional[CaptchaSolver] = None,
    captcha_max_attempts: int = 3,
    session=None,
) -> Optional[str]:
    """POST /api/v1/security/token → token dung lam header sig."""
    import requests

    # Auto-detect platform + act from path when caller leaves defaults.
    detected = resolve_sig_act(path)
    if detected:
        detected_plt, detected_act = detected
        if act is None:
            act = detected_act
        # Override default plt="tiktok" when path maps to another platform.
        if plt == "tiktok" or not plt:
            plt = detected_plt
    elif act is None:
        act = resolve_tiktok_sig_act(path)

    if not act:
        return None

    path_only, query = split_path_query(path)
    if body is None:
        body_str = ""
    elif isinstance(body, str):
        body_str = body
    elif isinstance(body, bytes):
        body_str = body.decode("utf-8")
    else:
        body_str = json.dumps(body, ensure_ascii=False, separators=(",", ":"))

    canon = normalize_path(path_only, base_url)
    mint_body_obj = {
        "plt": plt,
        "act": act,
        "req": {
            "method": method.upper(),
            "path": canon,
            "query": query,
            "body": body_str,
        },
    }
    if telemetry is not None:
        mint_body_obj["tel"] = dict(telemetry)
    else:
        tel_data = {
            "trg": "click",
            "aut": 0,
            "idle": secrets.randbelow(120) + 40,
            "iev": secrets.randbelow(1800) + 150,
            "vis": 1,
            "foc": 1,
        }
        if act == "complete_job" and isinstance(body, dict) and "val" in body:
            try:
                tel_data["val"] = int(body["val"])
            except (TypeError, ValueError):
                pass
        mint_body_obj["tel"] = tel_data
    mint_body = json.dumps(mint_body_obj, ensure_ascii=False, separators=(",", ":"))
    url = f"{SECURITY_API}{SECURITY_TOKEN_PATH}"
    http = session or requests

    def _mint_once() -> tuple:
        g_auth = generate_gweb_g_auth(
            method="POST",
            path=SECURITY_TOKEN_PATH,
            body=mint_body,
            signing_key=signing_key,
            device_id=device_id,
            user_id=normalize_user_id(user_id),
            scheme=scheme,
        )
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": ACCEPT_LANGUAGE,
            "Authorization": f"Bearer {_strip_bearer(token)}",
            "Content-Type": "application/json;charset=UTF-8",
            "g-auth": g_auth,
            "Origin": "https://app.golike.net",
            "Priority": PRIORITY_HEADER,
            "User-Agent": MOBILE_UA,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
        }

        response = http.post(
            url,
            headers=headers,
            data=mint_body.encode("utf-8"),
            timeout=timeout,
        )
        try:
            data = response.json()
        except Exception:
            raise SecurityTokenMintError(
                "POST /security/token returned non-JSON response: "
                f"HTTP {getattr(response, 'status_code', '?')}"
            )
        if getattr(response, "status_code", 200) >= 400:
            raise SecurityTokenMintError(
                f"POST /security/token failed: HTTP {response.status_code}: {data!r}",
                response=data if isinstance(data, Mapping) else None,
                retryable=response.status_code >= 500,
            )
        return data, _security_response_payload(data)

    def _token_or_error(
        data: Any, payload: Mapping[str, Any]
    ) -> Optional[str]:
        token_value = payload.get("token")
        if isinstance(token_value, str) and token_value:
            return token_value
        reason_value = payload.get("reason")
        reason = reason_value if isinstance(reason_value, str) else None
        action_value = payload.get("action")
        action = action_value if isinstance(action_value, str) else None
        message_value = payload.get("message")
        message = message_value if isinstance(message_value, str) else ""
        if not action:
            if reason == "captcha":
                action = "captcha"
            elif reason == "update_required":
                action = "update"
            elif message:
                action = "block"
            else:
                action = "retry"
        if action == "captcha":
            raise SecurityCaptchaRequired(
                message or "interactive captcha is required",
                reason=reason,
                response=payload,
            )
        detail = message or f"action={action!r}, reason={reason!r}"
        raise SecurityTokenMintError(
            "POST /security/token response is missing a token field: "
            f"{detail}; payload={data!r}",
            action=action,
            reason=reason,
            response=payload,
            retryable=action == "retry",
        )

    data, payload = _mint_once()
    try:
        return _token_or_error(data, payload)
    except SecurityCaptchaRequired as required:
        solver = captcha_solver or auto_solve_captcha
        if solver is None:
            raise
        solved = solve_security_captcha(
            solver=solver,
            signing_key=signing_key,
            device_id=device_id,
            user_id=normalize_user_id(user_id),
            token=token,
            message=str(required),
            max_attempts=captcha_max_attempts,
            timeout=timeout,
            scheme=scheme,
            session=session,
        )
        if not solved:
            raise SecurityCaptchaRequired(
                str(required),
                reason=required.reason,
                response=required.response,
            )
        # The web bundle keeps the current signing_key after a successful
        # challenge and retries the exact same security/token mint once.
        retry_data, retry_payload = _mint_once()
        return _token_or_error(retry_data, retry_payload)


def decode_g_auth(token: str, signing_key: str) -> dict:
    """Decrypt g-auth for debugging."""
    aes_key = derive_aes_key(signing_key)
    raw = b64url_decode(token)
    if len(raw) < 12 + 16:
        raise ValueError("g-auth token is too short to decrypt")
    iv, ct = raw[:12], raw[12:]
    pt = AESGCM(aes_key).decrypt(iv, ct, None)
    return json.loads(pt.decode("utf-8"))


def build_headers(
    *,
    token: str,
    signing_key: Optional[str] = None,
    security_signing_key: Optional[str] = None,
    user_id: Union[int, str] = 0,
    username: str = "",
    method: str = "GET",
    path: str = "/",
    body: JsonBody = None,
    device_id: Optional[str] = None,
    g_version: str = APP_VERSION,
    g_client: str = APP_CLIENT,
    user_agent: Optional[str] = None,
    extra: Optional[Mapping[str, str]] = None,
    with_sig: Optional[bool] = None,
    with_gauth: Optional[bool] = None,
    legacy_client_headers: bool = False,
    sig_telemetry: Optional[Mapping[str, Any]] = None,
    gweb_scheme: str = GWEB_SCHEME,
    captcha_solver: Optional[CaptchaSolver] = None,
    captcha_max_attempts: int = 3,
    timeout: float = 30,
    session=None,
) -> dict:
    """
    Build gateway headers.

    **Golike moi (2026):** chi can Bearer + g-device-id + g-username + t
    (khong g-auth, khong firebase_id, khong g-version/g-client) — giong curl app.

    **Legacy:** neu co signing_key va with_gauth=True (hoac auto khi co key
    + legacy_client_headers) thi them g-auth / sig.
    """
    did = generate_device_id(device_id)
    sign_body: JsonBody = "" if body is None else body
    ua = user_agent or MOBILE_UA
    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": ACCEPT_LANGUAGE,
        "authorization": f"Bearer {token}",
        "content-type": "application/json;charset=utf-8",
        "g-device-id": did,
        "origin": "https://app.golike.net",
        "priority": PRIORITY_HEADER,
        "referer": "https://app.golike.net/",
        "t": make_t_header(),
        "user-agent": ua,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
    }
    if username:
        headers["g-username"] = quote(
            username, safe="-_.!~*'()"
        )

    sk = (signing_key or "").strip() or None
    sig_sk = (security_signing_key or "").strip() or sk
    # Mac dinh: KHONG gui g-auth (API moi). Chi bat khi with_gauth=True.
    use_gauth = False
    if with_gauth is True:
        use_gauth = True
    elif with_gauth is False:
        use_gauth = False
    elif legacy_client_headers and sk:
        use_gauth = True

    if use_gauth:
        if not sk:
            raise ValueError("with_gauth=True requires a valid signing_key")
        headers["g-auth"] = generate_g_auth(
            method=method,
            path=path,
            body=sign_body,
            signing_key=sk,
            device_id=did,
            user_id=normalize_user_id(user_id),
        )
        if legacy_client_headers:
            headers["g-version"] = g_version
            headers["g-client"] = g_client

    # Mint sig via POST api.golike.net/api/v1/security/token (TikTok / Facebook / …)
    # with_sig None = off at build_headers level (caller decides)
    need_sig = bool(with_sig) if with_sig is not None else False
    if need_sig:
        if not sig_sk:
            raise ValueError(
                "Job requests that require sig need a signing_key; "
                "call GolikeAuth.from_token with fetch_session=True or pass signing_key"
            )
        detected = resolve_sig_act(path)
        plt_val = detected[0] if detected else "tiktok"
        act_val = detected[1] if detected else None
        sig = mint_security_token(
            method=method,
            path=path,
            body=sign_body,
            signing_key=sig_sk,
            device_id=did,
            user_id=normalize_user_id(user_id),
            token=token,
            plt=plt_val,
            act=act_val,
            telemetry=sig_telemetry,
            scheme=gweb_scheme,
            captcha_solver=captcha_solver,
            captcha_max_attempts=captcha_max_attempts,
            timeout=timeout,
            session=session,
        )
        if not sig:
            raise ValueError(
                "failed to mint sig: path is not a recognized jobs endpoint "
                "(publishers/<plt>/jobs or get-jobs-2026)"
            )
        headers["sig"] = sig
    if extra:
        headers.update(dict(extra))
    return headers


class GolikeAuth:
    """Golike auth helper with separate gateway and security-session keys."""

    def __init__(
        self,
        *,
        token: str,
        signing_key: Optional[str] = None,
        gateway_signing_key: Optional[str] = None,
        user_id: Union[int, str] = 0,
        username: str = "",
        device_id: Optional[str] = None,
        g_version: str = APP_VERSION,
        g_client: str = APP_CLIENT,
        base_url: str = BASE_API,
        user_agent: Optional[str] = None,
        enable_sig: bool = False,
        enable_gauth: Optional[bool] = None,
        gweb_scheme: str = GWEB_SCHEME,
        captcha_solver: Optional[CaptchaSolver] = None,
        captcha_max_attempts: int = 3,
    ) -> None:
        self.token = token
        self.signing_key = (signing_key or "").strip() or None
        self.security_signing_key = self.signing_key
        gateway_key = gateway_signing_key
        if gateway_key is None and enable_gauth is True:
            # Backward compatibility for direct callers that historically
            # supplied one key for an explicitly enabled gateway g-auth.
            gateway_key = signing_key
        self.gateway_signing_key = (
            (gateway_key or "").strip() or None
        )
        self.user_id = normalize_user_id(user_id)
        self.username = username or ""
        self.device_id = generate_device_id(device_id)
        self.g_version = g_version
        self.g_client = g_client
        self.base_url = base_url.rstrip("/")
        self.user_agent = user_agent or MOBILE_UA
        self.gweb_scheme = str(gweb_scheme or GWEB_SCHEME).strip().lower()
        _gweb_config(self.gweb_scheme)
        self.captcha_solver = captcha_solver or auto_solve_captcha
        self.captcha_max_attempts = int(captcha_max_attempts)
        if self.captcha_max_attempts < 1:
            raise ValueError("captcha_max_attempts must be at least 1")
        self.session = None
        self.profile: dict = {}
        self.security_session: dict = {}
        self.signing_key_exp: Optional[int] = None
        self.scheme_version: Optional[str] = None
        # Default False — does not touch non-TikTok job APIs
        self.enable_sig = bool(enable_sig)
        self.enable_gauth = enable_gauth if enable_gauth is not None else False

    @property
    def security_signing_key(self) -> Optional[str]:
        """Session key used only by the gweb security/token signer."""
        return self.signing_key

    @security_signing_key.setter
    def security_signing_key(self, value: Optional[str]) -> None:
        self.signing_key = (value or "").strip() or None

    # ------------------------------------------------------------------
    # Bootstrap tu token
    # ------------------------------------------------------------------
    @classmethod
    def from_token(
        cls,
        token: str,
        *,
        signing_key: Optional[str] = None,
        gateway_signing_key: Optional[str] = None,
        device_id: Optional[str] = None,
        username: Optional[str] = None,
        verify: bool = False,
        enable_sig: bool = False,
        enable_gauth: Optional[bool] = None,
        fetch_session: bool = True,
        gweb_scheme: str = GWEB_SCHEME,
        captcha_solver: Optional[CaptchaSolver] = None,
        captcha_max_attempts: int = 3,
        timeout: float = 30,
        session=None,
    ) -> "GolikeAuth":
        """
        Bootstrap from JWT only.

        1. GET gateway /users/me
        2. POST security/session with g-scheme:gweb-v2 → security signing_key
           when fetch_session=True
        3. Keep optional /users/me firebase_id separate for gateway g-auth
        4. TikTok jobs need enable_sig=True to mint header sig

        enable_sig defaults to False so other job APIs are unaffected.
        """
        token = (token or "").strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        user_id = jwt_user_id(token)
        did = generate_device_id(device_id)

        me = fetch_user_me(
            token, device_id=did, timeout=timeout, session=session
        )
        if me.get("id") is not None:
            user_id = normalize_user_id(me["id"])
        uname = (username or me.get("username") or me.get("name") or "user").strip()

        gateway_sk = resolve_signing_key(
            me, signing_key=gateway_signing_key
        )
        if (
            not gateway_sk
            and gateway_signing_key is None
            and enable_gauth is True
            and signing_key
        ):
            # Backward compatibility: from_token(signing_key=...,
            # enable_gauth=True) historically treated that key as gateway key.
            gateway_sk = resolve_signing_key(
                None, signing_key=signing_key
            )
        security_sk = (signing_key or "").strip() or None
        session_meta: dict = {}
        if fetch_session:
            try:
                session_meta = fetch_security_session(
                    token,
                    timeout=timeout,
                    session=session,
                    scheme=gweb_scheme,
                )
                security_sk = session_meta.get("signing_key")
            except Exception:
                if enable_sig or not (security_sk or gateway_sk):
                    raise
                security_sk = security_sk or gateway_sk
        elif not security_sk:
            # Legacy/direct mode only; gweb callers should fetch a session.
            security_sk = gateway_sk

        use_gauth = (
            bool(enable_gauth)
            if enable_gauth is not None
            else bool(enable_sig and gateway_sk)
        )
        if use_gauth and not gateway_sk:
            raise ValueError(
                "enable_gauth=True requires firebase_id from /users/me "
                "or an explicit gateway signing_key"
            )

        auth = cls(
            token=token,
            signing_key=security_sk,
            gateway_signing_key=gateway_sk,
            user_id=user_id,
            username=uname,
            device_id=did,
            user_agent=MOBILE_UA,
            enable_sig=enable_sig,
            enable_gauth=use_gauth,
            gweb_scheme=gweb_scheme,
            captcha_solver=captcha_solver,
            captcha_max_attempts=captcha_max_attempts,
        )
        auth.profile = dict(me)
        if session_meta:
            auth._apply_security_session(session_meta)

        if verify and use_gauth and gateway_sk:
            ok, detail = auth.verify_signing_key(timeout=timeout)
            if not ok:
                raise ValueError(
                    f"signing_key verification failed via /security/echo: {detail}"
                )
        return auth

    def _apply_security_session(self, meta: Mapping[str, Any]) -> None:
        self.security_session = dict(meta.get("raw") or meta)
        sk = meta.get("signing_key")
        if sk:
            self.signing_key = str(sk).strip()
            self.security_signing_key = self.signing_key
        exp = meta.get("exp")
        try:
            self.signing_key_exp = int(exp) if exp is not None else None
        except (TypeError, ValueError):
            self.signing_key_exp = None
        ver = meta.get("schemeVersion") or meta.get("scheme_version")
        self.scheme_version = str(ver) if ver else None

    def refresh_signing_key(
        self, *, timeout: float = 30, force: bool = False, session=None
    ) -> str:
        """
        Goi lai POST /security/session khi key het han (exp) hoac force=True.
        """
        if not force and self.signing_key and self.signing_key_exp:
            # refresh som 60s
            if int(time.time()) < int(self.signing_key_exp) - 60:
                return self.signing_key
        meta = fetch_security_session(
            self.token,
            timeout=timeout,
            session=session,
            scheme=self.gweb_scheme,
        )
        self._apply_security_session(meta)
        if not self.signing_key:
            raise ValueError("refresh_signing_key returned an empty signing_key")
        return self.signing_key

    @property
    def firebase_id(self) -> Optional[str]:
        """Legacy alias — API moi thuong None."""
        if self.gateway_signing_key:
            return self.gateway_signing_key
        val = (self.profile or {}).get("firebase_id")
        return str(val).strip() if val else None

    @firebase_id.setter
    def firebase_id(self, value: Optional[str]) -> None:
        self.gateway_signing_key = (value or "").strip() or None

    def verify_signing_key(self, timeout: float = 30) -> tuple:
        """
        POST /security/echo (legacy). API moi khong can.
        Returns (ok: bool, detail: dict|str)
        """
        import requests

        gateway_key = self.gateway_signing_key or self.signing_key
        if not gateway_key:
            return False, "no signing_key"
        body = json.dumps({"ping": 1}, separators=(",", ":"))
        headers = self.headers(
            "POST", "/security/echo", body=body, with_gauth=True
        )
        try:
            resp = requests.post(
                f"{self.base_url}/security/echo",
                headers=headers,
                data=body.encode("utf-8"),
                timeout=timeout,
            )
            data = resp.json()
        except Exception as e:
            return False, str(e)

        msg = str(data.get("message") or data.get("error") or "")
        if data.get("code") == 429 or "429" in msg or "qua nhanh" in msg.lower():
            return True, {"rate_limited": True, "message": msg}

        g = {}
        if isinstance(data.get("data"), dict):
            g = data["data"].get("gauth") or {}
        errs = g.get("errors") or []
        decoded = g.get("decoded")
        if decoded is not None and not any("decrypt" in str(e).lower() for e in errs):
            return True, {"decoded": decoded, "version": g.get("version_detected")}
        return False, {"errors": errs, "status": data.get("status"), "message": msg}

    def refresh_profile(self, timeout: float = 30) -> dict:
        """Cap nhat self.profile tu /users/me."""
        self.profile = fetch_user_me(
            self.token, device_id=self.device_id, timeout=timeout
        )
        if self.profile.get("username"):
            self.username = self.profile["username"]
        gateway_key = resolve_signing_key(self.profile)
        if gateway_key:
            self.gateway_signing_key = gateway_key
        return self.profile

    def g_auth(
        self,
        method: str,
        path: str,
        body: JsonBody = None,
        ts_ms: Optional[int] = None,
    ) -> str:
        gateway_key = self.gateway_signing_key or self.signing_key
        if not gateway_key:
            raise ValueError(
                "g_auth is unavailable without a signing_key; "
                "use headers, get, or post for the current API"
            )
        return generate_g_auth(
            method=method,
            path=path,
            body="" if body is None else body,
            signing_key=gateway_key,
            device_id=self.device_id,
            user_id=self.user_id,
            base_url=self.base_url,
            ts_ms=ts_ms,
        )

    def headers(
        self,
        method: str,
        path: str,
        body: JsonBody = None,
        extra: Optional[Mapping[str, str]] = None,
        with_sig: Optional[bool] = None,
        with_gauth: Optional[bool] = None,
        sig_telemetry: Optional[Mapping[str, Any]] = None,
        timeout: float = 30,
        session=None,
    ) -> dict:
        gauth_flag = self.enable_gauth if with_gauth is None else with_gauth
        if with_sig is not None:
            sig_flag = with_sig
        elif self.enable_sig:
            # Any publishers/<plt>/jobs (or get-jobs-2026) needs sig
            sig_flag = resolve_sig_act(path) is not None
        else:
            sig_flag = False

        need_sig = bool(sig_flag)
        if need_sig:
            try:
                self.refresh_signing_key(
                    force=False, timeout=timeout, session=session
                )
            except Exception:
                pass

        gateway_key = self.gateway_signing_key
        if gauth_flag and not gateway_key and not self.security_session:
            # Backward compatibility for direct GolikeAuth(...) callers.
            gateway_key = self.signing_key

        def _build() -> dict:
            return build_headers(
                token=self.token,
                signing_key=gateway_key,
                security_signing_key=(
                    self.security_signing_key or self.signing_key
                ),
                user_id=self.user_id,
                username=self.username,
                method=method,
                path=path,
                body=body,
                device_id=self.device_id,
                g_version=self.g_version,
                g_client=self.g_client,
                user_agent=self.user_agent,
                extra=extra,
                with_sig=sig_flag,
                with_gauth=gauth_flag,
                legacy_client_headers=bool(gauth_flag),
                sig_telemetry=sig_telemetry,
                gweb_scheme=self.gweb_scheme,
                captcha_solver=self.captcha_solver,
                captcha_max_attempts=self.captcha_max_attempts,
                timeout=timeout,
                session=session,
            )

        try:
            return _build()
        except SecurityTokenMintError as exc:
            if not need_sig or not exc.retryable:
                raise
            # Match the web app: clear/refresh the session key and retry once.
            self.refresh_signing_key(
                force=True, timeout=timeout, session=session
            )
            return _build()

    def decode(self, g_auth_token: str) -> dict:
        gateway_key = self.gateway_signing_key or self.signing_key
        if not gateway_key:
            raise ValueError("signing_key is required to decode a g-auth token")
        return decode_g_auth(g_auth_token, gateway_key)

    def _url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        return self.base_url + (path if path.startswith("/") else "/" + path)

    @staticmethod
    def _compact_json(obj: Any) -> str:
        """Match JS JSON.stringify (no spaces) — body bytes must equal signed body."""
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json: Any = None,
        json_body: Any = None,
        data: Any = None,
        timeout: float = 30,
        session=None,
        with_sig: Optional[bool] = None,
        sig_telemetry: Optional[Mapping[str, Any]] = None,
    ):
        """
        Signed HTTP request for ANY gateway path.

        - GET/HEAD/DELETE without body → sign body as ""
        - POST/PUT/PATCH with json=dict → sign + send compact JSON (no spaces)
        - TikTok paths auto-add header `sig` (plt/act binding)
        - Do not use requests' json= yourself (it may add spaces and break q hash)
        """
        import requests
        from urllib.parse import urlencode

        method_u = method.upper()
        payload = json if json is not None else json_body

        # Path dung de ky g-auth/sig: gop query vao path string
        # (g-auth chi lay pathname; sig can ca query)
        sign_path = path
        if params:
            encoded_params = urlencode(params, doseq=True)
            if encoded_params:
                separator = "&" if "?" in path else "?"
                sign_path = f"{path}{separator}{encoded_params}"

        if data is not None and payload is not None:
            raise ValueError("pass only one of data or json")

        if data is not None:
            if isinstance(data, (dict, list)):
                raw = self._compact_json(data)
                headers = self.headers(
                    method_u,
                    sign_path,
                    body=raw,
                    with_sig=with_sig,
                    sig_telemetry=sig_telemetry,
                    timeout=timeout,
                    session=session,
                )
                send: Any = raw.encode("utf-8")
            elif isinstance(data, str):
                headers = self.headers(
                    method_u,
                    sign_path,
                    body=data,
                    with_sig=with_sig,
                    sig_telemetry=sig_telemetry,
                    timeout=timeout,
                    session=session,
                )
                send = data.encode("utf-8")
            elif isinstance(data, bytes):
                headers = self.headers(
                    method_u,
                    sign_path,
                    body=data.decode("utf-8"),
                    with_sig=with_sig,
                    sig_telemetry=sig_telemetry,
                    timeout=timeout,
                    session=session,
                )
                send = data
            else:
                raise TypeError("data must be a dict, list, str, or bytes")
            return (session or requests).request(
                method_u,
                self._url(path),
                params=params,
                data=send,
                headers=headers,
                timeout=timeout,
            )

        if payload is not None:
            raw = self._compact_json(payload)
            headers = self.headers(
                method_u,
                sign_path,
                body=raw,
                with_sig=with_sig,
                sig_telemetry=sig_telemetry,
                timeout=timeout,
                session=session,
            )
            return (session or requests).request(
                method_u,
                self._url(path),
                params=params,
                data=raw.encode("utf-8"),
                headers=headers,
                timeout=timeout,
            )

        # no body
        headers = self.headers(
            method_u,
            sign_path,
            body="",
            with_sig=with_sig,
            sig_telemetry=sig_telemetry,
            timeout=timeout,
            session=session,
        )
        return (session or requests).request(
            method_u,
            self._url(path),
            params=params,
            headers=headers,
            timeout=timeout,
        )

    def get(self, path: str, *, params: Optional[Mapping[str, Any]] = None, **kw):
        return self.request("GET", path, params=params, **kw)

    def post(self, path: str, *, json: Any = None, params=None, **kw):
        return self.request("POST", path, json=json, params=params, **kw)

    def put(self, path: str, *, json: Any = None, params=None, **kw):
        return self.request("PUT", path, json=json, params=params, **kw)

    def delete(self, path: str, *, params=None, **kw):
        return self.request("DELETE", path, params=params, **kw)

    def wrap_links(self, urls: Sequence[str], *, timeout: float = 15) -> dict:
        jwt = _strip_bearer(self.token)
        headers = {
            "accept": "application/json, text/plain, */*",
            "accept-language": ACCEPT_LANGUAGE,
            "authorization": f"Bearer {jwt}",
            "content-type": "application/json;charset=UTF-8",
            "origin": "https://app.golike.net",
            "priority": PRIORITY_HEADER,
            "user-agent": self.user_agent,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
        }
        res = (self.session or requests).post(
            f"{SECURITY_API}/api/v1/link/wrap",
            headers=headers,
            json={"urls": list(urls)},
            timeout=timeout,
        )
        try:
            return res.json()
        except Exception:
            return {"status_code": getattr(res, "status_code", None), "text": getattr(res, "text", "")}