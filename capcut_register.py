#!/usr/bin/env python3
"""
CapCut Account Creator — Full Device Spoofing
Handles: fingerprint gen, mix_mode encoding, passport API, session management
Email provider is pluggable (default: dummy, will integrate Email API later)
"""
import json
import random
import re
import threading
import string
import time
import uuid
import hashlib
import base64
import sys
import os
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)

# ============================================================
# CONFIG
# ============================================================
CAPCUT_AID = "348188"
SDK_VERSION = "2.1.10-tiktok"
DEFAULT_REGION = "US"
LOGIN_DOMAIN = "https://login-row.www.capcut.com"
CAPCUT_WEB = "https://www.capcut.com"

ACCOUNTS_FILE = "accounts.json"
MAX_RETRIES = 3

# ============================================================
# MIX MODE ENCODING (XOR 0x05, output 2-digit hex per char)
# ============================================================
def mix_encode(text: str) -> str:
    """CapCut's mix_mode encoding: each char XOR 0x05, output as 2-digit lowercase hex"""
    return ''.join(f'{(ord(c) ^ 0x05):02x}' for c in text)


# ============================================================
# DEVICE FINGERPRINT GENERATOR
# ============================================================
class DeviceSpoof:
    """Generates unique device fingerprint per account"""

    # Windows + Mac user agents (Chrome, Edge, Firefox variants)
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/116.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    ]

    @staticmethod
    def generate_device_id() -> str:
        """19-digit numeric device ID"""
        return str(random.randint(10**18, 10**19 - 1))

    @staticmethod
    def generate_verify_fp() -> str:
        """
        verifyFp format: verify_<timestamp_base36>_<uuid_v4_style>
        UUID has dashes at pos 8,13,18,23 and '4' at pos 14
        """
        ts = int(time.time() * 1000)
        ts_b36 = ''
        n = ts
        chars = string.ascii_lowercase + string.digits
        while n > 0:
            ts_b36 = chars[n % 36] + ts_b36
            n //= 36
        if not ts_b36:
            ts_b36 = '0'

        # Generate UUID-like string with correct format
        hex_chars = '0123456789abcdef'
        uuid_parts = []
        for i in range(32):
            if i == 8 or i == 12 or i == 16 or i == 20:
                uuid_parts.append('-')
            if i == 12:
                uuid_parts.append('4')  # UUID v4
            elif i == 16:
                uuid_parts.append(random.choice('89ab'))  # variant
            else:
                uuid_parts.append(random.choice(hex_chars))

        return f"verify_{ts_b36}_{''.join(uuid_parts)}"

    @staticmethod
    def generate_ms_token() -> str:
        """107-char base64url token"""
        raw = os.urandom(80)
        token = base64.urlsafe_b64encode(raw).decode().rstrip('=')
        return token[:107]

    @staticmethod
    def generate_ttwid() -> str:
        """Generate fake ttwid cookie value"""
        raw = os.urandom(32)
        return base64.b64encode(raw).decode().rstrip('=')[:40]

    @staticmethod
    def get_random_ua() -> str:
        return random.choice(DeviceSpoof.USER_AGENTS)

    @classmethod
    def generate(cls, proxy: dict = None) -> dict:
        """Generate complete device fingerprint"""
        return {
            "device_id": cls.generate_device_id(),
            "verify_fp": cls.generate_verify_fp(),
            "ms_token": cls.generate_ms_token(),
            "ttwid": cls.generate_ttwid(),
            "user_agent": cls.get_random_ua(),
            "proxy": proxy,
        }


# ============================================================
# CAPCUT PASSPORT API CLIENT
# ============================================================
class CapCutClient:
    """CapCut passport API client with full device spoofing"""

    def __init__(self, device: dict, verbose: bool = True):
        self.device = device
        self.verbose = verbose

        # Build session
        self.session = requests.Session()

        # Proxy
        if device.get("proxy"):
            self.session.proxies = device["proxy"]

        # Retry logic
        retry = Retry(total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503])
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))

        # Headers
        self.session.headers.update({
            "User-Agent": device["user_agent"],
            "Origin": CAPCUT_WEB,
            "Referer": f"{CAPCUT_WEB}/",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        })

        # Cookies (pre-seed)
        self.session.cookies.set("ttwid", device["ttwid"], domain=".capcut.com")
        self.session.cookies.set("msToken", device["ms_token"], domain=".capcut.com")

        # State
        self.csrf_token = None
        self.login_domain = LOGIN_DOMAIN
        self.common_params = {
            "aid": CAPCUT_AID,
            "account_sdk_source": "web",
            "sdk_version": SDK_VERSION,
            "language": "en",
            "verifyFp": device["verify_fp"],
        }

    def log(self, msg: str):
        if self.verbose:
            print(f"  {msg}")

    # ----------------------------------------------------------
    # Step 1: Bootstrap — get CSRF token + login domain
    # ----------------------------------------------------------
    def bootstrap(self) -> bool:
        """Get region + CSRF token"""
        self.log("[1/6] Bootstrap: region + CSRF...")

        # First, hit capcut.com to get ttwid
        try:
            r = self.session.get(CAPCUT_WEB, timeout=15, allow_redirects=True)
            self.log(f"  capcut.com → {r.status_code}")
        except Exception as e:
            self.log(f"  [!] capcut.com failed: {e}")

        # Get region + CSRF
        url = f"{self.login_domain}/passport/web/region/"
        data = {
            "type": "2",
            "hashed_id": hashlib.md5(os.urandom(16)).hexdigest(),
        }

        try:
            r = self.session.post(url, data=data, params=self.common_params, timeout=15)
            resp = r.json()
            self.log(f"  region → {json.dumps(resp, indent=None)[:200]}")

            if resp.get("data", {}).get("domain"):
                domain = resp['data']['domain']
                if not domain.startswith("http"):
                    domain = f"https://{domain}"
                self.login_domain = domain
                self.log(f"  login domain: {self.login_domain}")

            # Extract CSRF from cookies
            for cookie in self.session.cookies:
                if cookie.name == "passport_csrf_token":
                    self.csrf_token = cookie.value
                    break

            if not self.csrf_token:
                # Generate random one
                self.csrf_token = hashlib.md5(os.urandom(16)).hexdigest()

            self.session.headers["x-tt-passport-csrf-token"] = self.csrf_token
            self.log(f"  CSRF: {self.csrf_token[:16]}...")
            return True

        except Exception as e:
            self.log(f"  [!] Region failed: {e}")
            return False

    # ----------------------------------------------------------
    # Step 2: Check if email is registered
    # ----------------------------------------------------------
    def check_email(self, email: str) -> bool:
        """Check if email already registered. Returns True if AVAILABLE (not registered)"""
        self.log(f"[2/6] Check email: {email}")
        url = f"{self.login_domain}/passport/web/user/check_email_registered"
        data = {
            "mix_mode": "1",
            "email": mix_encode(email),
            "fixed_mix_mode": "1",
        }

        try:
            r = self.session.post(url, data=data, params=self.common_params, timeout=15)
            resp = r.json()
            is_registered = resp.get("data", {}).get("is_registered", 0)
            self.log(f"  registered={is_registered} → {'taken' if is_registered else 'available'}")
            return is_registered == 0
        except Exception as e:
            self.log(f"  [!] check_email failed: {e}")
            return False

    # ----------------------------------------------------------
    # Step 3: Send OTP
    # ----------------------------------------------------------
    def send_otp(self, email: str, password: str) -> bool:
        """Send verification code. type=34 for register"""
        self.log(f"[3/6] Send OTP to {email}...")
        url = f"{self.login_domain}/passport/web/email/send_code/"
        data = {
            "mix_mode": "1",
            "email": mix_encode(email),
            "password": mix_encode(password),
            "type": "34",
            "fixed_mix_mode": "1",
        }

        try:
            r = self.session.post(url, data=data, params=self.common_params, timeout=15)
            resp = r.json()
            self.log(f"  send_code → {json.dumps(resp, indent=None)[:200]}")
            return resp.get("message", "").lower() == "success"
        except Exception as e:
            self.log(f"  [!] send_otp failed: {e}")
            return False

    # ----------------------------------------------------------
    # Step 4: Register + Verify
    # ----------------------------------------------------------
    def register_verify(self, email: str, password: str, otp_code: str,
                        birthday: str = None, region: str = DEFAULT_REGION) -> dict:
        """Register account with OTP verification"""
        if not birthday:
            # Random birthday between 18-35 years ago
            days = random.randint(18 * 365, 35 * 365)
            birthday = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")

        self.log(f"[4/6] Register + verify OTP={otp_code}...")
        url = f"{self.login_domain}/passport/web/email/register_verify_login/"
        data = {
            "mix_mode": "1",
            "email": mix_encode(email),
            "code": mix_encode(otp_code),
            "password": mix_encode(password),
            "type": "34",
            "birthday": birthday,
            "force_user_region": region,
            "biz_param": "{}",
            "fixed_mix_mode": "1",
        }
        params = {**self.common_params, "msToken": self.device["ms_token"]}

        try:
            r = self.session.post(url, data=data, params=params, timeout=15)
            resp = r.json()
            self.log(f"  register → {json.dumps(resp, indent=None)[:300]}")

            if resp.get("message", "").lower() == "success":
                user_data = resp.get("data", {})
                return {
                    "success": True,
                    "user_id": user_data.get("user_id"),
                    "user_id_str": user_data.get("user_id_str"),
                    "screen_name": user_data.get("screen_name"),
                    "email": email,
                    "password": password,
                    "birthday": birthday,
                    "session_cookies": {c.name: c.value for c in self.session.cookies
                                        if "session" in c.name.lower() or "sid" in c.name.lower()
                                        or "uid" in c.name.lower()},
                }
            return {"success": False, "error": resp.get("message", "unknown")}

        except Exception as e:
            self.log(f"  [!] register failed: {e}")
            return {"success": False, "error": str(e)}

    # ----------------------------------------------------------
    # Step 5: Get account info (post-login verification)
    # ----------------------------------------------------------
    def get_account_info(self) -> dict:
        """Fetch account info after login"""
        self.log("[5/6] Fetch account info...")
        url = f"{self.login_domain}/passport/web/account/info/"

        try:
            r = self.session.get(url, params=self.common_params, timeout=15)
            resp = r.json()
            self.log(f"  info → {json.dumps(resp, indent=None)[:300]}")
            return resp.get("data", {})
        except Exception as e:
            self.log(f"  [!] account_info failed: {e}")
            return {}

    # ----------------------------------------------------------
    # Full Registration Flow
    # ----------------------------------------------------------
    def register_account(self, email: str, password: str, otp_code: str,
                         region: str = DEFAULT_REGION) -> dict:
        """Full flow: bootstrap → check → send OTP → register"""

        # Step 1: Bootstrap
        if not self.bootstrap():
            return {"success": False, "error": "bootstrap_failed"}

        # Step 2: Check email
        available = self.check_email(email)
        if not available:
            return {"success": False, "error": "email_taken"}

        # Step 3: Send OTP
        otp_sent = self.send_otp(email, password)
        if not otp_sent:
            return {"success": False, "error": "otp_send_failed"}

        # At this point, caller needs to provide the OTP code
        # This is where Email API integration goes
        if not otp_code:
            return {
                "success": False,
                "error": "otp_required",
                "message": "OTP sent. Provide code to continue.",
                "can_continue": True,
            }

        # Step 4: Register
        result = self.register_verify(email, password, otp_code, region=region)
        if not result.get("success"):
            return result

        # Step 5: Verify with account info
        info = self.get_account_info()
        result["account_info"] = info

        # Step 6: Save
        self.log("[6/6] Account created ✅")
        return result


# ============================================================
# ACCOUNT STORAGE
# ============================================================
def load_accounts(filepath: str = ACCOUNTS_FILE) -> list:
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return []


def save_account(account: dict, filepath: str = ACCOUNTS_FILE):
    accounts = load_accounts(filepath)
    accounts.append({
        **account,
        "created_at": datetime.now().isoformat(),
    })
    with open(filepath, "w") as f:
        json.dump(accounts, f, indent=2)
    print(f"  💾 Saved to {filepath} ({len(accounts)} total)")


# ============================================================
# EMAIL PROVIDER INTERFACE (pluggable)
# ============================================================
class EmailProvider:
    """
    Base email provider. Override with EmailAPIProvider, mail.tm, etc.
    Must implement: create_email() → (email, provider_data)
                     get_otp(provider_data) → str or None
    """

    def create_email(self) -> tuple:
        """Returns (email_address, provider_specific_data)"""
        raise NotImplementedError

    def get_otp(self, provider_data, timeout: int = 120) -> str:
        """Poll for OTP code. Returns code string or None on timeout"""
        raise NotImplementedError


class DummyEmailProvider(EmailProvider):
    """For testing — asks user to input manually"""

    def create_email(self) -> tuple:
        domain = random.choice(["test.com", "demo.org", "example.net"])
        user = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        email = f"{user}@{domain}"
        print(f"  📧 Dummy email: {email}")
        return email, {}

    def get_otp(self, provider_data: dict, timeout: int = 120) -> str:
        code = input("  🔑 Enter OTP code: ").strip()
        return code if code else None


# ============================================================
# EMAIL API PROVIDER (Cloudflare Email Worker)
# ============================================================
TBM_WORKER_API = "https://email-api.example.com"
TBM_DOMAINS = ["example.com", "example.org", "example.net"]

# Anime names for random prefix
_TBM_NAMES = [
    "naruto", "sasuke", "sakura", "kakashi", "hinata", "itachi", "madara",
    "luffy", "zoro", "sanji", "nami", "ace", "shanks", "law",
    "goku", "vegeta", "trunks", "goten", "bulma", "frieza",
    "tanjiro", "nezuko", "zenitsu", "inosuke", "rengoku",
    "eren", "mikasa", "levi", "armin", "annie",
    "deku", "bakugo", "todoroki", "uravity", "allmight",
    "gojo", "itadori", "nobara", "sukuna", "megumi",
    "ichigo", "rukia", "aizen", "byakuya",
    "saitama", "genos", "tatsumaki", "fubuki",
    "rimuru", "shion", "shuna", "diablo", "benimaru",
    "ainz", "albedo", "shalltear", "cocytus",
    "kafka", "himeko", "bronya", "seele",
    "raiden", "nahida", "zhongli", "venti",
    "ayanokoji", "kei", "horikita", "ichinose",
    "jinwoo", "cha", "beru",
    "asta", "yuno", "noelle", "yami",
    "meliodas", "ban", "king", "elizabeth",
    "denji", "power", "aki", "makima",
    "frieren", "fern", "stark",
    "gon", "killua", "kurapika", "leorio", "hisoka",
    "rem", "ram", "emilia", "subaru",
    "aqua", "darkness", "megumin", "kazuma",
]

_OTP_RE = re.compile(r'(?:code|otp|pin|token|verif\w*)\s*[:]\s*[`"\']?\s*([A-Za-z0-9]{4,12})[`"\']?', re.I)
_OTP_IS_RE = re.compile(r'(?:code|otp|pin|token|verif\w*)\s*(?:is|:)\s*[`"\']?\s*([A-Za-z0-9]{4,12})[`"\']?', re.I)
_OTP_STANDALONE_RE = re.compile(r'(?:^|\n)\s*(\d{4,8})\s*(?:\n|$)', re.M)


def _extract_otp_from_text(text: str) -> str:
    """Simple OTP extraction from email body text."""
    if not text:
        return None
    # Pattern: "code: XXXXX" or "OTP: XXXXX" or "code is XXXXX"
    m = _OTP_IS_RE.search(text)
    if m:
        c = m.group(1).strip()
        if 4 <= len(c) <= 12:
            return c
    # Standalone 4-8 digit code on own line
    m = _OTP_STANDALONE_RE.search(text)
    if m:
        return m.group(1)
    return None


class EmailAPIProvider(EmailProvider):
    """
    Email API integration — Cloudflare Email Routing + Worker API.
    Creates temp email, polls worker for incoming OTP.

    Purchase an API key to use this provider:
    https://email-api.example.com
    """

    def __init__(self, api_url: str = TBM_WORKER_API, domains: list = None):
        self.api_url = api_url
        self.domains = domains or TBM_DOMAINS

    def create_email(self) -> tuple:
        """Generate random email on configured domain."""
        prefix = random.choice(_TBM_NAMES) + ''.join(random.choices(string.digits, k=4))
        domain = random.choice(self.domains)
        email = f"{prefix}@{domain}"
        print(f"  📧 Email: {email}")
        return email, {"email": email, "prefix": prefix, "domain": domain}

    def get_otp(self, provider_data: dict, timeout: int = 90) -> str:
        """Poll worker API for OTP code from CapCut. Returns first found code."""
        email = provider_data["email"]
        start = time.time()
        seen_keys = set()
        found_code = None

        while time.time() - start < timeout:
            try:
                url = f"{self.api_url}/check?email={quote(email)}"
                r = requests.get(url, headers={"User-Agent": "CapCutCreator/1.0"}, timeout=15)
                data = r.json()

                if data.get("success") and data.get("emails"):
                    for item in data["emails"]:
                        key = item.get("key", "")
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)

                        # Fetch full email
                        try:
                            detail_url = f"{self.api_url}/read?key={quote(key)}"
                            r2 = requests.get(detail_url, headers={"User-Agent": "CapCutCreator/1.0"}, timeout=15)
                            detail = r2.json()
                            if not detail.get("success"):
                                continue
                            email_data = detail.get("email", {})
                        except:
                            continue

                        subject = email_data.get("subject", "")
                        raw = email_data.get("raw", "")
                        body = ""
                        html_body = ""

                        # Parse raw email
                        try:
                            from email import message_from_bytes
                            msg = message_from_bytes(raw.encode("utf-8", errors="ignore") if isinstance(raw, str) else raw)
                            if msg.is_multipart():
                                for part in msg.walk():
                                    ct = part.get_content_type()
                                    if ct == "text/plain" and not body:
                                        body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                                    elif ct == "text/html" and not html_body:
                                        html_body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                            else:
                                raw_payload = msg.get_payload(decode=True)
                                if raw_payload:
                                    raw_str = raw_payload.decode("utf-8", errors="ignore")
                                    if msg.get_content_type() == "text/html":
                                        html_body = raw_str
                                    else:
                                        body = raw_str
                        except:
                            body = raw[:2000] if isinstance(raw, str) else ""

                        # Try extracting OTP from body, html, or subject
                        otp = _extract_otp_from_text(body)
                        if not otp and html_body:
                            m = re.search(r'(?:(?:font-size|font-weight)[^>]*>)\s*(\d{4,8})\s*<', html_body)
                            if m:
                                otp = m.group(1)
                        if not otp:
                            otp = _extract_otp_from_text(subject)

                        if otp:
                            found_code = otp
                            # Stabilize: wait 8s for late-arriving emails
                            stabilize_end = time.time() + 8
                            while time.time() < stabilize_end:
                                time.sleep(2)
                                try:
                                    r3 = requests.get(url, headers={"User-Agent": "CapCutCreator/1.0"}, timeout=15)
                                    data3 = r3.json()
                                    if data3.get("success") and data3.get("emails"):
                                        for item3 in data3["emails"]:
                                            k3 = item3.get("key", "")
                                            if k3 in seen_keys:
                                                continue
                                            seen_keys.add(k3)
                                            try:
                                                d3_url = f"{self.api_url}/read?key={quote(k3)}"
                                                r4 = requests.get(d3_url, headers={"User-Agent": "CapCutCreator/1.0"}, timeout=15)
                                                d4 = r4.json()
                                                if d4.get("success"):
                                                    ed4 = d4.get("email", {})
                                                    s4 = ed4.get("subject", "")
                                                    o4 = _extract_otp_from_text(s4)
                                                    if o4:
                                                        found_code = o4
                                            except:
                                                pass
                                except:
                                    pass
                            return found_code

            except Exception as e:
                pass  # silent retry

            time.sleep(3)

        return None


# ============================================================
# MAIN — FULL AUTO (Email API + CapCut)
# ============================================================
def main():
    print("=" * 60)
    print("  CapCut Account Creator — Full Auto (Email API)")
    print("=" * 60)

    # Generate device fingerprint
    device = DeviceSpoof.generate()
    print(f"\n📱 Device fingerprint:")
    print(f"  device_id:   {device['device_id']}")
    print(f"  verify_fp:   {device['verify_fp'][:40]}...")
    print(f"  ms_token:    {device['ms_token'][:30]}...")
    print(f"  user_agent:  {device['user_agent'][:60]}...")

    # Create client
    client = CapCutClient(device, verbose=True)

    # Email provider — Email API
    email_provider = EmailAPIProvider()

    # Generate email
    print(f"\n📧 Generating email...")
    email, email_data = email_provider.create_email()

    # Generate password
    password = ''.join(random.choices(
        string.ascii_letters + string.digits + "!@#$%", k=16
    ))
    print(f"🔑 Password: {password}")

    # Full registration flow
    print(f"\n🚀 Starting registration flow...\n")

    # Step 1: Bootstrap
    if not client.bootstrap():
        print("[!] Bootstrap failed!")
        return

    # Step 2: Check email
    if not client.check_email(email):
        print("[!] Email already taken!")
        return

    # Step 3: Send OTP
    if not client.send_otp(email, password):
        print("[!] Failed to send OTP!")
        return

    # Step 4: Wait for OTP (auto-poll Email API)
    print(f"\n⏳ Waiting for OTP via Email API...")
    otp_code = email_provider.get_otp(email_data, timeout=120)
    if not otp_code:
        print("[!] No OTP received!")
        return

    # Step 5: Register
    print(f"\n[5/6] Registering with OTP={otp_code}...")
    result = client.register_verify(email, password, otp_code)

    if result.get("success"):
        print(f"\n{'=' * 60}")
        print(f"  ✅ ACCOUNT CREATED!")
        print(f"  Email:    {result['email']}")
        print(f"  Password: {result['password']}")
        print(f"  User ID:  {result.get('user_id_str', 'N/A')}")
        print(f"  Name:     {result.get('screen_name', 'N/A')}")
        print(f"{'=' * 60}")

        # Save
        save_account({
            "email": result["email"],
            "password": result["password"],
            "user_id": result.get("user_id"),
            "user_id_str": result.get("user_id_str"),
            "screen_name": result.get("screen_name"),
            "session_cookies": result.get("session_cookies", {}),
            "device_id": device["device_id"],
            "verify_fp": device["verify_fp"],
        })
    else:
        print(f"\n[!] Registration failed: {result.get('error', 'unknown')}")


# ============================================================
# PARALLEL WORKER — single account registration
# ============================================================
# Thread-safe lock for save_account
_save_lock = threading.Lock()

def _create_one_account(idx: int, total: int) -> dict:
    """Register one CapCut account. Used by parallel workers."""
    MAX_RETRIES = 3
    OTP_TIMEOUT = 90
    MAX_RESENDS = 2

    for retry in range(MAX_RETRIES):
        try:
            device = DeviceSpoof.generate()
            client = CapCutClient(device, verbose=False)
            email_provider = EmailAPIProvider()

            email, email_data = email_provider.create_email()
            password = ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=16))

            # Step 1: Bootstrap
            if not client.bootstrap():
                time.sleep(2)
                continue

            # Step 2: Check email
            if not client.check_email(email):
                continue

            # Step 3: Send OTP
            if not client.send_otp(email, password):
                continue

            # Step 4: Wait for OTP with resend
            otp_code = None
            for attempt in range(MAX_RESENDS + 1):
                if attempt > 0:
                    # Resend OTP
                    time.sleep(2)
                    client.send_otp(email, password)

                otp_code = email_provider.get_otp(email_data, timeout=OTP_TIMEOUT)
                if otp_code:
                    break

            if not otp_code:
                continue

            # Step 5: Register
            result = client.register_verify(email, password, otp_code)
            if result.get("success"):
                with _save_lock:
                    save_account({
                        "email": result["email"],
                        "password": result["password"],
                        "user_id": result.get("user_id"),
                        "user_id_str": result.get("user_id_str"),
                        "screen_name": result.get("screen_name"),
                        "session_cookies": result.get("session_cookies", {}),
                        "device_id": device["device_id"],
                    })
                return result
            else:
                time.sleep(3)

        except Exception as e:
            time.sleep(3)

    return None


# ============================================================
# BULK MODE — PARALLEL WORKERS
# ============================================================
def bulk_create(count: int = 1, workers: int = 5):
    """Create multiple accounts in parallel."""
    workers = min(workers, count)
    print(f"\n{'=' * 60}")
    print(f"  Bulk CapCut Creator — {count} akun, {workers} worker(s)")
    print(f"{'=' * 60}\n")

    results = []
    start_time = time.time()
    done_count = 0
    done_lock = threading.Lock()

    def worker_wrapper(idx):
        nonlocal done_count
        r = _create_one_account(idx, count)
        with done_lock:
            done_count += 1
            if r:
                print(f"  ✅ [{done_count}/{count}] {r['email']} (uid: {r.get('user_id_str', '?')})")
            else:
                print(f"  ❌ [{done_count}/{count}] Failed")
        return r

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(worker_wrapper, i): i for i in range(count)}
        for future in as_completed(futures):
            r = future.result()
            if r:
                results.append(r)

    elapsed = int(time.time() - start_time)
    print(f"\n{'=' * 60}")
    print(f"  Done! {len(results)}/{count} akun dalam {elapsed}s")
    print(f"  Rate: {len(results)/(elapsed/60):.1f} akun/menit" if elapsed > 0 else "")
    print(f"{'=' * 60}")
    return results


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "bulk":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 5
        w = int(sys.argv[3]) if len(sys.argv) > 3 else 5
        bulk_create(n, w)
    else:
        main()
