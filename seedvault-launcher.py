#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multi-OS SeedVault Standalone Engine for Tails OS / Debian Linux / macOS / Windows
==================================================================================
- Runs 100% Out-of-the-Box on Tails OS Live USB (Offline Mode) using only standard
  pre-installed packages in Tails OS (`python3` + `openssl` / `libcrypto`).
- Shares 100% binary & cryptographic compatibility with `crypto-engine.js` & `vault-storage.js`:
  * AES-256-GCM (via ctypes libcrypto EVP_aes_256_gcm or cryptography module)
  * PBKDF2-HMAC-SHA512 (600,000 iterations) + Memory-Hard scrypt (N=65536, r=8, p=1)
  * HKDF-SHA256
  * Galois Field GF(256) & Shamir's Secret Sharing (K-of-N threshold)
  * Constant-Length 4096-byte Payload Padding
  * Portable Monotonic Counter & 3-Pass Zero-Wipe Self-Destruct (`seedvault.dat` + `.svlt_state.anchor`)
"""

import os
import sys
import json
import uuid
import time
import struct
import secrets
import hashlib
import hmac
import unicodedata
import subprocess
import ctypes
import ctypes.util
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
UI_DIR = os.path.join(BASE_DIR, "ui")

# If Node.js is available, delegate directly to app-server.js
def try_delegate_to_node():
    if os.environ.get("SEEDVAULT_FORCE_PYTHON") == "1":
        return
    for candidate in ["node", "/usr/local/bin/node", "/opt/homebrew/bin/node", "/usr/bin/node"]:
        try:
            res = subprocess.run([candidate, "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if res.returncode == 0:
                os.execv(candidate, [candidate, os.path.join(BASE_DIR, "app-server.js")])
        except Exception:
            pass

# ============================================================================
# 1. Native OpenSSL (libcrypto) AES-256-GCM Binding (Zero pip install required!)
# ============================================================================
class NativeAES256GCM:
    _lib = None

    @classmethod
    def _load_libcrypto(cls):
        if cls._lib is not None:
            return cls._lib

        candidates = [
            "libcrypto.so.3",
            "libcrypto.so.1.1",
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1",
            "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib",
            "/usr/local/opt/openssl@3/lib/libcrypto.dylib",
        ]
        found = ctypes.util.find_library("crypto")
        if found and "/usr/lib/libcrypto.dylib" not in found:
            candidates.insert(0, found)
        for name in candidates:
            if not name:
                continue
            try:
                lib = ctypes.CDLL(name)
                # Setup function signatures
                lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
                lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
                lib.EVP_aes_256_gcm.restype = ctypes.c_void_p
                lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
                lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
                lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
                lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
                lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
                lib.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
                lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
                cls._lib = lib
                return lib
            except Exception:
                continue
        return None

    @classmethod
    def encrypt(cls, plaintext: bytes, key: bytes, aad: bytes = b"") -> dict:
        iv = secrets.token_bytes(12)
        # Try python3-cryptography if pre-installed (standard on Tails OS)
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            ct_and_tag = aesgcm.encrypt(iv, plaintext, aad if aad else None)
            ct = ct_and_tag[:-16]
            tag = ct_and_tag[-16:]
            return {"iv": iv.hex(), "ciphertext": ct.hex(), "tag": tag.hex()}
        except ImportError:
            pass

        lib = cls._load_libcrypto()
        if not lib:
            raise RuntimeError("OpenSSL libcrypto not found")

        EVP_CTRL_GCM_SET_IVLEN = 0x9
        EVP_CTRL_GCM_GET_TAG = 0x10

        ctx = lib.EVP_CIPHER_CTX_new()
        try:
            cipher = lib.EVP_aes_256_gcm()
            if lib.EVP_EncryptInit_ex(ctx, cipher, None, None, None) != 1:
                raise RuntimeError("EVP_EncryptInit_ex failed")
            if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None) != 1:
                raise RuntimeError("Failed to set IV length")
            if lib.EVP_EncryptInit_ex(ctx, None, None, key, iv) != 1:
                raise RuntimeError("Failed to set key and IV")

            outlen = ctypes.c_int(0)
            if aad:
                if lib.EVP_EncryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad)) != 1:
                    raise RuntimeError("Failed to set AAD")

            outbuf = ctypes.create_string_buffer(len(plaintext) + 16)
            if lib.EVP_EncryptUpdate(ctx, outbuf, ctypes.byref(outlen), plaintext, len(plaintext)) != 1:
                raise RuntimeError("EVP_EncryptUpdate failed")
            total_len = outlen.value

            finalbuf = ctypes.create_string_buffer(16)
            if lib.EVP_EncryptFinal_ex(ctx, finalbuf, ctypes.byref(outlen)) != 1:
                raise RuntimeError("EVP_EncryptFinal_ex failed")

            tagbuf = ctypes.create_string_buffer(16)
            if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tagbuf) != 1:
                raise RuntimeError("Failed to get GCM tag")

            return {
                "iv": iv.hex(),
                "ciphertext": outbuf.raw[:total_len].hex(),
                "tag": tagbuf.raw.hex(),
            }
        finally:
            lib.EVP_CIPHER_CTX_free(ctx)

    @classmethod
    def decrypt(cls, enc_obj: dict, key: bytes, aad: bytes = b"") -> bytes:
        iv = bytes.fromhex(enc_obj["iv"])
        ciphertext = bytes.fromhex(enc_obj["ciphertext"])
        tag = bytes.fromhex(enc_obj["tag"])

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(iv, ciphertext + tag, aad if aad else None)
        except ImportError:
            pass

        lib = cls._load_libcrypto()
        if not lib:
            raise RuntimeError("OpenSSL libcrypto not found")

        EVP_CTRL_GCM_SET_IVLEN = 0x9
        EVP_CTRL_GCM_SET_TAG = 0x11

        ctx = lib.EVP_CIPHER_CTX_new()
        try:
            cipher = lib.EVP_aes_256_gcm()
            if lib.EVP_DecryptInit_ex(ctx, cipher, None, None, None) != 1:
                raise RuntimeError("EVP_DecryptInit_ex failed")
            if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), None) != 1:
                raise RuntimeError("Failed to set IV length")
            if lib.EVP_DecryptInit_ex(ctx, None, None, key, iv) != 1:
                raise RuntimeError("Failed to set key and IV")

            outlen = ctypes.c_int(0)
            if aad:
                if lib.EVP_DecryptUpdate(ctx, None, ctypes.byref(outlen), aad, len(aad)) != 1:
                    raise RuntimeError("Failed to set AAD")

            outbuf = ctypes.create_string_buffer(len(ciphertext) + 16)
            if lib.EVP_DecryptUpdate(ctx, outbuf, ctypes.byref(outlen), ciphertext, len(ciphertext)) != 1:
                raise RuntimeError("EVP_DecryptUpdate failed")
            total_len = outlen.value

            tagbuf = ctypes.create_string_buffer(tag, 16)
            if lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tagbuf) != 1:
                raise RuntimeError("Failed to set GCM expected tag")

            finalbuf = ctypes.create_string_buffer(16)
            res = lib.EVP_DecryptFinal_ex(ctx, finalbuf, ctypes.byref(outlen))
            if res != 1:
                raise ValueError("GCM Authentication Tag mismatch")

            return outbuf.raw[:total_len]
        finally:
            lib.EVP_CIPHER_CTX_free(ctx)


# ============================================================================
# 2. Galois Field GF(256) & Shamir's Secret Sharing (100% compatible with JS)
# ============================================================================
class GF256:
    EXP = [0] * 512
    LOG = [0] * 256

    @classmethod
    def _init_tables(cls):
        x = 1
        for i in range(255):
            cls.EXP[i] = x
            cls.LOG[x] = i
            x2 = (x << 1) ^ (0x1B if (x & 0x80) else 0x00)
            x = (x2 ^ x) & 0xFF
        for i in range(255, 512):
            cls.EXP[i] = cls.EXP[i - 255]

    @classmethod
    def add(cls, a: int, b: int) -> int:
        return (a ^ b) & 0xFF

    @classmethod
    def sub(cls, a: int, b: int) -> int:
        return (a ^ b) & 0xFF

    @classmethod
    def mul(cls, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        return cls.EXP[cls.LOG[a] + cls.LOG[b]]

    @classmethod
    def div(cls, a: int, b: int) -> int:
        if b == 0:
            raise ZeroDivisionError("GF256 division by zero")
        if a == 0:
            return 0
        return cls.EXP[cls.LOG[a] + 255 - cls.LOG[b]]

GF256._init_tables()


class ShamirSecretSharing:
    @staticmethod
    def split(secret: bytes, n: int, k: int):
        shares = [{"x": i, "y": bytearray(len(secret))} for i in range(1, n + 1)]
        for byte_idx in range(len(secret)):
            coeffs = [secret[byte_idx]] + list(secrets.token_bytes(k - 1))
            for s in range(n):
                x = shares[s]["x"]
                y = 0
                for c in range(k - 1, -1, -1):
                    y = GF256.add(GF256.mul(y, x), coeffs[c])
                shares[s]["y"][byte_idx] = y
        for s in shares:
            s["y"] = bytes(s["y"])
        return shares

    @staticmethod
    def combine(shares) -> bytes:
        secret_len = len(shares[0]["y"])
        out = bytearray(secret_len)
        k = len(shares)
        for byte_idx in range(secret_len):
            val = 0
            for i in range(k):
                xi = shares[i]["x"]
                yi = shares[i]["y"][byte_idx]
                num = 1
                den = 1
                for j in range(k):
                    if i == j:
                        continue
                    xj = shares[j]["x"]
                    num = GF256.mul(num, xj)
                    den = GF256.mul(den, GF256.sub(xi, xj))
                basis = GF256.div(num, den)
                val = GF256.add(val, GF256.mul(yi, basis))
            out[byte_idx] = val
        return bytes(out)


# ============================================================================
# 3. KDFs (PBKDF2-SHA512 + scrypt + HKDF-SHA256) & Payload Padding
# ============================================================================
ALLOWED_WORD_COUNTS = (12, 15, 18, 20, 24)
PBKDF2_ITERATIONS = 600000
FIXED_PAYLOAD_BLOCK_BYTES = 4096
MAGIC_HEADER = "SVLT1"
ANCHOR_DOMAIN_SECRET = "SeedVault-MonotonicAnchor-Integrity-Key-v2"


def normalize_answer(inp: str, case_sensitive: bool = False) -> str:
    if not isinstance(inp, str):
        return ""
    cleaned = " ".join(unicodedata.normalize("NFKC", inp).strip().split())
    return cleaned if case_sensitive else cleaned.lower()


def derive_key_hardened(secret_input: str, salt_hex: str, kdf_version: int = 2) -> bytes:
    salt = bytes.fromhex(salt_hex)
    stage1 = hashlib.pbkdf2_hmac("sha512", secret_input.encode("utf-8"), salt, PBKDF2_ITERATIONS, 32)
    if kdf_version == 1:
        return stage1
    scrypt_salt = hashlib.sha256(salt + b"SVLT-SCRYPT-v2").digest()
    if hasattr(hashlib, "scrypt"):
        return hashlib.scrypt(stage1, salt=scrypt_salt, n=65536, r=8, p=1, maxmem=128 * 1024 * 1024, dklen=32)

    lib = NativeAES256GCM._load_libcrypto()
    if not lib:
        raise RuntimeError("OpenSSL libcrypto not found for scrypt")
    lib.EVP_PBE_scrypt.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_char_p,
        ctypes.c_size_t,
    ]
    lib.EVP_PBE_scrypt.restype = ctypes.c_int
    outbuf = ctypes.create_string_buffer(32)
    res = lib.EVP_PBE_scrypt(
        stage1, len(stage1), scrypt_salt, len(scrypt_salt), 65536, 8, 1, 128 * 1024 * 1024, outbuf, 32
    )
    if res != 1:
        raise RuntimeError("EVP_PBE_scrypt failed")
    return outbuf.raw


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def combine_keys_hkdf(keys_list, context_info: str = "SeedVault-CombinedSlot") -> bytes:
    return hkdf_sha256(b"".join(keys_list), context_info.encode("utf-8"), 32)


def pack_fixed_size_payload(payload_obj: dict) -> bytes:
    json_bytes = json.dumps(payload_obj).encode("utf-8")
    block = bytearray(secrets.token_bytes(FIXED_PAYLOAD_BLOCK_BYTES))
    struct.pack_into(">I", block, 0, len(json_bytes))
    block[4 : 4 + len(json_bytes)] = json_bytes
    return bytes(block)


def unpack_fixed_size_payload(decrypted_bytes: bytes) -> dict:
    if len(decrypted_bytes) == FIXED_PAYLOAD_BLOCK_BYTES:
        json_len = struct.unpack_from(">I", decrypted_bytes, 0)[0]
        if 0 < json_len <= FIXED_PAYLOAD_BLOCK_BYTES - 4:
            return json.loads(decrypted_bytes[4 : 4 + json_len].decode("utf-8"))
    return json.loads(decrypted_bytes.decode("utf-8"))


# ============================================================================
# 4. Vault Storage & Self-Destruct Manager (Python Twin of vault-storage.js)
# ============================================================================
def resolve_default_data_dir() -> str:
    """Per-device data directory. The vault the app actually runs on lives HERE (internal disk of
    the Mac / PC / Tails), never on the Flash Drive, which only carries a master copy that is
    imported before use. Override with SEEDVAULT_DATA_DIR."""
    env = os.environ.get("SEEDVAULT_DATA_DIR")
    if env:
        return os.path.abspath(env)
    home = os.path.expanduser("~")
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support", "SeedVault")
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.join(home, "AppData", "Local")
        return os.path.join(base, "SeedVault")
    return os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.join(home, ".local", "share"), "seedvault")


def is_likely_removable_path(p: str) -> bool:
    ap = os.path.abspath(p)
    if sys.platform == "darwin":
        return ap.startswith("/Volumes/")
    if sys.platform == "win32":
        sys_drive = (os.environ.get("SystemDrive") or "C:").upper()
        return os.path.splitdrive(ap)[0].upper() != sys_drive
    return ap.startswith(("/media/", "/run/media/", "/mnt/"))


class PyVaultStorageManager:
    def __init__(self, storage_dir: str = BASE_DIR):
        self.storage_dir = storage_dir
        try:
            os.makedirs(storage_dir, mode=0o700, exist_ok=True)
        except Exception:
            pass
        self.vault_path = os.path.join(storage_dir, "seedvault.dat")
        self.portable_anchor_path = os.path.join(storage_dir, ".svlt_state.anchor")
        self.os_anchor_paths = self._resolve_os_anchor_paths()
        self.os_anchor_path = self.os_anchor_paths[0] if self.os_anchor_paths else None

    def _resolve_os_anchor_paths(self):
        paths = []
        try:
            home = os.path.expanduser("~")
            if home:
                paths.append(os.path.join(home, ".seedvault_anchor.dat"))
                if sys.platform == "darwin":
                    paths.append(os.path.join(home, "Library", "Application Support", ".svlt_core", ".svlt_ratchet.dat"))
                elif sys.platform == "win32":
                    app_data = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or os.path.join(home, "AppData", "Local")
                    paths.append(os.path.join(app_data, ".svlt_core", ".svlt_ratchet.dat"))
                else:
                    paths.append(os.path.join(home, ".config", ".svlt_core", ".svlt_ratchet.dat"))
            import tempfile
            tmp_dir = tempfile.gettempdir()
            if tmp_dir and os.path.exists(tmp_dir):
                paths.append(os.path.join(tmp_dir, ".svlt_sys_ratchet.dat"))
        except Exception:
            pass
        return paths

    def _derive_anchor_key(self, salt_hex: str) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", ANCHOR_DOMAIN_SECRET.encode("utf-8"), bytes.fromhex(salt_hex), 50000, 32
        )

    def _write_buffer_in_place(self, path_str: str, data_bytes: bytes):
        parent = os.path.dirname(path_str)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, mode=0o700, exist_ok=True)
        if os.path.exists(path_str):
            with open(path_str, "r+b") as f:
                f.seek(0)
                f.write(data_bytes)
                f.truncate(len(data_bytes))
                f.flush()
                os.fsync(f.fileno())
        else:
            with open(path_str, "wb") as f:
                f.write(data_bytes)
                f.flush()
                os.fsync(f.fileno())
        try:
            os.chmod(path_str, 0o600)
        except Exception:
            pass

    def _read_anchor_file(self, path_str: str):
        if not path_str or not os.path.exists(path_str):
            return {"exists": False, "data": {}, "tampered": False}
        try:
            with open(path_str, "r", encoding="utf-8") as f:
                parsed = json.load(f)
            if isinstance(parsed, dict) and parsed.get("v") == 2 and "salt" in parsed and "enc" in parsed:
                key = self._derive_anchor_key(parsed["salt"])
                dec = NativeAES256GCM.decrypt(parsed["enc"], key, b"SVLT-ANCHOR-v2")
                return {"exists": True, "data": json.loads(dec.decode("utf-8")), "tampered": False}
            if isinstance(parsed, dict) and "v" not in parsed:
                return {"exists": True, "data": parsed, "tampered": False}
            return {"exists": True, "data": {}, "tampered": True}
        except Exception:
            return {"exists": True, "data": {}, "tampered": True}

    def _write_anchor_file(self, path_str: str, data_obj: dict):
        if not path_str:
            return
        try:
            salt = secrets.token_bytes(16).hex()
            key = self._derive_anchor_key(salt)
            enc = NativeAES256GCM.encrypt(json.dumps(data_obj).encode("utf-8"), key, b"SVLT-ANCHOR-v2")
            payload = json.dumps({"v": 2, "salt": salt, "enc": enc}, indent=2).encode("utf-8")
            self._write_buffer_in_place(path_str, payload)
        except Exception:
            pass

    def _derive_rolling_outer_key(
        self, vault_id: str, seq: int, rolling_salt_hex: str, ratchet_secret_hex: str = ""
    ) -> bytes:
        secret_part = f":RATCHET:{ratchet_secret_hex}" if ratchet_secret_hex else ""
        return hashlib.pbkdf2_hmac(
            "sha256",
            f"OUTER:{vault_id}:SEQ:{seq}{secret_part}".encode("utf-8"),
            bytes.fromhex(rolling_salt_hex),
            25000,
            32,
        )

    def _read_max_observed_state(self, vault_id: str):
        max_failed = 0
        max_seq = 0
        wiped = False
        tampered = False
        latest_ratchet = ""
        latest_ratchet_seq = -1
        any_found = False

        all_paths = [self.portable_anchor_path] + list(self.os_anchor_paths)
        for p in all_paths:
            res = self._read_anchor_file(p)
            if res["tampered"]:
                tampered = True
            rec = res["data"].get(vault_id)
            if isinstance(rec, dict):
                any_found = True
                f_att = int(rec.get("failedAttempts", 0))
                if f_att > max_failed:
                    max_failed = f_att
                r_seq = int(rec.get("seq", 0))
                if r_seq >= max_seq:
                    max_seq = r_seq
                    if isinstance(rec.get("ratchetSecret"), str) and r_seq >= latest_ratchet_seq:
                        latest_ratchet = rec["ratchetSecret"]
                        latest_ratchet_seq = r_seq
                if rec.get("wiped"):
                    wiped = True
        return {
            "maxFailed": max_failed,
            "maxSeq": max_seq,
            "wiped": wiped,
            "tampered": tampered,
            "anyAnchorFound": any_found,
            "ratchetSecret": latest_ratchet,
        }

    def _write_observed_state(
        self, vault_id: str, failed_attempts: int, seq: int, wiped: bool = False, ratchet_secret: str = ""
    ):
        all_paths = [self.portable_anchor_path] + list(self.os_anchor_paths)
        for p in all_paths:
            if not p:
                continue
            res = self._read_anchor_file(p)
            data = {} if res["tampered"] else dict(res["data"])
            prev = data.get(vault_id, {"failedAttempts": 0, "seq": 0, "wiped": False, "ratchetSecret": ""})
            prev_seq = int(prev.get("seq", 0))
            is_wiped = bool(prev.get("wiped") or wiped)
            data[vault_id] = {
                "failedAttempts": max(int(prev.get("failedAttempts", 0)), failed_attempts),
                "seq": max(prev_seq, seq),
                "wiped": is_wiped,
                "ratchetSecret": ""
                if is_wiped
                else (ratchet_secret if (seq >= prev_seq and ratchet_secret) else prev.get("ratchetSecret", "")),
                "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            if len(data) > 64:
                sorted_keys = sorted(data.keys(), key=lambda k: str(data[k].get("updatedAt", "")))
                for k in sorted_keys[: len(data) - 64]:
                    if k != vault_id:
                        data.pop(k, None)
            self._write_anchor_file(p, data)

    def _save_vault_disk_state(self, inner_vault: dict):
        vault_id = inner_vault["vaultId"]
        seq = int(inner_vault.get("monotonicSeq", 0)) + 1
        inner_vault["monotonicSeq"] = seq

        rolling_salt = secrets.token_bytes(16).hex()
        ratchet_token = secrets.token_bytes(32).hex()
        outer_key = self._derive_rolling_outer_key(vault_id, seq, rolling_salt, ratchet_token)
        failed = inner_vault["securityCounter"]["failedAttempts"]
        aad = f"{MAGIC_HEADER}:{vault_id}:{seq}:{failed}".encode("utf-8")
        outer_encrypted = NativeAES256GCM.encrypt(json.dumps(inner_vault).encode("utf-8"), outer_key, aad)

        envelope = {
            "magic": MAGIC_HEADER,
            "vaultId": vault_id,
            "seq": seq,
            "ratchetToken": ratchet_token,
            "rollingSalt": rolling_salt,
            "failedAttempts": failed,
            "maxAttempts": inner_vault["securityCounter"]["maxAttempts"],
            "remainingAttempts": inner_vault["securityCounter"]["remainingAttempts"],
            "outerEncrypted": outer_encrypted,
        }
        serialized = json.dumps(envelope, indent=2).encode("utf-8")
        self._write_buffer_in_place(self.vault_path, serialized)
        self._write_observed_state(vault_id, failed, seq, False, ratchet_token)

    def _load_vault_disk_state(self):
        if not os.path.exists(self.vault_path):
            return None
        try:
            with open(self.vault_path, "r", encoding="utf-8") as f:
                env = json.load(f)
        except Exception:
            raise ValueError("ไฟล์ฐานข้อมูลเข้ารหัส (seedvault.dat) เสียหายหรือถูกดัดแปลง")

        if not isinstance(env, dict) or env.get("magic") != MAGIC_HEADER or not env.get("vaultId"):
            raise ValueError("รูปแบบไฟล์ seedvault.dat ไม่ถูกต้อง")

        vault_id = env["vaultId"]
        seq = int(env.get("seq", 0))
        rolling_salt = env["rollingSalt"]
        failed = int(env.get("failedAttempts", 0))
        ratchet_token = str(env.get("ratchetToken") or "")

        obs = self._read_max_observed_state(vault_id)
        if obs["wiped"]:
            self.secure_wipe_and_reset("ตรวจพบการนำไฟล์ที่ถูกทำลายไปแล้วกลับมาวางซ้ำ (Anti-Copy-Paste Protection)")
            return None

        if obs["anyAnchorFound"]:
            is_rollback = seq < obs["maxSeq"] or failed < obs["maxFailed"]
            is_ratchet_mismatch = (
                seq == obs["maxSeq"]
                and bool(obs["ratchetSecret"])
                and bool(ratchet_token)
                and obs["ratchetSecret"] != ratchet_token
            )
            if is_rollback or is_ratchet_mismatch:
                self.secure_wipe_and_reset(
                    "ตรวจพบการ Copy ไฟล์เก่ามา Paste ทับเพื่อรีเซ็ตจำนวนครั้ง (Rollback Attack Detected — ทำลายไฟล์ทันที)"
                )
                return None

        active_ratchet = ratchet_token or obs["ratchetSecret"] or ""
        outer_key = self._derive_rolling_outer_key(vault_id, seq, rolling_salt, active_ratchet)
        try:
            aad = f"{MAGIC_HEADER}:{vault_id}:{seq}:{failed}".encode("utf-8")
            dec = NativeAES256GCM.decrypt(env["outerEncrypted"], outer_key, aad)
            inner_vault = json.loads(dec.decode("utf-8"))
        except Exception:
            self.secure_wipe_and_reset("ตรวจพบการแก้ไขดัดแปลงไฟล์รหัสผ่านหรือวางไฟล์ไม่ตรงรุ่น (Integrity Check Failed)")
            raise ValueError("ตรวจพบการแก้ไขดัดแปลงไฟล์รหัสผ่าน (Integrity Check Failed — ข้อมูลถูกทำลายแล้ว)")

        if obs["maxFailed"] > inner_vault["securityCounter"]["failedAttempts"]:
            inner_vault["securityCounter"]["failedAttempts"] = obs["maxFailed"]
            inner_vault["securityCounter"]["remainingAttempts"] = max(
                0, inner_vault["securityCounter"]["maxAttempts"] - obs["maxFailed"]
            )
            if inner_vault["securityCounter"]["remainingAttempts"] <= 0:
                self.secure_wipe_and_reset("กรอกรหัสผิดเกินจำนวนที่กำหนด")
                return None
            self._save_vault_disk_state(inner_vault)
        else:
            self._write_observed_state(
                vault_id, inner_vault["securityCounter"]["failedAttempts"], seq, False, active_ratchet
            )
        return inner_vault

    def secure_wipe_and_reset(self, reason: str = "User requested reset"):
        vault_id = None
        seq = 999999
        if os.path.exists(self.vault_path):
            try:
                with open(self.vault_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                    vault_id = raw.get("vaultId")
                    seq = int(raw.get("seq", 0)) + 100
            except Exception:
                pass
            try:
                size = max(os.path.getsize(self.vault_path), 16384)
                with open(self.vault_path, "r+b") as f:
                    corrupted = json.dumps(
                        {
                            "magic": "WIPED",
                            "corrupted": True,
                            "outerEncrypted": {
                                "iv": secrets.token_bytes(12).hex(),
                                "tag": secrets.token_bytes(16).hex(),
                                "ciphertext": secrets.token_bytes(4096).hex(),
                            },
                        }
                    ).encode("utf-8")
                    f.seek(0)
                    f.write(corrupted)
                    f.flush()
                    os.fsync(f.fileno())

                    patterns = (
                        b"\x00" * size,
                        b"\xff" * size,
                        b"\x55" * size,
                        b"\xaa" * size,
                        secrets.token_bytes(size),
                        secrets.token_bytes(size),
                        b"\x00" * size,
                    )
                    for pattern in patterns:
                        f.seek(0)
                        f.write(pattern)
                        f.flush()
                        os.fsync(f.fileno())
                    f.truncate(0)
                    f.flush()
                    os.fsync(f.fileno())

                curr_path = self.vault_path
                for _ in range(3):
                    next_path = os.path.join(self.storage_dir, f".shred_{secrets.token_bytes(8).hex()}.tmp")
                    try:
                        os.rename(curr_path, next_path)
                        curr_path = next_path
                    except Exception:
                        break
                os.remove(curr_path)
            except Exception:
                try:
                    if os.path.exists(self.vault_path):
                        os.remove(self.vault_path)
                except Exception:
                    pass
        if vault_id:
            self._write_observed_state(vault_id, 999, seq, True, "")
        return {"wiped": True, "reason": reason, "mode": "SETUP"}

    def get_public_status(self):
        inner = self._load_vault_disk_state()
        if not inner:
            return {"initialized": False, "mode": "SETUP"}
        factors = inner["factors"]
        q_meta = factors.get("questionMeta")
        return {
            "initialized": True,
            "mode": "UNLOCK",
            "vaultId": inner["vaultId"],
            "version": inner.get("version", "2.0.0"),
            "kdfVersion": inner.get("kdfVersion", 2),
            "policyMode": inner["policyMode"],
            "securityCounter": inner["securityCounter"],
            "factors": {
                "hasQuestions": factors["hasQuestions"],
                "hasPhone": factors["hasPhone"],
                "hasSpecial": factors["hasSpecial"],
                "questions": {
                    "totalQuestions": q_meta["totalQuestions"],
                    "requiredCorrect": q_meta["requiredCorrect"],
                    "items": [{"id": q["id"], "question": q["question"]} for q in q_meta["items"]],
                }
                if factors["hasQuestions"] and q_meta
                else None,
            },
            "availableMethods": [{"slotType": s["slotType"], "slotLabel": s["slotLabel"]} for s in inner["keySlots"]],
            "gameModule": inner.get("gameModule", {"enabled": False, "gameType": "pattern_shield", "difficulty": 1}),
        }

    def initialize_new_vault(self, cfg: dict):
        # Build + validate FIRST so a rejected configuration can never destroy an existing vault.

        words = [w.strip().lower() for w in cfg.get("words", []) if isinstance(w, str) and w.strip()]
        if len(words) not in ALLOWED_WORD_COUNTS:
            raise ValueError(f"จำนวนคำของ Seedphrase ต้องเป็น 12, 15, 18, 20 หรือ 24 คำเท่านั้น (ได้รับ {len(words)} คำ)")
        passphrase25 = (cfg.get("passphrase25") or "").strip()

        raw_qs = cfg.get("questions") or []
        valid_qs = []
        for idx, q in enumerate(raw_qs):
            if isinstance(q, dict) and str(q.get("question", "")).strip():
                ans = normalize_answer(str(q.get("answer", "")), False)
                if not ans:
                    raise ValueError(f"กรุณากรอกคำตอบสำหรับคำถามข้อที่ {idx + 1}")
                valid_qs.append({"id": idx + 1, "question": str(q["question"]).strip(), "answer": ans})

        has_questions = len(valid_qs) > 0
        k_questions = min(max(1, int(cfg.get("requiredQuestionCount") or len(valid_qs) or 1)), len(valid_qs)) if has_questions else 0

        phone_last4 = str(cfg.get("phoneLast4") or "").strip()
        if phone_last4 and (len(phone_last4) != 4 or not phone_last4.isdigit()):
            raise ValueError("เบอร์โทรศัพท์ 4 ตัวท้าย ต้องเป็นตัวเลข 4 หลักเท่านั้น")
        has_phone = len(phone_last4) == 4

        special_code = normalize_answer(str(cfg.get("specialCode") or ""), True)
        has_special = len(special_code) > 0

        if not has_questions and not has_phone and not has_special:
            raise ValueError("กรุณาตั้งค่าวิธีการยืนยันตัวตนอย่างน้อย 1 รูปแบบ")

        max_attempts = int(cfg.get("maxAttempts") or 5)
        policy_mode = cfg.get("policyMode") or "OR_ANY"

        master_key = secrets.token_bytes(32)
        padded = pack_fixed_size_payload(
            {
                "wordCount": len(words),
                "words": words,
                "passphrase25": passphrase25,
                "hasPassphrase25": len(passphrase25) > 0,
                "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
        )
        encrypted_payload = NativeAES256GCM.encrypt(padded, master_key, b"SeedVault-PrimaryPayload-v1")

        question_key = None
        question_meta = None
        if has_questions:
            question_key = secrets.token_bytes(32)
            shares = ShamirSecretSharing.split(question_key, len(valid_qs), k_questions)
            q_items = []
            for idx, q in enumerate(valid_qs):
                q_salt = secrets.token_bytes(16).hex()
                ans_key = derive_key_hardened(f"Q:{q['id']}:{q['answer']}", q_salt, 2)
                sh = shares[idx]
                masked_share = bytes(a ^ b for a, b in zip(sh["y"], ans_key)).hex()
                q_items.append(
                    {
                        "id": q["id"],
                        "x": sh["x"],
                        "question": q["question"],
                        "salt": q_salt,
                        "shareScheme": "XOR_OTP_v2",
                        "maskedShare": masked_share,
                    }
                )
            question_meta = {"totalQuestions": len(valid_qs), "requiredCorrect": k_questions, "items": q_items}

        phone_key = None
        phone_salt = None
        if has_phone:
            phone_salt = secrets.token_bytes(16).hex()
            phone_key = derive_key_hardened(f"PHONE4:{phone_last4}", phone_salt, 2)

        special_key = None
        special_salt = None
        if has_special:
            special_salt = secrets.token_bytes(16).hex()
            special_key = derive_key_hardened(f"SPECIAL:{special_code}", special_salt, 2)

        key_slots = []
        def add_slot(slot_type, label, w_key):
            key_slots.append(
                {
                    "slotType": slot_type,
                    "slotLabel": label,
                    "wrappedMaster": NativeAES256GCM.encrypt(master_key, w_key, f"Slot:{slot_type}".encode("utf-8")),
                }
            )

        if policy_mode == "OR_ANY":
            if has_questions:
                add_slot("QUESTIONS_ONLY", f"ตอบคำถามให้ถูกอย่างน้อย {k_questions} จาก {len(valid_qs)} ข้อ", question_key)
            if has_phone:
                add_slot("PHONE_ONLY", "เบอร์โทรศัพท์ 4 ตัวท้าย", phone_key)
            if has_special:
                add_slot("SPECIAL_ONLY", "รหัสพิเศษ (Special Code)", special_key)
        elif policy_mode == "QUESTIONS_AND_PIN_OR_CODE":
            if has_questions and has_phone:
                add_slot("QUESTIONS_AND_PHONE", f"ตอบคำถาม ({k_questions}/{len(valid_qs)} ข้อ) + เบอร์โทร 4 ตัวท้าย", combine_keys_hkdf([question_key, phone_key], "Q+PHONE"))
            if has_questions and has_special:
                add_slot("QUESTIONS_AND_SPECIAL", f"ตอบคำถาม ({k_questions}/{len(valid_qs)} ข้อ) + รหัสพิเศษ", combine_keys_hkdf([question_key, special_key], "Q+SPECIAL"))
            if not has_questions:
                if has_phone:
                    add_slot("PHONE_ONLY", "เบอร์โทรศัพท์ 4 ตัวท้าย", phone_key)
                if has_special:
                    add_slot("SPECIAL_ONLY", "รหัสพิเศษ (Special Code)", special_key)
        elif policy_mode == "ALL_CONFIGURED":
            parts = [k for k in (question_key, phone_key, special_key) if k is not None]
            add_slot("ALL_CONFIGURED", "ต้องกรอกครบทั้งหมดที่ตั้งไว้", combine_keys_hkdf(parts, "ALL_FACTORS"))

        if cfg.get("allowPhoneInstantUnlock") and has_phone and not any(s["slotType"] == "PHONE_ONLY" for s in key_slots):
            add_slot("PHONE_ONLY", "ปลดล็อกด่วนด้วยเบอร์โทรศัพท์ 4 ตัวท้าย", phone_key)
        if cfg.get("allowSpecialInstantUnlock") and has_special and not any(s["slotType"] == "SPECIAL_ONLY" for s in key_slots):
            add_slot("SPECIAL_ONLY", "ปลดล็อกด่วนด้วยรหัสพิเศษ (Special Code)", special_key)

        inner_vault = {
            "version": "2.0.0",
            "kdfVersion": 2,
            "vaultId": str(uuid.uuid4()),
            "monotonicSeq": 0,
            "policyMode": policy_mode,
            "factors": {
                "hasQuestions": has_questions,
                "hasPhone": has_phone,
                "hasSpecial": has_special,
                "phoneSalt": phone_salt,
                "specialSalt": special_salt,
                "questionMeta": question_meta,
            },
            "gameModule": cfg.get("gameModuleConfig") or {"enabled": False, "gameType": "pattern_shield", "difficulty": 1},
            "securityCounter": {"maxAttempts": max_attempts, "remainingAttempts": max_attempts, "failedAttempts": 0},
            "keySlots": key_slots,
            "encryptedPayload": encrypted_payload,
        }
        # A 4-digit PIN alone is only 10^4 guesses; refuse any slot unlockable by the PIN by itself.
        if any(s["slotType"] == "PHONE_ONLY" for s in key_slots):
            raise ValueError(
                "ไม่อนุญาตให้ใช้เบอร์โทร 4 หลักเพียงอย่างเดียวในการปลดล็อก (เดาได้ครบใน 1–2 ชั่วโมงหากไฟล์หลุด) "
                "กรุณาใช้โหมด \"ต้องตอบคำถาม และ กรอกเบอร์/รหัสพิเศษ\" หรือโหมดเข้มงวดสูงสุด และปิดตัวเลือกทางด่วนเบอร์โทร"
            )
        if os.path.exists(self.vault_path):
            self.secure_wipe_and_reset("Re-initializing new vault")
        self._save_vault_disk_state(inner_vault)
        return self.get_public_status()

    def import_vault_file(self, file_bytes: bytes, replace_existing: bool = False):
        """Import a seedvault.dat carried on a Flash Drive into THIS device. Never destroys anything
        on a rejected import (stale / foreign / garbage files are simply refused)."""
        try:
            env = json.loads(bytes(file_bytes).decode("utf-8"))
        except Exception:
            raise ValueError("ไฟล์ที่เลือกไม่ใช่ seedvault.dat ที่ถูกต้อง")
        if (
            not isinstance(env, dict)
            or env.get("magic") != MAGIC_HEADER
            or not isinstance(env.get("vaultId"), str)
            or not isinstance(env.get("seq"), int)
            or not isinstance(env.get("failedAttempts"), int)
            or not env.get("outerEncrypted")
        ):
            raise ValueError("ไฟล์ที่เลือกไม่ใช่ seedvault.dat ที่ถูกต้อง")

        obs = self._read_max_observed_state(env["vaultId"])
        if obs["wiped"]:
            raise ValueError("Vault นี้ถูกทำลายบนเครื่องนี้ไปแล้ว ไม่สามารถนำเข้าซ้ำได้ (ใช้ไฟล์ล่าสุดจากเครื่องที่ใช้งานล่าสุด)")
        if obs["anyAnchorFound"] and (env["seq"] < obs["maxSeq"] or env["failedAttempts"] < obs["maxFailed"]):
            raise ValueError(
                "ไฟล์นี้เก่ากว่าสถานะที่เครื่องนี้เคยบันทึกไว้ จึงไม่ถูกนำเข้า (ป้องกันการย้อนจำนวนครั้ง) — "
                "ให้ส่งออกไฟล์ล่าสุดจากเครื่องนี้แทน หรือใช้ไฟล์ที่ใหม่กว่า"
            )

        if os.path.exists(self.vault_path):
            try:
                with open(self.vault_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = None
            same = bool(existing) and existing.get("vaultId") == env["vaultId"]
            if same and isinstance(existing.get("seq"), int) and existing["seq"] > env["seq"]:
                raise ValueError("เครื่องนี้มีไฟล์ Vault เดียวกันที่ใหม่กว่าอยู่แล้ว จึงไม่ถูกนำเข้า")
            if not same and not replace_existing:
                raise ValueError("เครื่องนี้มี Vault อื่นอยู่แล้ว การนำเข้าจะลบทำลายของเดิม — ยืนยันการแทนที่ก่อนนำเข้า")
            if not same:
                self.secure_wipe_and_reset("Replaced by imported vault")

        self._write_buffer_in_place(self.vault_path, bytes(file_bytes))
        inner = self._load_vault_disk_state()  # verifies integrity + syncs this device's anchors
        if not inner:
            raise ValueError("นำเข้าไม่สำเร็จ: ไฟล์ไม่ผ่านการตรวจสอบความสมบูรณ์")
        return self.get_public_status()

    def export_vault_file(self) -> bytes:
        inner = self._load_vault_disk_state()
        if not inner:
            raise ValueError("ไม่พบ Vault บนเครื่องนี้ให้ส่งออก")
        with open(self.vault_path, "rb") as f:
            return f.read()

    @staticmethod
    def _combinations(arr, k):
        if k == 0:
            return [[]]
        if len(arr) < k:
            return []
        res = []
        for idx in range(len(arr) - k + 1):
            head = arr[idx]
            for tail in PyVaultStorageManager._combinations(arr[idx + 1 :], k - 1):
                res.append([head] + tail)
        return res

    def unlock_vault(self, creds: dict):
        inner = self._load_vault_disk_state()
        if not inner:
            return {"success": False, "wiped": True, "mode": "SETUP", "error": "ไม่พบข้อมูลที่เข้ารหัสไว้ กรุณาตั้งค่าเริ่มต้นใหม่"}

        factors = inner["factors"]
        kdf_ver = inner.get("kdfVersion", 1)
        q_ans = creds.get("questionAnswers") or {}

        # Commit the attempt BEFORE the slow key derivation so killing the process mid-way
        # cannot give a free, uncounted guess.
        max_att = inner["securityCounter"]["maxAttempts"]
        if inner["securityCounter"]["remainingAttempts"] <= 0:
            self.secure_wipe_and_reset("กรอกรหัสผิดเกินจำนวนที่กำหนด")
            return {"success": False, "wiped": True, "mode": "SETUP", "remainingAttempts": 0, "error": "กรอกรหัสผิดเกินจำนวนที่กำหนด ข้อมูลที่เก็บไว้ถูกลบทำลายและรีเซ็ตโปรแกรมเรียบร้อยแล้ว"}
        inner["securityCounter"]["failedAttempts"] += 1
        inner["securityCounter"]["remainingAttempts"] = max(0, max_att - inner["securityCounter"]["failedAttempts"])
        self._save_vault_disk_state(inner)

        valid_shares = []
        if factors["hasQuestions"] and factors.get("questionMeta"):
            for q_item in factors["questionMeta"]["items"]:
                raw_a = q_ans.get(str(q_item["id"])) or q_ans.get(q_item["id"]) or ""
                norm_a = normalize_answer(str(raw_a), False)
                if not norm_a:
                    continue
                try:
                    a_key = derive_key_hardened(f"Q:{q_item['id']}:{norm_a}", q_item["salt"], kdf_ver)
                    if isinstance(q_item.get("maskedShare"), str):
                        masked_bytes = bytes.fromhex(q_item["maskedShare"])
                        sh_y = bytes(a ^ b for a, b in zip(masked_bytes, a_key))
                        valid_shares.append({"x": q_item["x"], "y": sh_y})
                    elif q_item.get("wrappedShare"):
                        sh_y = NativeAES256GCM.decrypt(q_item["wrappedShare"], a_key, f"Share-{q_item['x']}".encode("utf-8"))
                        valid_shares.append({"x": q_item["x"], "y": sh_y})
                except Exception:
                    pass

        rec_q_keys = []
        if factors["hasQuestions"] and factors.get("questionMeta"):
            req_k = factors["questionMeta"]["requiredCorrect"]
            if len(valid_shares) >= req_k:
                for combo in self._combinations(valid_shares, req_k):
                    try:
                        rec_q_keys.append(ShamirSecretSharing.combine(combo))
                    except Exception:
                        pass

        phone_in = str(creds.get("phoneLast4") or "").strip()
        der_phone_key = derive_key_hardened(f"PHONE4:{phone_in}", factors["phoneSalt"], kdf_ver) if (factors["hasPhone"] and len(phone_in) == 4) else None

        spec_in = normalize_answer(str(creds.get("specialCode") or ""), True)
        der_spec_key = derive_key_hardened(f"SPECIAL:{spec_in}", factors["specialSalt"], kdf_ver) if (factors["hasSpecial"] and spec_in) else None

        for slot in inner["keySlots"]:
            st = slot["slotType"]
            cands = []
            if st == "QUESTIONS_ONLY" and rec_q_keys:
                cands.extend(rec_q_keys)
            elif st == "PHONE_ONLY" and der_phone_key:
                cands.append(der_phone_key)
            elif st == "SPECIAL_ONLY" and der_spec_key:
                cands.append(der_spec_key)
            elif st == "QUESTIONS_AND_PHONE" and rec_q_keys and der_phone_key:
                for qk in rec_q_keys:
                    cands.append(combine_keys_hkdf([qk, der_phone_key], "Q+PHONE"))
            elif st == "QUESTIONS_AND_SPECIAL" and rec_q_keys and der_spec_key:
                for qk in rec_q_keys:
                    cands.append(combine_keys_hkdf([qk, der_spec_key], "Q+SPECIAL"))
            elif st == "ALL_CONFIGURED":
                q_list = rec_q_keys if factors["hasQuestions"] else [None]
                ok = True
                if factors["hasQuestions"] and not rec_q_keys:
                    ok = False
                if factors["hasPhone"] and not der_phone_key:
                    ok = False
                if factors["hasSpecial"] and not der_spec_key:
                    ok = False
                if ok:
                    for qk in q_list:
                        parts = [p for p in (qk, der_phone_key if factors["hasPhone"] else None, der_spec_key if factors["hasSpecial"] else None) if p is not None]
                        if parts:
                            cands.append(combine_keys_hkdf(parts, "ALL_FACTORS"))

            for cand in cands:
                try:
                    m_key = NativeAES256GCM.decrypt(slot["wrappedMaster"], cand, f"Slot:{st}".encode("utf-8"))
                    dec_bytes = NativeAES256GCM.decrypt(inner["encryptedPayload"], m_key, b"SeedVault-PrimaryPayload-v1")
                    payload = unpack_fixed_size_payload(dec_bytes)
                    # Correct: restore a full allowance under a fresh vaultId (anchors keep a monotonic
                    # maximum of failures per vaultId and would flag a plain reset as rollback).
                    inner["securityCounter"]["failedAttempts"] = 0
                    inner["securityCounter"]["remainingAttempts"] = inner["securityCounter"]["maxAttempts"]
                    inner["vaultId"] = str(uuid.uuid4())
                    inner["monotonicSeq"] = 0
                    self._save_vault_disk_state(inner)
                    return {
                        "success": True,
                        "matchedSlot": st,
                        "matchedSlotLabel": slot["slotLabel"],
                        "remainingAttempts": inner["securityCounter"]["remainingAttempts"],
                        "maxAttempts": inner["securityCounter"]["maxAttempts"],
                        "payload": payload,
                    }
                except Exception:
                    continue

        # Failed attempt (already counted and committed above)
        rem = inner["securityCounter"]["remainingAttempts"]
        if rem <= 0:
            self.secure_wipe_and_reset("กรอกรหัสผิดเกินจำนวนที่กำหนด (Self-Destruct Activated)")
            return {
                "success": False,
                "wiped": True,
                "mode": "SETUP",
                "remainingAttempts": 0,
                "maxAttempts": inner["securityCounter"]["maxAttempts"],
                "error": "คุณกรอกรหัสผิดเกินจำนวนที่กำหนด! ข้อมูล Seedphrase ที่เข้ารหัสไว้ถูกลบทำลายอย่างถาวร (Zero-Wipe) และรีเซ็ตโปรแกรมกลับสู่โหมดเริ่มต้นใหม่แล้ว",
            }
        return {
            "success": False,
            "wiped": False,
            "mode": "UNLOCK",
            "remainingAttempts": rem,
            "maxAttempts": inner["securityCounter"]["maxAttempts"],
            "failedAttempts": inner["securityCounter"]["failedAttempts"],
            "error": f"รหัสผ่านหรือคำตอบไม่ถูกต้อง! เหลือโอกาสกรอกได้อีก {rem} ครั้ง (หากครบกำหนดข้อมูลจะถูกลบทิ้งทันที)",
        }


# ============================================================================
# 5. Pure Python Secp256k1, BIP39/BIP32/BIP84 & Bitcoin SegWit/PSBT Signer
# ============================================================================
class PySecp256k1:
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    HALF_N = N >> 1
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    @classmethod
    def mod_inv(cls, a: int, m: int = P) -> int:
        return pow(a % m, m - 2, m)

    @classmethod
    def point_add(cls, p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2 and y1 != y2:
            return None
        if x1 == x2 and y1 == y2:
            if y1 == 0:
                return None
            lam = (3 * x1 * x1 * cls.mod_inv(2 * y1, cls.P)) % cls.P
        else:
            lam = ((y2 - y1) * cls.mod_inv(x2 - x1, cls.P)) % cls.P
        x3 = (lam * lam - x1 - x2) % cls.P
        y3 = (lam * (x1 - x3) - y1) % cls.P
        return (x3, y3)

    @classmethod
    def point_mul(cls, k: int, pt=None):
        if pt is None:
            pt = (cls.Gx, cls.Gy)
        scalar = k % cls.N
        if scalar == 0:
            return None
        res = None
        addend = pt
        while scalar > 0:
            if scalar & 1:
                res = cls.point_add(res, addend)
            addend = cls.point_add(addend, addend)
            scalar >>= 1
        return res

    @classmethod
    def get_pubkey(cls, priv_bytes: bytes) -> bytes:
        d = int.from_bytes(priv_bytes, "big")
        pt = cls.point_mul(d)
        prefix = 0x02 if (pt[1] & 1) == 0 else 0x03
        return bytes([prefix]) + pt[0].to_bytes(32, "big")

    @classmethod
    def sign_ecdsa(cls, msg_hash32: bytes, priv_key32: bytes) -> bytes:
        d = int.from_bytes(priv_key32, "big")
        z = int.from_bytes(msg_hash32, "big")
        v = b"\x01" * 32
        k = b"\x00" * 32
        k = hmac.new(k, v + b"\x00" + priv_key32 + msg_hash32, hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
        k = hmac.new(k, v + b"\x01" + priv_key32 + msg_hash32, hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()
        while True:
            v = hmac.new(k, v, hashlib.sha256).digest()
            cand = int.from_bytes(v, "big")
            if 1 <= cand < cls.N:
                nonce_k = cand
                break
            k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
            v = hmac.new(k, v, hashlib.sha256).digest()
        R = cls.point_mul(nonce_k)
        r = R[0] % cls.N
        s = (cls.mod_inv(nonce_k, cls.N) * ((z + r * d) % cls.N)) % cls.N
        if s > cls.HALF_N:
            s = cls.N - s

        def der_int(val: int) -> bytes:
            b = val.to_bytes((val.bit_length() + 7) // 8 or 1, "big")
            if b[0] & 0x80:
                b = b"\x00" + b
            return bytes([0x02, len(b)]) + b

        rb = der_int(r)
        sb = der_int(s)
        return bytes([0x30, len(rb) + len(sb)]) + rb + sb


def py_hash160(data: bytes) -> bytes:
    s = hashlib.sha256(data).digest()
    try:
        h = hashlib.new("ripemd160")
        h.update(s)
        return h.digest()
    except Exception:
        lib = NativeAES256GCM._load_libcrypto()
        out = ctypes.create_string_buffer(20)
        lib.RIPEMD160(s, len(s), out)
        return out.raw


def py_base58check(ver_byte: int, payload: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    data = bytes([ver_byte]) + payload
    chk = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    full = data + chk
    num = int.from_bytes(full, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = alphabet[rem] + out
    for b in full:
        if b == 0:
            out = "1" + out
        else:
            break
    return out


def py_bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    acc = 0
    bits = 0
    words = [witver]
    for val in witprog:
        acc = (acc << 8) | val
        bits += 8
        while bits >= 5:
            bits -= 5
            words.append((acc >> bits) & 31)
    if bits > 0:
        words.append((acc << (5 - bits)) & 31)

    hrp_exp = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    values = hrp_exp + words + [0, 0, 0, 0, 0, 0]
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    spec_const = 1 if witver == 0 else 0x2BC830A3
    mod = chk ^ spec_const
    checksum = [(mod >> (5 * (5 - p))) & 31 for p in range(6)]
    return hrp + "1" + "".join(charset[c] for c in (words + checksum))


def py_tagged_hash(tag: str, msg: bytes) -> bytes:
    th = hashlib.sha256(tag.encode("utf-8")).digest()
    return hashlib.sha256(th + th + msg).digest()


def py_derive_taproot(priv_bytes: bytes):
    d = int.from_bytes(priv_bytes, "big")
    pt = PySecp256k1.point_mul(d)
    if (pt[1] & 1) != 0:
        d = PySecp256k1.N - d
        pt = (pt[0], PySecp256k1.P - pt[1])
    internal_x = pt[0].to_bytes(32, "big")
    t = int.from_bytes(py_tagged_hash("TapTweak", internal_x), "big")
    q_pt = PySecp256k1.point_add(pt, PySecp256k1.point_mul(t))
    tweaked_priv = ((d + t) % PySecp256k1.N).to_bytes(32, "big")
    out_x = q_pt[0].to_bytes(32, "big")
    return out_x, tweaked_priv


def py_to_internal_change_path(path_str: str = "m/84'/0'/0'/0/0") -> str:
    clean = str(path_str or "m/84'/0'/0'/0/0").strip().lstrip("mM/")
    parts = [p for p in clean.split("/") if p]
    if len(parts) >= 5:
        chg_parts = list(parts)
        chg_parts[3] = "1"
        return "m/" + "/".join(chg_parts)
    if len(parts) == 3:
        return "m/" + "/".join(parts) + "/1/0"
    return "m/84'/0'/0'/1/0"


def py_addresses_for_point(pt, script_type: str):
    pub_comp = py_compress_point(pt)
    pkh = py_hash160(pub_comp)
    even_pt = pt if (pt[1] & 1) == 0 else (pt[0], PySecp256k1.P - pt[1])
    internal_x = even_pt[0].to_bytes(32, "big")
    t = int.from_bytes(py_tagged_hash("TapTweak", internal_x), "big")
    q_pt = PySecp256k1.point_add(even_pt, PySecp256k1.point_mul(t))
    tap_x = q_pt[0].to_bytes(32, "big")

    taproot_addr = py_bech32_encode("bc", 1, tap_x)
    segwit = py_bech32_encode("bc", 0, pkh)
    legacy = py_base58check(0x00, pkh)
    nested = py_base58check(0x05, py_hash160(b"\x00\x14" + pkh))

    active = segwit
    if script_type == "TAPROOT":
        active = taproot_addr
    elif script_type == "NESTED_SEGWIT":
        active = nested
    elif script_type == "LEGACY":
        active = legacy

    return {
        "active": active,
        "pub_comp": pub_comp,
        "pkh": pkh,
        "taproot_addr": taproot_addr,
        "segwit": segwit,
        "nested": nested,
        "legacy": legacy,
    }


def py_derive_wallet(words, passphrase25: str = "", path_str: str = "m/84'/0'/0'/0/0", script_type: str = "NATIVE_SEGWIT"):
    sentence = unicodedata.normalize("NFKD", " ".join(w.strip().lower() for w in words))
    salt = unicodedata.normalize("NFKD", "mnemonic" + (passphrase25 or ""))
    seed = hashlib.pbkdf2_hmac("sha512", sentence.encode("utf-8"), salt.encode("utf-8"), 2048, 64)
    I_master = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_priv, master_chain = I_master[:32], I_master[32:]
    master_fp = py_hash160(PySecp256k1.get_pubkey(master_priv))[:4].hex()

    def derive_priv_path(p_str):
        priv, chain = master_priv, master_chain
        segs = [s for s in p_str.strip().lstrip("mM/").split("/") if s]
        for seg in segs:
            hardened = seg.endswith("'") or seg.lower().endswith("h")
            idx = int(seg.rstrip("'hH"))
            if hardened:
                idx_val = (idx | 0x80000000) & 0xFFFFFFFF
                data = b"\x00" + priv + struct.pack(">I", idx_val)
            else:
                idx_val = idx & 0xFFFFFFFF
                data = PySecp256k1.get_pubkey(priv) + struct.pack(">I", idx_val)
            I = hmac.new(chain, data, hashlib.sha512).digest()
            il = int.from_bytes(I[:32], "big")
            kpar = int.from_bytes(priv, "big")
            priv = ((il + kpar) % PySecp256k1.N).to_bytes(32, "big")
            chain = I[32:]
        return priv

    priv = derive_priv_path(path_str)
    pub = PySecp256k1.get_pubkey(priv)
    pkh = py_hash160(pub)
    tap_x, tweaked_priv = py_derive_taproot(priv)
    taproot_addr = py_bech32_encode("bc", 1, tap_x)
    segwit = py_bech32_encode("bc", 0, pkh)
    legacy = py_base58check(0x00, pkh)
    nested = py_base58check(0x05, py_hash160(b"\x00\x14" + pkh))

    active = segwit
    if script_type == "TAPROOT":
        active = taproot_addr
    elif script_type == "NESTED_SEGWIT":
        active = nested
    elif script_type == "LEGACY":
        active = legacy

    change_path = py_to_internal_change_path(path_str)
    chg_priv = derive_priv_path(change_path)
    chg_pt = py_decompress_point(PySecp256k1.get_pubkey(chg_priv))
    chg_info = py_addresses_for_point(chg_pt, script_type)

    return {
        "path": path_str,
        "changePath": change_path,
        "changeAddress": chg_info["active"],
        "scriptType": script_type,
        "activeAddress": active,
        "masterFingerprint": master_fp,
        "privateKey": priv,
        "tweakedPrivateKey": tweaked_priv,
        "publicKeyHex": pub.hex(),
        "pubKeyHash": pkh,
        "taprootAddress": taproot_addr,
        "segwitAddress": segwit,
        "nestedSegwitAddress": nested,
        "legacyAddress": legacy,
    }


def py_decompress_point(pub_bytes: bytes):
    if len(pub_bytes) == 65 and pub_bytes[0] == 0x04:
        return int.from_bytes(pub_bytes[1:33], "big"), int.from_bytes(pub_bytes[33:65], "big")
    if len(pub_bytes) == 33 and pub_bytes[0] in (0x02, 0x03):
        x = int.from_bytes(pub_bytes[1:33], "big")
        rhs = (pow(x, 3, PySecp256k1.P) + 7) % PySecp256k1.P
        y = pow(rhs, (PySecp256k1.P + 1) // 4, PySecp256k1.P)
        if (y & 1) != (1 if pub_bytes[0] == 0x03 else 0):
            y = PySecp256k1.P - y
        return x, y
    raise ValueError("Invalid secp256k1 public key")


def py_compress_point(pt) -> bytes:
    prefix = 0x02 if (pt[1] & 1) == 0 else 0x03
    return bytes([prefix]) + pt[0].to_bytes(32, "big")


def py_derive_non_hardened_point(root_pt, root_chain: bytes, segs):
    pt = root_pt
    pub_comp = py_compress_point(pt)
    chain = root_chain
    for seg in segs:
        idx = int(seg) & 0xFFFFFFFF
        I = hmac.new(chain, pub_comp + struct.pack(">I", idx), hashlib.sha512).digest()
        il = int.from_bytes(I[:32], "big")
        pt = PySecp256k1.point_add(PySecp256k1.point_mul(il), pt)
        pub_comp = py_compress_point(pt)
        chain = I[32:]
    return pt


def py_derive_from_hw_pubkey(body: dict) -> dict:
    xpub = str(body.get("xpub") or "").strip()
    pub_hex = str(body.get("pubKeyHex") or "").strip()
    chain_hex = str(body.get("chainCodeHex") or "").strip()
    child_path = str(body.get("childPath") or "").strip()
    change_pub_hex = str(body.get("changePubKeyHex") or "").strip()
    script_type = str(body.get("scriptType") or "NATIVE_SEGWIT")
    path_str = str(body.get("derivationPath") or "m/84'/0'/0'/0/0")
    fp = str(body.get("masterFingerprint") or "HARDWARE")

    root_chain = bytes.fromhex(chain_hex) if chain_hex else None
    if xpub:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        num = 0
        for c in xpub:
            num = num * 58 + alphabet.index(c)
        raw = num.to_bytes(82, "big")
        payload, chk = raw[:78], raw[78:]
        if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != chk:
            raise ValueError("Invalid xpub checksum")
        if fp == "HARDWARE":
            fp = payload[5:9].hex()
        root_chain = payload[13:45]
        root_pt = py_decompress_point(payload[45:78])
    elif pub_hex:
        root_pt = py_decompress_point(bytes.fromhex(pub_hex))
    else:
        raise ValueError("ไม่ได้รับ Public Key หรือ Xpub จากอุปกรณ์ Hardware Wallet")

    segs = [s for s in child_path.lstrip("mM/").split("/") if s]
    pt = root_pt
    if segs and root_chain and len(root_chain) == 32:
        pt = py_derive_non_hardened_point(root_pt, root_chain, segs)

    main_info = py_addresses_for_point(pt, script_type)
    change_path = py_to_internal_change_path(path_str)
    change_addr = main_info["active"]

    if change_pub_hex:
        chg_pt = py_decompress_point(bytes.fromhex(change_pub_hex))
        change_addr = py_addresses_for_point(chg_pt, script_type)["active"]
    elif segs and root_chain and len(root_chain) == 32:
        chg_segs = ["1", segs[1] if len(segs) > 1 else "0"]
        chg_pt = py_derive_non_hardened_point(root_pt, root_chain, chg_segs)
        change_addr = py_addresses_for_point(chg_pt, script_type)["active"]

    scan_addresses = [{"address": main_info["active"], "derivationPath": path_str, "branch": "receive", "index": 0}]
    if segs and root_chain and len(root_chain) == 32:
        full_parts = [s for s in path_str.lstrip("mM/").split("/") if s]
        acct_prefix = ("m/" + "/".join(full_parts[:3])) if len(full_parts) >= 3 else "m/84'/0'/0'"
        scan_addresses = []
        for idx in range(5):
            cpt = py_derive_non_hardened_point(root_pt, root_chain, ["0", str(idx)])
            cinfo = py_addresses_for_point(cpt, script_type)
            scan_addresses.append({
                "address": cinfo["active"],
                "derivationPath": f"{acct_prefix}/0/{idx}",
                "branch": "receive",
                "index": idx,
            })
        for idx in range(3):
            cpt = py_derive_non_hardened_point(root_pt, root_chain, ["1", str(idx)])
            cinfo = py_addresses_for_point(cpt, script_type)
            scan_addresses.append({
                "address": cinfo["active"],
                "derivationPath": f"{acct_prefix}/1/{idx}",
                "branch": "change",
                "index": idx,
            })

    return {
        "path": path_str,
        "changePath": change_path,
        "changeAddress": change_addr,
        "scanAddresses": scan_addresses,
        "scriptType": script_type,
        "activeAddress": main_info["active"],
        "masterFingerprint": fp,
        "publicKeyHex": main_info["pub_comp"].hex(),
        "taprootAddress": main_info["taproot_addr"],
        "segwitAddress": main_info["segwit"],
        "nestedSegwitAddress": main_info["nested"],
        "legacyAddress": main_info["legacy"],
    }


def py_addr_to_script(addr: str) -> bytes:
    clean = addr.strip()
    if clean.lower().startswith(("bc1", "tb1")):
        charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        lower = clean.lower()
        pos = lower.rfind("1")
        data = [charset.index(c) for c in lower[pos + 1 : -6]]
        witver = data[0]
        acc = 0
        bits = 0
        prog = bytearray()
        for v in data[1:]:
            acc = (acc << 5) | v
            bits += 5
            while bits >= 8:
                bits -= 8
                prog.append((acc >> bits) & 0xFF)
        op_v = 0x00 if witver == 0 else (0x50 + witver)
        return bytes([op_v, len(prog)]) + bytes(prog)
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for c in clean:
        num = num * 58 + alphabet.index(c)
    full = num.to_bytes(25, "big")
    ver, h = full[0], full[1:21]
    if ver in (0x00, 0x6F):
        return b"\x76\xa9\x14" + h + b"\x88\xac"
    if ver in (0x05, 0xC4):
        return b"\xa9\x14" + h + b"\x87"
    raise ValueError("Unsupported Bitcoin address")


def py_varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def py_sign_btc_tx(body: dict) -> dict:
    sign_with_seed = body.get("signWithSeed") is not False
    script_type = body.get("scriptType") or "NATIVE_SEGWIT"
    inputs = body.get("inputs") or []
    outputs = body.get("outputs") or []
    if not inputs or not outputs:
        raise ValueError("กรุณาเลือก UTXO และระบุ Address ปลายทางให้ครบถ้วน")

    clean_in = []
    tot_in = 0
    for inp in inputs:
        txid = str(inp.get("txid") or "").strip()
        vout = int(round(float(inp.get("vout") or 0)))
        sats = int(round(float(inp.get("amountSats") or 0)))
        tot_in += sats
        clean_in.append({"txid_le": bytes.fromhex(txid)[::-1], "vout": vout, "sats": sats, "seq": 0xFFFFFFFD})

    clean_out = []
    tot_out = 0
    for out in outputs:
        spk = py_addr_to_script(str(out.get("address") or ""))
        sats = int(round(float(out.get("amountSats") or 0)))
        tot_out += sats
        clean_out.append({"sats": sats, "spk": spk})

    if tot_out > tot_in:
        raise ValueError("ยอดโอนออกมากกว่ายอดรวม UTXO ที่เลือก")
    fee = tot_in - tot_out

    ver_b = struct.pack("<I", 2)
    lock_b = struct.pack("<I", 0)
    ins_no_wit = [i["txid_le"] + struct.pack("<I", i["vout"]) + b"\x00" + struct.pack("<I", i["seq"]) for i in clean_in]
    outs_b = [struct.pack("<Q", o["sats"]) + py_varint(len(o["spk"])) + o["spk"] for o in clean_out]
    unsigned_tx = ver_b + py_varint(len(clean_in)) + b"".join(ins_no_wit) + py_varint(len(clean_out)) + b"".join(outs_b) + lock_b
    txid_hex = hashlib.sha256(hashlib.sha256(unsigned_tx).digest()).digest()[::-1].hex()

    w = None
    if sign_with_seed:
        w = py_derive_wallet(body.get("words") or [], body.get("passphrase25") or "", body.get("derivationPath") or "m/84'/0'/0'/0/0", script_type)
        in_spk = py_addr_to_script(w["activeAddress"])
    else:
        sender_addr = str(body.get("senderAddress") or "").strip()
        in_spk = py_addr_to_script(sender_addr) if sender_addr else (b"\x00\x14" + b"\x00" * 20)

    psbt_in = []
    for i in clean_in:
        u_val = struct.pack("<Q", i["sats"]) + py_varint(len(in_spk)) + in_spk
        psbt_in.append(b"\x01\x01" + py_varint(len(u_val)) + u_val + b"\x00")
    psbt_b = b"psbt\xff\x01\x00" + py_varint(len(unsigned_tx)) + unsigned_tx + b"\x00" + b"".join(psbt_in) + (b"\x00" * len(clean_out))
    import base64
    psbt_b64 = base64.b64encode(psbt_b).decode("ascii")

    if not sign_with_seed:
        return {
            "signed": False,
            "mode": "HARDWARE_WALLET_PSBT",
            "scriptType": script_type,
            "txid": txid_hex,
            "vsize": len(unsigned_tx) + len(clean_in) * 27,
            "feeSats": fee,
            "totalInSats": tot_in,
            "totalOutSats": tot_out,
            "unsignedPsbtBase64": psbt_b64,
            "unsignedTxHex": unsigned_tx.hex(),
            "signerAddress": body.get("senderAddress") or "(Hardware Wallet)",
            "binOutputs": [{"address": o["address"], "amountSats": o["sats"], "scriptPubKeyHex": o["spk"].hex(), "isChange": o.get("isChange", False)} for o in clean_out],
            "cleanInputs": [{"txid": i["txid"], "vout": i["vout"], "amountSats": i["sats"], "sequence": i["seq"]} for i in clean_in],
        }

    h_prev = hashlib.sha256(hashlib.sha256(b"".join(i["txid_le"] + struct.pack("<I", i["vout"]) for i in clean_in)).digest()).digest()
    h_seq = hashlib.sha256(hashlib.sha256(b"".join(struct.pack("<I", i["seq"]) for i in clean_in)).digest()).digest()
    h_out = hashlib.sha256(hashlib.sha256(b"".join(outs_b)).digest()).digest()
    scode = b"\x19\x76\xa9\x14" + w["pubKeyHash"] + b"\x88\xac"
    pub_b = bytes.fromhex(w["publicKeyHex"])

    wits = []
    for i in clean_in:
        pre = (
            ver_b
            + h_prev
            + h_seq
            + i["txid_le"]
            + struct.pack("<I", i["vout"])
            + scode
            + struct.pack("<Q", i["sats"])
            + struct.pack("<I", i["seq"])
            + h_out
            + lock_b
            + struct.pack("<I", 1)
        )
        sh = hashlib.sha256(hashlib.sha256(pre).digest()).digest()
        sig = PySecp256k1.sign_ecdsa(sh, w["privateKey"]) + b"\x01"
        wits.append(b"\x02" + py_varint(len(sig)) + sig + py_varint(len(pub_b)) + pub_b)

    signed_tx = ver_b + b"\x00\x01" + py_varint(len(clean_in)) + b"".join(ins_no_wit) + py_varint(len(clean_out)) + b"".join(outs_b) + b"".join(wits) + lock_b
    return {
        "signed": True,
        "scriptType": script_type,
        "txid": txid_hex,
        "vsize": (len(unsigned_tx) * 3 + len(signed_tx) + 3) // 4,
        "feeSats": fee,
        "totalInSats": tot_in,
        "totalOutSats": tot_out,
        "signedTxHex": signed_tx.hex(),
        "unsignedPsbtBase64": psbt_b64,
        "signerAddress": w["activeAddress"],
        "signerPublicKey": w["publicKeyHex"],
        "masterFingerprint": w["masterFingerprint"],
    }


def py_assemble_signed_btc_tx(body: dict) -> dict:
    script_type = body.get("scriptType") or "NATIVE_SEGWIT"
    inputs = body.get("inputs") or []
    outputs = body.get("outputs") or []
    signatures = body.get("signatures") or []
    if not inputs or not outputs or not signatures:
        raise ValueError("ข้อมูลสำหรับประกอบธุรกรรมไม่ครบถ้วน (inputs/outputs/signatures)")

    version = body.get("version") or 2
    lock_time = body.get("lockTime") or 0
    ver_b = struct.pack("<I", version)
    lock_b = struct.pack("<I", lock_time)

    sig_map = {int(s.get("inputIndex", 0)): s for s in signatures}

    clean_in = []
    ins_no_wit = []
    for inp in inputs:
        txid_le = bytes.fromhex(inp["txid"])[::-1]
        vout = int(inp["vout"])
        seq = int(inp.get("sequence", 0xFFFFFFFF))
        clean_in.append({"txid_le": txid_le, "vout": vout, "seq": seq})
        ins_no_wit.append(txid_le + struct.pack("<I", vout) + b"\x00" + struct.pack("<I", seq))

    outs_b = []
    for o in outputs:
        amt = int(round(float(o.get("amountSats", 0))))
        spk_hex = o.get("scriptPubKeyHex")
        if spk_hex:
            spk = bytes.fromhex(spk_hex)
        else:
            spk = py_address_to_spk(o["address"])
        outs_b.append(struct.pack("<Q", amt) + py_varint(len(spk)) + spk)

    is_segwit = script_type in ("NATIVE_SEGWIT", "NESTED_SEGWIT", "TAPROOT")
    wits = []
    final_ins = []
    for idx, inp in enumerate(clean_in):
        s_obj = sig_map.get(idx)
        if not s_obj:
            raise ValueError(f"ไม่พบ Signature ของ Input #{idx}")
        sig_b = bytes.fromhex(s_obj["signatureHex"])
        pk_b = bytes.fromhex(s_obj.get("pubKeyHex", "")) if s_obj.get("pubKeyHex") else b""

        if script_type == "TAPROOT":
            wits.append(b"\x01" + py_varint(len(sig_b)) + sig_b)
            final_ins.append(inp["txid_le"] + struct.pack("<I", inp["vout"]) + b"\x00" + struct.pack("<I", inp["seq"]))
            continue

        if len(sig_b) > 0 and sig_b[0] == 0x30:
            der_len = sig_b[1]
            if len(sig_b) == der_len + 2:
                sig_b += b"\x01"

        if script_type == "NATIVE_SEGWIT":
            wits.append(b"\x02" + py_varint(len(sig_b)) + sig_b + py_varint(len(pk_b)) + pk_b)
            final_ins.append(inp["txid_le"] + struct.pack("<I", inp["vout"]) + b"\x00" + struct.pack("<I", inp["seq"]))
        elif script_type == "NESTED_SEGWIT":
            pkh = hashlib.new("ripemd160", hashlib.sha256(pk_b).digest()).digest()
            redeem = b"\x16\x00\x14" + pkh
            wits.append(b"\x02" + py_varint(len(sig_b)) + sig_b + py_varint(len(pk_b)) + pk_b)
            final_ins.append(inp["txid_le"] + struct.pack("<I", inp["vout"]) + py_varint(len(redeem)) + redeem + struct.pack("<I", inp["seq"]))
        else:
            ssig = py_varint(len(sig_b)) + sig_b + py_varint(len(pk_b)) + pk_b
            final_ins.append(inp["txid_le"] + struct.pack("<I", inp["vout"]) + py_varint(len(ssig)) + ssig + struct.pack("<I", inp["seq"]))

    if is_segwit:
        signed_tx = ver_b + b"\x00\x01" + py_varint(len(clean_in)) + b"".join(final_ins) + py_varint(len(outs_b)) + b"".join(outs_b) + b"".join(wits) + lock_b
    else:
        signed_tx = ver_b + py_varint(len(clean_in)) + b"".join(final_ins) + py_varint(len(outs_b)) + b"".join(outs_b) + lock_b

    non_wit = ver_b + py_varint(len(clean_in)) + b"".join(ins_no_wit) + py_varint(len(outs_b)) + b"".join(outs_b) + lock_b
    txid = hashlib.sha256(hashlib.sha256(non_wit).digest()).digest()[::-1].hex()
    vsize = (len(non_wit) * 3 + len(signed_tx) + 3) // 4 if is_segwit else len(signed_tx)

    return {
        "txid": txid,
        "signedTxHex": signed_tx.hex(),
        "vsize": vsize,
    }


def py_parse_raw_btc_tx(raw_hex: str) -> dict:
    buf = bytes.fromhex(str(raw_hex or "").strip())
    if len(buf) < 10:
        raise ValueError("Raw transaction hex สั้นเกินไปหรือไม่ถูกต้อง")
    pos = [0]

    def read_u32():
        v = struct.unpack_from("<I", buf, pos[0])[0]
        pos[0] += 4
        return v

    def read_u64():
        v = struct.unpack_from("<Q", buf, pos[0])[0]
        pos[0] += 8
        return v

    def read_varint():
        first = buf[pos[0]]
        pos[0] += 1
        if first < 0xFD:
            return first
        if first == 0xFD:
            v = struct.unpack_from("<H", buf, pos[0])[0]
            pos[0] += 2
            return v
        if first == 0xFE:
            v = struct.unpack_from("<I", buf, pos[0])[0]
            pos[0] += 4
            return v
        v = struct.unpack_from("<Q", buf, pos[0])[0]
        pos[0] += 8
        return v

    ver = read_u32()
    is_segwit = False
    if buf[pos[0] : pos[0] + 2] == b"\x00\x01":
        is_segwit = True
        pos[0] += 2

    in_start = pos[0]
    in_cnt = read_varint()
    inputs = []
    for _ in range(in_cnt):
        prev_be = buf[pos[0] : pos[0] + 32][::-1].hex()
        pos[0] += 32
        prev_idx = read_u32()
        slen = read_varint()
        ssig = buf[pos[0] : pos[0] + slen].hex()
        pos[0] += slen
        seq = read_u32()
        inputs.append({"prevHashHex": prev_be, "prevIndex": prev_idx, "scriptSigHex": ssig, "sequence": seq})

    out_cnt = read_varint()
    bin_outs = []
    for _ in range(out_cnt):
        sats = read_u64()
        spk_len = read_varint()
        spk = buf[pos[0] : pos[0] + spk_len].hex()
        pos[0] += spk_len
        bin_outs.append({"amountSats": sats, "scriptPubKeyHex": spk})
    out_end = pos[0]

    if is_segwit:
        for _ in range(in_cnt):
            w_cnt = read_varint()
            for _ in range(w_cnt):
                w_len = read_varint()
                pos[0] += w_len

    lock_time = read_u32()
    non_wit = buf[:4] + buf[in_start:out_end] + buf[pos[0] - 4 : pos[0]]
    txid = hashlib.sha256(hashlib.sha256(non_wit).digest()).digest()[::-1].hex()
    return {
        "txid": txid,
        "version": ver,
        "lockTime": lock_time,
        "inputsCount": in_cnt,
        "outputsCount": out_cnt,
        "inputs": inputs,
        "binOutputs": bin_outs,
    }


# ============================================================================
# 6. Standalone Local Loopback Server for Tails OS / Linux
# ============================================================================
def run_standalone_python_server():
    data_dir = resolve_default_data_dir()
    storage = PyVaultStorageManager(data_dir)
    csrf_token = secrets.token_hex(32)
    game_sessions = {}
    valid_pass_tokens = {}  # token -> expiry (single-use)
    server_state = {"port": 0}

    # --- Anti-bot gate policy (mirrors game-module.js) ---
    GATE_MIN_SOLVE_S = 0.7
    GATE_TTL_S = 300
    GATE_MAX_WRONG = 3
    GATE_MAX_SESSIONS = 200
    GATE_THROTTLE_WINDOW_S = 60
    GATE_THROTTLE_MAX_FAILS = 10
    GATE_THROTTLE_LOCK_S = 30
    gate = {"fail_times": [], "locked_until": 0.0}

    def gate_throttled() -> bool:
        return time.time() < gate["locked_until"]

    def gate_record_failure():
        now = time.time()
        gate["fail_times"] = [t for t in gate["fail_times"] if now - t < GATE_THROTTLE_WINDOW_S]
        gate["fail_times"].append(now)
        if len(gate["fail_times"]) >= GATE_THROTTLE_MAX_FAILS:
            gate["locked_until"] = now + GATE_THROTTLE_LOCK_S
            gate["fail_times"] = []

    def gate_purge():
        now = time.time()
        for sid in [k for k, v in game_sessions.items() if now - v["createdAt"] > GATE_TTL_S]:
            game_sessions.pop(sid, None)
        for tk in [k for k, exp in valid_pass_tokens.items() if now > exp]:
            valid_pass_tokens.pop(tk, None)
        while len(game_sessions) > GATE_MAX_SESSIONS:
            game_sessions.pop(next(iter(game_sessions)), None)

    def consume_pass_token(tok) -> bool:
        exp = valid_pass_tokens.pop(tok, None) if isinstance(tok, str) else None
        return exp is not None and time.time() <= exp

    def public_challenge(gtype: str, ch: dict) -> dict:
        # Fields that only exist to check the answer (and that the UI never needs) stay server-side.
        if gtype == "chroma_slider":
            return {"colorSample": ch["colorSample"]}
        if gtype == "glyph_outlier":
            return {"totalItems": ch["totalItems"], "items": ch["items"]}
        if gtype == "bubble_sequence":
            return {"count": ch["count"], "bubbles": ch["bubbles"]}
        if gtype == "puzzle_slider":
            return {"targetPercent": ch["targetPercent"]}
        return ch

    def public_stage(sid: str, st: dict) -> dict:
        return {
            "sessionId": sid,
            "currentStageIndex": st["stageIndex"],
            "totalStages": st["totalStages"],
            "gameType": st["gameType"],
            "gameName": st["gameName"],
            "challenge": public_challenge(st["gameType"], st["challenge"]),
        }

    def build_stage_challenge(gtype: str, diff: int):
        if gtype == "orbital_lock":
            return "Orbital Timing Lock", {"rings": 3, "targets": [secrets.randbelow(320) + 20 for _ in range(3)], "toleranceDeg": max(8, 20 - diff * 3)}
        if gtype == "chroma_slider":
            th = secrets.randbelow(330) + 15
            tol = max(12, 26 - diff * 4)
            return "Chroma Spectrum Match", {"targetHue": th, "tolerance": tol, "colorSample": f"hsl({th}, 85%, 55%)"}
        if gtype == "glyph_outlier":
            pairs = [
                ("🛡️", "⚔️"), ("🔑", "🗝️"), ("🔒", "🔓"),
                ("⚡", "🔥"), ("🪙", "💎"), ("⭐", "🌙")
            ]
            common, outlier = pairs[secrets.randbelow(len(pairs))]
            tot = 8 if diff > 1 else 6
            out_idx = secrets.randbelow(tot)
            items = [{"id": i, "icon": outlier if i == out_idx else common} for i in range(tot)]
            return "Spot the Outlier", {"totalItems": tot, "items": items, "outlierIndex": out_idx}
        if gtype == "bubble_sequence":
            cnt = min(4 + diff, 6)
            s_set = set()
            while len(s_set) < cnt:
                s_set.add(secrets.randbelow(98) + 1)
            sorted_nums = sorted(list(s_set))
            shuffled = list(sorted_nums)
            for i in range(len(shuffled) - 1, 0, -1):  # CSPRNG Fisher-Yates
                j = secrets.randbelow(i + 1)
                shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
            return "Ascending Number Tap", {"count": cnt, "bubbles": [{"id": i, "value": v} for i, v in enumerate(shuffled)], "correctSequence": sorted_nums}
        if gtype == "puzzle_slider":
            tp = secrets.randbelow(60) + 28
            tol = max(4, 8 - diff)
            return "Slide to Snap", {"targetPercent": tp, "tolerance": tol}
        seq_len = min(3 + diff, 8)
        return "Cyber Matrix Pattern Shield", {"gridSize": 16, "sequence": [secrets.randbelow(16) for _ in range(seq_len)], "seqLength": seq_len}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def _send_json(self, code: int, obj: dict):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
            return json.loads(raw)

        def _check_host(self):
            # DNS-rebinding defence: only our own loopback origin is accepted.
            port = server_state["port"]
            allowed = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
            if str(self.headers.get("Host", "")).lower() not in allowed:
                raise PermissionError("Forbidden: Invalid Host header")
            origin = self.headers.get("Origin")
            if origin and origin not in {f"http://{h}" for h in allowed}:
                raise PermissionError("Forbidden: Cross-origin request rejected")

        def _check_csrf(self):
            self._check_host()
            tok = self.headers.get("X-SeedVault-Token", "")
            if not hmac.compare_digest(tok, csrf_token):
                raise ValueError("Invalid session token (กรุณารีเฟรชหน้าจอ)")

        def do_GET(self):
            try:
                self._check_host()
            except PermissionError as e:
                return self._send_json(403, {"ok": False, "error": str(e)})
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                with open(os.path.join(UI_DIR, "index.html"), "r", encoding="utf-8") as f:
                    html = f.read().replace(
                        "</head>", f'  <meta name="seedvault-token" content="{csrf_token}" />\n</head>'
                    )
                data = html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
                return
            if path in ("/styles.css", "/app.js"):
                ctype = "text/css" if path.endswith(".css") else "application/javascript"
                with open(os.path.join(UI_DIR, path.lstrip("/")), "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", f"{ctype}; charset=utf-8")
                self.end_headers()
                self.wfile.write(data)
                return
            if path == "/api/status":
                try:
                    return self._send_json(200, storage.get_public_status())
                except Exception as e:
                    return self._send_json(400, {"ok": False, "error": str(e)})
            self._send_json(404, {"ok": False, "error": "Not Found"})

        def do_POST(self):
            path = urlparse(self.path).path
            try:
                self._check_csrf()
                body = self._read_json()
                if path == "/api/setup":
                    st = storage.initialize_new_vault(body)
                    return self._send_json(200, {"ok": True, "status": st})
                if path == "/api/unlock":
                    st = storage.get_public_status()
                    if st.get("initialized") and st.get("gameModule", {}).get("enabled"):
                        # Single-use: the token is burned by every attempt, right or wrong.
                        if not consume_pass_token(body.get("gamePassToken")):
                            return self._send_json(403, {"success": False, "needGame": True, "error": "กรุณาเล่นด่านเกมส์ป้องกันบอทให้ผ่านครบทุกด่านก่อนกรอกรหัสผ่าน (ผ่านเกมได้ 1 ครั้งต่อการกรอกรหัส 1 ครั้ง)"})
                    return self._send_json(200, storage.unlock_vault(body))
                if path == "/api/vault/import":
                    b64 = body.get("fileBase64")
                    if not isinstance(b64, str) or not b64:
                        return self._send_json(400, {"ok": False, "error": "ไม่พบไฟล์ seedvault.dat ที่จะนำเข้า"})
                    import base64
                    status = storage.import_vault_file(base64.b64decode(b64), bool(body.get("replaceExisting") is True))
                    return self._send_json(200, {"ok": True, "status": status})
                if path == "/api/vault/export":
                    import base64
                    data_bytes = storage.export_vault_file()
                    return self._send_json(200, {"ok": True, "filename": "seedvault.dat", "fileBase64": base64.b64encode(data_bytes).decode("ascii")})
                if path == "/api/reset":
                    if body.get("confirmToken") != "RESET":
                        return self._send_json(400, {"ok": False, "error": "กรุณายืนยันด้วยคำว่า RESET"})
                    res = storage.secure_wipe_and_reset("User confirmed double-step reset")
                    return self._send_json(200, {"ok": True, **res})
                if path == "/api/game/start":
                    if gate_throttled():
                        return self._send_json(429, {"ok": False, "error": "ลองผิดบ่อยเกินไป กรุณารอสักครู่แล้วลองใหม่"})
                    gate_purge()
                    sid = str(uuid.uuid4())
                    primary = body.get("gameType") or "pattern_shield"
                    diff = int(body.get("difficulty") or 1)
                    count = min(max(1, int(body.get("requiredGamesCount") or 1)), 5)
                    avail = ["pattern_shield", "orbital_lock", "chroma_slider", "glyph_outlier", "bubble_sequence", "puzzle_slider"]
                    chain = [primary] + [avail[i % len(avail)] for i in range(1, count)]
                    stages = []
                    for idx, gt in enumerate(chain):
                        gn, ch = build_stage_challenge(gt, diff)
                        stages.append({"stageIndex": idx, "totalStages": len(chain), "gameType": gt, "gameName": gn, "challenge": ch, "issuedAt": time.time() if idx == 0 else 0.0})
                    game_sessions[sid] = {"currentStageIndex": 0, "stages": stages, "wrong": 0, "createdAt": time.time()}
                    return self._send_json(200, {"ok": True, "session": public_stage(sid, stages[0])})
                if path == "/api/game/verify":
                    if gate_throttled():
                        return self._send_json(429, {"ok": True, "verified": False, "throttled": True, "error": "ลองผิดบ่อยเกินไป กรุณารอสักครู่แล้วลองใหม่"})
                    gate_purge()
                    sid = body.get("sessionId")
                    sess = game_sessions.get(sid)
                    if not sess:
                        return self._send_json(200, {"ok": True, "verified": False, "sessionExpired": True, "error": "เซสชันหมดอายุ"})
                    idx = sess["currentStageIndex"]
                    st_obj = sess["stages"][idx]
                    sub = body.get("submission")
                    ch = st_obj["challenge"]
                    gt = st_obj["gameType"]

                    def fail_stage(reason: str):
                        sess["wrong"] += 1
                        gate_record_failure()
                        out = {"ok": True, "verified": False, "stageCleared": False, "error": reason}
                        if sess["wrong"] >= GATE_MAX_WRONG:
                            game_sessions.pop(sid, None)
                            out["sessionExpired"] = True
                            out["error"] = f"{reason} (ตอบผิดครบ {GATE_MAX_WRONG} ครั้ง ระบบสุ่มโจทย์ใหม่ให้)"
                        return self._send_json(200, out)

                    # Human-speed floor
                    if time.time() - (st_obj.get("issuedAt") or sess["createdAt"]) < GATE_MIN_SOLVE_S:
                        return fail_stage("ตอบเร็วผิดปกติ กรุณาเล่นด้วยตนเอง")
                    ok = False
                    try:
                        if gt == "pattern_shield":
                            ok = isinstance(sub, list) and [int(x) for x in sub] == ch["sequence"]
                        elif gt == "orbital_lock":
                            ok = isinstance(sub, list) and len(sub) == len(ch["targets"]) and all(
                                min(abs(int(sub[i]) - ch["targets"][i]) % 360, 360 - (abs(int(sub[i]) - ch["targets"][i]) % 360)) <= ch["toleranceDeg"]
                                for i in range(len(ch["targets"]))
                            )
                        elif gt == "chroma_slider":
                            val = float(sub)
                            hue_diff = abs(val - ch["targetHue"]) % 360
                            shortest = 360 - hue_diff if hue_diff > 180 else hue_diff
                            ok = shortest <= ch["tolerance"]
                        elif gt == "glyph_outlier":
                            ok = int(sub) == int(ch["outlierIndex"])
                        elif gt == "bubble_sequence":
                            ok = isinstance(sub, list) and [int(x) for x in sub] == ch["correctSequence"]
                        elif gt == "puzzle_slider":
                            ok = abs(float(sub) - ch["targetPercent"]) <= ch["tolerance"]
                    except Exception:
                        ok = False
                    if not ok:
                        return fail_stage("ยังไม่ผ่านด่านนี้")
                    sess["currentStageIndex"] += 1
                    if sess["currentStageIndex"] < len(sess["stages"]):
                        nxt = sess["stages"][sess["currentStageIndex"]]
                        nxt["issuedAt"] = time.time()
                        return self._send_json(200, {"ok": True, "verified": False, "stageCleared": True, "nextStage": public_stage(sid, nxt)})
                    tok = secrets.token_hex(32)
                    valid_pass_tokens[tok] = time.time() + 300
                    game_sessions.pop(sid, None)
                    return self._send_json(200, {"ok": True, "verified": True, "stageCleared": True, "allCompleted": True, "totalStages": len(sess["stages"]), "gamePassToken": tok})
                if path == "/api/btc/derive":
                    w = py_derive_wallet(
                        body.get("words") or [],
                        body.get("passphrase25") or "",
                        body.get("derivationPath") or "m/84'/0'/0'/0/0",
                        body.get("scriptType") or "NATIVE_SEGWIT",
                    )
                    return self._send_json(200, {"ok": True, "wallet": {k: v for k, v in w.items() if k not in ("privateKey", "tweakedPrivateKey", "pubKeyHash")}})
                if path == "/api/btc/hw-derive":
                    w = py_derive_from_hw_pubkey(body)
                    return self._send_json(200, {"ok": True, "wallet": w})
                if path == "/api/btc/sign":
                    tx_res = py_sign_btc_tx(body)
                    return self._send_json(200, {"ok": True, "txResult": tx_res})
                if path == "/api/btc/parse-rawtx":
                    parsed = py_parse_raw_btc_tx(body.get("rawTxHex") or "")
                    return self._send_json(200, {"ok": True, "parsedTx": parsed})
                if path == "/api/btc/assemble-signed-tx":
                    tx_res = py_assemble_signed_btc_tx(body)
                    return self._send_json(200, {"ok": True, "txResult": tx_res})
                return self._send_json(404, {"ok": False, "error": "Not Found"})
            except Exception as e:
                return self._send_json(400, {"ok": False, "error": str(e)})

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    server_state["port"] = port
    url = f"http://127.0.0.1:{port}"

    # Convenience for existing users: if this device has no vault yet but a seedvault.dat sits next to
    # the app (e.g. run straight from the Flash Drive), COPY it into the local data directory.
    legacy_file = os.path.join(BASE_DIR, "seedvault.dat")
    if (
        not os.path.exists(storage.vault_path)
        and os.path.exists(legacy_file)
        and os.path.abspath(BASE_DIR) != os.path.abspath(data_dir)
    ):
        try:
            with open(legacy_file, "rb") as lf:
                storage.import_vault_file(lf.read())
            print(f" 📥 นำเข้า seedvault.dat จาก {legacy_file} ลงเครื่องนี้แล้ว (ไฟล์ต้นฉบับไม่ถูกแก้ไข)")
        except Exception as e:
            print(f" ⚠️ ไม่ได้นำเข้า seedvault.dat เดิม: {e}")

    print("==============================================================")
    print(" 🔐 SeedVault Zero-Knowledge Vault & Bitcoin Signer (Tails OS)")
    print(f" 🌐 เปิดใช้งานที่: {url}")
    print(f" 💾 ข้อมูล Vault เก็บบนเครื่องนี้ที่: {data_dir}")
    if is_likely_removable_path(BASE_DIR):
        print(' 💡 โปรแกรมรันจาก Flash Drive แต่ข้อมูลจะถูกเก็บบนเครื่องนี้ ใช้ปุ่ม "ส่งออก" เพื่อนำไฟล์ล่าสุดกลับไปเก็บบน Flash Drive')
    print(" 🛑 กด Ctrl+C เพื่อปิดโปรแกรมเมื่อใช้งานเสร็จ")
    print("==============================================================")
    if os.environ.get("SEEDVAULT_NO_BROWSER") != "1":
        for browser_cmd in (["xdg-open", url], ["tor-browser", url], ["firefox", url], ["open", url]):
            try:
                subprocess.Popen(browser_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                break
            except Exception:
                continue
    server.serve_forever()


if __name__ == "__main__":
    try_delegate_to_node()
    run_standalone_python_server()
