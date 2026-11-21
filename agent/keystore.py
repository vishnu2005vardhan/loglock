"""SakshyaLog 2.0 ⑥ key custody: where the agent's sealing key lives at rest.

KEY_CUSTODY=auto (default) | dpapi | pkcs11 | software

* dpapi    Windows Data Protection API: the key file can only be opened by this Windows
           account on this machine (OS key store; TPM-backed when Windows is set up that way).
* pkcs11   A hardware security module or TPM 2.0 through PKCS#11 (e.g. tpm2-pkcs11, SoftHSM,
           a cloud HSM). The key is wrapped by an AES key that never leaves the token.
           Needs: pip install python-pkcs11, and PKCS11_LIB, PKCS11_TOKEN, PKCS11_PIN.
* software File readable only by this user (demo fallback on Linux/Mac).

The plain SEAL_KEY0 value is used once, to provision; afterwards the sealed copy is used.
Whatever the store, the forward-secure ratchet still destroys each epoch key after use.
"""
import os
import sys

KEY_DIR = os.getenv("KEY_DIR", os.path.join("data", "keys"))


def _dpapi(data, protect):
    import ctypes
    import ctypes.wintypes as wt

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    fn.argtypes = [ctypes.POINTER(BLOB), ctypes.c_wchar_p if protect else ctypes.c_void_p, ctypes.POINTER(BLOB),
                   ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(BLOB)]
    fn.restype = wt.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    buf = ctypes.create_string_buffer(data, len(data))
    inb = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = BLOB()
    ok = fn(ctypes.byref(inb), "SakshyaLog sealing key" if protect else None, None, None, None, 0x1, ctypes.byref(out))
    if not ok:
        raise OSError("DPAPI call failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


def _pkcs11(data, protect):
    import pkcs11  # python-pkcs11
    from pkcs11 import KeyType, ObjectClass
    lib = pkcs11.lib(os.environ["PKCS11_LIB"])
    token = lib.get_token(token_label=os.getenv("PKCS11_TOKEN", "sakshyalog"))
    with token.open(user_pin=os.getenv("PKCS11_PIN", ""), rw=True) as s:
        try:
            k = s.get_key(object_class=ObjectClass.SECRET_KEY, key_type=KeyType.AES, label="sakshyalog-wrap")
        except pkcs11.NoSuchKey:
            k = s.generate_key(KeyType.AES, 256, label="sakshyalog-wrap", store=True)
        if protect:
            iv = s.generate_random(128)
            return iv + k.encrypt(data, mechanism_param=iv)
        return k.decrypt(data[16:], mechanism_param=data[:16])


MODES = {
    "dpapi": ("Windows DPAPI (OS key store, bound to this Windows account)", _dpapi),
    "pkcs11": ("Hardware security module / TPM via PKCS#11", _pkcs11),
}


def _pick():
    want = os.getenv("KEY_CUSTODY", "auto").lower()
    if want == "auto":
        if os.getenv("PKCS11_LIB"):
            return "pkcs11"
        return "dpapi" if sys.platform == "win32" else "software"
    return want


def load_key0(host, provision_hex):
    """Return (key0 bytes, custody info). Never raises: falls back to software storage."""
    os.makedirs(KEY_DIR, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in host)
    mode = _pick()
    provision = bytes.fromhex(provision_hex)
    info = {"mode": "software", "label": "Software key file (readable only by this user)", "hardware": False,
            "production": "Use KEY_CUSTODY=pkcs11 with a TPM 2.0 or HSM token"}
    if mode in MODES:
        label, fn = MODES[mode]
        path = os.path.join(KEY_DIR, f"{safe}.{mode}.sealed")
        try:
            key = fn(open(path, "rb").read(), False) if os.path.exists(path) else None
            if key != provision:  # first run, or the provisioned key was rotated: (re)seal it
                blob = fn(provision, True)
                if fn(blob, False) != provision:
                    raise OSError("seal self-test failed")
                with open(path, "wb") as f:
                    f.write(blob)
                key = provision
            return key, {"mode": mode, "label": label, "hardware": mode == "pkcs11", "sealed_file": path,
                         "production": info["production"]}
        except Exception as ex:
            info["note"] = f"{mode} unavailable ({str(ex)[:80]}), using software storage"
    path = os.path.join(KEY_DIR, f"{safe}.software.key")
    try:
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(provision_hex)
            os.chmod(path, 0o600)
        key = bytes.fromhex(open(path).read().strip())
    except Exception:
        key = provision
    return key, info
