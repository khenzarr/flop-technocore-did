from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path


class DPAPIError(ValueError):
    pass


def _api():
    if sys.platform != "win32":
        raise DPAPIError("Windows DPAPI is unavailable on this platform")
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_Blob),
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_Blob),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_Blob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_Blob),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    return crypt32, kernel32


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def protect(data: bytes, description: str = "technocore-agent test key") -> bytes:
    if not isinstance(data, bytes) or not data:
        raise DPAPIError("data must be non-empty bytes")
    crypt32, kernel32 = _api()
    source = ctypes.create_string_buffer(data)
    inp = _Blob(len(data), ctypes.cast(source, ctypes.POINTER(ctypes.c_ubyte)))
    out = _Blob()
    if not crypt32.CryptProtectData(
        ctypes.byref(inp), description, None, None, None, 0, ctypes.byref(out)
    ):
        raise DPAPIError("DPAPI protection failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def unprotect(blob: bytes) -> bytes:
    if not isinstance(blob, bytes) or not blob:
        raise DPAPIError("protected data is invalid")
    crypt32, kernel32 = _api()
    source = ctypes.create_string_buffer(blob)
    inp = _Blob(len(blob), ctypes.cast(source, ctypes.POINTER(ctypes.c_ubyte)))
    out = _Blob()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)
    ):
        raise DPAPIError("DPAPI unprotection failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def save(path: Path, key: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(protect(key))
    os.chmod(path, 0o600)


def load(path: Path) -> bytes:
    try:
        return unprotect(Path(path).read_bytes())
    except FileNotFoundError as exc:
        raise DPAPIError("protected key file is missing") from exc
    except OSError as exc:
        raise DPAPIError("protected key file cannot be read") from exc
