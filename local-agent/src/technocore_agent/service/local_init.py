"""One-command, per-user Windows initialization for the local DID signer."""

from __future__ import annotations

import argparse
import ctypes
import getpass
import json
import os
import stat
import subprocess
from ctypes import wintypes
from pathlib import Path

from ..control.operator import OperatorAuth, OperatorAuthError
from ..signer.service import canonical_did
from .runtime import DPAPIKeyProvider

TOKEN_QUERY = 0x0008
TOKEN_USER = 1
LOCAL_MARKER_SCHEMA = "technocore-local-install-v1"


def default_local_state() -> Path:
    value = os.environ.get("LOCALAPPDATA")
    if not value:
        raise RuntimeError("LOCALAPPDATA is unavailable")
    return Path(value).resolve() / "TechnocoreAgent"


def _is_reparse(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _current_user_sid() -> str:
    if os.name != "nt":
        raise RuntimeError("Windows is required")
    advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    handle = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(handle)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = wintypes.DWORD()
        advapi32.GetTokenInformation(handle, TOKEN_USER, None, 0, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        if not advapi32.GetTokenInformation(
            handle, TOKEN_USER, buffer, size, ctypes.byref(size)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
        string_sid = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(
            ctypes.c_void_p(sid_pointer), ctypes.byref(string_sid)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return string_sid.value
        finally:
            kernel32.LocalFree(string_sid)
    finally:
        kernel32.CloseHandle(handle)


def _apply_private_acl(root: Path) -> None:
    sid = _current_user_sid()
    completed = subprocess.run(
        [
            str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "icacls.exe"),
            str(root),
            "/inheritance:r",
            "/grant:r",
            f"*{sid}:(OI)(CI)F",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0:
        raise PermissionError("failed to apply the private local-state ACL")


def _assert_regular_or_absent(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if not path.is_file() or _is_reparse(path):
        raise OperatorAuthError(f"trusted local-state file is invalid: {path.name}")


def initialize_local_identity(
    state_root: Path,
    *,
    passphrase_provider=getpass.getpass,
    acl_applier=_apply_private_acl,
    key_provider_factory=DPAPIKeyProvider,
) -> str:
    state_root = Path(state_root).resolve()
    state_root.mkdir(parents=True, exist_ok=True)
    if not state_root.is_dir() or _is_reparse(state_root):
        raise OperatorAuthError("local state root must be a regular non-reparse directory")
    operator_path = state_root / "operator.json"
    key_path = state_root / "identity.dpapi"
    marker_path = state_root / "local-install.json"
    for path in (operator_path, key_path, marker_path):
        _assert_regular_or_absent(path)
    if not marker_path.exists():
        allowed_partial = {"operator.json", "identity.dpapi"}
        unexpected = {item.name for item in state_root.iterdir()} - allowed_partial
        if unexpected:
            raise OperatorAuthError("unrecognized files exist before local initialization")
    acl_applier(state_root)
    auth = OperatorAuth(operator_path)
    if not auth.configured():
        first = passphrase_provider("Operator passphrase (20+ characters): ")
        second = passphrase_provider("Confirm operator passphrase: ")
        if first != second:
            raise OperatorAuthError("operator passphrases do not match")
        auth.enroll(first)
    key = key_provider_factory(key_path).load_or_create()
    did = canonical_did(key)
    marker = {"schema": LOCAL_MARKER_SCHEMA, "public_did": did}
    if marker_path.exists():
        try:
            existing = json.loads(marker_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise OperatorAuthError("local installation marker is invalid") from exc
        if existing != marker:
            raise OperatorAuthError("local installation marker does not match the DPAPI key")
    else:
        with marker_path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(marker, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
    acl_applier(state_root)
    return did


def main() -> None:
    parser = argparse.ArgumentParser(description="Initialize the Windows-local Technocore DID")
    parser.add_argument("--state", type=Path, default=default_local_state())
    args = parser.parse_args()
    expected = default_local_state()
    if args.state.resolve() != expected:
        parser.error(f"local state must be exactly {expected}")
    did = initialize_local_identity(expected)
    print(f"PUBLIC_DID {did}")
    print(f"STATE {expected}")
    print("PRIVATE_KEY Windows DPAPI protected; not exported")


if __name__ == "__main__":
    main()
