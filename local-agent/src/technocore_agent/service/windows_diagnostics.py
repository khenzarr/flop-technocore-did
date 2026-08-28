"""Small native probes used by the PowerShell proof harness.

No mutating SCM call exists here.  Non-Windows callers receive a clear error.
"""

from __future__ import annotations

import ctypes
import json
import subprocess
import sys
from ctypes import wintypes
from dataclasses import asdict, dataclass

SERVICE_CHANGE_CONFIG = 0x0002
SERVICE_START = 0x0010
SERVICE_STOP = 0x0020
PROCESS_TERMINATE = 0x0001
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
DELETE = 0x00010000
SC_MANAGER_CONNECT = 0x0001
TOKEN_QUERY = 0x0008
TOKEN_USER = 1
TOKEN_GROUPS = 2
TOKEN_INTEGRITY_LEVEL = 25
SE_GROUP_INTEGRITY = 0x20


@dataclass(frozen=True)
class ScmAccessProbe:
    requested_access: int
    success: bool
    error_code: int
    classification: str = "OTHER_ERROR"

    def as_dict(self) -> dict[str, int | bool | str]:
        return asdict(self)


def _classification(error_code: int) -> str:
    return {
        0: "UNEXPECTED_SUCCESS",
        5: "ACCESS_DENIED",
        1060: "SERVICE_NOT_FOUND",
        1722: "SCM_UNAVAILABLE",
    }.get(error_code, "OTHER_ERROR")


SCM_SECURITY_RIGHTS = {
    "SERVICE_CHANGE_CONFIG": SERVICE_CHANGE_CONFIG,
    "WRITE_DAC": WRITE_DAC,
    "WRITE_OWNER": WRITE_OWNER,
    "DELETE": DELETE,
    "SERVICE_START": SERVICE_START,
    "SERVICE_STOP": SERVICE_STOP,
}


def probe_service_access(service_name: str, requested_access: int) -> ScmAccessProbe:
    if sys.platform != "win32":
        raise OSError("Windows SCM is unavailable on this platform")
    advapi = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    advapi.OpenSCManagerW.restype = ctypes.c_void_p
    advapi.OpenSCManagerW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    advapi.OpenServiceW.restype = ctypes.c_void_p
    advapi.OpenServiceW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
    advapi.CloseServiceHandle.argtypes = [ctypes.c_void_p]
    scm = advapi.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not scm:
        error = ctypes.get_last_error()
        return ScmAccessProbe(requested_access, False, error, _classification(error))
    try:
        service = advapi.OpenServiceW(scm, service_name, requested_access)
        error = 0 if service else ctypes.get_last_error()
        if service:
            advapi.CloseServiceHandle(service)
        return ScmAccessProbe(requested_access, bool(service), error, _classification(error))
    finally:
        advapi.CloseServiceHandle(scm)


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class _TokenUser(ctypes.Structure):
    _fields_ = [("User", _SidAndAttributes)]


class _TokenGroupsOne(ctypes.Structure):
    _fields_ = [("GroupCount", wintypes.DWORD), ("Groups", _SidAndAttributes * 1)]


def _token_groups(buffer: ctypes.Array) -> list[_SidAndAttributes]:
    """Parse TOKEN_GROUPS using ctypes' native alignment (including x64)."""
    header = ctypes.cast(buffer, ctypes.POINTER(_TokenGroupsOne)).contents
    count = int(header.GroupCount)
    offset = _TokenGroupsOne.Groups.offset
    return list((_SidAndAttributes * count).from_buffer(buffer, offset))


class _TokenMandatoryLabel(ctypes.Structure):
    _fields_ = [("Label", _SidAndAttributes)]


def _sid_string(advapi, kernel32, sid: ctypes.c_void_p) -> str:
    value = wintypes.LPWSTR()
    if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(value)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if value.value is None:
            raise OSError("ConvertSidToStringSidW returned an empty SID")
        return value.value
    finally:
        kernel32.LocalFree(value)


def _token_information(advapi, token, information_class: int) -> ctypes.Array:
    required = wintypes.DWORD()
    advapi.GetTokenInformation(token, information_class, None, 0, ctypes.byref(required))
    error = ctypes.get_last_error()
    if error != 122:  # ERROR_INSUFFICIENT_BUFFER
        raise ctypes.WinError(error)
    buffer = ctypes.create_string_buffer(required.value)
    if not advapi.GetTokenInformation(
        token, information_class, buffer, required, ctypes.byref(required)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer


def current_process_token_evidence(expected_service_sid: str) -> dict[str, object]:
    """Return actual current-process token evidence for the trusted service."""
    if sys.platform != "win32":
        raise OSError("Windows access-token diagnostics are unavailable on this platform")
    advapi = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.LookupAccountSidW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_wchar_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.LookupAccountSidW.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        user_buffer = _token_information(advapi, token, TOKEN_USER)
        user = ctypes.cast(user_buffer, ctypes.POINTER(_TokenUser)).contents.User
        account_sid = _sid_string(advapi, kernel32, user.Sid)

        name_size, domain_size, sid_type = wintypes.DWORD(), wintypes.DWORD(), wintypes.DWORD()
        advapi.LookupAccountSidW(
            None,
            user.Sid,
            None,
            ctypes.byref(name_size),
            None,
            ctypes.byref(domain_size),
            ctypes.byref(sid_type),
        )
        name = ctypes.create_unicode_buffer(name_size.value)
        domain = ctypes.create_unicode_buffer(domain_size.value)
        if not advapi.LookupAccountSidW(
            None,
            user.Sid,
            name,
            ctypes.byref(name_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(sid_type),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        group_buffer = _token_information(advapi, token, TOKEN_GROUPS)
        group_sids = {
            _sid_string(advapi, kernel32, group.Sid) for group in _token_groups(group_buffer)
        }

        integrity_buffer = _token_information(advapi, token, TOKEN_INTEGRITY_LEVEL)
        integrity = ctypes.cast(
            integrity_buffer, ctypes.POINTER(_TokenMandatoryLabel)
        ).contents.Label
        integrity_sid = _sid_string(advapi, kernel32, integrity.Sid)
        return {
            "account_name": f"{domain.value}\\{name.value}" if domain.value else name.value,
            "account_sid": account_sid,
            "expected_service_sid": expected_service_sid,
            "service_sid_present": expected_service_sid in group_sids,
            "integrity_level": integrity_sid,
        }
    finally:
        kernel32.CloseHandle(token)


def probe_process_terminate(pid: int) -> ScmAccessProbe:
    """Non-destructively ask whether this token can open the service for termination."""
    if sys.platform != "win32":
        raise OSError("Windows process diagnostics are unavailable on this platform")
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    process = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    error = 0 if process else ctypes.get_last_error()
    if process:
        kernel32.CloseHandle(process)
    return ScmAccessProbe(PROCESS_TERMINATE, bool(process), error, _classification(error))


def query_path_effective_rights(path: str, principal_sids: set[str]) -> dict[str, object]:
    """Read a path DACL and evaluate only the Stage2D protected rights."""
    if sys.platform != "win32":
        raise OSError("Windows ACL diagnostics are unavailable on this platform")
    from .acl import AccessAce, assert_normal_user_denied

    # Get-Acl exposes the native SECURITY_DESCRIPTOR/ACL, including explicit
    # and inherited FileSystemAccessRule entries, without adding pywin32 to
    # the runtime closure.
    script = r"""
param([string]$Path)
$acl=Get-Acl -LiteralPath $Path
[pscustomobject]@{
  dacl_protected=$acl.AreAccessRulesProtected
  aces=@($acl.Access | ForEach-Object {
    $sid=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    [pscustomobject]@{sid=$sid;mask=[int]$_.FileSystemRights;allow=($_.AccessControlType -eq 'Allow');inherited=$_.IsInherited}
  })
} | ConvertTo-Json -Compress -Depth 5
"""
    completed = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script, path],
        capture_output=True,
        text=True,
        check=True,
    )
    native = json.loads(completed.stdout)
    aces = [
        AccessAce(
            str(ace["sid"]),
            int(ace["mask"]),
            bool(ace["allow"]),
            bool(ace["inherited"]),
        )
        for ace in (native.get("aces") or [])
    ]
    return {
        "path": path,
        "dacl_protected": bool(native["dacl_protected"]),
        "rights": assert_normal_user_denied(aces, principal_sids),
        "ace_count": len(aces),
    }
