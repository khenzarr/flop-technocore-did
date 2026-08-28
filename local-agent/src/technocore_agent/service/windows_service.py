from __future__ import annotations

import argparse
import ctypes
import threading
from ctypes import wintypes
from pathlib import Path

from ..control.web import create_server
from ..ipc.draft_server import DraftIPCServer
from ..policy.transport import RecordingTransport, TechnocoreTransport
from .proof import ProofIPCServer
from .runtime import DPAPIKeyProvider, TrustedPaths, TrustedRuntime

SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_START_PENDING = 0x2
SERVICE_STOP_PENDING = 0x3
SERVICE_RUNNING = 0x4
SERVICE_STOPPED = 0x1
SERVICE_ACCEPT_STOP = 0x1
SERVICE_CONTROL_STOP = 0x1


class ServiceStatus(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


class ServiceTableEntry(ctypes.Structure):
    _fields_ = [("name", wintypes.LPWSTR), ("procedure", ctypes.c_void_p)]


def _serve(
    state: Path,
    draft_port: int,
    dashboard_port: int,
    stop: threading.Event,
    proof_port: int = 0,
    transport_mode: str = "offline",
) -> None:
    paths = TrustedPaths.under(state)
    if not paths.operator.is_file():
        raise RuntimeError("operator credential is not initialized")
    runtime = TrustedRuntime(
        paths,
        DPAPIKeyProvider(paths.protected_key),
        transport=TechnocoreTransport() if transport_mode == "live" else RecordingTransport([]),
    )
    draft = DraftIPCServer(runtime.handle_agent_request, draft_port)
    dashboard = create_server(runtime.control, dashboard_port)
    proof = ProofIPCServer(runtime, proof_port) if proof_port else None
    threads = [
        threading.Thread(target=draft.serve_forever, daemon=True),
        threading.Thread(target=dashboard.serve_forever, daemon=True),
    ]
    if proof:
        threads.append(threading.Thread(target=proof.serve_forever, daemon=True))
    for thread in threads:
        thread.start()
    stop.wait()
    draft.shutdown()
    dashboard.shutdown()
    if proof:
        proof.shutdown()
    draft.server_close()
    dashboard.server_close()
    if proof:
        proof.server_close()
    for thread in threads:
        thread.join(timeout=10)


def run_service(
    name: str,
    state: Path,
    draft_port: int,
    dashboard_port: int,
    proof_port: int = 0,
    transport_mode: str = "offline",
) -> None:
    if not hasattr(ctypes, "WinDLL"):
        raise RuntimeError("Windows Service Control Manager is required")
    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    stop = threading.Event()
    handler_type = ctypes.WINFUNCTYPE(None, wintypes.DWORD)
    main_type = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
    advapi32.RegisterServiceCtrlHandlerW.argtypes = [wintypes.LPCWSTR, handler_type]
    advapi32.RegisterServiceCtrlHandlerW.restype = wintypes.HANDLE
    advapi32.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(ServiceStatus)]
    advapi32.SetServiceStatus.restype = wintypes.BOOL
    advapi32.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(ServiceTableEntry)]
    advapi32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
    status = ServiceStatus(SERVICE_WIN32_OWN_PROCESS, SERVICE_START_PENDING, 0, 0, 0, 0, 30000)
    handle = wintypes.HANDLE()

    def publish(current: int, accepted: int = 0, exit_code: int = 0) -> None:
        status.dwCurrentState = current
        status.dwControlsAccepted = accepted
        status.dwWin32ExitCode = exit_code
        if handle and not advapi32.SetServiceStatus(handle, ctypes.byref(status)):
            raise ctypes.WinError(ctypes.get_last_error())

    @handler_type
    def control(code: int) -> None:
        if code == SERVICE_CONTROL_STOP:
            publish(SERVICE_STOP_PENDING)
            stop.set()

    @main_type
    def service_main(_argc, _argv) -> None:
        nonlocal handle
        handle = advapi32.RegisterServiceCtrlHandlerW(name, control)
        if not handle:
            return
        try:
            publish(SERVICE_RUNNING, SERVICE_ACCEPT_STOP)
            _serve(state, draft_port, dashboard_port, stop, proof_port, transport_mode)
            publish(SERVICE_STOPPED)
        except Exception:
            publish(SERVICE_STOPPED, exit_code=1)

    table = (ServiceTableEntry * 2)(
        ServiceTableEntry(name, ctypes.cast(service_main, ctypes.c_void_p)),
        ServiceTableEntry(None, None),
    )
    if not advapi32.StartServiceCtrlDispatcherW(table):
        raise ctypes.WinError(ctypes.get_last_error())


def main() -> None:
    parser = argparse.ArgumentParser(description="Stage 2D Windows SCM service host")
    parser.add_argument("--name", default="TechnocoreAgentStage2DTest")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--draft-port", type=int, default=47831)
    parser.add_argument("--dashboard-port", type=int, default=47832)
    parser.add_argument("--proof-port", type=int, default=47833)
    parser.add_argument("--transport", choices=("offline", "live"), default="offline")
    args = parser.parse_args()
    run_service(
        args.name,
        args.state,
        args.draft_port,
        args.dashboard_port,
        args.proof_port,
        args.transport,
    )


if __name__ == "__main__":
    main()
