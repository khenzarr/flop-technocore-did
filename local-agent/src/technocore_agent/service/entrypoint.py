from __future__ import annotations

import argparse
import threading
from pathlib import Path

from ..control.web import create_server
from ..ipc.draft_server import DraftIPCServer
from ..policy.transport import RecordingTransport, TechnocoreTransport
from .local_init import default_local_state
from .proof import ProofIPCServer
from .runtime import DPAPIKeyProvider, TrustedPaths, TrustedRuntime


def main() -> None:
    parser = argparse.ArgumentParser(description="Trusted local Technocore signer service")
    parser.add_argument("--state", type=Path, default=default_local_state())
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--dashboard-port", type=int, default=47832)
    parser.add_argument("--proof-port", type=int, default=0)
    parser.add_argument("--transport", choices=("offline", "live"), default="offline")
    args = parser.parse_args()
    paths = TrustedPaths.under(args.state)
    if not paths.operator.is_file():
        parser.error("operator credential is not initialized; run technocore-agent-operator-init")
    transport = TechnocoreTransport() if args.transport == "live" else RecordingTransport([])
    runtime = TrustedRuntime(
        paths,
        DPAPIKeyProvider(paths.protected_key),
        transport=transport,
    )
    server = DraftIPCServer(runtime.handle_agent_request, args.port)
    dashboard = create_server(runtime.control, args.dashboard_port)
    proof_server = ProofIPCServer(runtime, args.proof_port) if args.proof_port else None
    print(f"LISTENING {server.server_address[1]}", flush=True)
    print(f"DASHBOARD http://127.0.0.1:{dashboard.server_port}", flush=True)
    print(f"MODE {runtime.control.mode}", flush=True)
    print(f"PUBLIC_DID {runtime.public_did}", flush=True)
    threading.Thread(target=dashboard.serve_forever, daemon=True).start()
    if proof_server:
        print(f"PROOF_LISTENING {proof_server.server_address[1]}", flush=True)
        threading.Thread(target=proof_server.serve_forever, daemon=True).start()
    try:
        server.serve_forever()
    finally:
        server.server_close()
        dashboard.shutdown()
        dashboard.server_close()
        if proof_server:
            proof_server.shutdown()
            proof_server.server_close()


if __name__ == "__main__":
    main()
