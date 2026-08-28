from __future__ import annotations

import argparse
import json

from ..ipc.draft_server import request


def main() -> None:
    parser = argparse.ArgumentParser(description="TEST-ONLY draft-only client")
    parser.add_argument("operation", choices=("submit_draft", "get_own_draft_status"))
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--room")
    parser.add_argument("--text")
    args = parser.parse_args()
    if args.operation == "submit_draft" and (args.room is None or args.text is None):
        parser.error("submit_draft requires --room and --text")
    payload = {"operation": args.operation, "request_id": args.request_id}
    if args.operation == "submit_draft":
        payload.update(room=args.room, text=args.text)
    # JSON keeps independent native-proof client processes machine-readable.
    print(json.dumps(request(args.port, payload), sort_keys=True))
