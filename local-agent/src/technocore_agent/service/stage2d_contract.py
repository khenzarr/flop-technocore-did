"""Pure, non-privileged validators shared by Stage 2D build/proof scripts."""

from __future__ import annotations

import re
from pathlib import Path

PROOF_SCHEMA = "stage2d-native-proof-v2"
REQUIRED_PHASE_GATES = {
    "Preflight": {"Preflight"},
    "AdminEvidence": {
        "SCM exact configuration",
        "SCM SID and descriptor",
        "Admin ACL structure",
    },
    "NormalUserEvidence": {
        "Normal-user effective/write denial",
        "SCM individual access denials",
        "PROCESS_TERMINATE denial",
    },
    "ServiceIdentityEvidence": {"Service token proof", "Port ownership"},
    "ApplicationFlowEvidence": {"Application flow"},
    "AdminDpapiCopy": {"DPAPI copy"},
    "NormalUserDpapi": {"DPAPI cross-identity denial"},
    "AdminDpapiCleanup": {"DPAPI cleanup"},
    "AdminStart": {"Bounded exact-service start"},
    "AdminRestart": {"Bounded exact-service restart"},
    "NormalReplay": {"Exact request replay"},
    "ConcurrencyEvidence": {"Multiprocess concurrency"},
    "NetworkEvidence": {"Network evidence"},
    "SecretScanEvidence": {"Secret sentinel"},
}
REQUIRED_RUNTIME = {
    "technocore-agent-local": "0.1.0",
    "cryptography": "50.0.0",
    "cffi": "2.1.1",
    "pycparser": "3.0",
}
REQUIRED_EVIDENCE_FIELDS = (
    "schema",
    "phase",
    "proof_run_id",
    "installation_id",
    "service_name",
    "install_root",
    "state_root",
    "timestamp",
    "gates",
)
PASS_STATUSES = frozenset({"PASS"})


def wheel_tag_compatible(python_tag: str, abi_tag: str, platform_tag: str) -> bool:
    if (python_tag, abi_tag, platform_tag) == ("py3", "none", "any"):
        return True
    if (python_tag, abi_tag, platform_tag) == ("cp312", "cp312", "win_amd64"):
        return True
    match = re.fullmatch(r"cp3(\d+)", python_tag)
    return bool(
        match and abi_tag == "abi3" and platform_tag == "win_amd64" and int(match.group(1)) <= 12
    )


def validate_locked_runtime(lock_text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for block in re.split(r"(?=\[\[package\]\])", lock_text):
        name = re.search(r'^name = "([^"]+)"', block, re.MULTILINE)
        version = re.search(r'^version = "([^"]+)"', block, re.MULTILINE)
        if name and version and name.group(1) in REQUIRED_RUNTIME:
            found[name.group(1)] = version.group(1)
    if found != REQUIRED_RUNTIME:
        raise ValueError(f"locked runtime mismatch: expected {REQUIRED_RUNTIME}, got {found}")
    return found


def validate_evidence(documents: dict[str, dict]) -> list[str]:
    errors: list[str] = []
    unexpected_phases = sorted(set(documents).difference(REQUIRED_PHASE_GATES))
    errors.extend(f"extra phase: {phase}" for phase in unexpected_phases)
    baseline = None
    identity_fields = (
        "proof_run_id",
        "installation_id",
        "service_name",
        "install_root",
        "state_root",
    )
    for phase, required_gates in REQUIRED_PHASE_GATES.items():
        document = documents.get(phase)
        if not isinstance(document, dict):
            errors.append(f"missing phase: {phase}")
            continue
        missing_fields = [field for field in REQUIRED_EVIDENCE_FIELDS if field not in document]
        if missing_fields:
            errors.append(f"missing evidence fields {phase}: {', '.join(missing_fields)}")
        if document.get("schema") != PROOF_SCHEMA or document.get("phase") != phase:
            errors.append(f"invalid schema/phase: {phase}")
        identity = tuple(document.get(field) for field in identity_fields)
        if any(not value for value in identity):
            errors.append(f"missing run identity: {phase}")
        elif baseline is None:
            baseline = identity
        elif identity != baseline:
            errors.append(f"run identity mismatch: {phase}")
        gates = document.get("gates")
        if not isinstance(gates, list):
            errors.append(f"missing gates: {phase}")
            continue
        names = [gate.get("gate") for gate in gates if isinstance(gate, dict)]
        expected_names = set(required_gates)
        if set(names) != expected_names:
            missing = sorted(expected_names.difference(names))
            extra = sorted(set(names).difference(expected_names))
            errors.append(f"gate set mismatch {phase}: missing={missing!r}, extra={extra!r}")
        if any(
            not isinstance(gate, dict) or gate.get("status") not in PASS_STATUSES for gate in gates
        ):
            errors.append(f"invalid gate result class: {phase}")
        for gate_name in required_gates:
            matches = [gate for gate in gates if gate.get("gate") == gate_name]
            if len(matches) != 1:
                errors.append(f"gate cardinality {phase}/{gate_name}: {len(matches)}")
            elif matches[0].get("status") not in PASS_STATUSES:
                errors.append(f"gate not PASS: {phase}/{gate_name}")
        if len(names) != len(set(names)):
            errors.append(f"duplicate gate: {phase}")
    return errors


def validate_evidence_directory(path: Path) -> list[str]:
    import json

    documents = {}
    for phase in REQUIRED_PHASE_GATES:
        file = Path(path) / f"{phase.lower()}-evidence.json"
        if file.is_file():
            try:
                documents[phase] = json.loads(file.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError) as exc:
                documents[phase] = {"parse_error": str(exc)}
    return validate_evidence(documents)
