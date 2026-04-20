import json
import base64
import copy
from typing import Any, Dict


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64_decode(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def save_sbox(container: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(container, f, indent=2)


def load_sbox(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def canonicalize_for_signature(container: Dict[str, Any]) -> bytes:
    container_copy = copy.deepcopy(container)

    container_copy.pop("signature", None)
    container_copy.pop("sig_alg", None)

    return json.dumps(
        container_copy,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")