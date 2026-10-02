from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from datetime import datetime
from decimal import Decimal
import hashlib
import json
from typing import Any


def canonical(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, Decimal):
        return {"__decimal__": format(value, "f")}
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return {"__float__": repr(value)}
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("datetime must be timezone-aware")
        return {"__datetime__": value.astimezone(timezone.utc).isoformat()}
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    if dataclasses.is_dataclass(value):
        value = dataclasses.asdict(value)
    if isinstance(value, Mapping):
        return {str(key): canonical(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple, frozenset)):
        return [canonical(item) for item in value]
    if isinstance(value, set):
        return [canonical(item) for item in sorted(value, key=repr)]
    raise TypeError(f"cannot canonicalize {type(value)!r}")


def canonical_json(value: Any) -> str:
    return json.dumps(
        canonical(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
