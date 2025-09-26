#!/usr/bin/env python3
"""
Validator for connector-produced socket facts (components).

Provides SocketFactsValidator.validate_data(data) -> List[str]
which returns an empty list when valid, otherwise human-readable errors.
This is a trimmed/adapted copy of scripts/validator.py for in-package use.
"""
from __future__ import annotations

from typing import Any, Iterable, List
import logging

try:
    from jsonschema import Draft7Validator
    from jsonschema.exceptions import SchemaError
except Exception:
    Draft7Validator = None  # type: ignore
    SchemaError = Exception  # type: ignore

logger = logging.getLogger(__name__)


# Minimal strict schema focusing on components/alerts shape used by connectors
JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "components": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "type": {"type": "string"},
                    "name": {"type": "string"},
                    "version": {"type": "string"},
                    "manifestFiles": {"type": "array"},
                    "alerts": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string", "minLength": 1},
                                "generatedBy": {"type": "string", "minLength": 1},
                                "severity": {"type": "string"},
                                "props": {"type": "object"},
                                "location": {"type": "object"},
                                "action": {"type": "string"},
                            },
                            "required": ["type", "generatedBy"],
                            "additionalProperties": True,
                        },
                    },
                },
                "required": ["id", "type"],
                "additionalProperties": True,
            },
        }
    },
    "required": ["components"],
    "additionalProperties": True,
}


class SocketFactsValidator:
    """Validate a connector-produced socket facts-like object.

    Returns a list of error messages; empty list means valid.
    """

    def __init__(self, schema: dict | None = None) -> None:
        if Draft7Validator is None:
            raise ImportError("jsonschema is required for validation: pip install jsonschema")
        self.schema = schema or JSON_SCHEMA
        self._validator = Draft7Validator(self.schema)

    def validate_data(self, data: Any) -> List[str]:
        errors: List[str] = []
        for err in sorted(self._validator.iter_errors(data), key=_error_sort_key):
            path = _format_path(err.path)
            msg = f"{path}: {err.message}" if path else err.message
            errors.append(msg)
        return errors


def _format_path(path_iter: Iterable[Any]) -> str:
    parts: List[str] = []
    for p in path_iter:
        if isinstance(p, int):
            if not parts:
                parts.append(f"[{p}]")
            else:
                parts[-1] = f"{parts[-1]}[{p}]"
        else:
            parts.append(str(p))
    return ".".join(parts)


def _error_sort_key(err) -> Any:
    try:
        return list(err.path)
    except Exception:
        return []
