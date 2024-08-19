"""
Utility for loading configuration files

Objects only, loading files consisting of arrays is not supported.
"""

import json
from pathlib import Path
from typing import Any, Dict

import yaml


def _normalize_jsonlike(data: Any) -> Dict[str, Any]:
    if data is None:
        return dict()
    return data


def load_yaml(f: Path) -> Dict[str, Any]:
    with f.open("r") as fd:
        return _normalize_jsonlike(yaml.safe_load(fd))


def load_json(f: Path) -> Dict[str, Any]:
    with f.open("r") as fd:
        return _normalize_jsonlike(json.load(fd))


def load_any(f: Path) -> Dict[str, Any]:
    ext = f.suffix[1:]
    if ext in ["yml", "yaml"]:
        return load_yaml(f)
    elif ext in ["json"]:
        return load_json(f)
    else:
        raise Exception("Unsupported extension")


SUPPORTED_EXTENSIONS = ["yml", "yaml", "json"]
