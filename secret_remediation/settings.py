"""Read this plugin's Hermes settings without printing the config file.

``config.yaml`` may hold other credentials. Only the ``secret-remediation``
settings mapping is returned, and only the keys this plugin understands.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _narrow(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    kept: dict[str, Any] = {}
    if "scan_paths" in raw:
        paths = raw.get("scan_paths")
        if isinstance(paths, list):
            kept["scan_paths"] = [str(item) for item in paths if isinstance(item, str)]
        elif paths is None:
            kept["scan_paths"] = []
    for key in ("include_logs", "include_sessions"):
        if key in raw and isinstance(raw[key], bool):
            kept[key] = raw[key]
    return kept


def _from_mapping(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return {}
    entries = plugins.get("entries")
    if not isinstance(entries, dict):
        return {}
    entry = entries.get("secret-remediation")
    if not isinstance(entry, dict):
        return {}
    return _narrow(entry.get("settings"))


def _parse(text: str) -> dict[str, Any]:
    try:
        import yaml
    except Exception:
        yaml = None
    if yaml is not None:
        try:
            return _from_mapping(yaml.safe_load(text) or {})
        except Exception:
            return {}
    return _parse_plain(text)


def _parse_plain(text: str) -> dict[str, Any]:
    """Fallback for the small settings block when PyYAML is not installed."""
    lines = text.splitlines()
    in_plugin = False
    in_settings = False
    in_paths = False
    settings: dict[str, Any] = {}
    paths: list[str] = []
    plugin_indent = None
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if stripped.startswith("secret-remediation:"):
            in_plugin = True
            in_settings = False
            in_paths = False
            plugin_indent = indent
            continue
        if in_plugin and plugin_indent is not None and indent <= plugin_indent and not stripped.startswith("-"):
            in_plugin = False
            in_settings = False
            in_paths = False
        if not in_plugin:
            continue
        if stripped.startswith("settings:"):
            in_settings = True
            in_paths = False
            continue
        if not in_settings:
            continue
        if stripped.startswith("scan_paths:"):
            in_paths = True
            settings["scan_paths"] = paths
            continue
        if in_paths and stripped.startswith("- "):
            paths.append(stripped[2:].strip().strip("\"'"))
            continue
        in_paths = False
        if stripped.startswith("include_logs:"):
            settings["include_logs"] = stripped.split(":", 1)[1].strip().lower() == "true"
        elif stripped.startswith("include_sessions:"):
            settings["include_sessions"] = stripped.split(":", 1)[1].strip().lower() == "true"
    return _narrow(settings)


def load_settings(home: Path) -> dict[str, Any]:
    path = home / "config.yaml"
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    return _parse(text)
