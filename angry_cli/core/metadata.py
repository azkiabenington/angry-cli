"""Comments, Favorites, and Openers management mirroring Angry IP Scanner's config modules."""

import copy
import re
from typing import Any, Dict, Optional

from angry_cli.core.results import get_host_detail
from angry_cli.core.targets import set_file_target, set_random_target, set_range_target


# --- Comments (CommentsConfig) ---

def list_comments(project: Dict[str, Any]) -> Dict[str, str]:
    """Return all IP/MAC host comments configured in the project."""
    return copy.deepcopy(project.get("comments", {}))


def set_comment(project: Dict[str, Any], key: str, comment: str) -> Dict[str, str]:
    """Attach a persistent comment to an IP address or MAC address."""
    clean_key = key.strip()
    if not clean_key:
        raise ValueError("Comment key (IP or MAC address) cannot be empty.")
    comments = project.setdefault("comments", {})
    if not comment.strip():
        comments.pop(clean_key, None)
    else:
        comments[clean_key] = comment.strip()
    return {"key": clean_key, "comment": comments.get(clean_key, "")}


def remove_comment(project: Dict[str, Any], key: str) -> Dict[str, Any]:
    """Remove a stored comment for an IP or MAC address."""
    clean_key = key.strip()
    comments = project.setdefault("comments", {})
    if clean_key not in comments:
        raise KeyError(f"No comment found for '{clean_key}'.")
    old = comments.pop(clean_key)
    return {"removed": clean_key, "previous_comment": old}


# --- Favorites (FavoritesConfig) ---

def list_favorites(project: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Return all saved favorite feeder targets."""
    return copy.deepcopy(project.get("favorites", {}))


def add_favorite(project: Dict[str, Any], name: str, target: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Save the current (or provided) target feeder configuration as a named favorite."""
    clean_name = name.strip()
    if not clean_name:
        raise ValueError("Favorite name cannot be empty.")
    fav_target = copy.deepcopy(target if target is not None else project.get("target"))
    if not fav_target or "feeder" not in fav_target:
        raise ValueError("Cannot save favorite: no target feeder configured.")
    favorites = project.setdefault("favorites", {})
    favorites[clean_name] = fav_target
    return {"name": clean_name, "target": copy.deepcopy(fav_target)}


def remove_favorite(project: Dict[str, Any], name: str) -> Dict[str, Any]:
    """Remove a named favorite target."""
    clean_name = name.strip()
    favorites = project.setdefault("favorites", {})
    if clean_name not in favorites:
        raise KeyError(f"Favorite '{clean_name}' not found.")
    old = favorites.pop(clean_name)
    return {"removed": clean_name, "target": old}


def use_favorite(project: Dict[str, Any], name: str) -> Dict[str, Any]:
    """Apply a saved favorite as the project's active feeder target."""
    clean_name = name.strip()
    favorites = project.get("favorites", {})
    if clean_name not in favorites:
        raise KeyError(f"Favorite '{clean_name}' not found.")
    fav = favorites[clean_name]
    feeder = fav.get("feeder")
    if feeder == "range":
        return set_range_target(project, fav["start_ip"], fav["end_ip"])
    if feeder == "random":
        return set_random_target(project, fav["base_ip"], fav["mask"], int(fav["count"]))
    if feeder == "file":
        return set_file_target(project, fav["file_path"])
    raise ValueError(f"Unsupported feeder '{feeder}' in favorite '{clean_name}'.")


# --- Openers (OpenersConfig) ---

def list_openers(project: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Return all configured host openers."""
    return copy.deepcopy(project.get("openers", {}))


def add_opener(
    project: Dict[str, Any],
    name: str,
    exec_string: str,
    in_terminal: bool = False,
    working_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Add or update an opener template (supports ``${fetcher.ip}``, ``${fetcher.hostname}``, etc.)."""
    clean_name = name.strip()
    if not clean_name:
        raise ValueError("Opener name cannot be empty.")
    if not exec_string.strip():
        raise ValueError("Opener exec_string cannot be empty.")
    entry = {
        "exec_string": exec_string.strip(),
        "in_terminal": bool(in_terminal),
        "working_dir": working_dir,
    }
    openers = project.setdefault("openers", {})
    openers[clean_name] = entry
    return {"name": clean_name, **copy.deepcopy(entry)}


def remove_opener(project: Dict[str, Any], name: str) -> Dict[str, Any]:
    """Delete a configured opener by name."""
    clean_name = name.strip()
    openers = project.setdefault("openers", {})
    if clean_name not in openers:
        raise KeyError(f"Opener '{clean_name}' not found.")
    old = openers.pop(clean_name)
    return {"removed": clean_name, "opener": old}


def render_opener(project: Dict[str, Any], name: str, ip: str) -> Dict[str, Any]:
    """Expand an opener's ``${fetcher.*}`` placeholders against a scanned host's values."""
    openers = project.get("openers", {})
    if name not in openers:
        raise KeyError(f"Opener '{name}' not found.")
    host = get_host_detail(project, ip)
    opener = openers[name]
    template = opener["exec_string"]
    values = host.get("values", {})

    def _replace(match: Any) -> str:
        key = match.group(1)
        if key == "fetcher.ip":
            return host["ip"]
        val = values.get(key)
        if val is None or str(val).startswith("["):
            return host["ip"] if key == "fetcher.hostname" else ""
        return str(val)

    rendered = re.sub(r"\$\{([^}]+)\}", _replace, template)
    return {
        "name": name,
        "ip": host["ip"],
        "template": template,
        "command": rendered,
        "in_terminal": opener.get("in_terminal", False),
        "working_dir": opener.get("working_dir"),
    }
