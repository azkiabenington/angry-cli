"""Stateful session management with undo/redo and locked JSON persistence."""

from __future__ import annotations

import copy
import json
import os
from datetime import datetime, timezone
from typing import Any, Optional


def _locked_save_json(path: str, data: Any, **dump_kwargs: Any) -> None:
    """Atomically write JSON with exclusive file locking where supported."""
    try:
        f = open(path, "r+", encoding="utf-8")
    except FileNotFoundError:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        f = open(path, "w", encoding="utf-8")
    with f:
        _locked = False
        try:
            import fcntl

            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            _locked = True
        except (ImportError, OSError):
            pass  # Windows / unsupported FS — proceed unlocked
        try:
            f.seek(0)
            f.truncate()
            json.dump(data, f, **dump_kwargs)
            f.flush()
        finally:
            if _locked:
                import fcntl

                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


class Session:
    """In-memory project session with deep-copy undo/redo stack and disk persistence."""

    def __init__(self, max_history: int = 50) -> None:
        self._project: Optional[dict[str, Any]] = None
        self.project_path: Optional[str] = None
        self._modified: bool = False
        self._undo_stack: list[tuple[str, dict[str, Any]]] = []
        self._redo_stack: list[tuple[str, dict[str, Any]]] = []
        self._history_log: list[dict[str, Any]] = []
        self._max_history: int = max_history

    def has_project(self) -> bool:
        """Return True if a project is currently loaded."""
        return self._project is not None

    def get_project(self) -> dict[str, Any]:
        """Return the active project dictionary, raising if none is open."""
        if self._project is None:
            raise RuntimeError(
                "No project is currently loaded. Create one with `project new` "
                "or open one with `--project <file>` / `project open <file>`."
            )
        return self._project

    def set_project(self, project: dict[str, Any], path: Optional[str] = None, modified: bool = False) -> None:
        """Load a project into the session, resetting undo/redo stacks."""
        self._project = project
        self.project_path = os.path.abspath(path) if path else None
        self._modified = modified
        self._undo_stack.clear()
        self._redo_stack.clear()

    def snapshot(self, description: str) -> None:
        """Capture a deep copy of current project state before a mutation."""
        proj = self.get_project()
        self._undo_stack.append((description, copy.deepcopy(proj)))
        if len(self._undo_stack) > self._max_history:
            self._undo_stack.pop(0)
        self._redo_stack.clear()
        self._modified = True
        self._history_log.append({
            "action": description,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })

    def undo(self) -> dict[str, Any]:
        """Revert the most recent mutation."""
        if not self._undo_stack:
            raise RuntimeError("Nothing to undo.")
        current = self.get_project()
        description, previous = self._undo_stack.pop()
        self._redo_stack.append((description, copy.deepcopy(current)))
        self._project = previous
        self._modified = True
        return {
            "undone": description,
            "undo_remaining": len(self._undo_stack),
            "redo_available": len(self._redo_stack),
        }

    def redo(self) -> dict[str, Any]:
        """Reapply the most recently undone mutation."""
        if not self._redo_stack:
            raise RuntimeError("Nothing to redo.")
        current = self.get_project()
        description, restored = self._redo_stack.pop()
        self._undo_stack.append((description, copy.deepcopy(current)))
        self._project = restored
        self._modified = True
        return {
            "redone": description,
            "undo_available": len(self._undo_stack),
            "redo_remaining": len(self._redo_stack),
        }

    def save_session(self, path: Optional[str] = None) -> str:
        """Persist the active project to disk using locked atomic JSON save."""
        proj = self.get_project()
        target = path or self.project_path
        if not target:
            raise RuntimeError("No project file path specified. Pass a path to `project save <path>`.")
        abs_target = os.path.abspath(target)
        proj["modified_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _locked_save_json(abs_target, proj, indent=2, ensure_ascii=False)
        self.project_path = abs_target
        self._modified = False
        return abs_target

    def history(self) -> list[dict[str, Any]]:
        """Return the chronological log of mutations performed in this session."""
        return list(self._history_log)

    def status(self) -> dict[str, Any]:
        """Return structured status of the current session."""
        return {
            "has_project": self.has_project(),
            "project_name": self._project.get("name") if self._project else None,
            "project_path": self.project_path,
            "modified": self._modified,
            "undo_depth": len(self._undo_stack),
            "redo_depth": len(self._redo_stack),
            "history_count": len(self._history_log),
        }
