"""Clean interactive REPL skin for angry-cli (`ipscan`)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Optional


_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_CYAN = "\033[38;5;80m"
_BLUE = "\033[38;5;75m"
_GREEN = "\033[38;5;78m"
_YELLOW = "\033[38;5;220m"
_RED = "\033[38;5;203m"
_GRAY = "\033[38;5;245m"
_WHITE = "\033[97m"


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class ReplSkin:
    """Styled terminal REPL chrome with prompt_toolkit fallback."""

    def __init__(self, app_name: str = "ipscan", version: str = "1.0.0") -> None:
        self.app_name = app_name
        self.version = version
        self._color = _supports_color()
        hist_dir = Path.home() / ".config" / "angry-cli"
        hist_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = str(hist_dir / "history")

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if self._color else text

    def print_banner(self) -> None:
        """Display the startup banner."""
        title = f"{self.app_name} v{self.version} — Angry IP Scanner CLI"
        hint = "Type 'help' for commands, 'quit' to exit"
        width = max(len(title), len(hint)) + 6
        bar = "-" * width
        print(self._c(_CYAN, f"+{bar}+"))
        print(self._c(_CYAN, "|") + "  " + self._c(_BOLD + _WHITE, title.ljust(width - 2)) + self._c(_CYAN, "|"))
        print(self._c(_CYAN, "|") + "  " + self._c(_GRAY, hint.ljust(width - 2)) + self._c(_CYAN, "|"))
        print(self._c(_CYAN, f"+{bar}+"))
        print()

    def create_prompt_session(self) -> Any:
        """Create a prompt_toolkit PromptSession when running in an interactive TTY."""
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            return None
        try:
            from prompt_toolkit import PromptSession
            from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
            from prompt_toolkit.history import FileHistory

            return PromptSession(
                history=FileHistory(self.history_file),
                auto_suggest=AutoSuggestFromHistory(),
                enable_history_search=True,
            )
        except Exception:
            return None

    def get_input(
        self,
        pt_session: Any,
        project_name: str = "",
        modified: bool = False,
    ) -> str:
        """Read one command line from prompt_toolkit or stdin."""
        ctx = ""
        if project_name:
            star = "*" if modified else ""
            ctx = f"[{project_name}{star}] "
        prompt = f"{self.app_name} {ctx}> "
        if pt_session is not None:
            return pt_session.prompt(prompt).strip()
        return input(prompt).strip()

    def help(self, commands: dict[str, str]) -> None:
        """Render a formatted command reference table."""
        print()
        print(self._c(_BOLD + _WHITE, "Commands:"))
        max_len = max((len(k) for k in commands), default=12)
        for cmd, desc in commands.items():
            print(f"  {self._c(_CYAN, cmd.ljust(max_len))}  {self._c(_GRAY, desc)}")
        print()

    def success(self, message: str) -> None:
        print(f"  {self._c(_GREEN, 'OK')} {message}")

    def error(self, message: str) -> None:
        print(f"  {self._c(_RED, 'ERR')} {message}", file=sys.stderr)

    def warning(self, message: str) -> None:
        print(f"  {self._c(_YELLOW, 'WARN')} {message}", file=sys.stderr)

    def info(self, message: str) -> None:
        print(f"  {self._c(_BLUE, '*')} {message}")

    def print_goodbye(self) -> None:
        print(self._c(_GRAY, "Goodbye."))
