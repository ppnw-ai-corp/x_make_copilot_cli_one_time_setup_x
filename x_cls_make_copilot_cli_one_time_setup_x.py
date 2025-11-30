"""JSON-in/JSON-out helper to verify GitHub Copilot CLI authentication."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, TextIO, cast

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    class _WinRegModule(Protocol):
        HKEY_CURRENT_USER: object

        def OpenKey(  # noqa: N802 - winreg API surface
            self, key: object, sub_key: str
        ) -> AbstractContextManager[object]: ...

        def QueryValueEx(  # noqa: N802 - winreg API surface
            self, key: object, name: str
        ) -> tuple[object, int]: ...

else:  # pragma: no cover - runtime alias for annotations
    _WinRegModule = object

winreg: _WinRegModule | None
try:  # pragma: no cover - Windows only helper
    import winreg as _winreg
except ModuleNotFoundError:  # pragma: no cover - non-Windows platforms
    winreg = None
else:  # pragma: no cover - import succeeds on Windows
    winreg = cast("_WinRegModule", _winreg)


PAT_ENV_KEYS: tuple[str, ...] = (
    "COPILOT_REQUESTS_PAT",
    "COPILOT_REQUESTS_TOKEN",
    "COPILOT_PAT",
    "COPILOT_TOKEN",
    "COPILOT_GITHUB_TOKEN",
    "GITHUB_COPILOT_TOKEN",
    "GH_COPILOT_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
)
_DEFAULT_TIMEOUT_SECONDS = 20.0


@dataclass(slots=True)
class ProbeResult:
    """Holds the outcome of a non-interactive Copilot CLI probe."""

    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
        }


def _read_user_environment_variable(name: str) -> str | None:
    if os.name != "nt":
        return None
    if winreg is None:
        return None
    winreg_local = winreg
    try:  # pragma: no cover - depends on host registry
        with winreg_local.OpenKey(winreg_local.HKEY_CURRENT_USER, "Environment") as key:
            value_obj, _value_type = winreg_local.QueryValueEx(key, name)
    except FileNotFoundError:
        return None
    except OSError:
        return None
    if isinstance(value_obj, str):
        return value_obj
    return None


def _resolve_pat(explicit: str | None = None) -> tuple[str | None, list[str]]:
    sources: list[str] = []
    if explicit:
        return explicit.strip(), ["input"]
    env = os.environ
    for key in PAT_ENV_KEYS:
        value = env.get(key)
        if value:
            sources.append(key)
            return value.strip(), sources
    if os.name == "nt":
        for key in PAT_ENV_KEYS:
            value = _read_user_environment_variable(key)
            if value:
                sources.append(f"registry:{key}")
                return value.strip(), sources
    return None, sources


def _hash_token(token: str) -> str:
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return digest[:16]


def _build_env(pat: str) -> dict[str, str]:
    env = dict(os.environ)
    for key in PAT_ENV_KEYS:
        if key in {"GITHUB_TOKEN", "GH_TOKEN"} and env.get(key):
            continue
        env[key] = pat
    env.setdefault("COPILOT_ALLOW_ALL", "1")
    env.setdefault("COPILOT_CLI_ALLOW_UNSAFE", "1")
    return env


def _ensure_copilot_cli() -> str | None:
    candidates = (
        "copilot",
        "copilot.exe",
        "github-copilot-cli",
        "github-copilot-cli.exe",
        "copilot.ps1",
    )
    for name in candidates:
        path = shutil.which(name)
        if path:
            return path
    return None


def _run_probe(env: Mapping[str, str], *, timeout: float) -> ProbeResult:
    powershell = shutil.which("powershell") or "powershell"
    command = (
        "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; "
        "copilot --prompt 'Copilot CLI setup probe' --allow-all-tools --stream off "
        "--no-color"
    )
    try:
        completed = subprocess.run(  # noqa: S603 - command string is static
            [powershell, "-NoProfile", "-Command", command],
            env=env,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = (
            exc.stderr or "Probe timed out (Copilot CLI likely awaits trust or /login)."
        )
        if isinstance(stdout, bytes):  # pragma: no cover - defensive
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):  # pragma: no cover - defensive
            stderr = stderr.decode("utf-8", "replace")
        return ProbeResult(
            returncode=None, stdout=stdout, stderr=stderr, timed_out=True
        )
    else:
        return ProbeResult(
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            timed_out=False,
        )


def _launch_interactive(env: Mapping[str, str]) -> int:
    powershell = shutil.which("powershell") or "powershell"
    command = (
        "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; copilot"
    )
    completed = subprocess.run(  # noqa: S603 - command string is static
        [powershell, "-NoProfile", "-Command", command],
        env=env,
        check=False,
    )
    return completed.returncode


def _bool_option(
    payload: Mapping[str, object], key: str, *, default: bool = False
) -> bool:
    value = payload.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on", "y"}:
            return True
        if lowered in {"0", "false", "no", "off", "n"}:
            return False
    return default


class x_cls_make_copilot_cli_one_time_setup_x:  # noqa: N801 - legacy public API
    """Ensure the Copilot CLI sees a Copilot Requests PAT."""

    def __init__(self, ctx: object | None = None) -> None:
        self._ctx = ctx

    def run(self, request: Mapping[str, object] | None = None) -> dict[str, object]:
        payload = dict(request or {})
        explicit_pat = payload.get("pat")
        pat_value = explicit_pat.strip() if isinstance(explicit_pat, str) else None
        pat, sources = _resolve_pat(pat_value)
        if not pat:
            return {
                "status": "missing_pat",
                "message": (
                    "No Copilot Requests PAT was provided or discovered in the "
                    "environment."
                ),
                "pat_present": False,
                "pat_sources": sources,
                "probe": None,
            }

        cli_path = _ensure_copilot_cli()
        if not cli_path:
            return {
                "status": "copilot_cli_not_found",
                "message": (
                    "GitHub Copilot CLI was not located on PATH. Install it (npm "
                    "install -g @github/copilot) and retry."
                ),
                "pat_present": True,
                "pat_sources": sources,
                "pat_hash": _hash_token(pat),
                "probe": None,
            }

        timeout_obj = payload.get("probe_timeout", _DEFAULT_TIMEOUT_SECONDS)
        timeout_value = _DEFAULT_TIMEOUT_SECONDS
        if isinstance(timeout_obj, (int, float, str)):
            try:
                timeout_value = float(timeout_obj)
            except ValueError:
                timeout_value = _DEFAULT_TIMEOUT_SECONDS

        env = _build_env(pat)
        probe = _run_probe(env, timeout=timeout_value)
        stdout = probe.stdout.strip()
        stderr = probe.stderr.strip()

        result: dict[str, object] = {
            "status": "unknown",
            "message": "",
            "pat_present": True,
            "pat_sources": sources,
            "pat_hash": _hash_token(pat),
            "copilot_cli_path": cli_path,
            "probe": probe.to_dict(),
            "interactive_launched": False,
        }

        if probe.timed_out:
            result.update(
                {
                    "status": "probe_timeout",
                    "message": (
                        "Probe timed out; Copilot CLI likely awaits folder trust "
                        "or /login."
                    ),
                }
            )
            return result

        if probe.returncode == 0 and stdout:
            result.update(
                {
                    "status": "success",
                    "message": "Copilot CLI accepted the PAT without requiring /login.",
                    "answer_preview": stdout[:400],
                }
            )
            return result

        if probe.returncode == 0 and not stdout:
            message = (
                "Copilot CLI returned no output. Launch `copilot`, approve "
                "folder trust, then run `/login` once."
            )
            result.update(
                {
                    "status": "needs_login",
                    "message": message,
                }
            )
            if _bool_option(payload, "launch_interactive"):
                exit_code = _launch_interactive(env)
                result.update(
                    {
                        "interactive_launched": True,
                        "interactive_exit_code": exit_code,
                    }
                )
            return result

        error_message = stderr or stdout or "Copilot CLI probe failed."
        result.update(
            {
                "status": "probe_failed",
                "message": error_message,
                "probe_returncode": probe.returncode,
            }
        )
        return result


def _load_request() -> Mapping[str, object]:
    stdin = cast("TextIO", sys.stdin)
    if stdin.isatty():
        return cast("Mapping[str, object]", {})
    raw = stdin.read()
    if not raw.strip():
        return cast("Mapping[str, object]", {})
    try:
        data_obj: object = json.loads(raw)
    except json.JSONDecodeError as exc:  # pragma: no cover - simple pass-through
        error_message = f"Invalid JSON input: {exc}"
        raise SystemExit(error_message) from exc
    if not isinstance(data_obj, Mapping):
        error_message = "Input JSON must describe an object."
        raise SystemExit(error_message)
    return cast("Mapping[str, object]", data_obj)


def main() -> int:
    try:
        request = _load_request()
        result = x_cls_make_copilot_cli_one_time_setup_x().run(request)
        print(json.dumps(result, indent=2))
        status_value = result.get("status")
        is_probe_failure = (
            isinstance(status_value, str) and status_value == "probe_failed"
        )
    except SystemExit:  # propagate explicit exits
        raise
    except Exception as exc:  # pragma: no cover - defensive logging  # noqa: BLE001
        error_payload = {
            "status": "error",
            "message": str(exc),
        }
        print(json.dumps(error_payload, indent=2))
        return 1
    else:
        return 1 if is_probe_failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
