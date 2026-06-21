from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path


ENV_KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_dotenv_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export ") :].lstrip()
    if "=" not in stripped:
        return None

    key, raw_value = stripped.split("=", 1)
    key = key.strip()
    if not ENV_KEY_PATTERN.match(key):
        raise RuntimeError(f"Invalid .env key: {key!r}")

    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    else:
        value = _strip_inline_comment(value)
    return key, value


def _strip_inline_comment(value: str) -> str:
    for index, char in enumerate(value):
        if char == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    return value


def load_dotenv(path: Path, *, override: bool = False) -> list[str]:
    if not path.exists():
        return []

    loaded: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            parsed = parse_dotenv_line(line)
        except RuntimeError as exc:
            raise RuntimeError(f"{path}:{line_number}: {exc}") from exc
        if parsed is None:
            continue
        key, value = parsed
        if override or key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded


def default_provider() -> str:
    configured = os.getenv("SECMINI_PROVIDER")
    if configured:
        return configured.lower()
    if os.getenv("XFYUN_API_KEY"):
        return "xfyun"
    if os.getenv("ARK_API_KEY") or os.getenv("VOLCENGINE_API_KEY"):
        return "volcengine"
    if os.getenv("OPENAI_API_KEY"):
        return "openai"
    return "fake"


def default_model(provider: str) -> str:
    explicit = os.getenv("SECMINI_MODEL")
    if explicit:
        return explicit
    if provider == "xfyun":
        return os.getenv("XFYUN_MODEL", "")
    if provider == "volcengine":
        return os.getenv("ARK_MODEL") or os.getenv("VOLCENGINE_MODEL", "doubao-seed-1-6-251015")
    if provider == "openai":
        return os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    return "fake-security-model"


@dataclass(slots=True)
class AppConfig:
    cwd: Path
    provider: str
    model: str
    max_turns: int = 8
    max_context_chars: int = 80_000
    max_tool_output_chars: int = 12_000
    auto_approve: bool = False
    session_id: str | None = None
    forced_skills: tuple[str, ...] = ()
    stream_output: bool = True

    @classmethod
    def from_values(
        cls,
        *,
        cwd: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        max_turns: int = 8,
        max_context_chars: int = 80_000,
        max_tool_output_chars: int = 12_000,
        auto_approve: bool = False,
        session_id: str | None = None,
        forced_skills: list[str] | tuple[str, ...] | None = None,
        stream_output: bool = True,
    ) -> "AppConfig":
        selected_provider = (provider or default_provider()).lower()
        return cls(
            cwd=Path(cwd or os.getcwd()).resolve(),
            provider=selected_provider,
            model=model or default_model(selected_provider),
            max_turns=max_turns,
            max_context_chars=max_context_chars,
            max_tool_output_chars=max_tool_output_chars,
            auto_approve=auto_approve,
            session_id=session_id,
            forced_skills=tuple(forced_skills or ()),
            stream_output=stream_output,
        )
