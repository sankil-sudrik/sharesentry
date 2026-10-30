"""Runtime configuration read from environment variables (and an optional .env file)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional

try:  # python-dotenv is optional at runtime; the environment alone is enough
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None


@dataclass(frozen=True)
class Provider:
    label: str
    base_url: str
    default_model: str


# Every provider speaks the OpenAI-compatible chat-completions protocol.
PROVIDERS: Dict[str, Provider] = {
    "nvidia": Provider("NVIDIA API Catalog", "https://integrate.api.nvidia.com/v1", "nvidia/nemotron-3-super-120b-a12b"),
    "nebius": Provider("Nebius Token Factory", "https://api.tokenfactory.nebius.com/v1", "nvidia/Nemotron-3-Ultra"),
    "groq": Provider("Groq", "https://api.groq.com/openai/v1", "openai/gpt-oss-120b"),
    "custom": Provider("Custom OpenAI-compatible endpoint", "", ""),
}
DEFAULT_PROVIDER = "nvidia"


@dataclass(frozen=True)
class AIConfig:
    provider: str = DEFAULT_PROVIDER
    base_url: str = PROVIDERS[DEFAULT_PROVIDER].base_url
    api_key: str = ""
    model: str = PROVIDERS[DEFAULT_PROVIDER].default_model
    timeout_seconds: float = 45.0
    max_output_tokens: int = 900
    max_input_chars: int = 6000

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key and self.model)

    @property
    def is_nemotron(self) -> bool:
        return "nemotron" in self.model.lower()

    @property
    def provider_label(self) -> str:
        return PROVIDERS[self.provider].label


@dataclass(frozen=True)
class Settings:
    ai: AIConfig
    data_dir: Path
    max_upload_mb: int

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


def _number(env: Mapping[str, str], key: str, default, cast):
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        value = cast(raw)
    except ValueError:
        raise ValueError(f"{key} must be a number, got {raw!r}") from None
    if value <= 0:
        raise ValueError(f"{key} must be greater than zero, got {raw!r}")
    return value


def load_settings(env: Optional[Mapping[str, str]] = None) -> Settings:
    """Build Settings. Pass `env` explicitly in tests; otherwise .env + os.environ are used."""
    if env is None:
        if load_dotenv is not None:
            load_dotenv(override=False)
        env = os.environ
    provider_key = env.get("AI_PROVIDER", DEFAULT_PROVIDER).strip().lower() or DEFAULT_PROVIDER
    if provider_key not in PROVIDERS:
        raise ValueError(f"AI_PROVIDER must be one of {sorted(PROVIDERS)}, got {provider_key!r}")
    preset = PROVIDERS[provider_key]
    ai = AIConfig(
        provider=provider_key,
        base_url=(env.get("AI_BASE_URL", "").strip() or preset.base_url).rstrip("/"),
        api_key=env.get("AI_API_KEY", "").strip(),
        model=env.get("AI_MODEL", "").strip() or preset.default_model,
        timeout_seconds=_number(env, "AI_TIMEOUT_SECONDS", 45.0, float),
        max_output_tokens=_number(env, "AI_MAX_OUTPUT_TOKENS", 900, int),
        max_input_chars=_number(env, "AI_MAX_INPUT_CHARS", 6000, int),
    )
    return Settings(
        ai=ai,
        data_dir=Path(env.get("SHARESENTRY_DATA_DIR", "./data")).expanduser(),
        max_upload_mb=_number(env, "SHARESENTRY_MAX_UPLOAD_MB", 10, int),
    )
