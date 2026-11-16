"""AI providers: Anthropic (Claude), OpenAI and Azure OpenAI.

Uses only the Python standard library (urllib), so the tool installs with
no extra dependencies. Settings come from environment variables.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


class ProviderError(RuntimeError):
    """Raised when a provider is misconfigured or the API call fails."""


class Provider:
    name = "base"

    def complete(self, system: str, user: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError


def _post_json(url: str, headers: dict, payload: dict, timeout: int = 120) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for key, value in headers.items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        raise ProviderError(f"API returned HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise ProviderError(f"Could not reach the API: {exc.reason}") from exc


def _require(var: str) -> str:
    value = os.environ.get(var)
    if not value:
        raise ProviderError(f"Set the {var} environment variable first.")
    return value


class AnthropicProvider(Provider):
    name = "anthropic"
    url = "https://api.anthropic.com/v1/messages"

    def __init__(self, model: str | None = None):
        self.api_key = _require("ANTHROPIC_API_KEY")
        self.model = model or os.environ.get("M365AI_MODEL") or "claude-sonnet-5-5"

    def complete(self, system: str, user: str) -> str:
        result = _post_json(
            self.url,
            {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
            {
                "model": self.model,
                "max_tokens": 4096,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        return "".join(block.get("text", "") for block in result.get("content", []))


class OpenAIProvider(Provider):
    name = "openai"
    url = "https://api.openai.com/v1/chat/completions"

    def __init__(self, model: str | None = None):
        self.api_key = _require("OPENAI_API_KEY")
        self.model = model or os.environ.get("M365AI_MODEL") or _require("OPENAI_MODEL")

    def complete(self, system: str, user: str) -> str:
        result = _post_json(
            self.url,
            {"Authorization": f"Bearer {self.api_key}"},
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        return result["choices"][0]["message"]["content"]


class AzureOpenAIProvider(Provider):
    """Azure OpenAI, for teams that keep AI traffic inside their Azure tenant."""

    name = "azure"

    def __init__(self, model: str | None = None):
        self.endpoint = _require("AZURE_OPENAI_ENDPOINT").rstrip("/")
        self.api_key = _require("AZURE_OPENAI_API_KEY")
        self.deployment = model or os.environ.get("M365AI_MODEL") or _require("AZURE_OPENAI_DEPLOYMENT")
        self.api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-10-21")

    def complete(self, system: str, user: str) -> str:
        url = (
            f"{self.endpoint}/openai/deployments/{self.deployment}/chat/completions"
            f"?api-version={self.api_version}"
        )
        result = _post_json(
            url,
            {"api-key": self.api_key},
            {"messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ]},
        )
        return result["choices"][0]["message"]["content"]


PROVIDERS = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "azure": AzureOpenAIProvider,
}


def get_provider(name: str | None = None, model: str | None = None) -> Provider:
    """Pick a provider by name, or by whichever API key is set."""
    if not name:
        name = os.environ.get("M365AI_PROVIDER")
    if not name:
        if os.environ.get("ANTHROPIC_API_KEY"):
            name = "anthropic"
        elif os.environ.get("AZURE_OPENAI_API_KEY"):
            name = "azure"
        elif os.environ.get("OPENAI_API_KEY"):
            name = "openai"
        else:
            raise ProviderError(
                "No AI provider configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, "
                "or AZURE_OPENAI_API_KEY (see README)."
            )
    try:
        return PROVIDERS[name](model=model)
    except KeyError:
        raise ProviderError(f"Unknown provider '{name}'. Choose from: {', '.join(PROVIDERS)}") from None
