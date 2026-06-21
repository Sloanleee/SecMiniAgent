from __future__ import annotations

from .openai_client import OpenAIClient


class VolcengineClient(OpenAIClient):
    """Volcengine Ark OpenAI-compatible adapter."""

    provider = "volcengine"

    def __init__(
        self,
        *,
        model: str,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: int = 120,
    ) -> None:
        super().__init__(
            model=model,
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            api_key_envs=("ARK_API_KEY", "VOLCENGINE_API_KEY"),
            base_url_envs=("ARK_BASE_URL", "VOLCENGINE_BASE_URL"),
            default_base_url="https://ark.cn-beijing.volces.com/api/v3",
            error_label="Volcengine Ark",
        )
