from __future__ import annotations

import os

from .openai_client import OpenAIClient


class XfyunClient(OpenAIClient):
    """XFYun MaaS OpenAI-compatible adapter."""

    provider = "xfyun"

    def __init__(
        self,
        *,
        model: str,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: int = 120,
    ) -> None:
        if not model:
            raise RuntimeError("XFYUN_MODEL or --model is required for xfyun provider.")
        super().__init__(
            model=model,
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            api_key_envs=("XFYUN_API_KEY",),
            base_url_envs=("XFYUN_BASE_URL",),
            default_base_url="http://maas-api.cn-huabei-1.xf-yun.com/v1",
            error_label="XFYun MaaS",
            extra_headers={"lora_id": os.getenv("XFYUN_LORA_ID", "0")},
            stream_options={"include_usage": True},
        )
