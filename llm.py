"""LLM backends: openai-compatible (Ollama, llama.cpp server, vLLM, OpenAI), anthropic, and a mock for smoke tests."""
import json
import os
import requests
import time
from urllib.parse import urlparse


class LLM:
    def __init__(self, backend="openai", model="llama3.1:8b", base_url="http://localhost:11434/v1",
                 api_key_env=None, temperature=0.0, seed=0, max_tokens=120):
        self.backend, self.model, self.base_url = backend, model, base_url.rstrip("/")
        self.api_key = os.environ.get(api_key_env, "") if api_key_env else ""
        self.temperature, self.seed, self.max_tokens = temperature, seed, max_tokens

    def begin_episode(self, ctx): pass

    def chat(self, system: str, messages: list) -> str:
        if self.backend == "openai":
            msgs = [{"role": "system", "content": system}] + messages
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            request = {
                "model": self.model, "messages": msgs, "temperature": self.temperature,
                "max_tokens": self.max_tokens,
            }
            if urlparse(self.base_url).hostname != "generativelanguage.googleapis.com":
                request["seed"] = self.seed
            for attempt in range(3):
                try:
                    r = requests.post(f"{self.base_url}/chat/completions", headers=headers, timeout=300, json=request)
                except requests.Timeout:
                    if attempt >= 1:
                        raise
                    time.sleep(2)
                    continue
                if r.status_code not in (429, 500, 502, 503, 504) or attempt == 2:
                    break
                retry_after = r.headers.get("Retry-After")
                try:
                    delay = float(retry_after) if retry_after else 2 ** (attempt + 1)
                except ValueError:
                    delay = 2 ** (attempt + 1)
                time.sleep(min(delay, 30))
            if not r.ok:
                raise requests.HTTPError(
                    f"API request failed ({r.status_code}): {r.text}",
                    response=r,
                )
            data = r.json()
            choices = data.get("choices")
            if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                raise ValueError(f"API response has no valid first choice: {data}")
            choice = choices[0]
            message = choice.get("message")
            if not isinstance(message, dict):
                raise ValueError(f"API response choice has no message: {choice}")
            content = message.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                text = "".join(
                    part["text"] for part in content
                    if isinstance(part, dict) and isinstance(part.get("text"), str)
                )
                if text:
                    return text
            raise ValueError(
                "API response contained no text content "
                f"(finish_reason={choice.get('finish_reason')!r}, "
                f"message_fields={sorted(message.keys())})"
            )
        if self.backend == "anthropic":
            import anthropic  # pip install anthropic ; needs ANTHROPIC_API_KEY (or --api-key-env)
            client = anthropic.Anthropic(api_key=self.api_key or None)
            r = client.messages.create(model=self.model, system=system, messages=messages,
                                       temperature=self.temperature, max_tokens=self.max_tokens)
            return "".join(b.text for b in r.content if b.type == "text")
        raise ValueError(self.backend)


class MockLLM(LLM):
    """Deterministic fake model for testing the pipeline. It follows an injection only if the
    payload text appears verbatim in the last tool result (so spotlighting 'defeats' it)."""
    def __init__(self):
        super().__init__(backend="mock", model="mock-v0")
        self.ctx = {}
        self.i = 0
        self.injected = False

    def begin_episode(self, ctx):
        self.ctx, self.i, self.injected = ctx, 0, False

    def chat(self, system, messages):
        last = messages[-1]["content"]
        payload = self.ctx.get("payload")
        if payload is not None and not self.injected and json.dumps(payload.text)[1:-1] in last:
            self.injected = True
            return json.dumps(payload.mock_action)
        plan = self.ctx.get("mock_actions", [])
        if self.i < len(plan):
            a = plan[self.i]; self.i += 1
            return json.dumps(a)
        return json.dumps({"final": "Done. Level is 50."})
