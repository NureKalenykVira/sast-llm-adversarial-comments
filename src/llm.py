import hashlib
import json
import os
import re
import sqlite3
import threading

from openai import OpenAI


CHARS_PER_TOKEN = 2.5


class ContextError(RuntimeError):
    pass


def estimate_tokens(messages):
    return int(sum(len(m["content"]) for m in messages) / CHARS_PER_TOKEN) + 8 * len(messages)


class LLM:
    def __init__(self, cfg, seed, cache_path):
        self.model = cfg["model"]
        self.max_context = cfg["max_context"]
        self.largest_prompt = 0
        self.temperature = cfg.get("temperature", 0)
        self.max_tokens = cfg.get("max_tokens", 600)
        self.json_mode = cfg.get("json_mode", True)
        self.seed = seed
        api_key = os.environ.get(cfg.get("api_key_env", ""), "") or "none"
        self.client = OpenAI(base_url=cfg["base_url"], api_key=api_key, timeout=600, max_retries=8)
        self.db = sqlite3.connect(str(cache_path), check_same_thread=False)
        self.lock = threading.Lock()
        self.db.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, response TEXT)")
        self.requests = 0
        self.cache_hits = 0

    def chat(self, messages, salt=0):
        tokens = estimate_tokens(messages)
        self.largest_prompt = max(self.largest_prompt, tokens)
        if tokens + self.max_tokens > self.max_context:
            raise ContextError(
                f"A prompt for {self.model} needs about {tokens} tokens plus {self.max_tokens} for the answer, "
                f"which exceeds max_context = {self.max_context}. Raise the context window of the model server "
                "and max_context in config.yaml (see README), then launch the same command again."
            )
        request = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "seed": self.seed + salt,
        }
        if self.json_mode:
            request["response_format"] = {"type": "json_object"}
        key = hashlib.sha256(json.dumps(request, sort_keys=True).encode("utf-8")).hexdigest()
        with self.lock:
            row = self.db.execute("SELECT response FROM cache WHERE key = ?", (key,)).fetchone()
            if row:
                self.cache_hits += 1
                return row[0]
            self.requests += 1
        response = self.client.chat.completions.create(**request)
        text = response.choices[0].message.content or ""
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO cache VALUES (?, ?)", (key, text))
            self.db.commit()
        return text

    def ask_json(self, messages, required, tries=3, salt=0):
        text = ""
        for attempt in range(tries):
            text = self.chat(messages, salt + attempt)
            data = parse_json(text)
            if data is not None and all(k in data for k in required):
                return data, text
        return None, text


def parse_json(text):
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) else None
