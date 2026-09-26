"""
cobcheck/llm_arm/client.py
─────────────────────────────
Groq call for the LLM-only arm. Mirrors the call pattern in
pii/tagger.py's _call_groq_llm (sync client, temperature 0.0, model
passed as a param) but asks for a JSON array of findings instead of a
single classification.
"""

from __future__ import annotations
import json
import logging
import time
from typing import Optional

from .codebook import CodebookEntry, build_system_prompt

logger = logging.getLogger("cobcheck.llm_arm")


class LlmArmCallError(Exception):
    pass


import time


def call_groq_for_rule(
    entry: CodebookEntry,
    source_bundle: str,
    api_key: str,
    model: str,
    max_retries: int = 4,
    base_wait: float = 10.0,
) -> list[dict]:
    try:
        from groq import Groq  # type: ignore
    except ImportError:
        logger.warning("groq package not installed; LLM-only arm cannot run")
        return []

    user_msg = (
        "COBOL source (copybooks already expanded inline):\n\n"
        f"{source_bundle}\n\n"
        f"Decide obligation {entry.rule_id} over every personal-data field "
        "you can identify in this source."
    )

    client = Groq(api_key=api_key)
    system_prompt = build_system_prompt(entry)

    last_exc: Optional[Exception] = None

    for attempt in range(1, max_retries + 1):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_msg},
                ],
                max_tokens=4096,
                temperature=0.0,
            )
            reply = (response.choices[0].message.content or "").strip()

            if not reply:
                raise LlmArmCallError(
                    f"{entry.rule_id}: empty response body from Groq "
                    f"(attempt {attempt}/{max_retries})"
                )

            # strip accidental markdown fences, defensively
            if reply.startswith("```"):
                reply = reply.strip("`")
                if reply.lower().startswith("json"):
                    reply = reply[4:].strip()

            try:
                findings = json.loads(reply)
            except json.JSONDecodeError as exc:
                # A malformed/empty body from a retried request looks
                # identical to a genuine parse failure unless we log the
                # raw reply — do that here rather than losing it.
                logger.error(
                    "%s: could not parse LLM response as JSON "
                    "(attempt %d/%d): %s | raw reply: %r",
                    entry.rule_id, attempt, max_retries, exc, reply[:500],
                )
                raise

            if not isinstance(findings, list):
                logger.warning(
                    "%s: LLM did not return a JSON array, got %s — treating as 0 findings",
                    entry.rule_id, type(findings),
                )
                return []

            return findings

        except json.JSONDecodeError as exc:
            last_exc = exc
        except Exception as exc:
            last_exc = exc
            # Only worth retrying on things that are plausibly transient
            # (rate limits, timeouts, empty bodies). Anything else — bad
            # API key, model not found — will fail identically every time,
            # so don't burn the retry budget on it.
            msg = str(exc).lower()
            transient = any(
                tok in msg for tok in (
                    "429", "rate limit", "timeout", "timed out",
                    "empty response", "503", "502", "overloaded",
                )
            )
            if not transient:
                logger.error(
                    "%s: non-transient Groq error, not retrying: %s",
                    entry.rule_id, exc,
                )
                raise LlmArmCallError(
                    f"Groq API error for rule {entry.rule_id}: {exc}"
                ) from exc

        if attempt < max_retries:
            wait = base_wait * (2 ** (attempt - 1))
            logger.warning(
                "%s: attempt %d/%d failed (%s), retrying in %.0fs",
                entry.rule_id, attempt, max_retries, last_exc, wait,
            )
            time.sleep(wait)

    logger.error(
        "%s: giving up after %d attempts, last error: %s",
        entry.rule_id, max_retries, last_exc,
    )
    return []