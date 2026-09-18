"""
patch_groq_fix.py
───────────────────
One-time patch for cobcheck/pii/tagger.py:

1. Replaces the decommissioned Groq model "llama3-8b-8192" with a
   currently-served model, "openai/gpt-oss-20b" (Groq's recommended
   fast-tier replacement), and makes it overridable via a GROQ_MODEL
   env var so the next deprecation doesn't require another patch.

2. Adds a circuit breaker: today, when the configured model is dead,
   EVERY unclassified field gets its own doomed API call and its own
   full traceback-level warning (you saw ~20 of them for one small
   sample). A dead model fails the same way for every field, so this
   patches PiiTagger to disable the LLM fallback after the FIRST
   failure for the rest of the run, logging one clear warning instead
   of one per field.

Usage (from your repo root -- the folder containing cobcheck/):
    python patch_groq_fix.py

Safe to re-run: if the file already contains the patch markers, it
exits without making changes.
"""

import pathlib
import sys

TARGET = pathlib.Path("cobcheck/pii/tagger.py")


def main() -> int:
    if not TARGET.exists():
        print(f"ERROR: {TARGET} not found. Run this from your repo root "
              f"(the folder containing the 'cobcheck' package).")
        return 1

    content = TARGET.read_text(encoding="utf-8")

    if "_GroqCallError" in content:
        print("Already patched — nothing to do.")
        return 0

    # ── 1. Add a sentinel + custom exception near the top of the LLM section ──
    old_marker = "# ─── Stage 3: Groq LLM fallback ──────────────────────────────────────────────"
    if old_marker not in content:
        print("ERROR: could not find the Stage 3 marker comment. "
              "Your tagger.py may have diverged further — send it to me "
              "and I'll redo this patch against it.")
        return 1

    new_marker = (
        old_marker
        + "\n\n"
        + "class _GroqCallError(Exception):\n"
        + "    \"\"\"Raised when a Groq API call fails for a reason that will "
        + "fail identically\n    for every subsequent field (bad/decommissioned "
        + "model, auth error, etc.) —\n    used to trip PiiTagger's circuit "
        + "breaker rather than retry per field.\"\"\"\n"
    )
    content = content.replace(old_marker, new_marker, 1)

    # ── 2. Make _call_groq_llm raise _GroqCallError instead of swallowing ──
    old_except = (
        "    except Exception as exc:\n"
        "\n"
        "        logger.warning(\n"
        "            \"Groq API error for %s: %s\",\n"
        "            field_name,\n"
        "            exc,\n"
        "        )\n"
        "\n"
        "        return None"
    )
    new_except = (
        "    except Exception as exc:\n"
        "\n"
        "        raise _GroqCallError(\n"
        "            f\"Groq API error for {field_name}: {exc}\"\n"
        "        ) from exc"
    )
    if old_except not in content:
        print("ERROR: could not find _call_groq_llm's except block "
              "verbatim. Your tagger.py may have diverged further — "
              "send it to me and I'll redo this patch against it.")
        return 1
    content = content.replace(old_except, new_except, 1)

    # ── 3. Change the default model + make it env-overridable ──
    old_default = '        model: str = "llama3-8b-8192",'
    new_default = (
        '        model: str = _DEFAULT_GROQ_MODEL,'
    )
    if old_default not in content:
        print("ERROR: could not find the default model parameter "
              "verbatim. Your tagger.py may have diverged further — "
              "send it to me and I'll redo this patch against it.")
        return 1
    content = content.replace(old_default, new_default, 1)

    # Add the _DEFAULT_GROQ_MODEL constant right before the marker we
    # already anchored on, so it's defined before the class uses it.
    content = content.replace(
        new_marker,
        new_marker
        + "\n"
        + "# Groq deprecates chat models on a rolling schedule (see "
        + "console.groq.com/docs/deprecations).\n"
        + "# Override with GROQ_MODEL if this one is retired too — no code "
        + "change needed.\n"
        + "_DEFAULT_GROQ_MODEL = os.getenv(\n"
        + "    \"GROQ_MODEL\", \"openai/gpt-oss-20b\"\n"
        + ")\n",
        1,
    )

    # ── 4. Add the circuit-breaker flag to __init__ ──
    old_init_tail = (
        "        self._model = model\n"
        "        self._llm_limit = llm_threshold\n"
        "        self._llm_calls = 0\n"
    )
    new_init_tail = (
        "        self._model = model\n"
        "        self._llm_limit = llm_threshold\n"
        "        self._llm_calls = 0\n"
        "        self._llm_disabled = False\n"
    )
    if old_init_tail not in content:
        print("ERROR: could not find __init__'s tail verbatim. "
              "Your tagger.py may have diverged further — send it to "
              "me and I'll redo this patch against it.")
        return 1
    content = content.replace(old_init_tail, new_init_tail, 1)

    # ── 5. Guard the call site + trip the breaker on _GroqCallError ──
    old_call_site = (
        "        if (\n"
        "            self._api_key\n"
        "            and self._llm_calls\n"
        "            < self._llm_limit\n"
        "        ):\n"
        "\n"
        "            self._llm_calls += 1\n"
        "\n"
        "            category = _call_groq_llm(\n"
        "                field_name=field_name,\n"
        "                picture=picture,\n"
        "                context_lines=context,\n"
        "                api_key=self._api_key,\n"
        "                model=self._model,\n"
        "            )\n"
        "\n"
        "            if category is not None:\n"
        "\n"
        "                self._stats[\"llm\"] += 1\n"
        "\n"
        "                return (\n"
        "                    category,\n"
        "                    \"llm\",\n"
        "                )\n"
    )
    new_call_site = (
        "        if (\n"
        "            self._api_key\n"
        "            and not self._llm_disabled\n"
        "            and self._llm_calls\n"
        "            < self._llm_limit\n"
        "        ):\n"
        "\n"
        "            self._llm_calls += 1\n"
        "\n"
        "            try:\n"
        "                category = _call_groq_llm(\n"
        "                    field_name=field_name,\n"
        "                    picture=picture,\n"
        "                    context_lines=context,\n"
        "                    api_key=self._api_key,\n"
        "                    model=self._model,\n"
        "                )\n"
        "            except _GroqCallError as exc:\n"
        "                self._llm_disabled = True\n"
        "                logger.warning(\n"
        "                    \"%s -- disabling LLM fallback for the rest \"\n"
        "                    \"of this run (a dead/misconfigured model \"\n"
        "                    \"fails identically for every field, so \"\n"
        "                    \"remaining unclassified fields are tagged \"\n"
        "                    \"'none' instead of retrying). Set GROQ_MODEL \"\n"
        "                    \"to a currently-served model and re-run.\",\n"
        "                    exc,\n"
        "                )\n"
        "                category = None\n"
        "\n"
        "            if category is not None:\n"
        "\n"
        "                self._stats[\"llm\"] += 1\n"
        "\n"
        "                return (\n"
        "                    category,\n"
        "                    \"llm\",\n"
        "                )\n"
    )
    if old_call_site not in content:
        print("ERROR: could not find the Stage 3 call site verbatim. "
              "Your tagger.py may have diverged further — send it to "
              "me and I'll redo this patch against it.")
        return 1
    content = content.replace(old_call_site, new_call_site, 1)

    TARGET.write_text(content, encoding="utf-8")
    print(f"Patched {TARGET} successfully.")
    print("Default model is now: openai/gpt-oss-20b "
          "(override with the GROQ_MODEL env var).")
    print("LLM fallback will now disable itself after the first failed "
          "call instead of retrying for every field.")
    return 0


if __name__ == "__main__":
    sys.exit(main())