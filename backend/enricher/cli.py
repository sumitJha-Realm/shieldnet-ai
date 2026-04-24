#!/usr/bin/env python3
"""CLI entry point — python -m enricher.cli <url>

Prints both structured JSON (Output A) and natural language narrative (Output B).
"""

from __future__ import annotations

import asyncio
import json
import sys

from enricher.enricher import enrich_url


async def main(url: str) -> None:
    result = await enrich_url(url)

    print("=" * 72)
    print("  OUTPUT A — Structured JSON")
    print("=" * 72)
    # Exclude narrative + embedding from JSON output (it's Output B)
    data = result.model_dump(exclude={"narrative"})
    print(json.dumps(data, indent=2, default=str))

    print()
    print("=" * 72)
    print("  OUTPUT B — Natural Language Behavioral Prompt")
    print("=" * 72)
    print(result.narrative)

    print()
    print(f"[Enrichment completed in {result.enrichment_time_ms}ms]")
    if result.errors:
        print(f"[Warnings: {', '.join(result.errors)}]")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python -m enricher.cli <url>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
