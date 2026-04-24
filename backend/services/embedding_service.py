"""Voyage AI embedding service."""

import httpx
import os
import logging

logger = logging.getLogger(__name__)

VOYAGE_API_KEY = os.getenv("VOYAGE_AI_API_KEY")
VOYAGE_MODEL = os.getenv("VOYAGE_MODEL", "voyage-4")
VOYAGE_URL = "https://ai.mongodb.com/v1/embeddings"


async def get_embedding(text: str) -> list[float]:
    """Generate embedding using Voyage AI API."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            VOYAGE_URL,
            headers={
                "Authorization": f"Bearer {VOYAGE_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "input": [text],
                "model": VOYAGE_MODEL,
            },
            timeout=30.0,
        )
        response.raise_for_status()
        data = response.json()
        return data["data"][0]["embedding"]


async def get_batch_embeddings(texts: list[str]) -> list[list[float]]:
    """Generate embeddings for multiple texts in a single API call."""
    if not texts:
        return []
    # Voyage AI supports up to 128 texts per batch
    all_embeddings: list[list[float]] = []
    batch_size = 128
    async with httpx.AsyncClient() as client:
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            response = await client.post(
                VOYAGE_URL,
                headers={
                    "Authorization": f"Bearer {VOYAGE_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "input": batch,
                    "model": VOYAGE_MODEL,
                },
                timeout=60.0,
            )
            response.raise_for_status()
            data = response.json()
            all_embeddings.extend(item["embedding"] for item in data["data"])
    return all_embeddings
