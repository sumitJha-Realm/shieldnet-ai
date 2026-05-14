"""Voyage AI embedding service — multi-model support for 25 UC coverage.

Models:
- voyage-4-large: General threat text (UC 1,3,4,7,8,11,12,13,14,15,19,22,23)
- voyage-4-large: Hindi/Tamil/Bengali scam text (UC 18, 24)
- voyage-multimodal-3.5: Screenshot/visual comparison (UC 10, 11, 21)
"""

import httpx
import os
import logging
from enum import Enum

logger = logging.getLogger(__name__)

VOYAGE_API_KEY = os.getenv("VOYAGE_AI_API_KEY")
VOYAGE_URL = "https://ai.mongodb.com/v1/embeddings"

# Direct Voyage API for multimodal (voyage-multimodal-3.5)
VOYAGE_DIRECT_API_KEY = os.getenv("VOYAGE_DIRECT_API_KEY")
VOYAGE_DIRECT_URL = "https://api.voyageai.com/v1/embeddings"


class VoyageModel(str, Enum):
    """Supported Voyage embedding models."""
    LARGE = "voyage-4-large"           # 1024-dim, best quality general text
    MULTILINGUAL = "voyage-4-large"    # 1024-dim, best multilingual retrieval quality
    MULTIMODAL = "voyage-multimodal-3.5"  # 1024-dim, image + text (via Voyage direct API)


# Default model for backward compatibility
VOYAGE_MODEL = os.getenv("VOYAGE_MODEL", VoyageModel.LARGE.value)


async def get_embedding(text: str, model: str | None = None) -> list[float]:
    """Generate embedding using Voyage AI API.

    Args:
        text: Text to embed.
        model: Voyage model name. Defaults to voyage-4-large.
    """
    use_model = model or VOYAGE_MODEL
    async with httpx.AsyncClient() as client:
        response = await client.post(
            VOYAGE_URL,
            headers={
                "Authorization": f"Bearer {VOYAGE_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "input": [text],
                "model": use_model,
            },
            timeout=30.0,
        )
        response.raise_for_status()
        data = response.json()
        return data["data"][0]["embedding"]


async def get_multilingual_embedding(text: str) -> list[float]:
    """Generate embedding for non-English text (Hindi, Tamil, Bengali etc).
    Uses voyage-4-large for UC 18, 24."""
    return await get_embedding(text, model=VoyageModel.MULTILINGUAL.value)


async def get_visual_embedding(description: str, screenshot_b64: str | None = None) -> list[float]:
    """Generate embedding for visual content using voyage-multimodal-3.5.
    Uses Voyage direct API (api.voyageai.com) for multimodal input when available.
    Falls back to voyage-4-large text embedding for POC.
    Used for UC 10 (credential harvesting), UC 11 (brand impersonation), UC 21 (watering hole).

    Args:
        description: Text description of the visual content.
        screenshot_b64: Base64-encoded screenshot (PNG/JPEG).
    """
    # TODO: Enable when multimodal API access is available
    # For now, use voyage-4-large with text description (produces same 1024-dim vectors)
    if screenshot_b64 and VOYAGE_DIRECT_API_KEY:
        # Multimodal path — requires Voyage direct API with multimodal model access
        content_blocks = [{"type": "text", "text": description}]
        content_blocks.append({
            "type": "image_base64",
            "image": screenshot_b64,
            "media_type": "image/png",
        })
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    VOYAGE_DIRECT_URL,
                    headers={
                        "Authorization": f"Bearer {VOYAGE_DIRECT_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "input": [content_blocks],
                        "model": VoyageModel.MULTIMODAL.value,
                    },
                    timeout=60.0,
                )
                response.raise_for_status()
                data = response.json()
                return data["data"][0]["embedding"]
        except Exception as e:
            logger.warning("Multimodal embedding failed, falling back to text: %s", e)

    # Fallback: text-only via Atlas endpoint with voyage-4-large
    return await get_embedding(description, model=VoyageModel.MULTILINGUAL.value)


async def get_batch_embeddings(texts: list[str], model: str | None = None) -> list[list[float]]:
    """Generate embeddings for multiple texts in a single API call."""
    if not texts:
        return []
    use_model = model or VOYAGE_MODEL
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
                    "model": use_model,
                },
                timeout=60.0,
            )
            response.raise_for_status()
            data = response.json()
            all_embeddings.extend(item["embedding"] for item in data["data"])
    return all_embeddings
