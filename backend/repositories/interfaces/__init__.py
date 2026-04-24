"""Abstract base classes for repository interfaces."""

from abc import ABC, abstractmethod
from typing import Any, Optional


class URLRepositoryInterface(ABC):
    """Interface for URL data access operations."""

    @abstractmethod
    async def insert_one(self, document: dict) -> str:
        ...

    @abstractmethod
    async def find_by_id(self, doc_id: str) -> Optional[dict]:
        ...

    @abstractmethod
    async def find_many(
        self, filter_doc: dict | None = None, skip: int = 0, limit: int = 20,
        sort: list[tuple] | None = None,
    ) -> list[dict]:
        ...

    @abstractmethod
    async def update_one(self, doc_id: str, update: dict) -> bool:
        ...

    @abstractmethod
    async def count(self, filter_doc: dict | None = None) -> int:
        ...

    @abstractmethod
    async def aggregate(self, pipeline: list[dict]) -> list[dict]:
        ...


class SearchRepositoryInterface(ABC):
    """Interface for search operations."""

    @abstractmethod
    async def search(self, pipeline: list[dict]) -> list[dict]:
        ...
