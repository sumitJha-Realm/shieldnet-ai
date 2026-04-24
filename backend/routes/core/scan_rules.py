"""API routes for scan rules configuration."""

from fastapi import APIRouter, Depends

from repositories.impl.scan_rules_repository import ScanRulesRepository
from services.dependencies import get_database

router = APIRouter(tags=["Scan Rules"])


def _get_rules_repo() -> ScanRulesRepository:
    return ScanRulesRepository(get_database())


@router.get("/rules")
async def get_rules(repo: ScanRulesRepository = Depends(_get_rules_repo)):
    """Return current scanning rules."""
    return await repo.get_rules()


@router.patch("/rules")
async def update_rules(
    body: dict,
    repo: ScanRulesRepository = Depends(_get_rules_repo),
):
    """Partial-update scanning rules.  Only supplied keys are changed."""
    return await repo.update_rules(body)


@router.post("/rules/reset")
async def reset_rules(repo: ScanRulesRepository = Depends(_get_rules_repo)):
    """Reset all rules to factory defaults."""
    return await repo.reset_rules()
