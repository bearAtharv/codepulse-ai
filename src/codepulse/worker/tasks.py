"""Celery task definitions.

Phase 2: stub for ``orchestrate_pr_analysis``.
Phase 6 will wire this to the actual task DAG (fetch → chunk → [AST ∥ LLM]
→ aggregate → post).
"""

from __future__ import annotations

import logging

from codepulse.worker.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    name="tasks.orchestrate_pr_analysis",
    bind=True,
    queue="cp-high",
)
def orchestrate_pr_analysis(
    self,
    *,
    installation_id: int,
    repository_full_name: str,
    pull_request_number: int,
    head_sha: str,
    base_sha: str,
    pr_author: str,
    webhook_received_at: str,
    analysis_run_id: str,
) -> dict:
    """Entry point for the PR analysis pipeline.

    TODO (Phase 6): Wire to the actual task graph.
    Currently a stub that logs receipt and returns immediately.
    """
    logger.info(
        "[STUB] orchestrate_pr_analysis: %s#%d @ %s (run=%s)",
        repository_full_name,
        pull_request_number,
        head_sha[:8],
        analysis_run_id,
    )
    return {"status": "stub", "analysis_run_id": analysis_run_id}
