"""End-to-End Browser verification tests using Playwright against live stack.

Captures mandatory visual screenshots:
  - docs/screenshots/analyze-results.png
  - docs/screenshots/simulate-completed.png
  - docs/screenshots/runs-list.png
  - docs/screenshots/run-details.png
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

pytest.importorskip("playwright", reason="playwright is required for browser E2E tests (installed on host)")
from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8000")
SCREENSHOTS_DIR = Path(__file__).resolve().parent.parent / "docs" / "screenshots"


@pytest.fixture(scope="module")
def browser_context():
    """Launch headless Chromium browser and clean screenshot directory."""
    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 900})
        page = context.new_page()
        yield page
        browser.close()


def test_e2e_analyze_code_flow(browser_context):
    """Flow 1: Test interactive code analysis, sample insertion, line highlight, and screenshot."""
    page = browser_context
    page.goto(f"{BASE_URL}/ui/analyze")
    assert "Analyze Code" in page.title()

    # Click sample button for SQL Injection
    page.click('button[data-sample="sqli"]')
    assert "SELECT id, username" in page.input_value("#code-input")

    # Enable mock AI
    if not page.is_checked("#use-ai"):
        page.check("#use-ai")

    # Submit analysis
    page.click("#btn-analyze-submit")
    page.wait_for_selector("#analysis-results", timeout=10000)

    # Click first finding card to trigger line highlighting
    first_finding = page.locator(".finding-card").first
    assert first_finding.is_visible()
    first_finding.click()

    # Give animation a moment and capture screenshot
    page.wait_for_timeout(500)
    screenshot_path = SCREENSHOTS_DIR / "analyze-results.png"
    page.screenshot(path=str(screenshot_path), full_page=True)
    assert screenshot_path.is_file() and screenshot_path.stat().st_size > 0


def test_e2e_simulate_pr_flow(browser_context):
    """Flow 2: Test PR webhook simulation, async Celery chord execution, polling, and results."""
    page = browser_context
    page.goto(f"{BASE_URL}/ui/simulate")
    assert "Simulate PR" in page.title()

    page.fill("#repo-name", "corp-demo/repo-sample")
    page.fill("#pr-number", "202")

    # Submit simulation webhook
    page.click("#btn-simulate-submit")
    page.wait_for_selector("#simulation-progress-container", timeout=10000)

    # Wait for status to transition to COMPLETED (polling /ui/api/runs/{id})
    badge = page.locator("#sim-status-badge")
    for _ in range(30):
        text = badge.inner_text().strip().upper()
        if text in ("COMPLETED", "FAILED"):
            break
        page.wait_for_timeout(1000)

    # Wait for results card to be revealed
    page.wait_for_selector("#sim-results-card", state="visible", timeout=10000)
    page.wait_for_timeout(500)

    screenshot_path = SCREENSHOTS_DIR / "simulate-completed.png"
    page.screenshot(path=str(screenshot_path), full_page=True)
    assert screenshot_path.is_file() and screenshot_path.stat().st_size > 0


def test_e2e_runs_list_and_details_flow(browser_context):
    """Flow 3: View paginated runs table and navigate into run telemetry details."""
    page = browser_context

    # 1. Runs Table
    page.goto(f"{BASE_URL}/ui/runs")
    assert "Recent Runs" in page.title()
    page.wait_for_selector("#runs-table", timeout=10000)

    runs_screenshot_path = SCREENSHOTS_DIR / "runs-list.png"
    page.screenshot(path=str(runs_screenshot_path), full_page=True)
    assert runs_screenshot_path.is_file() and runs_screenshot_path.stat().st_size > 0

    # 2. Click first run details
    details_link = page.locator("#runs-table a.btn-secondary").first
    assert details_link.is_visible()
    details_link.click()

    # Wait for run details view
    page.wait_for_selector(".data-table", timeout=10000)
    page.wait_for_timeout(500)

    details_screenshot_path = SCREENSHOTS_DIR / "run-details.png"
    page.screenshot(path=str(details_screenshot_path), full_page=True)
    assert details_screenshot_path.is_file() and details_screenshot_path.stat().st_size > 0
