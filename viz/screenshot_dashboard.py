"""PNG of docs/audit-dashboard.html with headless Chromium (Playwright, requirements-dev.txt)."""
from __future__ import annotations

from playwright.sync_api import sync_playwright

from mfviz import DOCS


def main():
    DOCS.joinpath("screenshots").mkdir(exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page(viewport={"width": 1340, "height": 900}, device_scale_factor=2)
        page.goto((DOCS / "audit-dashboard.html").as_uri())
        page.screenshot(path=str(DOCS / "screenshots" / "audit_dashboard.png"), full_page=True)
        b.close()


if __name__ == "__main__":
    main()
