from playwright.sync_api import sync_playwright
import time
from pathlib import Path

out_dir = Path(r"C:\Users\wondr\HermesWorkspace\oss-dependency-intelligence\docs\screenshots")
out_dir.mkdir(parents=True, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    
    # 1. Overview
    page.goto("http://127.0.0.1:8089", wait_until="networkidle")
    time.sleep(1)
    page.screenshot(path=str(out_dir / "overview.png"))
    print("Captured overview.png")

    # 2. Dependencies
    page.locator("button:has-text('Dependencies')").first.click()
    time.sleep(0.5)
    page.screenshot(path=str(out_dir / "dependencies.png"))
    print("Captured dependencies.png")

    # 3. Vulnerabilities
    page.locator("button:has-text('Vulnerabilities')").first.click()
    time.sleep(0.5)
    page.screenshot(path=str(out_dir / "vulnerabilities.png"))
    print("Captured vulnerabilities.png")

    # 4. Licenses
    page.locator("button:has-text('License Compliance')").first.click()
    time.sleep(0.5)
    page.screenshot(path=str(out_dir / "licenses.png"))
    print("Captured licenses.png")

    # 5. SBOM Export
    page.locator("button:has-text('SBOM Export')").first.click()
    time.sleep(0.5)
    page.screenshot(path=str(out_dir / "sbom.png"))
    print("Captured sbom.png")

    # 6. Governance Policies
    page.locator("button:has-text('Governance Policies')").first.click()
    time.sleep(0.5)
    page.screenshot(path=str(out_dir / "policies.png"))
    print("Captured policies.png")

    browser.close()
