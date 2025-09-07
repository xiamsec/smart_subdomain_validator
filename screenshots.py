
import asyncio, os
from typing import Optional

async def capture_screenshot(url: str, out_path: str, timeout: int = 8000) -> Optional[str]:
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return None
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            ctx = await browser.new_context(viewport={"width":1280,"height":800})
            page = await ctx.new_page()
            await page.goto(url, timeout=timeout)
            await page.screenshot(path=out_path, full_page=True)
            await browser.close()
        return out_path
    except Exception:
        return None
