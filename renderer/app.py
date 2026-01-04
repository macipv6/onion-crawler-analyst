
import os, io, time, hashlib
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from PIL import Image
from playwright.sync_api import sync_playwright

TOR_HOST = os.getenv("TOR_HOST", "tor")
TOR_PORT = int(os.getenv("TOR_PORT", "9050"))
BIND = os.getenv("RENDER_BIND", "0.0.0.0:8080")

SHOTS_DIR = "/shots"
os.makedirs(SHOTS_DIR, exist_ok=True)

app = FastAPI(title="Onion Renderer", version="1.0")
app.mount("/shots", StaticFiles(directory="/shots"), name="shots")

def is_onion(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return host.endswith(".onion")
    except Exception:
        return False

def save_thumbnail(png_path: str, width=256):
    try:
        im = Image.open(png_path).convert("RGB")
        w, h = im.size
        if w <= width:
            thumb_path = png_path.replace(".png", ".thumb.jpg")
            im.save(thumb_path, format="JPEG", quality=80, optimize=True)
            return thumb_path
        ratio = width / float(w)
        new_size = (width, int(h * ratio))
        im = im.resize(new_size, Image.LANCZOS)
        thumb_path = png_path.replace(".png", ".thumb.jpg")
        im.save(thumb_path, format="JPEG", quality=80, optimize=True)
        return thumb_path
    except Exception:
        return None

@app.get("/healthz")
def health():
    return {"status": "ok"}

@app.get("/shot")
def shot(
    url: str = Query(..., description="http://<v3>.onion/"),
    mode: str = Query("safe", pattern="^(safe|full)$"),
    width: int = Query(1280, ge=320, le=3840),
    height: int = Query(800, ge=320, le=2160),
    timeout: int = Query(45, ge=10, le=120)
):
    if not is_onion(url):
        raise HTTPException(status_code=400, detail="Only .onion URLs allowed")
    proxy = f"socks5://{TOR_HOST}:{TOR_PORT}"
    ua = "OnionRenderer/1.0 (+legal; screenshot only; no-login)"
    ts = int(time.time())
    safe = (mode == "safe")
    fname = f"{ts}_{hashlib.sha256(url.encode()).hexdigest()[:16]}.png"
    out_path = os.path.join(SHOTS_DIR, fname)

    with sync_playwright() as p:
        browser = p.chromium.launch(args=[f"--proxy-server={proxy}", "--disable-web-security", "--disable-features=IsolateOrigins,site-per-process"])
        ctx = browser.new_context(
            user_agent=ua,
            viewport={"width": width, "height": height},
            java_script_enabled=(not safe)
        )
        page = ctx.new_page()

        if safe:
            def route_handler(route):
                r = route.request
                if r.resource_type in {"image","media","font","stylesheet","script"}:
                    return route.abort()
                return route.continue_()
            page.route("**/*", route_handler)

        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout*1000)
            page.wait_for_timeout(500)
            page.screenshot(path=out_path, full_page=True)
        except Exception as e:
            ctx.close(); browser.close()
            raise HTTPException(status_code=502, detail=f"Navigation failed: {type(e).__name__}")
        ctx.close(); browser.close()

    thumb = save_thumbnail(out_path, width=256)
    return JSONResponse({
        "url": url,
        "mode": mode,
        "file": os.path.basename(out_path),
        "path": out_path,
        "thumbnail": os.path.basename(thumb) if thumb else None
    })
