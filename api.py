# api.py
import os
# Silence noisy gRPC logs before importing Google libs
os.environ.setdefault("GRPC_VERBOSITY", "ERROR")
os.environ.setdefault("GRPC_TRACE", "")

import re
import json
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import requests
from flask import Flask, jsonify, request, Response, redirect
from flask_cors import CORS
from google.cloud import firestore
from google.oauth2 import service_account

# ----------------- Config -----------------
PROJECT_ID = (os.getenv("GOOGLE_CLOUD_PROJECT") or "").strip()
FETCH_WINDOW = int(os.getenv("FETCH_WINDOW", "500"))  # newest docs window for /articles
FALLBACK_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
PICKER_VERSION = "v4"   # image picker build marker
CACHE_PATH = os.path.join(os.path.dirname(__file__), "cache_articles.json")

# Gate the scheduler so it runs in exactly ONE process
RUN_JOBS = os.getenv("RUN_JOBS", "0") == "1"
# ------------------------------------------

# Flask
app = Flask(__name__)
app.url_map.strict_slashes = False
CORS(app)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("api")

# ----------------- Helpers (cache + time) -----------------
def _write_cache(rows: list) -> None:
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False)
    except Exception as e:
        log.warning("Cache write skipped: %s", e)

def _read_cache() -> list:
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def _parse_ts_maybe(v):
    """Accept datetime or ISO string; fallback to epoch."""
    if isinstance(v, datetime):
        return v
    if isinstance(v, str):
        s = v.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(s)
        except Exception:
            pass
    return datetime(1970, 1, 1, tzinfo=timezone.utc)

def doc_to_public(d):
    out = dict(d)
    for k in ("publishedAt", "ingestedAt"):
        v = out.get(k)
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
    return out

# ---------- Ensure imageUrl/image_url for outbound articles ----------
def ensure_image_fields(d: dict) -> dict:
    """Guarantee imageUrl/image_url on an article dict by pulling from DB or page."""
    url = d.get("url") or d.get("link")
    img = d.get("imageUrl") or d.get("image_url") or d.get("image")

    if (not img) and url:
        try:
            img = _pick_image_from_page(url)
        except Exception:
            img = None

    if img:
        d["imageUrl"]  = img      # camelCase
        d["image_url"] = img      # snake_case mirror
        d["image"]     = img      # alias
    return d
# -------------------------------------------------------------------

# ----------------- Firestore (credential-aware) -----------------
CREDS_PATH = (os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or "").strip()

def _is_service_account_json(path: str) -> bool:
    try:
        if not path or not os.path.exists(path):
            return False
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return (
            data.get("type") == "service_account"
            and data.get("client_email")
            and data.get("token_uri")
        )
    except Exception:
        return False

if _is_service_account_json(CREDS_PATH):
    creds = service_account.Credentials.from_service_account_file(CREDS_PATH)
    db = firestore.Client(project=(PROJECT_ID or creds.project_id), credentials=creds)
    log.info(f"Firestore: using service account at {CREDS_PATH}")
else:
    db = firestore.Client(project=(PROJECT_ID or None))
    log.info("Firestore: using Application Default Credentials")

coll = db.collection("articles")

# ----------------- CORS + cache headers -----------------
@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, HEAD, OPTIONS, POST"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"

    if request.path.startswith("/articles"):
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    elif request.path.startswith("/img"):
        resp.headers["Cache-Control"] = "public, max-age=86400"
    elif request.path.startswith(("/pick_image", "/latest")):
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp

# ----------------- Root (simple info) -----------------
@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "ok": True,
        "service": "radiant-waves",
        "endpoints": ["/articles", "/img", "/pick_image", "/diag", "/health", "/latest", "/r/<docid>"]
    })

# ----------------- Articles API -----------------
@app.route("/articles", methods=["GET", "OPTIONS"])
def list_articles():
    if request.method == "OPTIONS":
        return ("", 204)

    feed = request.args.get("feed")
    q = (request.args.get("q") or "").strip().lower()

    # limit logic: browse vs search
    is_search = bool(q)
    try:
        raw_limit = int(request.args.get("limit", 0))
    except Exception:
        raw_limit = 0

    if is_search:
        limit = min(raw_limit or 50, 500)
        window = min(max(limit, 200), FETCH_WINDOW)
    else:
        limit = min(raw_limit or 150, 150)
        window = FETCH_WINDOW

    from_cache = False
    # Primary: Firestore
    try:
        qref = coll.order_by("ingestedAt", direction=firestore.Query.DESCENDING).limit(window)
        docs = []
        for _doc in qref.stream():
            d = _doc.to_dict()
            d["id"] = _doc.id  # include stable id for Zapier/redirects
            docs.append(d)
        _write_cache([doc_to_public(d) for d in docs])  # refresh cache including id
    except Exception as e:
        log.warning("Firestore fetch failed, using cache: %s", e)
        docs = _read_cache()
        from_cache = True
        if not docs:
            resp = jsonify([])
            resp.headers["X-From-Cache"] = "1"
            return resp

    # Optional filters
    if feed:
        docs = [d for d in docs if (d.get("feed") or "").lower() == feed.lower()]
    if q:
        tl = lambda s: (s or "").lower()
        docs = [
            d for d in docs
            if q in tl(d.get("title_lower") or d.get("title"))
            or q in tl(d.get("summary"))
        ]

    # Ensure newest-first
    def key(d):
        return _parse_ts_maybe(d.get("ingestedAt") or d.get("publishedAt"))

    docs.sort(key=key, reverse=True)

    if not from_cache:
        docs = [doc_to_public(d) for d in docs]

    resp = jsonify(docs[:limit])
    resp.headers["X-From-Cache"] = "1" if from_cache else "0"
    return resp

# ----------------- Image proxy (streamed, memory-safe) -----------------
@app.route("/img", methods=["GET"])
def proxy_image():
    raw = (request.args.get("url") or "").strip()
    if not raw or not raw.startswith(("http://", "https://")):
        return ("Bad Request", 400)
    try:
        p = urlparse(raw)
        headers = {
            "User-Agent": FALLBACK_USER_AGENT,
            "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
            "Referer": f"{p.scheme}://{p.netloc}/",
        }
        # stream to avoid loading the whole file into RAM
        r = requests.get(raw, headers=headers, timeout=(5, 10), allow_redirects=True, stream=True)
        if r.status_code >= 400:
            return ("Image fetch failed", 502)

        ct = r.headers.get("Content-Type", "image/jpeg")
        # optional safety: cap ~5MB
        max_bytes = 5 * 1024 * 1024
        sent = 0

        def generate():
            nonlocal sent
            for chunk in r.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    break
                sent += len(chunk)
                if sent > max_bytes:
                    break
                yield chunk

        return Response(generate(), content_type=ct)
    except Exception:
        return ("Image proxy error", 502)

# ----------------- Image picker -----------------
_LOGOISH = re.compile(r"(logo|favicon|sprite|placeholder|default|brand|og[-_]?default)", re.I)
_GOOD_EXT = (".jpg", ".jpeg", ".png", ".webp", ".bmp")
_BAD_HOST_BITS = (
    "scorecardresearch.com",
    "doubleclick.net",
    "googletagmanager.com",
    "google-analytics.com",
    "analytics.google.com",
    "adservice.google.com",
    "quantserve.com",
    "pixel.wp.com",
    "stats.wp.com",
    "facebook.com/tr",
)

def _looks_like_logo(u):
    s = (u or "").lower()
    if any(x in s for x in ("1x1", "pixel", "spacer")):
        return True
    return bool(_LOGOISH.search(s)) or s.endswith(".svg")

def _pick_from_srcset(srcset):
    if not srcset:
        return ""
    best = ""
    best_w = -1
    for part in srcset.split(","):
        seg = part.strip().split()
        if not seg:
            continue
        url = seg[0]
        w = 0
        if len(seg) > 1 and seg[1].endswith("w"):
            try:
                w = int(seg[1][:-1])
            except Exception:
                w = 0
        if w > best_w:
            best_w, best = w, url
    return best or srcset.split(",")[0].strip().split()[0]

def _extract_from_jsonld(html):
    urls = []
    if not html:
        return urls
    for m in re.finditer(r'<script[^>]+application/ld\+json[^>]*>(.*?)</script>', html, re.I | re.S):
        try:
            data = json.loads(m.group(1))
        except Exception:
            continue

        def walk(node):
            if isinstance(node, dict):
                img = node.get("image") or node.get("thumbnailUrl")
                if isinstance(img, str):
                    urls.append(img)
                elif isinstance(img, dict) and img.get("url"):
                    urls.append(img["url"])
                elif isinstance(img, list):
                    for x in img:
                        if isinstance(x, str):
                            urls.append(x)
                        elif isinstance(x, dict) and x.get("url"):
                            urls.append(x["url"])
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(data)
    return urls

def _extract_from_meta_and_dom(html, page_url):
    urls = []
    amp_url = None

    # meta tags
    for m in re.finditer(
        r'<meta[^>]+(?:property|name|itemprop)=["\'](?:og:image(?::(?:secure_url|url))?|twitter:image(?::src)?|image)["\'][^>]+content=["\']([^"\']+)["\']',
        html, re.I
    ):
        urls.append(m.group(1))

    # <link rel="image_src">
    m = re.search(r'<link[^>]+rel=["\']image_src["\'][^>]+href=["\']([^"\']+)["\']', html, re.I)
    if m:
        urls.append(m.group(1))

    # srcset
    for m in re.finditer(r'<(?:source|img)[^>]+srcset=["\']([^"\']+)["\']', html, re.I):
        cand = _pick_from_srcset(m.group(1))
        if cand:
            urls.append(cand)
    for m in re.finditer(r'<(?:source|img)[^>]+data-srcset=["\']([^"\']+)["\']', html, re.I):
        cand = _pick_from_srcset(m.group(1))
        if cand:
            urls.append(cand)

    # <figure> and general <img>
    for m in re.finditer(r'<figure[^>]*>.*?<img[^>]+src=["\']([^"\']+)["\']', html, re.I | re.S):
        urls.append(m.group(1))
    for m in re.finditer(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.I):
        urls.append(m.group(1))

    # lazy data-*
    for m in re.finditer(r'<img[^>]+data-(?:src|original|lazy|lazy-src)=["\']([^"\']+)["\']', html, re.I):
        urls.append(m.group(1))

    # CSS background images
    for m in re.finditer(r'background-image\s*:\s*url\((["\']?)([^"\')]+)\1\)', html, re.I):
        urls.append(m.group(2))

    # noscript blocks
    for nm in re.finditer(r'<noscript[^>]*>(.*?)</noscript>', html, re.I | re.S):
        part = nm.group(1) or ""
        for m in re.finditer(r'<img[^>]+src=["\']([^"\']+)["\']', part, re.I):
            urls.append(m.group(1))
        for m in re.finditer(r'<img[^>]+data-(?:src|original|lazy|lazy-src)=["\']([^"\']+)["\']', part, re.I):
            urls.append(m.group(1))
        for m in re.finditer(r'<(?:source|img)[^>]+srcset=["\']([^"\']+)["\']', part, re.I):
            cand = _pick_from_srcset(m.group(1))
            if cand:
                urls.append(cand)

    # AMP
    amp = re.search(r'<link[^>]+rel=["\']amphtml["\'][^>]+href=["\']([^"\']+)["\']', html, re.I)
    if amp:
        amp_url = (amp.group(1) or "").strip()

    # absolutize/protocol-fix
    abs_urls = []
    for u in urls:
        if not u:
            continue
        u = u.strip()
        if u.startswith("//"):
            u = "https:" + u
        if not u.startswith(("http://", "https://")):
            u = urljoin(page_url, u)
        abs_urls.append(u)

    return abs_urls, amp_url

def _is_good_image_candidate(u):
    try:
        p = urlparse(u)
        host = (p.netloc or "").lower()
        path = (p.path or "").lower()
        if any(b in host for b in _BAD_HOST_BITS):
            return False
        if path.endswith(".svg"):
            return False
        base = path.rsplit("/", 1)[-1]
        if not any(base.endswith(ext) for ext in _GOOD_EXT):
            if not any(x in path for x in ("/images/", "/image/", "/img/", "/media/", "/uploads/", "/wp-content/")):
                return False
        return True
    except Exception:
        return False

def _score_candidate(u):
    score = 0
    s = u.lower()
    if any(ext in s for ext in _GOOD_EXT):
        score += 4
    if any(x in s for x in ("/images/", "/image/", "/img/", "/media/", "/uploads/", "/wp-content/")):
        score += 3
    if any(x in s for x in ("hero", "cover", "article", "story", "photo")):
        score += 2
    if "sprite" in s or "logo" in s or "placeholder" in s:
        score -= 5
    if "pixel" in s or "tracker" in s or "beacon" in s:
        score -= 5
    return score

def _head_big_enough(url):
    try:
        r = requests.head(url, headers={"User-Agent": FALLBACK_USER_AGENT}, timeout=6, allow_redirects=True)
        ct = (r.headers.get("Content-Type") or "").lower()
        clen = int(r.headers.get("Content-Length") or "0")
        if not ct.startswith("image/"):
            return False
        return clen >= 1500
    except Exception:
        return False

def _site_specific(page_url, html):
    """Hard rules for known CMS/sites (example: Sidearm/Sports pages)."""
    host = (urlparse(page_url).netloc or "").lower()
    hlow = html.lower()

    if "frostburgsports.com" in host or "sidearmsports" in hlow:
        m = re.search(r'property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
        if m:
            u = m.group(1).strip()
            if u.startswith("//"): u = "https:" + u
            if not u.startswith(("http://", "https://")): u = urljoin(page_url, u)
            return u
        m = re.search(r'<img[^>]+class=["\'][^"\']*(roster|headshot|profile)[^"\']*["\'][^>]+(?:data-src|src)=["\']([^"\']+)["\']', html, re.I)
        if m:
            u = m.group(2).strip()
            if u.startswith("//"): u = "https:" + u
            if not u.startswith(("http://", "https://")): u = urljoin(page_url, u)
            return u
    return None

def _pick_image_from_page(page_url, timeout=15):
    if not page_url:
        return None
    try:
        r = requests.get(
            page_url,
            timeout=timeout,
            headers={"User-Agent": FALLBACK_USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
            allow_redirects=True,
        )
    except Exception:
        return None
    if r.status_code != 200 or not r.text:
        return None

    html = r.text

    # 0) site-specific hook
    special = _site_specific(page_url, html)
    if special and _is_good_image_candidate(special) and _head_big_enough(special):
        return special

    # 1) generic extraction
    cands = []
    cands += _extract_from_jsonld(html)
    meta_urls, amp_url = _extract_from_meta_and_dom(html, page_url)
    cands += meta_urls

    # 2) AMP, if present
    if amp_url:
        try:
            if amp_url.startswith("//"):
                amp_url = "https:" + amp_url
            if not amp_url.startswith(("http://", "https://")):
                amp_url = urljoin(page_url, amp_url)
            rr = requests.get(
                amp_url,
                timeout=timeout,
                headers={"User-Agent": FALLBACK_USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
                allow_redirects=True,
            )
            if rr.status_code == 200 and rr.text:
                more_urls, _ = _extract_from_meta_and_dom(rr.text, amp_url)
                cands += more_urls
        except Exception:
            pass

    # 3) clean/filter/dedupe + pick
    cleaned = []
    seen = set()
    for u in cands:
        if not u or u.startswith("data:"):
            continue
        if u.startswith("//"):
            u = "https:" + u
        if not u.startswith(("http://", "https://")):
            continue
        key = u.split("?", 1)[0].lower()
        if key in seen:
            continue
        seen.add(key)
        if _looks_like_logo(u):
            continue
        if not _is_good_image_candidate(u):
            continue
        cleaned.append(u)

    cleaned.sort(key=_score_candidate, reverse=True)

    for u in cleaned[:12]:
        if _head_big_enough(u):
            return u
    return None

@app.get("/pick_image")
def pick_image():
    page_url = (request.args.get("url") or "").strip()
    if not page_url:
        return jsonify({"version": PICKER_VERSION, "imageUrl": ""}), 400
    u = _pick_image_from_page(page_url) or ""
    # final safety: never return analytics/pixel hosts
    try:
        host = (urlparse(u).netloc or "").lower()
        if any(b in host for b in _BAD_HOST_BITS):
            u = ""
    except Exception:
        u = ""
    return jsonify({"version": PICKER_VERSION, "imageUrl": u}), 200

# ----------------- Diag / Health -----------------
@app.get("/diag")
def diag():
    info = {
        "ok": True,
        "projectId": PROJECT_ID or "(default)",
        "cachePath": CACHE_PATH,
        "cacheExists": os.path.exists(CACHE_PATH),
        "cacheBytes": 0,
        "cacheMtime": None,
        "hasDoc": False,
        "sampleCount": 0,
    }
    try:
        if os.path.exists(CACHE_PATH):
            st = os.stat(CACHE_PATH)
            info["cacheBytes"] = st.st_size
            info["cacheMtime"] = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
    except Exception:
        pass
    try:
        sample = list(coll.limit(3).stream())
        info["sampleCount"] = len(sample)
        info["hasDoc"] = bool(sample)
    except Exception as e:
        info["ok"] = False
        info["error"] = str(e)
        return jsonify(info), 500
    return jsonify(info)

@app.get("/health")
def health():
    return "ok"

# ----------------- Latest (for Zapier) -----------------
@app.route("/latest", methods=["GET"])
def latest():
    try:
        qref = coll.order_by("ingestedAt", direction=firestore.Query.DESCENDING).limit(1)
        out = []
        for _doc in qref.stream():
            d = _doc.to_dict()
            d["id"] = _doc.id
            d = ensure_image_fields(d)  # ensure imageUrl/image_url present
            out.append(doc_to_public(d))
        if not out:
            return jsonify({"ok": False, "error": "no_articles"}), 404
        return jsonify({"ok": True, "article": out[0]}), 200
    except Exception as e:
        log.exception("latest failed")
        return jsonify({"ok": False, "error": str(e)}), 500

# ----------------- Redirect (branded link) -----------------
@app.route("/r/<docid>", methods=["GET", "HEAD", "OPTIONS"])
def redirect_article(docid):
    # Preflight
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        snap = coll.document(docid).get()
        if not snap.exists:
            return "Not found", 404
        url = (snap.to_dict() or {}).get("url") or "/"
        # You can increment analytics here if needed
        return redirect(url, code=302)
    except Exception:
        log.exception("redirect failed")
        return "Error", 500

# ----------------- Scheduler (runs under gunicorn) -----------------
import subprocess
from apscheduler.schedulers.background import BackgroundScheduler
from atexit import register

def run_ingest_job():
    log.info("🚀 Ingest job starting…")
    # call your separate script so logic stays isolated
    subprocess.run(["python", "scripts/ingest.py"], check=False)
    log.info("✅ Ingest job finished")

if RUN_JOBS:
    try:
        _sched = BackgroundScheduler(daemon=True, timezone="UTC")
        # Align exactly at :00 and :30 every hour
        _sched.add_job(run_ingest_job, "cron", minute="0,30")
        _sched.start()
        log.info("🕒 Scheduler started (cron at :00/:30 UTC)")
        register(lambda: _sched.shutdown(wait=False))
    except Exception:
        log.exception("Failed to start APScheduler")

# ----------------- Local dev runner -----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))

