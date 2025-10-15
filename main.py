import os
import re
import json
import logging
from datetime import datetime, timezone
from urllib.parse import (
    urljoin, urlparse, parse_qs, unquote,
    urlunparse, urlencode, parse_qsl
)

import feedparser
import requests
from google.cloud import firestore

# Optional modern Firestore filter (silences positional-arg warning if available)
try:
    from google.cloud.firestore_v1 import FieldFilter
except Exception:
    FieldFilter = None

# ----------------- Config -----------------
PROJECT_ID = (os.getenv("GOOGLE_CLOUD_PROJECT") or "").strip()

FALLBACK_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

FEEDS = {
    "politics": [
        "https://www.google.com/alerts/feeds/09855239715608489155/1350228738014628326",
    ],
    "football": [
        "https://www.google.com/alerts/feeds/09855239715608489155/11728161082198066318",
    ],
    "celebrity": [
        "https://www.google.com/alerts/feeds/09855239715608489155/16695839084782454682",
    ],
}

# Allow deep-scrape for all feeds (was {"football"} before)
ALLOW_DEEP_SCRAPE_FEEDS = {"football", "politics", "celebrity"}
# ------------------------------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ingestor")

db = firestore.Client(project=PROJECT_ID) if PROJECT_ID else firestore.Client()
coll = db.collection("articles")

# Limit full-page scrapes per run (politeness + speed)
SCRAPE_BUDGET = 20
_MIN_BYTES = 1500  # allow real thumbnails; avoid 1x1 pixels etc.

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
    "facebook.com",  # don't include path here; we match host only
)


def dt_utc_now():
    return datetime.now(timezone.utc)


def parse_published(entry):
    """Turn feedparser's time_struct into datetime; fallback to now."""
    try:
        pp = entry.get("published_parsed") or entry.get("updated_parsed")
        if pp:
            return datetime(*pp[:6], tzinfo=timezone.utc)
    except Exception:
        pass
    return dt_utc_now()


def clean_text(s):
    return (s or "").strip()


def first_non_empty(*vals):
    for v in vals:
        if v:
            v = clean_text(v)
            if v:
                return v
    return ""


def unwrap_google_redirect(u: str) -> str:
    """
    Unwrap Google redirect URLs like:
      https://www.google.com/url?...&url=REAL_URL
    """
    try:
        if not u:
            return u
        p = urlparse(u)
        if p.netloc.endswith("google.com") and p.path == "/url":
            q = parse_qs(p.query)
            target = (q.get("url") or q.get("q") or [None])[0]
            if target:
                return unquote(target)
        return u
    except Exception:
        return u


def looks_like_logo(u: str) -> bool:
    """Heuristic to skip logos/placeholders/thin sprites."""
    lo = (u or "").lower()
    bad_bits = (
        "logo", "favicon", "sprite", "placeholder", "default",
        "brandmark", "opengraph-default", "apple-touch-icon",
        "mask-icon", "site-icon",
        # extra placeholders commonly seen
        "generic_image_missing", "generic-image-missing", "image_missing",
        "image-missing", "noimage", "no-image", "missingimage", "missing-image",
        "blank"
    )
    bad_exts = (".svg",)
    if any(x in lo for x in ("1x1", "pixel", "spacer")):
        return True
    return any(b in lo for b in bad_bits) or lo.endswith(bad_exts)


def _good_article_url(u: str) -> bool:
    try:
        p = urlparse(u)
        if p.scheme not in ("http", "https"):
            return False
        if not p.netloc:
            return False
        # Prefer URLs that actually have an article path (not just domain root)
        return bool(p.path and p.path != "/")
    except Exception:
        return False


def resolve_real_link(entry, link: str) -> str:
    """
    For Google News URLs, try hard to recover the publisher article URL:
      - url= param in the link
      - non-google hrefs in entry.links
      - url= param in those hrefs
      - anchors in summary HTML
    Falls back to original link if nothing better found.
    """
    link = unwrap_google_redirect(link)
    try:
        host = urlparse(link).netloc.lower()
    except Exception:
        host = ""

    if "news.google.com" in host:
        candidates = []

        # 1) url= in the link itself
        try:
            q = parse_qs(urlparse(link).query)
            if "url" in q and q["url"]:
                candidates.append(unquote(q["url"][0]))
        except Exception:
            pass

        # 2) from entry.links (unwrap, check url= too)
        for l in (entry.get("links") or []):
            h = (l.get("href") if isinstance(l, dict) else None) or ""
            if not h:
                continue
            h = unwrap_google_redirect(h)
            try:
                lh = urlparse(h).netloc.lower()
            except Exception:
                lh = ""
            if "news.google.com" not in lh and h.startswith("http"):
                candidates.append(h)
            else:
                # maybe this also has url=
                try:
                    q2 = parse_qs(urlparse(h).query)
                    if "url" in q2 and q2["url"]:
                        candidates.append(unquote(q2["url"][0]))
                except Exception:
                    pass

        # 3) <a href="..."> in summary HTML
        for href in re.findall(r'href=["\'](https?://[^"\']+)["\']', entry.get("summary") or "", re.I):
            href = unwrap_google_redirect(href)
            try:
                hh = urlparse(href).netloc.lower()
            except Exception:
                hh = ""
            if "news.google.com" not in hh:
                candidates.append(href)
            else:
                try:
                    q3 = parse_qs(urlparse(href).query)
                    if "url" in q3 and q3["url"]:
                        candidates.append(unquote(q3["url"][0]))
                except Exception:
                    pass

        # Prefer candidates with a real article path
        for c in candidates:
            if _good_article_url(c):
                return c

        # else, if we found anything at all, return first
        if candidates:
            return candidates[0]

    return link


def _normalize_image_url(u: str) -> str:
    """Bump width/height params and strip trackers (keep signed params like itok)."""
    if not u:
        return u
    try:
        p = urlparse(u)
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        # Upscale common CDN params gently
        for key in ("w", "width"):
            if key in q:
                try:
                    q[key] = str(max(int(q[key]), 1200))
                except Exception:
                    pass
        for key in ("h", "height"):
            if key in q:
                try:
                    q[key] = str(max(int(q[key]), 675))
                except Exception:
                    pass
        # Strip obvious trackers (leave itok intact)
        for k in ("utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"):
            q.pop(k, None)
        return urlunparse(p._replace(query=urlencode(q)))
    except Exception:
        return u


def _pick_from_srcset(srcset: str) -> str:
    """Choose the largest candidate from a srcset list."""
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


def _head_ok(url: str, session: requests.Session) -> bool:
    try:
        r = session.head(url, headers={"User-Agent": FALLBACK_USER_AGENT}, timeout=6, allow_redirects=True)
        ct = (r.headers.get("Content-Type") or "").lower()
        clen = int(r.headers.get("Content-Length", "0") or "0")
        if ct.startswith("image/") and clen >= _MIN_BYTES:
            return True
        # fallback: try a tiny GET to verify content-type without downloading full image
        rg = session.get(
            url,
            headers={"User-Agent": FALLBACK_USER_AGENT, "Range": "bytes=0-4096"},
            timeout=8,
            allow_redirects=True,
        )
        ctg = (rg.headers.get("Content-Type") or "").lower()
        return ctg.startswith("image/")
    except Exception:
        # be permissive if everything fails
        return True


def _fetch_html(url: str, session: requests.Session) -> str:
    headers = {
        "User-Agent": FALLBACK_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": f"{urlparse(url).scheme}://{urlparse(url).netloc}/",
    }
    r = session.get(url, headers=headers, timeout=10, allow_redirects=True)
    r.raise_for_status()
    return r.text


def _extract_from_jsonld(html: str):
    urls = []
    if not html:
        return urls
    # Lightweight regex capture of JSON-LD blocks
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


def _extract_from_meta_and_dom(html: str, page_url: str):
    urls = []
    if not html:
        return urls

    # 1) OG/Twitter/meta (+ secure_url variants)
    for m in re.finditer(
        r'<meta[^>]+(?:property|name)=["\'](?:og:image(?::secure_url|:url)?|twitter:image(?::src)?)["\'][^>]+content=["\']([^"\']+)["\']',
        html, re.I
    ):
        urls.append(m.group(1))

    # 2) <link rel="image_src">
    m = re.search(r'<link[^>]+rel=["\']image_src["\'][^>]+href=["\']([^"\']+)["\']', html, re.I)
    if m:
        urls.append(m.group(1))

    # 3) srcset / data-srcset (pick largest)
    for m in re.finditer(r'<(?:source|img)[^>]+srcset=["\']([^"\']+)["\']', html, re.I):
        cand = _pick_from_srcset(m.group(1))
        if cand:
            urls.append(cand)
    for m in re.finditer(r'<(?:source|img)[^>]+data-srcset=["\']([^"\']+)["\']', html, re.I):
        cand = _pick_from_srcset(m.group(1))
        if cand:
            urls.append(cand)

    # 4) <figure> first <img>, then general <img>
    for m in re.finditer(r'<figure[^>]*>.*?<img[^>]+src=["\']([^"\']+)["\']', html, re.I | re.S):
        urls.append(m.group(1))
    for m in re.finditer(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.I):
        urls.append(m.group(1))

    # 5) lazy data-* (data-src, data-original, data-lazy, data-lazy-src)
    for m in re.finditer(r'<img[^>]+data-(?:src|original|lazy|lazy-src)=["\']([^"\']+)["\']', html, re.I):
        urls.append(m.group(1))

    # 6) CSS background-image URLs in inline styles
    for m in re.finditer(r'background-image\s*:\s*url\((["\']?)([^"\')]+)\1\)', html, re.I):
        urls.append(m.group(2))

    # 7) <noscript> blocks often contain real <img>
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

    # 8) AMP link (we'll fetch later if present)
    amp = re.search(r'<link[^>]+rel=["\']amphtml["\'][^>]+href=["\']([^"\']+)["\']', html, re.I)
    amp_url = (amp.group(1) or "").strip() if amp else None

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

    # stash AMP marker (so caller can fetch AMP page)
    if amp_url:
        if amp_url.startswith("//"):
            amp_url = "https:" + amp_url
        if not amp_url.startswith(("http://", "https://")):
            amp_url = urljoin(page_url, amp_url)
        abs_urls.append(amp_url + "#__AMP_FETCH__")

    return abs_urls


def extract_football_specific_image(article_url, html):
    """Specialized extraction for football/sports websites."""
    try:
        domain = (urlparse(article_url).netloc or "").lower()

        site_patterns = [
            # ESPN
            (r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', ['espn.com']),
            (r'<img[^>]+class=["\'][^"\']*article-image[^"\']*["\'][^>]+src=["\']([^"\']+)["\']', ['espn.com']),
            # BBC Sport
            (r'<meta[^>]+name=["\']twitter:image["\'][^>]+content=["\']([^"\']+)["\']', ['bbc.co.uk','bbc.com']),
            (r'<div[^>]+class=["\'][^"\']*sp-o-media-wrapper[^"\']*["\'][^>]*>.*?<img[^>]+src=["\']([^"\']+)["\']', ['bbc.co.uk','bbc.com']),
            # Sky Sports
            (r'<figure[^>]+class=["\'][^"\']*sdc-site-image[^"\']*["\'][^>]*>.*?<img[^>]+src=["\']([^"\']+)["\']', ['skysports.com']),
            (r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', ['skysports.com']),
            # General sports/CMS
            (r'<div[^>]+class=["\'][^"\']*article-featured-image[^"\']*["\'][^>]*>.*?<img[^>]+src=["\']([^"\']+)["\']', []),
            (r'<img[^>]+class=["\'][^"\']*wp-post-image[^"\']*["\'][^>]+src=["\']([^"\']+)["\']', []),
            (r'<div[^>]+class=["\'][^"\']*hero-image[^"\']*["\'][^>]*>.*?<img[^>]+src=["\']([^"\']+)["\']', []),
        ]

        for pattern, domains in site_patterns:
            if not domains or any(d in domain for d in domains):
                matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    u = (match or "").strip()
                    if not u:
                        continue
                    if u.startswith("//"):
                        u = "https:" + u
                    if not u.startswith(("http://", "https://")):
                        u = urljoin(article_url, u)
                    if not looks_like_logo(u):
                        return u
    except Exception as e:
        log.info("Football-specific extraction error: %s", e)

    return None


def deep_pick_image(article_url: str, session=None):
    """
    Fetch the article (and AMP page if present) and pick a real content image
    (non-logo, likely large). Uses JSON-LD, OG/Twitter, <figure>, srcset.
    """
    sess = session or requests.Session()
    try:
        html = _fetch_html(article_url, sess)
    except Exception as e:
        log.info("Deep scrape fetch error: %s -> %s", article_url, e)
        return None

    # Football-first specialized extraction
    foot_img = extract_football_specific_image(article_url, html)
    if foot_img:
        return foot_img

    cands = []
    cands += _extract_from_jsonld(html)
    cands += _extract_from_meta_and_dom(html, article_url)

    # If AMP href included, fetch AMP page too
    amp_hrefs = [u for u in cands if u.endswith("#__AMP_FETCH__")]
    if amp_hrefs:
        try:
            amp_url = amp_hrefs[-1].replace("#__AMP_FETCH__", "")
            amp_html = _fetch_html(amp_url, sess)
            cands += _extract_from_meta_and_dom(amp_html, amp_url)
        except Exception as e:
            log.info("AMP fetch error: %s -> %s", article_url, e)

    # Clean/normalize/dedupe
    cleaned = []
    seen = set()
    for u in cands:
        if not u or u.startswith("data:"):
            continue
        if u.startswith("//"):
            u = "https:" + u
        if not u.startswith(("http://", "https://")):
            continue
        u = _normalize_image_url(u)
        pr = urlparse(u)
        host = (pr.netloc or "").lower()
        key = (host + pr.path).lower()
        if key in seen:
            continue
        seen.add(key)
        if looks_like_logo(u):
            continue
        # skip tracker/pixel hosts
        if any(b in host for b in _BAD_HOST_BITS):
            continue
        cleaned.append(u)

    # Prefer candidates that pass size/type checks
    for u in cleaned[:10]:  # cap small number for speed
        if _head_ok(u, sess):
            return u

    return cleaned[0] if cleaned else None


def fetch_og_image(page_url: str, timeout=8):
    """
    Fetch page and extract an image via common patterns:
      - <meta property="og:image"> / og:image:secure_url / og:image:url
      - <meta name="twitter:image"> / twitter:image:src
      - <link rel="image_src" href="...">
      - (last resort) first <img src="...">
    Returns absolute URL or None.
    """
    if not page_url:
        return None

    try:
        r = requests.get(
            page_url,
            timeout=timeout,
            headers={
                "User-Agent": FALLBACK_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Referer": f"{urlparse(page_url).scheme}://{urlparse(page_url).netloc}/",
            },
            allow_redirects=True,
        )
    except Exception as e:
        log.info("OG fetch error: %s -> %s", page_url, e)
        return None

    if r.status_code != 200 or not r.text:
        log.info("OG fetch status: %s -> %s", page_url, r.status_code)
        return None

    html = r.text

    # 1) Meta tags
    pat1 = re.compile(
        r'<meta[^>]+(?:property|name)=["\'](?:og:image(?::(?:secure_url|url))?|twitter:image(?::src)?)["\'][^>]+content=["\']([^"\']+)["\']',
        re.I,
    )
    pat2 = re.compile(
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\'](?:og:image(?::(?:secure_url|url))?|twitter:image(?::src)?)["\']',
        re.I,
    )
    candidates = pat1.findall(html) + pat2.findall(html)
    for u in candidates:
        u = u.strip()
        if u.startswith("//"):
            u = "https:" + u
        if not u.startswith(("http://", "https://")):
            u = urljoin(page_url, u)
        if u.startswith(("http://", "https://")) and not looks_like_logo(u):
            return u

    # 2) <link rel="image_src" href="...">
    m = re.search(r'<link[^>]+rel=["\']image_src["\'][^>]+href=["\']([^"\']+)["\']', html, re.I)
    if m:
        u = m.group(1).strip()
        if u.startswith("//"):
            u = "https:" + u
        if not u.startswith(("http://", "https://")):
            u = urljoin(page_url, u)
        if u.startswith(("http://", "https://")) and not looks_like_logo(u):
            return u

    # 3) First <img src="...">
    m = re.search(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.I)
    if m:
        u = m.group(1).strip()
        if u.startswith("//"):
            u = "https:" + u
        if not u.startswith(("http://", "https://")):
            u = urljoin(page_url, u)
        if u.startswith(("http://", "https://")) and not looks_like_logo(u):
            return u

    log.info("OG none: %s", page_url)
    return None


def find_image_in_entry(entry, feed_name: str):
    """
    Best-effort image finder:
      1) media:thumbnail / media:content
      2) enclosure links that are images
      3) <img> in summary/content (src, data-src, data-original, data-lazy-src, srcset)
      4) Fallback:
         - for ALLOW_DEEP_SCRAPE_FEEDS: deep page scrape (JSON-LD, OG/Twitter, <figure>, srcset, AMP, football-specific)
         - else: OG/Twitter meta scrape first, then deep as last resort
    """
    # 1) media:* fields
    for t in (entry.get("media_thumbnail") or []):
        u = (t.get("url") if isinstance(t, dict) else None)
        if u and str(u).startswith(("http://", "https://")) and not looks_like_logo(u):
            log.info("IMG via media_thumbnail: %s", u)
            return u
    for c in (entry.get("media_content") or []):
        u = (c.get("url") if isinstance(c, dict) else None)
        if u and str(u).startswith(("http://", "https://")) and not looks_like_logo(u):
            log.info("IMG via media_content: %s", u)
            return u

    # 2) image enclosures
    for l in (entry.get("links") or []):
        if isinstance(l, dict) and l.get("rel") == "enclosure":
            ctype = str(l.get("type", "")).lower()
            if ctype.startswith("image/"):
                u = l.get("href")
                if u and str(u).startswith(("http://", "https://")) and not looks_like_logo(u):
                    log.info("IMG via enclosure: %s", u)
                    return u

    # 3) parse HTML for images (lazy attributes + srcset)
    html_chunks = []
    if entry.get("summary"):
        html_chunks.append(entry["summary"])
    sd = entry.get("summary_detail") or {}
    if isinstance(sd, dict):
        html_chunks.append(sd.get("value") or "")
    for c in (entry.get("content") or []):
        if isinstance(c, dict):
            html_chunks.append(c.get("value") or "")

    link = entry.get("link") or ((entry.get("links") or [{}])[0].get("href"))

    def norm(u: str) -> str:
        if not u:
            return ""
        u = u.strip()
        if u.startswith("//"):
            u = "https:" + u
        if not u.startswith(("http://", "https://")) and link:
            u = urljoin(link, u)
        return u

    def ok(u: str) -> bool:
        if not u or not u.startswith(("http://", "https://")):
            return False
        if u.lower().startswith("data:"):
            return False
        if looks_like_logo(u):
            return False
        return True

    IMG_SRC_RE  = re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.I)
    IMG_DATA_RE = re.compile(r'<img[^>]+data-(?:src|original|lazy-src)=["\']([^"\']+)["\']', re.I)
    SRCSET_RE   = re.compile(r'srcset=["\']([^"\']+)["\']', re.I)

    for html in html_chunks:
        if not html:
            continue

        candidates = []
        candidates += IMG_SRC_RE.findall(html)
        candidates += IMG_DATA_RE.findall(html)

        for srcset in SRCSET_RE.findall(html):
            # choose largest candidate from srcset
            best = _pick_from_srcset(srcset)
            if best:
                candidates.append(best)

        for raw in candidates:
            u = norm(raw)
            if ok(u):
                log.info("IMG via HTML parse: %s", u)
                return u

    # 4) Fallback: deep or OG scrape (respect budget)
    if link:
        global SCRAPE_BUDGET
        if SCRAPE_BUDGET > 0:
            SCRAPE_BUDGET -= 1
            try:
                feed_key = (feed_name or "").lower()
                if feed_key in ALLOW_DEEP_SCRAPE_FEEDS:
                    with requests.Session() as s:
                        img = deep_pick_image(link, s)
                    if img and ok(img):
                        log.info("IMG via DEEP scrape: %s", img)
                        return img
                    # deep failed — try OG
                    img2 = fetch_og_image(link)
                    if img2 and ok(img2):
                        log.info("IMG via OG scrape: %s", img2)
                        return img2
                else:
                    # Try OG first; if it fails, try deep as last resort
                    img2 = fetch_og_image(link)
                    if img2 and ok(img2):
                        log.info("IMG via OG scrape: %s", img2)
                        return img2
                    with requests.Session() as s:
                        img = deep_pick_image(link, s)
                    if img and ok(img):
                        log.info("IMG via DEEP scrape: %s", img)
                        return img
            except Exception as e:
                log.info("Fallback image error: %s", e)

    return None


def upsert_article(doc):
    """
    Upsert by URL (one doc per URL). Only set ingestedAt when the URL is NEW.
    """
    url = doc.get("url")
    if not url:
        return False

    # Look up by URL
    if FieldFilter:
        existing = list(coll.where(filter=FieldFilter("url", "==", url)).limit(1).stream())
    else:
        existing = list(coll.where("url", "==", url).limit(1).stream())

    if existing:
        existing_doc = existing[0].to_dict() or {}
        if "ingestedAt" in existing_doc:
            doc["ingestedAt"] = existing_doc["ingestedAt"]
        else:
            doc["ingestedAt"] = dt_utc_now()
        coll.document(existing[0].id).set(doc, merge=True)
        return True
    else:
        doc["ingestedAt"] = dt_utc_now()
        coll.add(doc)
        return True


def ingest():
    logging.info("Starting ingestion run")
    written = skipped = 0

    for feed_name, urls in FEEDS.items():
        urls = urls if isinstance(urls, (list, tuple)) else [urls]
        for feed_url in urls:
            logging.info(f"Fetching feed: {feed_url} ({feed_name})")
            parsed = feedparser.parse(feed_url)

            for e in parsed.entries:
                title = first_non_empty(e.get("title"))
                orig_link = first_non_empty(e.get("link"))
                link = resolve_real_link(e, unwrap_google_redirect(orig_link))
                summary = first_non_empty(e.get("summary"))
                source = first_non_empty(parsed.feed.get("title"))

                if not link or not title:
                    skipped += 1
                    continue

                e2 = dict(e)
                e2["link"] = link

                image_url = find_image_in_entry(e2, feed_name)

                doc = {
                    "feed": feed_name,
                    "source": source,
                    "title": title,
                    "title_lower": (title or "").lower(),
                    "summary": summary,
                    "url": link,
                    "publishedAt": parse_published(e),
                    "imageUrl": image_url or "",
                }

                if upsert_article(doc):
                    written += 1
                else:
                    skipped += 1

    logging.info(f"Ingestion done. written={written} skipped={skipped}")


if __name__ == "__main__":
    ingest()
