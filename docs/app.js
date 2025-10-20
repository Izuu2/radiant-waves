import { API_BASE, REFRESH_INTERVAL_MS } from "./settings.js?v=20250827a";

const LOADER = document.getElementById('rw-loader');
const showLoader = () => { if (LOADER) LOADER.style.display = 'grid'; };
const hideLoader = () => { if (LOADER) LOADER.style.display = 'none'; };

const els = {
  navLinks: document.querySelectorAll(".nav-link"),
  form: document.getElementById("searchForm"),
  q: document.getElementById("q"),
  status: document.getElementById("status"),
  home: document.getElementById("home"),
  results: document.getElementById("results"),
};

let currentFeed = ""; // "" = Home; else: "politics" | "football" | "celebrity"
const DEFAULT_LIMIT = 12;      // keep
const HOME_PER_FEED = 20;      // was 50 → reduce to 20 for speed

const POLL_MS = Number.isFinite(REFRESH_INTERVAL_MS) ? REFRESH_INTERVAL_MS : 30 * 60 * 1000;

const FEED_TITLES = { politics: "Politics", football: "Football", celebrity: "Celebrity" };

/* ---------- UTILS ---------- */
function escapeHtml(s) {
  return (s || "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
}
function fmtTime(iso) {
  if (!iso) return "";
  try { return new Date(iso).toLocaleString(); } catch { return ""; }
}
function stripTags(html) {
  const tmp = document.createElement("div");
  tmp.innerHTML = html || "";
  return (tmp.textContent || tmp.innerText || "").trim();
}

function makePlaceholder(label = "News") {
  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630">
      <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="#0f1720"/><stop offset="100%" stop-color="#1e2935"/></linearGradient></defs>
      <rect width="100%" height="100%" fill="url(#g)"/>
      <g font-family="Inter, Segoe UI, Roboto, Arial, sans-serif" fill="#a7cd3a" text-anchor="middle">
        <text x="50%" y="45%" font-size="84" font-weight="700">RADIANT</text>
        <text x="50%" y="58%" font-size="38" fill="#e5e7eb">${label}</text>
      </g>
    </svg>`;
  return "data:image/svg+xml;charset=UTF-8," + encodeURIComponent(svg);
}

function isLogoish(url) {
  const s = String(url || "").toLowerCase();
  return s.includes("logo") || s.includes("favicon") || s.includes("sprite") ||
         s.includes("placeholder") || s.includes("default") || s.includes("brand") ||
         s.endsWith(".svg");
}

let inflight = false;
let lastUpdated = null;

function markUpdated() {
  lastUpdated = new Date();
  const base = (els.status.textContent || "").replace(/\s*\|\s*Updated.*/i, "").trim();
  els.status.textContent = base
    ? `${base} | Updated ${lastUpdated.toLocaleTimeString()}`
    : `Updated ${lastUpdated.toLocaleTimeString()}`;
}

async function safeLoad() {
  if (inflight) return;
  inflight = true;
  showLoader();
  try {
    await load();
    markUpdated();
  } finally {
    hideLoader();
    inflight = false;
  }
}


/* ---------- FETCH ---------- */
async function fetchJSON(u) {
  const url = (u instanceof URL) ? u : new URL(u, API_BASE);
  url.searchParams.set("_t", Date.now());
  const res = await fetch(url.toString(), { cache: "no-store" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function fetchJSONRelaxed(u, fallback = []) {
  try {
    return await fetchJSON(u);
  } catch (e) {
    console.warn("fetch failed for", u, e);
    return Array.isArray(fallback) ? fallback : fallback;
  }
}

/* ---------- IMAGE PIPE ---------- */
function proxied(u) { return `${API_BASE}/img?url=${encodeURIComponent(u)}`; }

async function resolveImageFor(imgEl, articleUrl) {
  try {
    const { imageUrl } = await fetchJSON(`${API_BASE}/pick_image?url=${encodeURIComponent(articleUrl)}`);
    if (imageUrl && !isLogoish(imageUrl)) {
      imgEl.src = proxied(imageUrl);
      imgEl.dataset.lazy = "0";
    }
  } catch { /* ignore */ }
}

/* ---------- RENDER ---------- */
function cardHtml(a, { sectionLabel = "News" } = {}) {
  const titleText = stripTags(a.title || "(untitled)");
  const summaryText = stripTags(a.summary || "").slice(0, 240);

  let imgSrc = "";
  let lazyAttr = "";
  if (a.imageUrl && !isLogoish(a.imageUrl)) {
    imgSrc = proxied(a.imageUrl);
  } else {
    imgSrc = makePlaceholder(sectionLabel);
    lazyAttr = ` data-lazy="1" data-article-url="${escapeHtml(a.url || "")}"`;
  }

  return `
    <li class="card">
      <div class="thumb-wrap">
        <img class="thumb" src="${imgSrc}" alt="" loading="lazy" decoding="async"
             onerror="this.dataset.fallback='1'; this.src='${makePlaceholder(sectionLabel)}';"${lazyAttr}>
        <div class="headline-overlay">
          <a class="title headline-title" href="${a.url}" target="_blank" rel="noopener">${escapeHtml(titleText)}</a>
        </div>
      </div>
      <div class="content">
        <div class="meta">${escapeHtml(a.source || "")} • ${fmtTime(a.publishedAt)}</div>
        <p class="summary">${escapeHtml(summaryText)}</p>
      </div>
    </li>`;
}

function hydrateLazyImages(root) {
  const imgs = (root || document).querySelectorAll('img[data-lazy="1"]');
  imgs.forEach(img => {
    const url = img.dataset.articleUrl;
    if (url) resolveImageFor(img, url);
  });
}

function renderEmptyState(container, msg = "No articles available right now.") {
  container.innerHTML = `
    <li class="card" style="padding:16px; text-align:center;">
      ${escapeHtml(msg)}
    </li>`;
}

/* ---------- LOADERS ---------- */
async function loadFeed() {
  const q = els.q.value.trim();
  const url = new URL(`${API_BASE}/articles`);
  if (q) url.searchParams.set("q", q);
  if (currentFeed) url.searchParams.set("feed", currentFeed);
  url.searchParams.set("limit", String(DEFAULT_LIMIT));

  els.status.textContent = "Loading…";
  const items = await fetchJSONRelaxed(url, []);
  els.status.textContent = q ? `${items.length} result(s)` : `${items.length} latest (showing up to 150)`;

  els.home.innerHTML = "";
  els.home.style.display = "none";

  const label = FEED_TITLES[currentFeed] || "Results";
  els.results.innerHTML = items.map(a => cardHtml(a, { sectionLabel: label })).join("");
  els.results.style.display = "";

  if (!items.length) renderEmptyState(els.results, "Nothing to show yet. Please try another feed or search.");

  hydrateLazyImages(els.results);
}

async function loadHome() {
  els.status.textContent = "Loading…";

  // Load hero (relaxed)
  const newest = await fetchJSONRelaxed(`${API_BASE}/articles?limit=1`, []);
  const hero = newest[0];

  // Load sections concurrently (relaxed)
  const [pol, foot, cele] = await Promise.all([
    fetchJSONRelaxed(`${API_BASE}/articles?feed=politics&limit=${HOME_PER_FEED}`, []),
    fetchJSONRelaxed(`${API_BASE}/articles?feed=football&limit=${HOME_PER_FEED}`, []),
    fetchJSONRelaxed(`${API_BASE}/articles?feed=celebrity&limit=${HOME_PER_FEED}`, []),
  ]);

  els.status.textContent = "";

  let heroHtml = "";
  if (hero) {
    const heroHasImg = hero.imageUrl && !isLogoish(hero.imageUrl);
    const heroImgSrc = heroHasImg ? proxied(hero.imageUrl) : makePlaceholder("Latest");
    const needLazyHero = !heroHasImg;
    const heroTitle = stripTags(hero.title || "");
    heroHtml = `
      <section class="hero">
        <img class="hero-img" src="${heroImgSrc}" alt=""
             ${needLazyHero ? `data-lazy="1" data-article-url="${escapeHtml(hero.url || "")}"` : ""}
             onerror="this.remove()">
        <div class="hero-overlay"></div>
        <div class="hero-body">
          <span class="hero-badge">Latest</span>
          <h2 class="hero-title"><a class="title" href="${hero.url}" target="_blank" rel="noopener">${escapeHtml(heroTitle)}</a></h2>
          <div class="hero-meta">${escapeHtml(hero.source || "")} • ${fmtTime(hero.publishedAt)}</div>
        </div>
      </section>`;
  }

  function sectionHtml(feedKey, items) {
    const cards = items.map(a => cardHtml(a, { sectionLabel: FEED_TITLES[feedKey] })).join("");
    const fallback = !items.length
      ? `<ul class="section-grid"><li class="card" style="padding:16px;text-align:center;">No ${FEED_TITLES[feedKey]} yet.</li></ul>`
      : `<ul class="section-grid">${cards}</ul>`;
    return `
      <section class="section">
        <div class="section-head">
          <h3 class="section-title">${FEED_TITLES[feedKey]}</h3>
          <button class="see-all-btn" data-feed="${feedKey}">See all →</button>
        </div>
        ${fallback}
      </section>`;
  }

  els.home.innerHTML = `
    ${heroHtml}
    ${sectionHtml("politics", pol)}
    ${sectionHtml("football", foot)}
    ${sectionHtml("celebrity", cele)}
  `;
  els.home.style.display = "";

  els.results.innerHTML = "";
  els.results.style.display = "none";

  // Bind “See all” buttons (created dynamically)
  document.querySelectorAll(".see-all-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      currentFeed = btn.dataset.feed;
      els.navLinks.forEach(a => {
        a.classList.toggle("active", a.dataset.feed === currentFeed);
        a.removeAttribute("aria-current");
        if (a.dataset.feed === currentFeed) a.setAttribute("aria-current", "page");
      });
      safeLoad(); // guarded reload
    });
  });

  hydrateLazyImages(els.home);
}

/* ---------- CONTROLLER ---------- */
async function load() {
  try {
    const q = els.q.value.trim();
    if (!q && !currentFeed) {
      await loadHome();
    } else {
      await loadFeed();
    }
  } catch (e) {
    els.status.textContent = "Failed to load.";
    console.error(e);
  }
}

/* ---------- EVENTS ---------- */
els.navLinks.forEach(link => {
  link.addEventListener("click", (e) => {
    e.preventDefault();
    currentFeed = link.dataset.feed || "";
    els.navLinks.forEach(a => a.classList.remove("active"));
    link.classList.add("active");
    els.navLinks.forEach(a => a.removeAttribute("aria-current"));
    link.setAttribute("aria-current", "page");
    if (!currentFeed) els.q.value = "";
    safeLoad(); // guarded
  });
});

els.form.addEventListener("submit", e => {
  e.preventDefault();
  safeLoad(); // guarded
});

/* ---------- AUTORELOADS ---------- */
// initial render (guarded)
safeLoad();

// silent auto-refresh
setInterval(() => safeLoad(), POLL_MS);

// refresh when the tab becomes visible again
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") safeLoad();
});

// refresh when the network comes back
window.addEventListener("online", () => safeLoad());

// ---- Dark mode toggle ----
const themeKey = 'rw-theme';
const root = document.documentElement;
function setTheme(mode) {
  if (mode === 'dark') {
    root.setAttribute('data-theme', 'dark');
    localStorage.setItem(themeKey, 'dark');
  } else {
    root.removeAttribute('data-theme');
    localStorage.setItem(themeKey, 'light');
  }
}
document.getElementById('themeToggle')?.addEventListener('click', () => {
  const isDark = root.getAttribute('data-theme') === 'dark';
  setTheme(isDark ? 'light' : 'dark');
});
// initialize
setTheme(localStorage.getItem(themeKey) || 'light');

