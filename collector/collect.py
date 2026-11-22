#!/usr/bin/env python3
"""
Zero-Day Board collector.

Mengambil data dari CISA KEV + feed RSS keamanan, menyaring yang benar-benar
dieksploitasi (zero-day / in-the-wild), memberi verdict, lalu menulis
docs/data.json yang dibaca halaman web. Hanya memakai library standar Python.

Env opsional:
  ANTHROPIC_API_KEY  -> aktifkan analisis AI untuk artikel berita
  CLAUDE_MODEL       -> default claude-haiku-5-5
  WINDOW_DAYS        -> default 30
  SOURCES_FILE       -> default collector/sources.json
  OUTPUT_FILE        -> default docs/data.json
  MAX_AI_CALLS       -> batas analisis AI per run, default 30
"""
import hashlib
import json
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WINDOW_DAYS = int(os.environ.get("WINDOW_DAYS", "30"))
SOURCES_FILE = os.environ.get("SOURCES_FILE", os.path.join(ROOT, "collector", "sources.json"))
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", os.path.join(ROOT, "docs", "data.json"))
API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
MODEL = os.environ.get("CLAUDE_MODEL", "claude-haiku-5-5")
MAX_AI_CALLS = int(os.environ.get("MAX_AI_CALLS", "30"))
UA = "ZeroDayBoard/1.0 (+https://github.com)"

NOW = datetime.now(timezone.utc)
CUTOFF = NOW - timedelta(days=WINDOW_DAYS)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
# Kata kunci kandidat: artikel harus menyebut salah satu ini agar dianalisis
CANDIDATE_RE = re.compile(
    r"zero[- ]?day|0[- ]?day|exploited in the wild|actively exploited|"
    r"under active exploitation|exploited as a zero|in-the-wild", re.I)
# Frasa bukti kuat (untuk mode tanpa AI)
STRONG_RE = re.compile(
    r"exploited in the wild|actively exploited|under active exploitation|"
    r"exploited as a zero[- ]?day|zero[- ]?day (?:flaw|vulnerability|bug|exploit)s? "
    r"(?:was |were |is |are |has been |have been )?(?:exploited|abused|used in attacks)|"
    r"exploited zero[- ]?day|added to (?:cisa'?s )?(?:kev|known exploited)", re.I)
# Tanda artikel bukan zero-day sungguhan
NOISE_RE = re.compile(
    r"\b(?:webinar|podcast|sponsored|deal|discount|review|how to|seminar|panduan|what is|apa itu|"
    r"explained|survey|predictions?|best practices|top \d+|year in review|trends?|opinion|"
    r"guide|tips|checklist|playbook|market|stocks?)\b", re.I)
ZD_TITLE_RE = re.compile(r"zero[- ]?day|0[- ]?day", re.I)
# Petunjuk eksploitasi / belum ada patch (Inggris + Indonesia)
CUES_RE = re.compile(
    r"exploited|exploitation|in the wild|unpatched|no patch|not (?:yet )?patched|no fix|"
    r"dieksploitasi|eksploitasi aktif|sedang dieksploitasi|"
    r"belum (?:ada )?(?:patch|penambal|perbaikan|ditambal)|tanpa (?:patch|penambal)", re.I)
RULES_VERSION = 4  # naikkan agar artikel lama dianalisis ulang
MAX_FETCH = int(os.environ.get("MAX_FETCH", "25"))


def log(*a):
    print("[collector]", *a, file=sys.stderr)


def fetch(url, timeout=30, data=None, headers=None):
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_date(s):
    if not s:
        return None
    s = s.strip()
    try:
        return parsedate_to_datetime(s).astimezone(timezone.utc)
    except Exception:
        pass
    try:
        if len(s) == 10:
            return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def strip_html(s):
    s = re.sub(r"<[^>]+>", " ", s or "")
    return re.sub(r"\s+", " ", unescape(s)).strip()


# ---------------------------------------------------------------- sumber data

def load_kev(url):
    try:
        data = json.loads(fetch(url, timeout=60))
    except Exception as e:
        log("KEV gagal diambil:", e)
        return None
    catalog = {}
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID", "").upper()
        if cve:
            catalog[cve] = v
    log(f"KEV: {len(catalog)} entri katalog")
    return catalog


def parse_feed(raw, feed_name):
    items = []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        log(f"Feed {feed_name} tidak valid:", e)
        return items
    ns_atom = "{http://www.w3.org/2005/Atom}"
    # RSS 2.0
    for it in root.iter("item"):
        items.append({
            "title": strip_html(it.findtext("title")),
            "link": (it.findtext("link") or "").strip(),
            "summary": strip_html(it.findtext("description") or
                                  it.findtext("{http://purl.org/rss/1.0/modules/content/}encoded")),
            "date": parse_date(it.findtext("pubDate") or
                               it.findtext("{http://purl.org/dc/elements/1.1/}date")),
        })
    # Atom
    for it in root.iter(ns_atom + "entry"):
        link = ""
        for l in it.findall(ns_atom + "link"):
            if l.get("rel", "alternate") == "alternate":
                link = l.get("href", "")
                break
        items.append({
            "title": strip_html(it.findtext(ns_atom + "title")),
            "link": link,
            "summary": strip_html(it.findtext(ns_atom + "summary") or it.findtext(ns_atom + "content")),
            "date": parse_date(it.findtext(ns_atom + "published") or it.findtext(ns_atom + "updated")),
        })
    for i in items:
        i["source"] = feed_name
    return items


def load_feeds(feeds):
    out = []
    for f in feeds:
        try:
            items = parse_feed(fetch(f["url"]), f["name"])
            for i in items:
                i["primary"] = bool(f.get("primary"))
                if f["name"].startswith("Google News") and " - " in i["title"]:
                    t, o = i["title"].rsplit(" - ", 1)
                    if 0 < len(o) <= 40:
                        i["title"], i["outlet"] = t.strip(), o.strip()
            out.extend(items)
            log(f"Feed {f['name']}: {len(items)} artikel")
        except Exception as e:
            log(f"Feed {f['name']} gagal:", e)
    return out


# ---------------------------------------------------------------- analisis

AI_PROMPT = """Kamu analis threat intelligence. Tentukan apakah artikel berikut melaporkan
kerentanan ZERO-DAY yang NYATA: dieksploitasi di dunia nyata (in the wild) sebelum
atau saat patch dirilis, atau dikonfirmasi aktif dieksploitasi oleh vendor/CISA/peneliti.

Aturan:
- "confirmed": vendor, CISA, atau peneliti kredibel menyatakan eksploitasi aktif.
- "likely": dilaporkan dieksploitasi tetapi belum ada konfirmasi vendor/CISA.
- "rejected": hanya PoC, hanya kritis tanpa bukti eksploitasi, broker/hadiah bug bounty,
  kompetisi (Pwn2Own), opini, ringkasan mingguan tanpa temuan baru, atau iklan.
Jawab HANYA JSON:
{"verdict":"confirmed|likely|rejected","cves":["CVE-..."],"vendor":"","product":"",
"title":"judul ringkas bahasa Indonesia maks 90 karakter","reason":"alasan singkat bahasa Indonesia maks 200 karakter"}

Sumber: {source}
Judul: {title}
Ringkasan: {summary}"""


def ai_analyze(item):
    prompt = (AI_PROMPT.replace("{source}", item["source"])
              .replace("{title}", item["title"])
              .replace("{summary}", item["summary"][:3000]))
    body = json.dumps({
        "model": MODEL,
        "max_tokens": 400,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    raw = fetch("https://api.anthropic.com/v1/messages", timeout=60, data=body, headers={
        "x-api-key": API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    })
    text = "".join(b.get("text", "") for b in json.loads(raw).get("content", []))
    m = re.search(r"\{.*\}", text, re.S)
    res = json.loads(m.group(0))
    if res.get("verdict") not in ("confirmed", "likely", "rejected"):
        res["verdict"] = "rejected"
    res["cves"] = sorted({c.upper() for c in res.get("cves", []) if CVE_RE.fullmatch(c or "")})
    res["method"] = "ai"
    return res


def fetch_article_text(url):
    """Ambil isi artikel (tag <article> jika ada) supaya ID CVE di badan artikel terbaca."""
    html = fetch(url, timeout=15)[:400000].decode("utf-8", "ignore")
    html = re.sub(r"<(script|style|nav|footer|aside)[^>]*>.*?</\1>", " ", html, flags=re.S | re.I)
    m = re.search(r"<article[^>]*>(.*?)</article>", html, re.S | re.I)
    return strip_html(m.group(1) if m else html)[:8000]


def rule_analyze(item):
    title, text = item["title"], f"{item['title']} {item['summary']}"
    cves = sorted({c.upper() for c in CVE_RE.findall(text)})
    strong = bool(STRONG_RE.search(text))
    zd_cues = bool(ZD_TITLE_RE.search(title) and CUES_RE.search(text))
    if NOISE_RE.search(title):
        verdict, reason = "rejected", "Judul menandakan iklan/panduan, bukan temuan baru."
    elif cves and (strong or zd_cues):
        verdict, reason = "likely", "Artikel menyebut CVE dan indikasi eksploitasi aktif (analisis kata kunci)."
    elif not cves and zd_cues:
        verdict, reason = "likely", "Judul menyebut zero-day dan isi menunjukkan eksploitasi/belum ada patch. Belum ada ID CVE, verifikasi manual."
    else:
        verdict, reason = "rejected", "Tidak ada bukti eksploitasi aktif di teks."
    return {"verdict": verdict, "cves": cves, "vendor": "", "product": "",
            "title": item["title"][:120], "reason": reason, "method": "rules", "rv": RULES_VERSION}


# ---------------------------------------------------------------- utama

def main():
    with open(SOURCES_FILE) as f:
        sources = json.load(f)

    prev = {}
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE) as f:
                prev = json.load(f)
        except Exception:
            prev = {}
    prev_items = {i["id"]: i for i in prev.get("items", [])}
    cache = prev.get("analysis_cache", {})  # link -> {verdict, ..., analyzed_at}

    kev = load_kev(sources["kev_url"])
    kev_ok = kev is not None
    kev = kev or {}

    entries = {}  # id -> entry

    def entry_for(eid, first_seen):
        e = entries.get(eid)
        if not e:
            old = prev_items.get(eid, {})
            e = {
                "id": eid, "cves": [], "title": old.get("title", ""), "vendor": "", "product": "",
                "verdict": "likely", "reason": "", "first_seen": old.get("first_seen", first_seen),
                "sources": [], "kev": None, "analysis": old.get("analysis", ""),
            }
            entries[eid] = e
        return e

    # 1) CISA KEV: entri baru dalam jendela waktu = confirmed
    for cve, v in kev.items():
        added = parse_date(v.get("dateAdded"))
        if not added or added < CUTOFF:
            continue
        e = entry_for(cve, iso(added))
        e.update({
            "cves": [cve],
            "title": v.get("vulnerabilityName") or e["title"],
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "verdict": "confirmed",
            "reason": "Masuk katalog CISA Known Exploited Vulnerabilities (eksploitasi aktif terkonfirmasi).",
            "description": v.get("shortDescription", ""),
            "kev": {
                "date_added": v.get("dateAdded"), "due_date": v.get("dueDate"),
                "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                "action": v.get("requiredAction", ""),
            },
        })
        e["first_seen"] = min(e["first_seen"], iso(added))
        e["sources"].append({
            "name": "CISA KEV", "date": iso(added),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}", "title": "CISA KEV + detail NVD",
        })

    # 2) Feed berita/vendor: saring kandidat lalu analisis
    articles = load_feeds(sources.get("feeds", []))
    ai_calls = 0
    fetched = 0
    for a in articles:
        if not a["link"] or not a["date"] or a["date"] < CUTOFF:
            continue
        if not CANDIDATE_RE.search(f"{a['title']} {a['summary']}"):
            continue
        res = cache.get(a["link"])
        stale = bool(res) and res.get("method") == "rules" and (
            (API_KEY and ai_calls < MAX_AI_CALLS) or res.get("rv") != RULES_VERSION)
        if not res or stale:
            no_cve = not CVE_RE.search(f"{a['title']} {a['summary']}")
            # Link Google News hanya halaman pengalihan, jadi isi artikelnya tidak diambil
            if no_cve and not NOISE_RE.search(a["title"]) and not a.get("outlet"):
                if fetched >= MAX_FETCH:
                    continue  # tunda ke run berikutnya, jangan di-cache tanpa isi artikel
                fetched += 1
                try:
                    a["summary"] = (a["summary"] + " " + fetch_article_text(a["link"]))[:9000]
                except Exception as ex:
                    log("Gagal ambil isi artikel:", a["link"], ex)
            if API_KEY and ai_calls < MAX_AI_CALLS:
                try:
                    res = ai_analyze(a)
                    ai_calls += 1
                except Exception as ex:
                    log("Analisis AI gagal, pakai aturan:", ex)
                    res = rule_analyze(a)
            else:
                res = rule_analyze(a)
            res["analyzed_at"] = iso(NOW)
            res["date"] = iso(a["date"])
            cache[a["link"]] = res
        if res["verdict"] == "rejected":
            continue

        src = {"name": a.get("outlet") or a["source"], "url": a["link"], "title": a["title"],
               "date": iso(a["date"]), "primary": bool(a.get("primary"))}
        ids = res["cves"] or ["ART-" + hashlib.sha1(a["link"].encode()).hexdigest()[:10]]
        for eid in ids:
            e = entry_for(eid, iso(a["date"]))
            if eid.startswith("CVE-"):
                e["cves"] = sorted(set(e["cves"]) | {eid})
            if eid in kev:
                kv = kev[eid]
                e["verdict"] = "confirmed"
                e["reason"] = e["reason"] or "Dilaporkan sebagai zero-day dan tercatat di CISA KEV."
                e["vendor"] = e["vendor"] or kv.get("vendorProject", "")
                e["product"] = e["product"] or kv.get("product", "")
                e["title"] = e["title"] or kv.get("vulnerabilityName", "")
            elif e["verdict"] != "confirmed":
                v = res["verdict"]
                if v == "likely" and a.get("primary") and res.get("method") == "ai":
                    v = "confirmed"  # pengumuman langsung dari vendor/peneliti utama
                e["verdict"] = v
                e["reason"] = res.get("reason", "")
            e["title"] = e["title"] or res.get("title") or a["title"]
            e["vendor"] = e["vendor"] or res.get("vendor", "")
            e["product"] = e["product"] or res.get("product", "")
            e["analysis"] = res.get("method", "")
            e["first_seen"] = min(e["first_seen"], iso(a["date"]))
            if src["url"] not in {s["url"] for s in e["sources"]}:
                e["sources"].append(src)

    # Jika KEV gagal diambil kali ini, pertahankan entri KEV lama agar tidak hilang
    if not kev_ok:
        for eid, old in prev_items.items():
            if eid not in entries and old.get("kev"):
                entries[eid] = old

    # Verifikasi silang: berita saja tidak cukup untuk tampil sebagai temuan
    for e in entries.values():
        if e["verdict"] == "confirmed" or e.get("kev"):
            continue
        outlets = {x["name"] for x in e["sources"]}
        has_primary = any(x.get("primary") for x in e["sources"])
        if e["cves"] and (len(outlets) >= 2 or has_primary):
            e["verdict"] = "likely"
            e["reason"] = (f"CVE dilaporkan oleh {len(outlets)} sumber berbeda"
                           + (", termasuk sumber utama." if has_primary else "."))
        else:
            e["verdict"] = "watch"
            e["reason"] = ("Belum terverifikasi: " + ("tidak ada ID CVE" if not e["cves"] else "baru satu sumber")
                           + ". Cek manual sebelum dipercaya.")

    # Buang yang di luar jendela 30 hari, urutkan terbaru dulu
    items = [e for e in entries.values() if (parse_date(e["first_seen"]) or NOW) >= CUTOFF]
    for e in items:
        e["sources"].sort(key=lambda s: s.get("date", ""), reverse=True)
        e["last_update"] = max([s.get("date", "") for s in e["sources"]] + [e["first_seen"]])
    items.sort(key=lambda e: e["last_update"], reverse=True)

    cache = {k: v for k, v in cache.items() if (parse_date(v.get("date")) or NOW) >= CUTOFF}

    out = {
        "generated_at": iso(NOW),
        "window_days": WINDOW_DAYS,
        "analysis_mode": "ai" if API_KEY else "rules",
        "kev_status": "ok" if kev_ok else "error",
        "counts": {
            "total": len(items),
            "confirmed": sum(1 for i in items if i["verdict"] == "confirmed"),
            "likely": sum(1 for i in items if i["verdict"] == "likely"),
            "watch": sum(1 for i in items if i["verdict"] == "watch"),
        },
        "items": items,
        "analysis_cache": cache,
    }
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    tmp = OUTPUT_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    os.replace(tmp, OUTPUT_FILE)
    log(f"Selesai: {out['counts']} | AI calls: {ai_calls} | mode: {out['analysis_mode']}")


if __name__ == "__main__":
    main()
