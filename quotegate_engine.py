#!/usr/bin/env python3
"""
quotegate — Universal Citation & Factual Grounding Gate (v1.0)
Checks claims and quotes in Markdown/text LLM outputs or live web articles
against actual fetched page content, with SSRF protection, chrome/nav stripping,
cross-language protection, and JS/paywall SKIP handling.

Verdicts per check:
  OK   - exact quote or claimed numbers/facts confirmed in fetched page text
  FAIL - page delivered readable content, but claimed quote/facts are absent (HTTP 200 hallucination)
  SKIP - blocked, paywalled, JS-only shell, timeout, cross-language translation, or generic link

Zero external dependencies (Python 3.10+ stdlib only). MIT License.
"""
from __future__ import annotations

import concurrent.futures
import html
import ipaddress
import json
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from typing import List, Optional, Tuple

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 quotegate/1.0"
)
MAX_BYTES = 1_500_000
FETCH_TIMEOUT = 8.0
MAX_CHECKS = 15

BLOCKED_HTTP_STATUS = {401, 402, 403, 407, 429, 451}
JS_SHELL_MARKERS = (
    "enable javascript",
    "please turn javascript on",
    "you need to enable javascript",
    "cf-browser-verification",
    "just a moment...",
    "checking your browser",
    "access denied | cloudflare",
    "ddos-guard",
    "__next_error__",
)

NOISE_TAGS = {"script", "style", "noscript", "svg", "iframe", "template"}
CHROME_TAGS = {"nav", "header", "footer", "aside"}
BLOCK_TAGS = {
    "p", "li", "div", "section", "article", "blockquote", "h1", "h2", "h3", "h4",
    "h5", "h6", "tr", "td", "th", "br", "hr", "figcaption", "pre", "dd", "dt",
}


def _is_safe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


def validate_public_url(url: str) -> Tuple[bool, str]:
    try:
        parsed = urllib.parse.urlparse(url.strip())
    except Exception:
        return False, "invalid URL"
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False, "unsupported scheme or empty host"
    host = parsed.hostname.lower()
    if host in ("localhost", "localhost.localdomain") or host.endswith(".local") or host.endswith(".internal"):
        return False, "blocked internal hostname"
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        return False, f"DNS resolution failed: {e}"
    if not infos:
        return False, "DNS returned no addresses"
    for info in infos:
        addr = info[4][0].split("%")[0]
        if not _is_safe_ip(addr):
            return False, f"blocked non-public IP ({addr})"
    return True, "ok"


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        joined = urllib.parse.urljoin(req.full_url, newurl)
        ok, reason = validate_public_url(joined)
        if not ok:
            raise urllib.error.URLError(f"Blocked redirect target: {reason}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _TextExtractor(HTMLParser):
    def __init__(self, base_url: str = "") -> None:
        super().__init__(convert_charrefs=False)
        self.base_url = base_url
        self._skip_depth = 0
        self._chrome_depth = 0
        self.chunks: List[str] = []
        self.links: List[Tuple[str, str, str]] = []  # (url, anchor, block_context)
        self._cur_href: Optional[str] = None
        self._cur_anchor: List[str] = []
        self._in_link = False
        self._block_text: List[str] = []
        self._block_links: List[Tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        t = tag.lower()
        if t in NOISE_TAGS:
            self._skip_depth += 1
            return
        if t in CHROME_TAGS:
            self._chrome_depth += 1
        if self._skip_depth > 0:
            return
        if t in BLOCK_TAGS:
            self.chunks.append(" ")
            self._flush_block()
        if t == "a" and self._chrome_depth == 0:
            href = dict(attrs).get("href", "").strip()
            if href and not href.startswith("#") and not href.lower().startswith("javascript:"):
                abs_url = urllib.parse.urljoin(self.base_url, href)
                if abs_url.startswith(("http://", "https://")):
                    self._cur_href = abs_url
                    self._cur_anchor = []
                    self._in_link = True

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in NOISE_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
            return
        if t in CHROME_TAGS and self._chrome_depth > 0:
            self._chrome_depth -= 1
        if self._skip_depth > 0:
            return
        if t == "a" and self._in_link:
            anchor = " ".join("".join(self._cur_anchor).split())
            if self._cur_href:
                self._block_links.append((self._cur_href, anchor))
            self._cur_href = None
            self._cur_anchor = []
            self._in_link = False
            self.chunks.append(" ")
            self._block_text.append(" ")
        elif t in BLOCK_TAGS:
            self.chunks.append(" ")
            self._flush_block()
        elif t in {"span", "label", "button", "small", "time"}:
            self.chunks.append(" ")
            if self._chrome_depth == 0:
                self._block_text.append(" ")

    def _flush_block(self) -> None:
        block_str = " ".join("".join(self._block_text).split())
        if block_str and self._block_links:
            for href, anchor in self._block_links:
                self.links.append((href, anchor, block_str))
        self._block_text = []
        self._block_links = []

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        self.chunks.append(data)
        if self._chrome_depth == 0:
            self._block_text.append(data)
            if self._in_link:
                self._cur_anchor.append(data)

    def handle_entityref(self, name: str) -> None:
        self.handle_data(html.unescape(f"&{name};"))

    def handle_charref(self, name: str) -> None:
        self.handle_data(html.unescape(f"&#{name};"))


def normalize_text(text: str) -> str:
    text = html.unescape(text)
    replacements = {
        "\u00a0": " ",
        "\u202f": " ",
        "\u2009": " ",
        "\u200a": " ",
        "\u2007": " ",
        "\u205f": " ",
        "\u3000": " ",
        "\u200b": "",
        "\u200c": "",
        "\u200d": "",
        "\u2060": "",
        "\ufeff": "",
        "\xad": "",
        "«": '"',
        "»": '"',
        "“": '"',
        "”": '"',
        "„": '"',
        "’": "'",
        "‘": "'",
        "—": "-",
        "–": "-",
        "−": "-",
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2212": "-",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return re.sub(r"\s+", " ", text).strip()


def normalize_for_match(text: str) -> str:
    return normalize_text(text).lower().replace("ё", "е")


def _cyrillic_ratio(text: str) -> float:
    letters = re.findall(r"[A-Za-zА-Яа-яЁё]", text)
    if not letters:
        return 0.0
    cyr = sum(1 for ch in letters if ("а" <= ch.lower() <= "я") or ch.lower() == "ё")
    return cyr / len(letters)


@dataclass
class FetchedPage:
    url: str
    final_url: str
    status: int
    text: str
    links: List[Tuple[str, str, str]]
    skip_reason: Optional[str] = None


def fetch_page(url: str, timeout: float = FETCH_TIMEOUT) -> FetchedPage:
    ok, reason = validate_public_url(url)
    if not ok:
        return FetchedPage(url=url, final_url=url, status=0, text="", links=[], skip_reason=reason)

    opener = urllib.request.build_opener(_SafeRedirectHandler())
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,text/plain,text/markdown;q=0.9,*/*;q=0.8",
            "Accept-Language": "ru,en;q=0.9",
        },
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200) or 200
            final_url = resp.geturl()
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if ctype and not any(t in ctype for t in ("text/", "html", "xml", "json", "markdown")):
                return FetchedPage(url, final_url, status, "", [], f"non-text content-type ({ctype.split(';')[0]})")
            raw = resp.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raw = raw[:MAX_BYTES]
            charset = resp.headers.get_content_charset() or "utf-8"
            try:
                body = raw.decode(charset, errors="replace")
            except LookupError:
                body = raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        code = e.code or 0
        if code in BLOCKED_HTTP_STATUS:
            return FetchedPage(url, url, code, "", [], f"HTTP {code} (paywall / anti-bot / auth)")
        if code == 404 or code >= 500:
            return FetchedPage(url, url, code, "", [], f"HTTP {code} unavailable")
        return FetchedPage(url, url, code, "", [], f"HTTP {code}")
    except Exception as e:
        return FetchedPage(url, url, 0, "", [], f"network error: {str(e)[:80]}")

    if status in BLOCKED_HTTP_STATUS:
        return FetchedPage(url, final_url, status, "", [], f"HTTP {status} (paywall / anti-bot)")

    if "<html" in body.lower() or "<body" in body.lower() or "<p" in body.lower() or "<div" in body.lower():
        parser = _TextExtractor(base_url=final_url)
        try:
            parser.feed(body)
            parser.close()
        except Exception:
            pass
        clean = normalize_text("".join(parser.chunks))
        links = parser.links
    else:
        clean = normalize_text(body)
        links = []

    low = clean.lower()
    if len(clean) < 160:
        return FetchedPage(url, final_url, status, clean, links, f"page yielded too little readable text ({len(clean)} chars; likely JS-rendered)")
    if any(m in low for m in JS_SHELL_MARKERS) and len(clean) < 1200:
        return FetchedPage(url, final_url, status, clean, links, "JS/Cloudflare anti-bot shell detected")

    return FetchedPage(url, final_url, status, clean, links, None)


@dataclass
class CheckSpec:
    id: str
    url: str
    quote: str = ""
    context: str = ""
    kind: str = "markdown"


@dataclass
class CheckResult:
    id: str
    url: str
    status: str  # OK | FAIL | SKIP
    http_status: int
    reason: str
    claim: str
    matched_snippet: str = ""


_NUM_TOKEN_RE = re.compile(
    r"(?:\$|€|₽)?\b\d+(?:(?:[\s\u00a0\u202f\u2009]|,)\d{3})*(?:[.,]\d+)?\s*(?:[%₽$€]|тыс|млн|млрд)?\b"
)
_QUOTED_SPAN_RE = re.compile(r'(?:«([^»]{12,280})»|"([^"]{12,280})"|„([^“]{12,280})“)')
_MD_LINK_RE = re.compile(r"\[([^\]]{1,140})\]\((https?://[^\s)]+)\)")
_RAW_URL_RE = re.compile(r"(https?://[^\s<>()\[\]\"']+)")


def _strip_trailing_punct(url: str) -> str:
    return url.rstrip(".,;:!?\"'»)")


def _extract_meaningful_numbers(text: str) -> List[str]:
    nums: List[str] = []
    clean = _MD_LINK_RE.sub(r"\1", text)
    clean = _RAW_URL_RE.sub(" ", clean)
    for m in _NUM_TOKEN_RE.finditer(clean):
        raw_tok = m.group(0).strip()
        num_core = re.sub(r"[^0-9.,]", "", raw_tok)
        digits = re.sub(r"\D", "", num_core)
        if not digits:
            continue
        if len(digits) == 1 and not any(ch in raw_tok for ch in "%$₽€"):
            continue
        dec_match = re.match(r"^(\d+)[.,](\d{1,2})$", num_core)
        token = f"{dec_match.group(1)}.{dec_match.group(2)}" if dec_match else digits
        nums.append(token)
    seen = set()
    out = []
    for n in nums:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _significant_words(text: str) -> List[str]:
    clean = _MD_LINK_RE.sub(r"\1", text)
    clean = _RAW_URL_RE.sub(" ", clean)
    words = re.findall(r"[A-Za-zА-Яа-яЁё0-9-]{5,}", clean.lower().replace("ё", "е"))
    stop = {
        "https", "http", "quotegate", "report", "source", "цитата", "источник",
        "ссылка", "почему", "который", "которая", "которые", "можно", "нужно",
        "также", "через", "более", "после", "перед", "около", "about", "there",
        "their", "which", "where", "these", "those", "could", "would", "should",
    }
    return [w for w in words if w not in stop]


def parse_checks_from_text(text: str) -> List[CheckSpec]:
    text = text.replace("\r\n", "\n")
    lines = text.split("\n")

    legacy_specs: List[CheckSpec] = []
    cur_id = cur_url = cur_quote = ""

    def flush_legacy():
        nonlocal cur_id, cur_url, cur_quote
        if cur_id:
            legacy_specs.append(CheckSpec(id=cur_id, url=cur_url, quote=cur_quote, context=cur_quote, kind="legacy_dsl"))
        cur_id = cur_url = cur_quote = ""

    for line in lines:
        s = line.strip()
        m_id = re.match(r"^\[?(S\d+)\]?\s*(.*)$", s)
        if m_id and ("URL:" in line or re.match(r"^\[S\d+\]", s)):
            flush_legacy()
            cur_id = m_id.group(1)
            m_u = _RAW_URL_RE.search(line)
            if m_u:
                cur_url = _strip_trailing_punct(m_u.group(1))
        elif cur_id and re.match(r"^[-*]?\s*URL\s*:", s, re.I):
            m_u = _RAW_URL_RE.search(s)
            if m_u:
                cur_url = _strip_trailing_punct(m_u.group(1))
        elif cur_id and re.match(r"^[-*]?\s*(?:Цитата|Quote)\s*:", s, re.I):
            val = s.split(":", 1)[1].strip().strip("«»\"' ")
            cur_quote = val
    flush_legacy()

    if legacy_specs:
        return legacy_specs[:MAX_CHECKS]

    blocks: List[str] = []
    cur_para: List[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            if cur_para:
                blocks.append(" ".join(cur_para))
                cur_para = []
        elif re.match(r"^(?:[-*+•]|\d+[.)])\s+", stripped):
            if cur_para:
                blocks.append(" ".join(cur_para))
                cur_para = []
            blocks.append(re.sub(r"^(?:[-*+•]|\d+[.)])\s+", "", stripped))
        else:
            cur_para.append(stripped)
    if cur_para:
        blocks.append(" ".join(cur_para))

    specs: List[CheckSpec] = []
    idx = 1
    seen_pairs = set()

    for block in blocks:
        found_urls: List[Tuple[str, str]] = []
        md_spans = []
        for m in _MD_LINK_RE.finditer(block):
            anchor, url = m.group(1).strip(), _strip_trailing_punct(m.group(2))
            found_urls.append((url, anchor))
            md_spans.append((m.start(), m.end()))
        for m in _RAW_URL_RE.finditer(block):
            if any(a <= m.start() < b for a, b in md_spans):
                continue
            found_urls.append((_strip_trailing_punct(m.group(1)), ""))

        if not found_urls:
            continue

        quotes_in_block = []
        for qm in _QUOTED_SPAN_RE.finditer(block):
            q = next(g for g in qm.groups() if g is not None).strip()
            if len(q) >= 12:
                quotes_in_block.append(q)

        sentences = re.split(r"(?<=[.!?])\s+(?=[A-ZА-ЯЁ\[])", block)
        for url, anchor in found_urls:
            if url.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".pdf", ".zip")):
                continue
            ctx = block
            for sent in sentences:
                if url in sent:
                    ctx = sent
                    break
            ctx_quote = ""
            for qm in _QUOTED_SPAN_RE.finditer(ctx):
                ctx_quote = next(g for g in qm.groups() if g is not None).strip()
                break
            if not ctx_quote and len(found_urls) == 1 and quotes_in_block:
                ctx_quote = quotes_in_block[0]

            pair_key = (url, ctx_quote or ctx[:140])
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            kind = "explicit_quote" if ctx_quote else "factual_claim"
            specs.append(CheckSpec(id=f"S{idx:02d}", url=url, quote=ctx_quote, context=ctx or anchor, kind=kind))
            idx += 1
            if len(specs) >= MAX_CHECKS:
                return specs

    return specs


def _find_number_match(num_token: str, page_norm_compact_digits: str, page_norm: str) -> Optional[int]:
    if "." in num_token:
        whole, frac = num_token.split(".", 1)
        m_dec = re.search(rf"(?<!\d){re.escape(whole)}[.,]{re.escape(frac)}(?!\d)", page_norm)
        if m_dec:
            return m_dec.start()
        return None
    m = re.search(rf"(?<!\d){re.escape(num_token)}(?!\d)", page_norm)
    if m:
        return m.start()
    if len(num_token) >= 4:
        # Handle space- or comma-grouped thousands like "1 669", "15 000", or "1,500"
        spaced = r"[\s\u00a0,]?".join(re.escape(ch) for ch in num_token)
        m2 = re.search(rf"(?<!\d){spaced}(?!\d)", page_norm)
        if m2:
            return m2.start()
    return None


def evaluate_spec(spec: CheckSpec, page: FetchedPage) -> CheckResult:
    claim_display = spec.quote or spec.context or "(no claim text)"
    if len(claim_display) > 220:
        claim_display = claim_display[:217] + "..."

    if page.skip_reason:
        return CheckResult(spec.id, spec.url, "SKIP", page.status, page.skip_reason, claim_display)

    page_norm = normalize_for_match(page.text)

    # Cross-language protection: don't fail a Cyrillic translation against an English page
    if len(page.text) >= 160:
        claim_cyr = _cyrillic_ratio(spec.quote or spec.context)
        page_cyr = _cyrillic_ratio(page.text[:4000])
        if claim_cyr > 0.35 and page_cyr < 0.05:
            return CheckResult(
                spec.id,
                spec.url,
                "SKIP",
                page.status,
                "cross-language citation (Cyrillic claim vs non-Cyrillic page; skipped to prevent false accusation)",
                claim_display,
            )

    if spec.quote:
        q_norm = normalize_for_match(spec.quote)
        if not q_norm:
            return CheckResult(spec.id, spec.url, "SKIP", page.status, "empty quote text", claim_display)
        pos = page_norm.find(q_norm)
        if pos != -1:
            snippet = page.text[max(0, pos - 40): min(len(page.text), pos + len(q_norm) + 60)].strip()
            return CheckResult(spec.id, spec.url, "OK", page.status, "exact quote confirmed in page text", claim_display, snippet)
        q_words = [w for w in re.findall(r"[a-zа-яё0-9]+", q_norm) if len(w) > 1]
        if len(q_words) >= 5:
            pattern = r"\W+".join(re.escape(w) for w in q_words)
            m = re.search(pattern, page_norm)
            if m:
                snippet = page.text[max(0, m.start() - 30): min(len(page.text), m.end() + 50)].strip()
                return CheckResult(spec.id, spec.url, "OK", page.status, "quote confirmed in page text (normalized punctuation)", claim_display, snippet)
        return CheckResult(
            spec.id,
            spec.url,
            "FAIL",
            page.status,
            f"FABRICATED QUOTE: page returned HTTP {page.status} ({len(page.text)} chars), but quote not found",
            claim_display,
        )

    nums = _extract_meaningful_numbers(spec.context)
    sig_words = _significant_words(spec.context)

    if not nums and len(sig_words) < 3:
        return CheckResult(spec.id, spec.url, "SKIP", page.status, "generic reference link (no specific quote or numbers to falsify)", claim_display)

    if nums:
        missing_nums = []
        first_pos = -1
        for n in nums:
            p = _find_number_match(n, "", page_norm)
            if p is None:
                missing_nums.append(n)
            elif first_pos == -1:
                first_pos = p
        matched_words = [w for w in sig_words if w[:5] in page_norm]
        if missing_nums:
            return CheckResult(
                spec.id,
                spec.url,
                "FAIL",
                page.status,
                f"FABRICATED FIGURE: claimed number(s) {', '.join(missing_nums)} not found on live HTTP {page.status} page",
                claim_display,
            )
        if sig_words and len(matched_words) == 0:
            return CheckResult(
                spec.id,
                spec.url,
                "FAIL",
                page.status,
                f"CONTEXT MISMATCH: numbers matched, but none of key terms ({', '.join(sig_words[:3])}) exist on HTTP {page.status} page",
                claim_display,
            )
        snippet = page.text[max(0, first_pos - 50): min(len(page.text), first_pos + 90)].strip() if first_pos != -1 else ""
        return CheckResult(spec.id, spec.url, "OK", page.status, f"claimed figure(s) ({', '.join(nums[:3])}) and context verified on page", claim_display, snippet)

    matched = [w for w in sig_words if w[:5] in page_norm]
    ratio = len(matched) / max(1, len(sig_words))
    if ratio >= 0.45 and len(matched) >= 2:
        wpos = page_norm.find(matched[0][:5])
        snippet = page.text[max(0, wpos - 40): min(len(page.text), wpos + 100)].strip() if wpos != -1 else ""
        return CheckResult(spec.id, spec.url, "OK", page.status, f"key claim terms confirmed on page ({len(matched)}/{len(sig_words)})", claim_display, snippet)
    if len(sig_words) >= 4 and len(matched) <= 1:
        return CheckResult(spec.id, spec.url, "FAIL", page.status, f"UNSUPPORTED CLAIM: HTTP {page.status} page lacks claimed terms ({', '.join(sig_words[:4])})", claim_display)
    return CheckResult(spec.id, spec.url, "SKIP", page.status, "insufficient literal anchors to falsify reliably", claim_display)


def audit_input(raw_input: str) -> dict:
    raw_input = (raw_input or "").strip()
    if not raw_input:
        return {
            "mode": "empty",
            "verdict": "SKIPPED",
            "summary": {"ok": 0, "fail": 0, "skip": 0, "total": 0},
            "results": [],
            "error": "Empty input",
        }

    is_single_url = bool(re.match(r"^https?://\S+$", raw_input))
    mode = "url_audit" if is_single_url else "report_audit"

    specs: List[CheckSpec] = []
    source_meta: dict = {}

    if is_single_url:
        page = fetch_page(raw_input)
        source_meta = {
            "source_url": raw_input,
            "http_status": page.status,
            "text_chars": len(page.text),
            "skip_reason": page.skip_reason,
        }
        if page.skip_reason:
            return {
                "mode": mode,
                "verdict": "SKIPPED",
                "source": source_meta,
                "summary": {"ok": 0, "fail": 0, "skip": 1, "total": 1},
                "results": [asdict(CheckResult("S01", raw_input, "SKIP", page.status, f"Source article skipped: {page.skip_reason}", raw_input))],
            }
        src_host = (urllib.parse.urlparse(page.final_url).hostname or "").lower()
        idx = 1
        seen_urls = set()
        for href, anchor, ctx in page.links:
            h_host = (urllib.parse.urlparse(href).hostname or "").lower()
            if not h_host or h_host == src_host or h_host.endswith("." + src_host):
                continue
            if any(bad in h_host for bad in ("t.me", "vk.com", "youtube.com", "twitter.com", "x.com", "facebook.com", "instagram.com")):
                if not _extract_meaningful_numbers(ctx):
                    continue
            if href in seen_urls or href.endswith((".png", ".jpg", ".webp", ".svg", ".pdf")):
                continue
            claim_ctx = ctx if len(ctx) >= len(anchor) else anchor
            if len(claim_ctx) < 24:
                continue
            if not _extract_meaningful_numbers(claim_ctx) and not _QUOTED_SPAN_RE.search(claim_ctx) and len(_significant_words(claim_ctx)) < 4:
                continue
            seen_urls.add(href)
            q_match = _QUOTED_SPAN_RE.search(claim_ctx)
            quote = next((g for g in q_match.groups() if g is not None), "").strip() if q_match else ""
            # Only treat quote as exact quote in url_audit if >= 18 chars (avoid UI labels)
            if len(quote) < 18:
                quote = ""
            specs.append(CheckSpec(id=f"S{idx:02d}", url=href, quote=quote, context=claim_ctx, kind="explicit_quote" if quote else "factual_claim"))
            idx += 1
            if len(specs) >= MAX_CHECKS:
                break
        if not specs:
            return {
                "mode": mode,
                "verdict": "SKIPPED",
                "source": source_meta,
                "summary": {"ok": 0, "fail": 0, "skip": 1, "total": 1},
                "results": [asdict(CheckResult("S01", raw_input, "SKIP", page.status, "No external factual citations with numbers or quotes found inside article body", raw_input))],
            }
    else:
        specs = parse_checks_from_text(raw_input)
        if not specs:
            return {
                "mode": mode,
                "verdict": "SKIPPED",
                "summary": {"ok": 0, "fail": 0, "skip": 0, "total": 0},
                "results": [],
                "error": "No http/https URLs found to verify in text",
            }

    unique_urls = list(dict.fromkeys(s.url for s in specs))
    pages: dict[str, FetchedPage] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        future_map = {pool.submit(fetch_page, u): u for u in unique_urls}
        for fut in concurrent.futures.as_completed(future_map):
            u = future_map[fut]
            try:
                pages[u] = fut.result()
            except Exception as e:
                pages[u] = FetchedPage(u, u, 0, "", [], f"fetch error: {str(e)[:60]}")

    results = [evaluate_spec(s, pages[s.url]) for s in specs]
    ok_cnt = sum(1 for r in results if r.status == "OK")
    fail_cnt = sum(1 for r in results if r.status == "FAIL")
    skip_cnt = sum(1 for r in results if r.status == "SKIP")
    verdict = "FAILED" if fail_cnt > 0 else ("PASSED" if ok_cnt > 0 else "SKIPPED")

    return {
        "mode": mode,
        "verdict": verdict,
        "source": source_meta or None,
        "summary": {"ok": ok_cnt, "fail": fail_cnt, "skip": skip_cnt, "total": len(results)},
        "results": [asdict(r) for r in results],
    }


def format_cli_report(data: dict) -> str:
    lines: List[str] = []
    if data.get("error"):
        lines.append(f"SKIP: {data['error']}")
    for r in data.get("results", []):
        lines.append(f"{r['status']}: {r['id']} — {r['reason']} ({r['url']})")
        if r["status"] == "FAIL":
            lines.append(f"      Claim: {r['claim']}")
        elif r["status"] == "OK" and r.get("matched_snippet"):
            snip = r["matched_snippet"][:120].replace("\n", " ")
            lines.append(f"      Match: «{snip}»")
    s = data.get("summary", {})
    lines.append("----")
    lines.append(f"TOTAL: OK={s.get('ok', 0)} FAIL={s.get('fail', 0)} SKIP={s.get('skip', 0)}")
    lines.append(f"VERDICT: {data.get('verdict', 'SKIPPED')}")
    return "\n".join(lines)


def main(argv: List[str]) -> int:
    args = argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print("usage: quotegate <report.md | https://article-url | -> [--json]")
        return 0
    as_json = "--json" in args
    target = next((a for a in args if a == "-" or not a.startswith("-")), "")
    if not target:
        print("usage: quotegate <report.md | https://article-url | -> [--json]", file=sys.stderr)
        return 2
    if target == "-":
        raw = sys.stdin.read()
    elif re.match(r"^https?://", target):
        raw = target
    else:
        with open(target, encoding="utf-8") as f:
            raw = f.read()

    data = audit_input(raw)
    if as_json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print(format_cli_report(data))
    return 1 if data.get("summary", {}).get("fail", 0) > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
