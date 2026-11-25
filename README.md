# quotegate

Fails your LLM-written report (or article) when a cited quote or claimed number isn't on the page.

An HTTP `200` proves the page exists. It does not prove the quote is on it — a live page with a fabricated citation returns `200` too. **Link-checking is not fact-checking.**

`quotegate` fetches each cited page, strips HTML nav/chrome/scripts, normalizes typography, and checks whether the claimed quote or numbers actually appear on the page. JS-rendered shells, paywalls, HTTP 403/429 blocks, and cross-language translations are marked `SKIP` — never falsely accused as `FAIL`.

**Live Web Scanner (no install):** https://pulsare-lab.space/check

## Zero-dependency install & run (Python 3.10+ stdlib only)

```bash
git clone https://github.com/enigmagen3-dot/quotegate.git
cd quotegate
./quotegate fixture/report.md
```

It works on **any** format:
- Standard Markdown LLM output (`[source](https://...)` + claims / `"quotes"` / numbers)
- Raw live article URL audit (`./quotegate https://habr.com/...` checks outgoing cited claims)
- Structured CI blocks (`[S01] URL: ...` + `Quote:` / `Цитата:`)

## Example output

```text
OK:   S01 — exact quote confirmed in page text (https://example.com)
      Match: «Example Domain This domain is for use in documentation examples without needing permission»
FAIL: S02 — FABRICATED QUOTE: page returned HTTP 200 (5631 chars), but quote not found (https://vc.ru/chatgpt/3251595-kak-kupit-chatgpt-plus-v-rossii)
      Claim: Клодыч продаёт ChatGPT Plus за 100 рублей в месяц
SKIP: S03 — HTTP 403 (paywall / anti-bot / auth) (https://www.sciencedirect.com/...)
----
TOTAL: OK=1 FAIL=1 SKIP=1
VERDICT: FAILED
```

Exits `1` on any `FAIL`, `0` on `OK` or `SKIP` — drops directly into GitHub Actions / pre-commit / agent verification gates:

```bash
./quotegate my_ai_report.md --json
```

## Features

- **Zero pip dependencies** (pure Python standard library).
- **Anti-false-positive design:** strips `<nav>`, `<header>`, `<footer>`, `<aside>`, `<script>`, detects JS-only/Cloudflare shells (`<160` readable chars -> `SKIP`), skips paywalled `401/403/429`, and safely skips cross-language translated citations.
- **SSRF protection included** for hosted web deployments (`web_server.py` rejects private, loopback, link-local, Tailscale CGNAT `100.64.0.0/10`, and unsafe redirects).

## Tests

```bash
python3 -m unittest -v test_quotegate.py
```

## License

MIT (`LICENSE`).

---

Built by PULSAR Lab. Full agent state machine (`P-S-E-V`), 2-loop reviewer, anti-slop gate, and team CI skill packs (**Iron Suit**): https://t.me/Forge_Systems_0bot?start=quotegate_gh
