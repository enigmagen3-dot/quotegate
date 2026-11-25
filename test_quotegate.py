import json
import os
import tempfile
import threading
import unittest
import urllib.request
from unittest.mock import patch

import quotegate_engine as qg


class TestQuotegate(unittest.TestCase):
    def test_ssrf_blocks_private_and_tailscale(self):
        for bad in (
            "http://127.0.0.1:8080/healthz",
            "http://localhost/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/",
            "http://100.100.27.56/",
            "file:///etc/passwd",
        ):
            ok, _reason = qg.validate_public_url(bad)
            self.assertFalse(ok, f"Should block SSRF target: {bad}")

    def test_html_extractor_strips_nav_and_separates_tags(self):
        html_doc = """
        <html><body>
          <nav><a href="https://mts.ru">Настройка языка</a><span>Техническая поддержка</span></nav>
          <main><article><p>Согласно <a href="https://real.example/study">исследованию</a>, рост составил 47% за 2026 год.</p></article></main>
          <footer><a href="https://spam.example">Footer 100% link</a></footer>
        </body></html>
        """
        p = qg._TextExtractor(base_url="https://origin.example/post")
        p.feed(html_doc)
        p.close()
        clean = qg.normalize_text(" ".join(p.chunks))
        self.assertIn("языка Техническая", clean)
        self.assertNotIn("языкаТехническая", clean)
        self.assertEqual(len(p.links), 1)
        self.assertEqual(p.links[0][0], "https://real.example/study")

    def test_parse_arbitrary_markdown_and_legacy_dsl(self):
        md = """
        Here is our AI market scan:
        - According to [VcRu review](https://example.org/post), ChatGPT Plus costs 333 ₽ per month while "no password handoff is required".
        - Another claim with bare link https://example.com/report saying revenue grew 47% in 2026 across 1200 users.
        """
        specs = qg.parse_checks_from_text(md)
        self.assertEqual(len(specs), 2)
        self.assertEqual(specs[0].url, "https://example.org/post")
        self.assertEqual(specs[0].quote, "no password handoff is required")
        self.assertEqual(specs[1].url, "https://example.com/report")
        self.assertEqual(specs[1].kind, "factual_claim")

        legacy = """
        [S01] URL: https://example.com/doc
        Цитата: «Example Domain is for use in illustrative examples»
        """
        lspecs = qg.parse_checks_from_text(legacy)
        self.assertEqual(len(lspecs), 1)
        self.assertEqual(lspecs[0].id, "S01")
        self.assertEqual(lspecs[0].kind, "legacy_dsl")

    def test_evaluate_ok_fail_skip_and_cross_language(self):
        ok_page = qg.FetchedPage(
            url="https://example.com/a",
            final_url="https://example.com/a",
            status=200,
            text="Our benchmark covered 1200 users and showed revenue grew 47% across Q3 2026 teams. No password handoff is required.",
            links=[],
        )
        fail_page = qg.FetchedPage(
            url="https://example.com/b",
            final_url="https://example.com/b",
            status=200,
            text="Notice how 13900 is different from 39 and nothing about fabricated quotes appears anywhere in this readable article body that has over 200 characters easily.",
            links=[],
        )
        js_skip_page = qg.FetchedPage(
            url="https://example.com/c",
            final_url="https://example.com/c",
            status=403,
            text="",
            links=[],
            skip_reason="HTTP 403 (paywall / anti-bot / auth)",
        )
        en_page = qg.FetchedPage(
            url="https://example.com/d",
            final_url="https://example.com/d",
            status=200,
            text="Scientists discovered fungal electrical signaling patterns across soil hyphae networks in controlled lab trials over several months of observation in the United Kingdom.",
            links=[],
        )

        report = """
        - Fact A: "No password handoff is required" per [Doc](https://example.com/a)
        - Fact B: Costs $39 one-time according to [Fake](https://example.com/b)
        - Fact C: "Blocked quote" per [Paywall](https://example.com/c)
        - Fact D: «Учёные обнаружили электрические сигналы грибов» по данным [EN](https://example.com/d)
        """
        page_map = {
            "https://example.com/a": ok_page,
            "https://example.com/b": fail_page,
            "https://example.com/c": js_skip_page,
            "https://example.com/d": en_page,
        }

        with patch("quotegate_engine.fetch_page", side_effect=lambda u: page_map[u]):
            out = qg.audit_input(report)

        self.assertEqual(out["verdict"], "FAILED")
        self.assertEqual(out["summary"], {"ok": 1, "fail": 1, "skip": 2, "total": 4})
        self.assertEqual(out["results"][0]["status"], "OK")
        self.assertEqual(out["results"][1]["status"], "FAIL")
        self.assertEqual(out["results"][2]["status"], "SKIP")
        self.assertEqual(out["results"][3]["status"], "SKIP")

    def test_web_server_health_and_run_endpoint(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["QUOTEGATE_DB"] = os.path.join(tmpdir, "test.sqlite3")
            import importlib
            import web_server
            importlib.reload(web_server)

            srv = web_server.ThreadingHTTPServer(("127.0.0.1", 0), web_server.QuotegateHandler)
            port = srv.server_address[1]
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/check/healthz") as r:
                    self.assertEqual(r.status, 200)
                    self.assertTrue(json.loads(r.read())["ok"])

                with urllib.request.urlopen(f"http://127.0.0.1:{port}/check") as r:
                    self.assertEqual(r.status, 200)
                    self.assertIn(b"PULSAR // QUOTEGATE", r.read())

                fake_page = qg.FetchedPage(
                    "https://example.com", "https://example.com", 200,
                    "This domain is for use in documentation examples without needing permission and has plenty of text to pass length gate comfortably.",
                    [],
                )
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/check/run",
                    data=json.dumps({"input": "- [Ex](https://example.com) says \"for use in documentation examples\""}).encode(),
                    headers={"Content-Type": "application/json"},
                )
                with patch("quotegate_engine.fetch_page", return_value=fake_page):
                    with urllib.request.urlopen(req) as r:
                        resp = json.loads(r.read())
                        self.assertTrue(resp["ok"])
                        self.assertEqual(resp["audit"]["verdict"], "PASSED")
                        self.assertEqual(resp["stats"]["total_scans"], 1)
            finally:
                srv.shutdown()
                srv.server_close()

    def test_messy_unicode_spaces_spans_yo_and_decimals(self):
        html_doc = (
            "<html><body><main>"
            "<span>AI и нейросети</span><span>GPT-агенты работают\u202fв\u00a0CRM с точностью 99,9% и чеком 1\u202f500 ₽, всё проверено.</span>"
            "</main></body></html>"
        )
        p = qg._TextExtractor(base_url="https://example.org/ru")
        p.feed(html_doc)
        p.close()
        clean = qg.normalize_text("".join(p.chunks))
        self.assertIn("нейросети GPT-агенты", clean)
        self.assertNotIn("нейросетиGPT", clean)

        page = qg.FetchedPage("https://example.org/ru", "https://example.org/ru", 200, clean + " " * 150, [])
        res_quote = qg.evaluate_spec(
            qg.CheckSpec("S01", "https://example.org/ru", quote="работают в CRM с точностью 99,9% и чеком 1 500 ₽, все проверено"),
            page,
        )
        self.assertEqual(res_quote.status, "OK")

        res_num = qg.evaluate_spec(
            qg.CheckSpec("S02", "https://example.org/ru", context="Точность агента 99.9% при чеке 1 500 ₽ по https://example.org/ru"),
            page,
        )
        self.assertEqual(res_num.status, "OK")


if __name__ == "__main__":
    unittest.main()
