import unittest

from solution import BlockedURL, WebhookURLValidator, is_public_ip

PUBLIC = "93.184.215.14"


class FakeDNS:
    def __init__(self, table):
        self.table = table
        self.calls = 0

    def __call__(self, host, port):
        self.calls += 1
        if host not in self.table:
            raise OSError("NXDOMAIN")
        return self.table[host]


def naive_validate(url):
    """The original check: block the literal metadata IP and 'localhost' only."""
    return "169.254.169.254" not in url and "localhost" not in url


class SSRFTests(unittest.TestCase):
    def setUp(self):
        self.dns = FakeDNS({
            "hooks.example.com": [PUBLIC],
            "evil-rebind.example": ["10.0.0.5"],
            "mixed.example": [PUBLIC, "127.0.0.1"],
            "v6-mapped.example": ["::ffff:169.254.169.254"],
            "redirector.example": [PUBLIC],
        })
        self.v = WebhookURLValidator(resolver=self.dns)

    def test_naive_filter_bypasses(self):
        bypasses = ["http://2852039166/latest/meta-data/",        # decimal 169.254.169.254
                    "http://0xa9fea9fe/", "http://[::1]:6379/", "http://127.1/",
                    "http://evil-rebind.example/"]
        self.assertTrue(all(naive_validate(u) for u in bypasses))  # reproduces incident

    def test_public_https_allowed(self):
        t = self.v.validate("https://hooks.example.com/events?x=1")
        self.assertEqual((t.ip, t.host, t.port, t.path), (PUBLIC, "hooks.example.com", 443,
                                                          "/events?x=1"))

    def test_blocks_internal_targets(self):
        dns = FakeDNS({h: [h] for h in ("169.254.169.254", "127.0.0.1", "10.1.2.3",
                                        "192.168.1.1", "100.64.0.1", "0.0.0.0", "::1",
                                        "fd00::1", "fe80::1")})
        v = WebhookURLValidator(resolver=dns)
        for host in dns.table:
            url = f"https://[{host}]/" if ":" in host else f"https://{host}/"
            with self.assertRaises(BlockedURL, msg=host):
                v.validate(url)

    def test_alternate_ip_encodings_blocked_with_system_resolver(self):
        # numeric hosts are parsed locally by getaddrinfo (no network needed)
        v = WebhookURLValidator()
        for host in ("2852039166", "0xa9fea9fe", "127.1", "017700000001"):
            with self.assertRaises(BlockedURL, msg=host):
                v.validate(f"https://{host}/latest/meta-data/")

    def test_hostname_resolving_to_private_blocked(self):
        with self.assertRaises(BlockedURL):
            self.v.validate("https://evil-rebind.example/")

    def test_any_private_record_blocks(self):
        with self.assertRaises(BlockedURL):
            self.v.validate("https://mixed.example/")

    def test_ipv4_mapped_ipv6_blocked(self):
        with self.assertRaises(BlockedURL):
            self.v.validate("https://v6-mapped.example/")
        self.assertFalse(is_public_ip("::ffff:10.0.0.1"))
        self.assertFalse(is_public_ip("2002:a9fe:a9fe::1"))      # 6to4 of 169.254.169.254

    def test_scheme_port_credentials(self):
        for url in ("http://hooks.example.com/", "file:///etc/passwd", "gopher://x/",
                    "https://hooks.example.com:6379/", "https://user:pw@hooks.example.com/",
                    "https://hooks.example.com@10.0.0.1/", "https://hooks.example.com:99999/",
                    "https://localhost/", "https://db.internal/", "https:///nohost",
                    "https://hooks.example.com/a\r\nX-Injected: 1"):
            with self.assertRaises(BlockedURL, msg=url):
                self.v.validate(url)

    def test_dns_failure_blocked(self):
        with self.assertRaises(BlockedURL):
            self.v.validate("https://does-not-exist.example/")

    def test_resolves_once_and_pins_ip(self):
        t = self.v.validate("https://hooks.example.com/")
        self.assertEqual(self.dns.calls, 1)
        self.assertEqual(t.ip, PUBLIC)          # caller connects here: no rebinding window

    def test_redirect_to_metadata_blocked(self):
        dns = FakeDNS({"redirector.example": [PUBLIC], "169.254.169.254": ["169.254.169.254"]})
        v = WebhookURLValidator(resolver=dns)
        fetch = lambda t: (302, "https://169.254.169.254/latest/meta-data/")
        with self.assertRaises(BlockedURL):
            v.follow("https://redirector.example/hook", fetch)

    def test_redirect_loop_limited(self):
        fetch = lambda t: (302, "/again")
        with self.assertRaises(BlockedURL):
            self.v.follow("https://hooks.example.com/", fetch)

    def test_good_redirect_followed(self):
        hops = iter([(301, "/v2/hook"), (200, None)])
        status, t = self.v.follow("https://hooks.example.com/hook", lambda t: next(hops))
        self.assertEqual((status, t.path), (200, "/v2/hook"))


if __name__ == "__main__":
    unittest.main()
