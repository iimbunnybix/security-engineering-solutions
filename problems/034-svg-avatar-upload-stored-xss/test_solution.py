import unittest

from solution import (APP_ORIGIN, MAX_AVATAR_BYTES, USER_CONTENT_ORIGIN, AvatarStore,
                      HttpResponse, NaiveAvatarStore, UploadRejected, browser_runs_script,
                      script_runs_with_app_session, validate_avatar)

PNG_HEADER = b"\x89PNG\r\n\x1a\n"
SVG_PAYLOAD = (b'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64">'
               b"<script>fetch('/api/me/email',{method:'POST',body:'x'})</script></svg>")
HTML_PAYLOAD = b"<html><body><script>fetch('/api/me')</script></body></html>"


def png_bytes(extra: bytes = b"") -> bytes:
    """A PNG-signed file (enough for type detection), optionally with bytes appended."""
    return PNG_HEADER + b"\x00" * 32 + extra


def jpeg_bytes() -> bytes:
    return b"\xff\xd8\xff\xe0" + b"\x00" * 32


def gif_bytes() -> bytes:
    return b"GIF89a" + b"\x00" * 32


def webp_bytes() -> bytes:
    return b"RIFF" + (32).to_bytes(4, "little") + b"WEBP" + b"\x00" * 24


def stored_name(url: str) -> str:
    return url.rsplit("/", 1)[1]


class ReproduceProblem(unittest.TestCase):
    def setUp(self):
        self.store = NaiveAvatarStore()

    def test_svg_avatar_runs_script_on_the_app_origin(self):
        url = self.store.upload("avatar.svg", "image/svg+xml", SVG_PAYLOAD)
        response = self.store.serve(stored_name(url))
        self.assertTrue(url.startswith(APP_ORIGIN))
        self.assertEqual(response.headers["Content-Type"], "image/svg+xml")
        self.assertTrue(script_runs_with_app_session(response))

    def test_html_file_labelled_as_png_is_served_as_html(self):
        url = self.store.upload("cute-cat.html", "image/png", HTML_PAYLOAD)
        response = self.store.serve(stored_name(url))
        self.assertEqual(response.headers["Content-Type"], "text/html")
        self.assertTrue(script_runs_with_app_session(response))

    def test_vague_type_without_nosniff_is_sniffed_as_html(self):
        url = self.store.upload("avatar.txt", "image/png", HTML_PAYLOAD)
        response = self.store.serve(stored_name(url))
        self.assertEqual(response.headers["Content-Type"], "text/plain")
        self.assertTrue(script_runs_with_app_session(response))


class FixRasterOnlySeparateOrigin(unittest.TestCase):
    def setUp(self):
        self.store = AvatarStore()

    def upload_and_serve(self, data: bytes, filename: str = "me.png",
                         declared_type: str = "image/png") -> tuple[str, HttpResponse]:
        url = self.store.upload(filename, declared_type, data)
        return url, self.store.serve(stored_name(url))

    def test_svg_upload_is_rejected(self):
        with self.assertRaises(UploadRejected):
            self.store.upload("avatar.svg", "image/svg+xml", SVG_PAYLOAD)

    def test_html_disguised_as_png_is_rejected(self):
        with self.assertRaises(UploadRejected):
            self.store.upload("avatar.png", "image/png", HTML_PAYLOAD)

    def test_each_raster_format_is_detected_from_its_bytes(self):
        cases = [(png_bytes(), "image/png", ".png"), (jpeg_bytes(), "image/jpeg", ".jpg"),
                 (gif_bytes(), "image/gif", ".gif"), (webp_bytes(), "image/webp", ".webp")]
        for data, expected_type, expected_ext in cases:
            url, response = self.upload_and_serve(data, filename="x.svg", declared_type="image/svg+xml")
            self.assertEqual(response.headers["Content-Type"], expected_type)
            self.assertTrue(url.endswith(expected_ext), url)

    def test_client_file_name_is_not_used_for_storage(self):
        url, _response = self.upload_and_serve(png_bytes(), filename="../../evil.html")
        self.assertNotIn("evil", url)
        self.assertRegex(stored_name(url), r"^[0-9a-f]{32}\.png$")

    def test_avatars_are_served_from_the_user_content_origin(self):
        url, response = self.upload_and_serve(png_bytes())
        self.assertTrue(url.startswith(USER_CONTENT_ORIGIN + "/"))
        self.assertEqual(response.origin, USER_CONTENT_ORIGIN)

    def test_served_avatar_has_protective_headers(self):
        _url, response = self.upload_and_serve(png_bytes())
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Content-Disposition"], "attachment")
        self.assertIn("sandbox", response.headers["Content-Security-Policy"])

    def test_png_polyglot_with_appended_html_does_not_run(self):
        _url, response = self.upload_and_serve(png_bytes(extra=HTML_PAYLOAD))
        self.assertFalse(browser_runs_script(response))
        self.assertFalse(script_runs_with_app_session(response))

    def test_empty_and_oversized_files_are_rejected(self):
        for data in (b"", png_bytes(b"\x00" * MAX_AVATAR_BYTES)):
            with self.assertRaises(UploadRejected):
                validate_avatar(data)

    def test_file_exactly_at_the_size_limit_is_accepted(self):
        data = png_bytes(b"\x00" * (MAX_AVATAR_BYTES - len(png_bytes())))
        self.assertEqual(len(data), MAX_AVATAR_BYTES)
        self.assertEqual(validate_avatar(data), ("image/png", "png"))

    def test_riff_file_that_is_not_webp_is_rejected(self):
        wav_like = b"RIFF" + (32).to_bytes(4, "little") + b"WAVE" + b"\x00" * 24
        with self.assertRaises(UploadRejected):
            validate_avatar(wav_like)

    def test_unknown_name_returns_404(self):
        self.assertEqual(self.store.serve("missing.png").status, 404)


class BrowserModelSanityChecks(unittest.TestCase):
    def test_each_header_on_its_own_stops_the_svg_on_the_app_origin(self):
        protections = [{"Content-Disposition": "attachment"},
                       {"Content-Security-Policy": "sandbox"}]
        for extra in protections:
            headers = {"Content-Type": "image/svg+xml", **extra}
            response = HttpResponse(200, headers, SVG_PAYLOAD, APP_ORIGIN)
            self.assertFalse(script_runs_with_app_session(response), extra)

    def test_nosniff_alone_does_not_stop_a_real_svg(self):
        headers = {"Content-Type": "image/svg+xml", "X-Content-Type-Options": "nosniff"}
        response = HttpResponse(200, headers, SVG_PAYLOAD, APP_ORIGIN)
        self.assertTrue(script_runs_with_app_session(response))


if __name__ == "__main__":
    unittest.main()
