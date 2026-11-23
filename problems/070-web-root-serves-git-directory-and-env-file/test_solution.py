import secrets
import unittest

from solution import (HTTP_NOT_FOUND, HTTP_OK, UnsafeDeploy, naive_serve, plan_publish, publish,
                      serve)


def fake_secret(prefix):
    """Secret-shaped test values are generated at runtime, never committed."""
    return f"{prefix}-{secrets.token_hex(8)}"


def repository_checkout():
    """What the old deploy put in the web root: the whole repository."""
    token = fake_secret("deploytoken")
    api_key = fake_secret("apikey")
    return {
        "index.html": b"<h1>Welcome</h1>",
        "assets/site.css": b"body {}",
        "assets/app.js": b"console.log('hi')",
        ".well-known/security.txt": b"Contact: mailto:security@example.com",
        ".git/config": f"url = https://ci:{token}@git.example.com/site.git".encode(),
        ".git/HEAD": b"ref: refs/heads/main",
        ".env": f"PAYMENT_API_KEY={api_key}".encode(),
        "src/build.py": b"print('build')",
        "README.md": b"# site",
    }


def clean_build_output():
    files = repository_checkout()
    for path in [".git/config", ".git/HEAD", ".env"]:
        del files[path]
    return files


class ReproduceProblem(unittest.TestCase):
    def test_git_config_with_deploy_token_is_public(self):
        status, body = naive_serve(repository_checkout(), "/.git/config")
        self.assertEqual(status, HTTP_OK)
        self.assertIn(b"deploytoken-", body)

    def test_env_file_with_api_key_is_public(self):
        status, body = naive_serve(repository_checkout(), "/.env")
        self.assertEqual(status, HTTP_OK)
        self.assertIn(b"PAYMENT_API_KEY=", body)

    def test_source_files_are_public_too(self):
        status, _ = naive_serve(repository_checkout(), "/src/build.py")
        self.assertEqual(status, HTTP_OK)


class FixPublishAllowlist(unittest.TestCase):
    def test_deploy_with_hidden_files_fails(self):
        with self.assertRaises(UnsafeDeploy) as caught:
            publish(repository_checkout())
        self.assertIn(".env", str(caught.exception))
        self.assertIn(".git/config", str(caught.exception))

    def test_clean_build_publishes_only_site_assets(self):
        published = publish(clean_build_output())
        self.assertEqual(sorted(published),
                         [".well-known/security.txt", "assets/app.js", "assets/site.css", "index.html"])

    def test_source_and_docs_are_skipped_not_published(self):
        plan = plan_publish(clean_build_output())
        self.assertEqual(plan.skipped, ["README.md", "src/build.py"])

    def test_secret_looking_names_are_blocked_anywhere(self):
        plan = plan_publish({"backup/id_rsa": b"x", "infra/terraform.tfstate": b"{}"})
        self.assertEqual(plan.blocked, ["backup/id_rsa", "infra/terraform.tfstate"])

    def test_nested_hidden_file_is_blocked(self):
        plan = plan_publish({"assets/.DS_Store": b"x", "assets/.env.production": b"x"})
        self.assertEqual(plan.blocked, ["assets/.DS_Store", "assets/.env.production"])


class FixServerDeniesHiddenPaths(unittest.TestCase):
    def setUp(self):
        self.web_root = repository_checkout()  # worst case: layer 1 was bypassed

    def assert_not_found(self, path):
        status, body = serve(self.web_root, path)
        self.assertEqual(status, HTTP_NOT_FOUND, path)
        self.assertEqual(body, b"")

    def test_git_and_env_paths_are_not_found(self):
        for path in ["/.git/config", "/.git/HEAD", "/.env"]:
            with self.subTest(path=path):
                self.assert_not_found(path)

    def test_percent_encoded_dot_is_decoded_before_the_check(self):
        self.assert_not_found("/%2egit/config")
        self.assert_not_found("/%2Eenv")

    def test_dot_segments_cannot_reach_hidden_files(self):
        self.assert_not_found("/assets/../.git/config")
        self.assert_not_found("/assets/./../.env")

    def test_well_known_stays_reachable(self):
        status, _ = serve(self.web_root, "/.well-known/security.txt")
        self.assertEqual(status, HTTP_OK)

    def test_normal_pages_still_work(self):
        self.assertEqual(serve(self.web_root, "/")[0], HTTP_OK)
        self.assertEqual(serve(self.web_root, "/assets/site.css")[0], HTTP_OK)

    def test_hidden_and_missing_files_look_the_same(self):
        self.assertEqual(serve(self.web_root, "/.env"), serve(self.web_root, "/no-such-file"))


if __name__ == "__main__":
    unittest.main()
