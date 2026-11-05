import tempfile
import unittest
from pathlib import Path

from solution import (MAX_UPLOAD_BYTES, Customer, UnsafeXml, naive_parse_customers,
                      safe_parse_customers)

PLAIN_UPLOAD = (b'<?xml version="1.0"?><customers>'
                b'<customer><name>Asha &amp; Co</name><email>asha@shop.example</email></customer>'
                b'<customer><name>Ravi</name><email>ravi@shop.example</email></customer>'
                b'</customers>')


def external_entity_upload(file_uri: str) -> bytes:
    """An upload that asks the parser to inline a local file into <name>."""
    return (f'<?xml version="1.0"?><!DOCTYPE customers ['
            f'<!ENTITY leak SYSTEM "{file_uri}">]>'
            f'<customers><customer><name>&leak;</name><email>x@evil.example</email>'
            f'</customer></customers>').encode()


def nested_entity_upload(levels: int) -> bytes:
    """A small 'laughs' document: each level repeats the previous one 10 times."""
    declarations = ['<!ENTITY e0 "lol">']
    for level in range(1, levels + 1):
        declarations.append(f'<!ENTITY e{level} "{("&e" + str(level - 1) + ";") * 10}">')
    return (f'<?xml version="1.0"?><!DOCTYPE customers [{"".join(declarations)}]>'
            f'<customers><customer><name>&e{levels};</name><email>a@b.example</email>'
            f'</customer></customers>').encode()


class SecretFileMixin(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.secret_file = Path(directory.name) / "app.env"
        self.secret_file.write_text("DB_PASSWORD=not-a-real-password\n")


class ReproduceProblem(SecretFileMixin):
    def test_naive_parser_inlines_a_local_file_into_the_record(self) -> None:
        customers = naive_parse_customers(external_entity_upload(self.secret_file.as_uri()))
        self.assertIn("DB_PASSWORD", customers[0].name)

    def test_naive_parser_expands_nested_entities_far_beyond_the_upload_size(self) -> None:
        upload = nested_entity_upload(levels=4)
        customers = naive_parse_customers(upload)
        self.assertEqual(len(customers[0].name), 3 * 10 ** 4)
        self.assertGreater(len(customers[0].name), 50 * len(upload))


class FixRejectsDtdConstructs(SecretFileMixin):
    def test_external_entity_is_rejected(self) -> None:
        with self.assertRaises(UnsafeXml):
            safe_parse_customers(external_entity_upload(self.secret_file.as_uri()))

    def test_nested_entity_bomb_is_rejected(self) -> None:
        with self.assertRaises(UnsafeXml):
            safe_parse_customers(nested_entity_upload(levels=4))

    def test_doctype_without_entities_is_rejected(self) -> None:
        with self.assertRaises(UnsafeXml):
            safe_parse_customers(b'<!DOCTYPE customers><customers/>')

    def test_parameter_entity_is_rejected(self) -> None:
        upload = (b'<!DOCTYPE customers [<!ENTITY % remote SYSTEM "file:///nonexistent">'
                  b'%remote;]><customers/>')
        with self.assertRaises(UnsafeXml):
            safe_parse_customers(upload)

    def test_doctype_hidden_in_utf16_is_still_rejected(self) -> None:
        # A plain substring check for b"<!DOCTYPE" would miss this encoding.
        upload = external_entity_upload(self.secret_file.as_uri()).decode()
        upload = upload.replace('<?xml version="1.0"?>', '<?xml version="1.0" encoding="UTF-16"?>')
        utf16_bytes = upload.encode("utf-16")
        self.assertNotIn(b"<!DOCTYPE", utf16_bytes)
        with self.assertRaisesRegex(UnsafeXml, "DOCTYPE"):
            safe_parse_customers(utf16_bytes)


class FixStillImportsNormalFiles(unittest.TestCase):
    def test_plain_upload_is_imported_with_builtin_entities(self) -> None:
        self.assertEqual(safe_parse_customers(PLAIN_UPLOAD), [
            Customer("Asha & Co", "asha@shop.example"),
            Customer("Ravi", "ravi@shop.example"),
        ])

    def test_oversize_upload_is_rejected_before_parsing(self) -> None:
        with self.assertRaises(UnsafeXml):
            safe_parse_customers(b" " * (MAX_UPLOAD_BYTES + 1))

    def test_malformed_xml_is_reported_as_unsafe_xml(self) -> None:
        with self.assertRaises(UnsafeXml):
            safe_parse_customers(b"<customers><customer>")


if __name__ == "__main__":
    unittest.main()
