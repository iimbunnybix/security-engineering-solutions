"""Safe XML import: refuse DOCTYPE and entity declarations before they run.

The customer-import endpoint parsed uploaded XML with SAX and had external
general entities switched on (to support shared "include" fragments). An
uploaded file could declare <!ENTITY x SYSTEM "file:///etc/..."> and the
server read that local file into the imported record (XXE). Nested internal
entities also let a few hundred bytes expand into a huge string.

``safe_parse_customers`` uses expat directly and aborts as soon as the parser
sees a DOCTYPE, an entity declaration or an external entity reference, and
caps the upload size. Plain customer XML never needs any of these.
"""
from __future__ import annotations

import io
import xml.parsers.expat
import xml.sax
import xml.sax.handler
from dataclasses import dataclass

# Imports are a few thousand customers; 5 MiB leaves plenty of headroom.
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
CUSTOMER_FIELDS = ("name", "email")


class UnsafeXml(ValueError):
    """The upload contains a construct we never accept (DOCTYPE, entities)."""


@dataclass
class Customer:
    name: str
    email: str


class _CustomerCollector:
    """Turns start/end/character events into Customer records.

    Shared by the naive SAX handler and the safe expat parser so the only
    difference between them is how the XML is parsed.
    """

    def __init__(self) -> None:
        self.customers: list[Customer] = []
        self._current: dict[str, str] | None = None
        self._field: str | None = None

    def start(self, tag: str, attributes: object = None) -> None:
        """Begin a record or a field; attributes are not used by the import."""
        if tag == "customer":
            self._current = {name: "" for name in CUSTOMER_FIELDS}
        elif self._current is not None and tag in CUSTOMER_FIELDS:
            self._field = tag

    def end(self, tag: str) -> None:
        """Finish the current record or field."""
        if tag == "customer" and self._current is not None:
            self.customers.append(Customer(**self._current))
            self._current = None
        elif tag == self._field:
            self._field = None

    def text(self, data: str) -> None:
        """Append character data to the field being read, if any."""
        if self._current is not None and self._field is not None:
            self._current[self._field] += data


class _SaxAdapter(xml.sax.handler.ContentHandler):
    """Feeds SAX callbacks into a _CustomerCollector."""

    def __init__(self, collector: _CustomerCollector) -> None:
        super().__init__()
        self.collector = collector

    def startElement(self, name: str, attrs: object) -> None:
        self.collector.start(name, attrs)

    def endElement(self, name: str) -> None:
        self.collector.end(name)

    def characters(self, content: str) -> None:
        self.collector.text(content)


def naive_parse_customers(upload: bytes) -> list[Customer]:
    """The original importer: SAX with external general entities enabled."""
    collector = _CustomerCollector()
    parser = xml.sax.make_parser()
    parser.setContentHandler(_SaxAdapter(collector))
    # This one line is the vulnerability: it lets the document read files.
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    parser.parse(io.BytesIO(upload))
    return collector.customers


def _reject(*_args: object) -> None:
    """Expat handler that aborts parsing for any forbidden construct."""
    raise UnsafeXml("DOCTYPE and entity declarations are not allowed")


def _reject_external_ref(*_args: object) -> int:
    """Called for external entity references; must not return success."""
    raise UnsafeXml("external entities are not allowed")


def _build_hardened_parser(collector: _CustomerCollector) -> xml.parsers.expat.XMLParserType:
    """Create an expat parser that refuses DTDs and entities outright."""
    parser = xml.parsers.expat.ParserCreate()
    # Refusing the DOCTYPE itself blocks every entity trick in one place;
    # the other handlers are defence in depth if that ever changes.
    parser.StartDoctypeDeclHandler = _reject
    parser.EntityDeclHandler = _reject
    parser.UnparsedEntityDeclHandler = _reject
    parser.ExternalEntityRefHandler = _reject_external_ref
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.StartElementHandler = collector.start
    parser.EndElementHandler = collector.end
    parser.CharacterDataHandler = collector.text
    return parser


def safe_parse_customers(upload: bytes) -> list[Customer]:
    """Parse a customer upload, rejecting oversize files and any DTD."""
    if len(upload) > MAX_UPLOAD_BYTES:
        raise UnsafeXml(f"upload larger than {MAX_UPLOAD_BYTES} bytes")
    collector = _CustomerCollector()
    parser = _build_hardened_parser(collector)
    try:
        parser.Parse(upload, True)
    except xml.parsers.expat.ExpatError as error:
        # Malformed XML is a client error too; report it the same way.
        raise UnsafeXml(f"malformed XML: {error}") from error
    return collector.customers
