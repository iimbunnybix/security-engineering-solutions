"""Contact-form email that cannot be turned into a spam relay.

The "Contact us" form built the notification email by pasting the visitor's
name, email address and subject straight into header lines. A subject such
as "Hi\\r\\nBcc: victim1@..., victim2@..." ends the Subject header and adds a
new Bcc header, so the shop's own mail server delivers spam to anyone the
attacker lists. This module rejects line breaks and control characters in
every header value and builds the message with email.message.EmailMessage,
which quotes display names and refuses CR/LF in headers.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from email import policy
from email.errors import HeaderParseError
from email.headerregistry import Address
from email.message import EmailMessage
from email.parser import Parser
from email.utils import getaddresses

SITE_SENDER = "contact-form@shop.example"
SUPPORT_INBOX = "support@shop.example"
SUBJECT_PREFIX = "[Contact] "

# Generous for real subjects and names, small enough to stop header stuffing.
MAX_SUBJECT_LENGTH = 200
MAX_NAME_LENGTH = 100

# Headers a mail server reads to decide who receives a message (sendmail -t).
RECIPIENT_HEADERS = ("To", "Cc", "Bcc")

# Unicode categories that act as line or paragraph breaks or are control
# characters. Some mail software treats U+2028 or NEL (U+0085) as newlines,
# so blocking only "\r" and "\n" is not enough.
FORBIDDEN_CATEGORIES = ("Cc", "Zl", "Zp")


class ContactFormRejected(ValueError):
    """The submitted form cannot be turned into a safe email."""


@dataclass(frozen=True)
class ContactForm:
    name: str
    email: str
    subject: str
    message: str


def naive_build_contact_email(form: ContactForm) -> str:
    """Original code: header lines built by string concatenation. Vulnerable."""
    headers = (
        f"From: {SITE_SENDER}\r\n"
        f"To: {SUPPORT_INBOX}\r\n"
        f"Reply-To: {form.name} <{form.email}>\r\n"
        f"Subject: {SUBJECT_PREFIX}{form.subject}\r\n"
    )
    return headers + "\r\n" + form.message


def recipients_mta_would_deliver_to(raw_message: str) -> list[str]:
    """Parse a raw message and list every address in To, Cc and Bcc.

    This is what a mail server does when asked to take recipients from the
    headers, so it shows who would actually receive the email.
    """
    parsed = Parser(policy=policy.compat32).parsestr(raw_message)
    header_values: list[str] = []
    for header_name in RECIPIENT_HEADERS:
        header_values.extend(parsed.get_all(header_name, []))
    recipients: list[str] = []
    for _display_name, address in getaddresses(header_values):
        if address:
            recipients.append(address)
    return recipients


def require_single_line(field_name: str, value: str, max_length: int) -> str:
    """Return the value unchanged if it is a safe single-line header value.

    We reject instead of stripping: silently removing "\\r\\n" would still
    let an attacker glue extra text into the subject, and a clear error
    is easier to monitor.
    """
    if len(value) > max_length:
        raise ContactFormRejected(f"{field_name} is longer than {max_length} characters")
    for character in value:
        if unicodedata.category(character) in FORBIDDEN_CATEGORIES:
            raise ContactFormRejected(f"{field_name} contains a line break or control character")
    return value


def parse_reply_to(name: str, email_address: str) -> Address:
    """Build the visitor's Reply-To address, accepting exactly one mailbox.

    Address() refuses commas, angle brackets and extra addresses in the
    addr_spec, so "a@x.test, b@y.test" cannot smuggle in a second address.
    The display name is quoted by the email package when serialised.
    """
    safe_name = require_single_line("name", name, MAX_NAME_LENGTH)
    try:
        return Address(display_name=safe_name, addr_spec=email_address)
    except (ValueError, HeaderParseError) as error:
        raise ContactFormRejected(f"email is not a single valid address: {error}") from error


def build_contact_email(form: ContactForm) -> EmailMessage:
    """Fixed version: validated values placed into a structured EmailMessage.

    From and To are fixed by the server; only Reply-To and Subject carry
    visitor input, and the message text goes in the body, where line
    breaks are harmless.
    """
    reply_to = parse_reply_to(form.name, form.email)
    subject = require_single_line("subject", form.subject, MAX_SUBJECT_LENGTH)
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = SITE_SENDER
    message["To"] = SUPPORT_INBOX
    message["Reply-To"] = reply_to
    message["Subject"] = SUBJECT_PREFIX + subject
    message.set_content(form.message)
    return message
