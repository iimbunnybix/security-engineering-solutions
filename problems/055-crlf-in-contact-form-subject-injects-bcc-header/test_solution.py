import unittest

from solution import (
    SUPPORT_INBOX,
    ContactForm,
    ContactFormRejected,
    build_contact_email,
    naive_build_contact_email,
    recipients_mta_would_deliver_to,
)

SPAM_TARGETS = ["victim1@mail.example", "victim2@mail.example"]


def form_with(subject: str = "Where is my order?", name: str = "Asha Rao",
              email: str = "asha@customer.example",
              message: str = "Order 1042 has not arrived.") -> ContactForm:
    return ContactForm(name=name, email=email, subject=subject, message=message)


def bcc_injection() -> str:
    """Subject that closes the Subject header and opens a Bcc header."""
    return "Hi\r\nBcc: " + ", ".join(SPAM_TARGETS) + "\r\n\r\nCheap watches at spam.example"


class ReproduceProblem(unittest.TestCase):
    def test_crlf_in_subject_adds_bcc_recipients(self):
        raw = naive_build_contact_email(form_with(subject=bcc_injection()))
        recipients = recipients_mta_would_deliver_to(raw)
        self.assertEqual(recipients, [SUPPORT_INBOX] + SPAM_TARGETS)

    def test_injected_blank_line_replaces_the_message_body(self):
        raw = naive_build_contact_email(form_with(subject=bcc_injection()))
        body = raw.split("\r\n\r\n", 1)[1]
        self.assertTrue(body.startswith("Cheap watches"))

    def test_crlf_in_email_field_also_adds_recipients(self):
        injected_email = "asha@customer.example>\r\nCc: victim1@mail.example\r\nX-Junk: <x"
        raw = naive_build_contact_email(form_with(email=injected_email))
        self.assertIn("victim1@mail.example", recipients_mta_would_deliver_to(raw))


class FixRejectsHeaderInjection(unittest.TestCase):
    def test_crlf_in_subject_is_rejected(self):
        with self.assertRaises(ContactFormRejected):
            build_contact_email(form_with(subject=bcc_injection()))

    def test_bare_line_feed_in_subject_is_rejected(self):
        with self.assertRaises(ContactFormRejected):
            build_contact_email(form_with(subject="Hi\nBcc: victim1@mail.example"))

    def test_unicode_line_separator_in_subject_is_rejected(self):
        with self.assertRaises(ContactFormRejected):
            build_contact_email(form_with(subject="Hi Bcc: victim1@mail.example"))

    def test_line_break_in_name_is_rejected(self):
        with self.assertRaises(ContactFormRejected):
            build_contact_email(form_with(name="Asha\r\nBcc: victim1@mail.example"))

    def test_crlf_in_email_field_is_rejected(self):
        with self.assertRaises(ContactFormRejected):
            build_contact_email(form_with(email="asha@customer.example\r\nBcc: victim1@mail.example"))

    def test_two_addresses_in_email_field_are_rejected(self):
        with self.assertRaises(ContactFormRejected):
            build_contact_email(form_with(email="asha@customer.example, victim1@mail.example"))

    def test_overlong_subject_is_rejected(self):
        with self.assertRaises(ContactFormRejected):
            build_contact_email(form_with(subject="a" * 201))


class FixKeepsLegitimateMessagesWorking(unittest.TestCase):
    def test_built_message_is_delivered_only_to_support(self):
        message = build_contact_email(form_with())
        self.assertEqual(recipients_mta_would_deliver_to(message.as_string()), [SUPPORT_INBOX])

    def test_reply_to_points_at_the_visitor(self):
        message = build_contact_email(form_with())
        self.assertEqual(message["Reply-To"].addresses[0].addr_spec, "asha@customer.example")

    def test_name_with_comma_and_quotes_stays_one_reply_to_address(self):
        message = build_contact_email(form_with(name='Rao, "Asha" <boss@corp.example>'))
        reparsed = recipients_mta_would_deliver_to(message.as_string())
        self.assertEqual(reparsed, [SUPPORT_INBOX])
        self.assertEqual(len(message["Reply-To"].addresses), 1)

    def test_line_breaks_in_the_message_body_are_kept(self):
        message = build_contact_email(form_with(message="Line one\nBcc: not-a-header@x.example"))
        self.assertIn("Bcc: not-a-header", message.get_content())
        self.assertEqual(recipients_mta_would_deliver_to(message.as_string()), [SUPPORT_INBOX])

    def test_non_ascii_subject_is_allowed(self):
        message = build_contact_email(form_with(subject="Commande reçue ? 注文"))
        self.assertEqual(str(message["Subject"]), "[Contact] Commande reçue ? 注文")

    def test_subject_at_the_length_limit_is_allowed(self):
        message = build_contact_email(form_with(subject="a" * 200))
        self.assertTrue(str(message["Subject"]).endswith("a" * 200))


if __name__ == "__main__":
    unittest.main()
