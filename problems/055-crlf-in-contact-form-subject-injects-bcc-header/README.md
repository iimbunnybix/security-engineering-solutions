# 055 · The shop's mail provider suspended sending after the "Contact us" form mailed spam to thousands of strangers

## Problem
An online furniture shop's "Contact us" form emails each submission to
`support@shop.example`. One weekend the shop's transactional mail provider
suspended the account for spam complaints, so order confirmations and
password-reset emails stopped going out until support restored it. The
provider's logs showed tens of thousands of messages from
`contact-form@shop.example` to addresses nobody at the shop had ever heard
of. Every one came from a form submission whose subject looked like:

```
Hi\r\nBcc: victim1@mail.example, victim2@mail.example\r\n\r\nCheap watches at spam.example
```

## Root cause
The handler built the email as text:

```python
f"Reply-To: {name} <{email}>\r\nSubject: [Contact] {subject}\r\n"
```

In an email, CR LF ends a header line and a blank line ends the headers. A
subject containing `\r\nBcc: ...` therefore *creates a new Bcc header*, and
the following blank line replaces the body with the attacker's text. The
mail server, told to take recipients from the headers, delivers to every
injected address. The name and email fields are injectable the same way.
This is CRLF / email header injection (CWE-93); the form's normal input
checks never looked for line breaks because the text "looked like a subject".

## Solution
`build_contact_email`:

- **Rejects line breaks and control characters** in name and subject,
  using Unicode categories `Cc`, `Zl` and `Zp`, so `\r`, `\n`, `NEL`
  (U+0085) and `U+2028` are all refused, not just CR/LF. It rejects rather
  than strips so attacks are visible and nothing is silently glued together.
- **Accepts exactly one mailbox for Reply-To** via `email.headerregistry.Address`,
  which refuses CR/LF and a second address such as `a@x.test, b@y.test`.
- **Builds an `EmailMessage`** instead of a string. From and To are fixed by
  the server, the display name is quoted on output (so a name like
  `Rao, "Asha" <boss@corp.example>` stays one Reply-To address), and the
  `email` package itself raises if a header still contains CR or LF.
- **Puts the visitor's free text in the body**, where line breaks are
  harmless.
- **Caps subject (200) and name (100) length** to stop header stuffing.

The tests parse each raw message the way a mail server reading recipients
from headers would: the naive message is delivered to support *and* both
injected addresses; the fixed message goes only to support.

## Trade-offs
- Tabs are control characters too, so a subject pasted with a tab is
  rejected. Replacing tabs with spaces before validation is a reasonable,
  safe relaxation.
- Header injection is only half of contact-form abuse: a valid form can
  still be used to send the *shop* junk. Rate limits and a CAPTCHA are
  still needed.
- Never put the visitor's address in `From`; it fails SPF/DMARC and lets
  anyone impersonate anyone. `Reply-To` gives support the same convenience.
- Passing an explicit recipient list to `smtplib.SMTP.send_message(..., to_addrs=[SUPPORT_INBOX])`
  is a second layer: even an injected Bcc header would not add recipients.

## Run
```bash
python -m unittest -v test_solution.py
```
