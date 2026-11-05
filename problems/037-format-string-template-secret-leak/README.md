# 037 · A tenant's "order shipped" email printed the platform's webhook signing key instead of a tracking number

## Problem
An e-commerce platform lets each merchant (about 1,800 tenants) customise its
order-notification emails in the admin panel, using placeholders such as
`{customer.name}` and `{order.id}`. A merchant account that had been taken
over saved a template containing
`{order.__init__.__globals__[WEBHOOK_SIGNING_KEY]}` and sent itself a test
email. The email contained the key the platform uses to sign outgoing
webhooks to *every* merchant, so the attacker could forge "payment captured"
webhooks to other merchants' fulfilment systems. The key had to be rotated
across all tenants, and every merchant had to update their webhook
verification at the same time.

## Root cause
**User-controlled format string (CWE-134) given live objects.** The renderer
was:

```python
template.format(customer=customer, order=order)
```

`str.format` does not just substitute names: a field like
`{order.__init__.__globals__[NAME]}` follows attributes and indexes on the
real object. Every Python function defined in a module has `__globals__`, so
from `order.__init__` the template reaches the module's global variables,
including secrets kept there. `{customer.__dict__}` similarly dumps every
field on the object, not just the ones meant for templates. The reproduction
test shows both leaks. A format spec like `{order.id:>999999999}` also lets a
template allocate about a gigabyte per render.

## Solution
`render_template` in `solution.py`:

1. **Plain-string context:** `build_context` copies only the allowed fields
   into a `dict[str, str]`. The template never receives an object, so there is
   no attribute chain to walk.
2. **Parse, don't `format`:** `string.Formatter().parse` splits the template
   into literal text and placeholders. Each placeholder must be *exactly* one
   of `ALLOWED_PLACEHOLDERS`; `{order}`, `{customer.name[0]}`, dunder names,
   conversions (`!r`) and format specs are rejected with `TemplateError`.
3. **Values are inserted as text and never re-parsed**, so a customer whose
   name is `{order.__init__.__globals__}` is printed literally.
4. Escaped braces (`{{`) still work, unmatched braces raise `TemplateError`,
   and templates are capped at 2,000 characters.

Call it when the merchant *saves* a template as well as when sending, so a
bad template is refused in the admin panel instead of failing at send time.

## Trade-offs
- The allow-list must be updated when product wants a new placeholder; that
  friction is the point.
- No formatting (dates, currency) inside templates: pre-format values in
  `build_context` instead. If merchants need loops or conditionals, use a
  sandboxed template engine (e.g. Jinja2's `SandboxedEnvironment`) rather
  than growing this parser, and still pass plain data, not ORM objects.
- Keeping secrets in a secrets manager instead of module globals limits what
  any similar bug can reach, but does not fix the injection itself.
- HTML emails also need output escaping of the values (see problem 014); this
  renderer only controls *which* values appear.

## Run
```bash
python -m unittest -v test_solution.py
```
