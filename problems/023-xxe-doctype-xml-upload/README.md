# 023 · Customer import returned the server's config file contents in the "name" column of the preview

## Problem
A B2B CRM lets account admins upload an XML file of customers (a few thousand
`<customer>` records) and shows a preview table before importing. A security
researcher uploaded a file whose `<name>` field was `&leak;`, with `leak`
declared as `<!ENTITY leak SYSTEM "file:///…/app.env">`. The preview table
showed the server's environment file, including database credentials. The
same endpoint could be pinned at 100% CPU and memory by a tiny upload of
nested entities. Every tenant admin could reach this endpoint, so any
compromised admin account meant full credential disclosure.

## Root cause
**XML External Entity (XXE) processing.** The importer used `xml.sax` and
had turned on `feature_external_ges` years ago so partner files could
`<!ENTITY header SYSTEM "common.xml">` a shared fragment. With that flag the
parser resolves `SYSTEM` URIs, including `file://` paths, and inlines the
file into the document. Internal entities that reference each other also
expand multiplicatively: in the tests, a 369-byte upload with 4 levels of
10× nesting expands to a 30,000-character name (about 81× the input), and
each extra level multiplies it by 10 again.

`ReproduceProblem` reads a temporary "secret" file through the naive parser
and measures the expansion. No network access is used.

## Solution
`safe_parse_customers` uses expat directly and **refuses the DTD itself**:

1. `StartDoctypeDeclHandler` raises `UnsafeXml` the moment a `<!DOCTYPE` is
   seen, before any entity is declared or expanded. Customer files never need
   a DTD, so this is the simplest rule that blocks every entity trick.
2. As defence in depth, entity declarations, unparsed entities and external
   entity references also raise, and parameter-entity parsing is set to
   `NEVER`.
3. Uploads over 5 MiB are rejected before parsing, and malformed XML is
   reported as the same `UnsafeXml` client error.

The check runs inside the parser, not as a substring search, so a DOCTYPE in
a UTF-16 encoded upload (where `b"<!DOCTYPE"` never appears in the raw
bytes) is still caught. Built-in entities like `&amp;` keep working.

## Trade-offs
- Partners who relied on `SYSTEM` includes must now send self-contained
  files. If includes are truly needed, resolve them server-side from an
  allowlisted directory, never from the document.
- Python's defaults are already safer than this importer: since 3.7.1 SAX
  does not resolve external entities unless asked, and recent expat versions
  limit entity amplification. Those defaults depend on library versions and
  flags, so an explicit "no DTD" rule is more robust.
- `defusedxml` packages the same idea for ElementTree, SAX, minidom and
  lxml. Prefer it where third-party packages are allowed.
- Rejecting all DTDs also rejects legitimate documents that carry a harmless
  DOCTYPE (some exporters add one). Those uploads get a clear error message
  instead of being silently accepted.

## Run
```bash
python -m unittest -v test_solution.py
```
