# 030 · Attackers ran commands on the web servers by sending a crafted "remember me" cookie

## Problem
A recipe-sharing site (a Python web app on a fleet of autoscaled servers)
kept "remember me" logins and display preferences in a cookie. The on-call
engineer was paged for CPU at 100% on every web server: each one was
running a cryptocurrency miner as the web app's user. The miner had been
started by the web process itself. Forensics found requests with a long,
odd-looking `remember_me` cookie arriving shortly before each server was
infected. The servers had to be rebuilt, and because the same processes
held database credentials and the session-signing key, all of them had to
be rotated and the user table treated as possibly read.

## Root cause
The cookie was `base64(pickle.dumps(prefs))`, and the app called
`pickle.loads` on whatever the browser sent back. Pickle is not a data
format but a small program for rebuilding objects: an object's
`__reduce__` can tell the loader to **call any importable function with
any arguments**, such as `os.system`. The Python docs warn never to unpickle
untrusted data for exactly this reason. `ReproduceProblem` builds such a
cookie with a harmless stand-in function that only records the command it
was given, and shows `naive_decode` calling it during loading.

## Solution
1. **JSON instead of pickle.** `json.loads` can only produce dicts, lists,
   strings, numbers, booleans and null; it never calls code.
2. **HMAC-SHA256 signature.** The cookie is `base64url(JSON) . base64url(HMAC)`.
   The signature is checked with `hmac.compare_digest` **before** the body is
   decoded or parsed, so nothing a client made up is processed at all. A
   cookie signed with a different key or with an edited body is rejected.
3. **Strict schema.** Exactly the fields `user_id` (non-empty string, at most
   64 characters), `theme` (`light` or `dark`) and `expires_at` (integer, not
   a boolean). Extra fields such as `"role": "admin"` are refused even when
   correctly signed, and we refuse to issue a cookie we would not accept.
4. **Expiry and size.** The cookie expires after 30 days, and anything over
   4096 characters is rejected before any work is done.

## Trade-offs
- Signing a pickle is **not** enough: if the key ever leaks (config file,
  logs, a backup), signed pickles are remote code execution again. With
  signed JSON a leaked key lets an attacker forge preferences or a login,
  which is serious but not code execution on the server.
- A signed cookie cannot be revoked before it expires. Remember-me tokens
  that must survive "log out everywhere" should be random IDs looked up in
  the database (see problem 007), with the cookie holding only that ID.
- The cookie is signed, not encrypted: the user can read its contents. Do
  not put anything secret in it.
- Rotating the HMAC key signs everyone out of "remember me" unless the
  reader accepts both the old and new key for a while (e.g. a key id prefix).
- The same rule applies elsewhere: never `pickle.loads`, `yaml.load` without
  a safe loader, or `marshal.loads` anything that crossed a trust boundary
  (cache entries, queue messages, uploaded files).

## Run
```bash
python -m unittest -v test_solution.py
```
