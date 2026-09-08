# Python UBS Samples

| File | Category | What UBS should flag |
|------|----------|----------------------|
| `buggy/buggy_async_security.py` | Async/await pitfalls + insecure requests | unguarded awaits, missing try/except, `verify=False` |
| `buggy/resource_lifecycle.py` | File/task cleanup | missing `close()`/`cancel()` |
| `buggy/security_injection.py` | Code & command injection, yaml.load, eval | eval/exec, yaml.load without Loader, shell=True |
| `security/command_injection_buggy.py` | Command execution security | request/stdin data reaching `shell=True`, shell `-c`, `os.system`, aliased subprocess calls, or executable selection |
| `security/subprocess_timeout_buggy.py` | Process execution reliability | subprocess calls without explicit bounded `timeout=` values |
| `security/sql_injection_buggy.py` | SQL injection security | f-string, `%`, `.format()`, and concatenated SQL reaching execute/raw/extra/read_sql sinks |
| `security/nosql_injection_buggy.py` | NoSQL injection security | request dictionaries, operator payloads, dynamic keys, `$where`, aggregation pipelines, and MongoDB commands reaching PyMongo-style sinks |
| `security/redos_regex_buggy.py` | Regex DoS security | request/stdin/argv patterns reaching `re`, `regex`, or pandas string regex sinks without `re.escape` or fixed allow-lists |
| `security/template_injection_buggy.py` | Template injection security | request-controlled template source strings reaching Flask/Jinja2/Django/Mako renderers |
| `security/header_injection_buggy.py` | Response header injection security | request-controlled values reaching response headers, header dictionaries, and download filename parameters |
| `security/email_header_injection_buggy.py` | Email header injection security | request-controlled values reaching email subject/from/to/cc/bcc/reply-to/custom headers or SMTP envelope fields |
| `security/ldap_injection_buggy.py` | LDAP injection security | request-controlled values reaching LDAP search filters, filter keywords, bind DNs, or modification DNs without LDAP escaping |
| `security/archive_extraction_buggy.py` | Archive extraction security | tarfile/zipfile `extract()` or `extractall()` without member path validation |
| `security/open_redirect_buggy.py` | Web redirect security | request-derived Flask/Django/Starlette redirect targets without allow-list validation |
| `security/host_header_poisoning_buggy.py` | Host header poisoning security | request Host, `get_host()`, `build_absolute_uri()`, or external `url_for()` used to generate absolute links without a configured canonical base URL or host allow-list |
| `security/ssrf_buggy.py` | Outbound HTTP security | request-derived URLs reaching requests/httpx/aiohttp/urllib clients without host allow-list validation |
| `security/http_timeout_buggy.py` | Outbound HTTP reliability | requests/httpx/aiohttp/urllib/urllib3 calls or clients without explicit bounded timeouts |
| `security/path_traversal_buggy.py` | File download/upload security | request/header-derived paths reaching `open`, `send_file`, `FileResponse`, `Path.read_*`, or uploaded-file `save()` without containment validation |
| `security/jwt_verification_buggy.py` | JWT verification security | `jwt.decode` calls that disable signature/claim checks or allow `algorithms=["none"]` |
| `security/cors_misconfig_buggy.py` | CORS configuration security | credentialed Flask-CORS, Starlette/FastAPI, or Django CORS configs that allow wildcard origins |
| `security/cookie_security_buggy.py` | Cookie/session security | Django/Flask cookie settings or response cookies that disable Secure/HttpOnly or use SameSite=None without Secure |
| `security/csrf_disable_buggy.py` | CSRF protection security | Django `csrf_exempt`, Flask-WTF exemptions, and settings that disable CSRF checks |
| `security/template_autoescape_buggy.py` | Template/XSS security | Jinja2/Flask template environments and options that disable autoescape |
| `security/safe_html_xss_buggy.py` | Safe HTML/XSS security | request-controlled values passed to `mark_safe`, `Markup`, `SafeString`, or related safe-HTML APIs without escaping or sanitization |
| `security/mass_assignment_buggy.py` | Mass-assignment security | request dictionaries passed into model constructors, ORM creates/updates, object updates, or `setattr` loops |
| `security/unsafe_deserialization_buggy.py` | Deserialization security | marshal/dill/cloudpickle/joblib/jsonpickle/shelve/pandas/yaml unsafe loaders, NumPy pickle arrays, and unsafe torch checkpoints |
| `security/yaml_loader_buggy.py` | YAML Loader classification (GH #102) | `yaml.load`/`load_all` with `Loader`/`UnsafeLoader`/`FullLoader`/`None`, subclasses of those under reassuring names, SafeLoader subclasses registering `python/` tags or eval-ing constructors (critical); imported, dynamic, or unresolvable loaders (manual-review warning). `yaml_loader_clean.py` holds the trivial and strict-mapping SafeLoader subclasses that must stay clean |
| `security/password_hashing_buggy.py` | Password hashing security | plaintext, MD5, SHA1, unsalted, or legacy Django/Werkzeug/Passlib password hashers |
| `security/crypto_misuse_buggy.py` | Cryptography misuse security | ECB mode, DES/ARC4-style legacy ciphers, and static IV/nonces in PyCryptodome or `cryptography` APIs |
| `security/constant_time_compare_buggy.py` | Constant-time comparison security | HMACs, signatures, API keys, CSRF tokens, bearer tokens, or reset tokens compared with `==` or `!=` instead of `compare_digest` |
| `security/public_checksum_compare_buggy.py` | Digest role in constant-time comparison (GH #102) | keyed MAC tags (`hmac.new`, `blake2b(..., key=)`), hashes of secret material, hash objects `update()`d with a secret, and digests of unknown provenance compared with `==`/`!=`. `public_checksum_compare_clean.py` holds the public SHA-256 manifest integrity check that must stay clean |
| `security/assert_security_buggy.py` | Security-sensitive asserts | authorization, ownership, CSRF, token, API key, or permission checks implemented with `assert` |
| `security/file_permissions_buggy.py` | Filesystem permission security | world-writable `chmod`/`mkdir`/`os.open` modes and `umask(0)` |
| `security/debug_host_config_buggy.py` | Debug/host configuration security | production debug flags, debugger-enabled app runs, and wildcard host allow-lists |
| `security/xml_parser_buggy.py` | XML parser security | request/upload XML parsed by stdlib/lxml parsers or lxml parsers with DTD/entity-expansion flags |
| `security/random_security_buggy.py` | Security randomness | tokens, sessions, OTPs, salts, and keys generated with the non-cryptographic `random` module |
| `security/tls_verification_buggy.py` | TLS verification security | `httpx`, `aiohttp`, `urllib3`, and `ssl` configurations that disable certificate or hostname checks |
| `buggy/mutable_defaults.py` | Function scope issues | mutable defaults, swallowed exceptions, weak hash |
| `clean/*.py` mirrors | Defensive patterns | safe YAML, parameterized SQL, integer cents |

Run:

```bash
ubs --only=python --fail-on-warning test-suite/python/buggy
ubs --only=python test-suite/python/clean
```
