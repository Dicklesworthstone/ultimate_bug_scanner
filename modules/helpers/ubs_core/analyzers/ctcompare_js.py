"""ubs_core.analyzers.ctcompare_js — constant-time secret-compare analysis for JS/TS (bead A2).

Logic moved verbatim from the ctcompare heredoc in modules/ubs-js.sh, which keeps
its own copy until that module's port bead lands (transitional duplication is
sanctioned). Also exposes a structured `run(ctx)` for the `python3 -m ubs_core`
CLI. `main(argv)` reproduces the heredoc emit dialect exactly: first stdout line
is the finding count, followed by up to 25 `path\tline\tcode` sample rows.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Iterable

from ubs_core.registry import Analyzer, RunContext, register
from ubs_core.suppression import SourceSuppressions
from ubs_core.lexer import javascript_lexical_views

exts = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}
skip_dirs = {'.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.cache', '.turbo'}

compare_re = re.compile(r'(?<![=!<>])(?:===|!==|==|!=)(?!=)')
assignment_head_re = re.compile(r'(?<![\w$])(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?!=)')
assignment_prefix_re = re.compile(
    r'^\s*(?:(?:const|let|var)\s+)?[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*'
    r'(?:\*\*|>>>|<<|>>|&&|\|\||\?\?|[+\-*/%&|^])?=(?!=|>)\s*'
)
open_jsx_tag_re = re.compile(r'<[A-Za-z_$][\w.$:-]*(?=[\s/>]|$)[^<>]*$')
identifier_re = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]*')
safe_compare_re = re.compile(
    r'\b(?:crypto\.)?(?:timingSafeEqual|safeEqual|safeCompare|constantTimeEqual|compareDigest|verifyWebhookSignature)\s*\('
    r'|\b(?:subtle|crypto\.subtle)\s*\.\s*verify\s*\(',
    re.IGNORECASE,
)
# Map each weak sensitive term to a *concept family*.  Synonyms that name the
# same kind of secret share a family, so a real self-comparison like
# `req.headers.authorization === expectedToken` (authorization vs token, both
# bearer-auth credentials) still counts as "same concept on both sides", while
# `doneToken !== sessionNonce` (a bearer token vs an unrelated correlation
# nonce) does not.  See issue #61.
# Two-tier identifier vocabulary (GH #85; identical to the Python and Go
# modules).  A STRONG term names a secret on its own (password, hmac, csrf...)
# unless the very next term is METADATA (tokenType, secretName, keyId).  A WEAK
# term (token, key, session, nonce...) only counts when the SAME identifier also
# carries a QUALIFIER (authToken, api_key, sessionSecret): bare `token`, `key`,
# `id` or `nonce` are everyday parser/DB/cache vocabulary and must not taint.
STRONG_TERMS = {
    'secret', 'password', 'passwd', 'pwd', 'bearer', 'hmac', 'csrf', 'xsrf',
    'otp', 'totp', 'mfa', 'signature', 'sig', 'credential', 'credentials',
    'authorization', 'jwt',
}
WEAK_TERMS = {
    'token', 'key', 'mac', 'digest', 'nonce', 'session', 'auth', 'reset',
    'webhook', 'invite', 'verification', 'recovery',
}
QUALIFIER_TERMS = {
    'api', 'auth', 'access', 'refresh', 'session', 'reset', 'recovery',
    'verification', 'invite', 'jwt', 'csrf', 'xsrf', 'webhook', 'hmac',
    'bearer', 'secret', 'signing', 'signature', 'private', 'otp', 'totp',
    'mfa', 'password', 'passwd', 'pwd', 'credential', 'credentials',
}
METADATA_TERMS = {
    'field', 'format', 'kind', 'layout', 'policy', 'schema', 'state',
    'status', 'type', 'mode', 'scheme', 'parser', 'alg', 'algorithm',
    'aud', 'audience', 'claim', 'claims', 'exp', 'expiration', 'header',
    'headers', 'issuer', 'iss', 'kid', 'name', 'label', 'id', 'index',
    'count', 'len', 'length', 'scope', 'scopes',
}
# Concept family of each vocabulary term, used to decide whether two
# name-sensitive operands compare the SAME secret (issue #61).
TERM_FAMILY = {
    'token': 'token', 'bearer': 'token', 'jwt': 'token',
    'authorization': 'token', 'auth': 'token',
    'secret': 'secret', 'password': 'secret', 'passwd': 'secret',
    'pwd': 'secret', 'credential': 'secret', 'credentials': 'secret',
    'key': 'key',
    'signature': 'signature', 'sig': 'signature', 'hmac': 'signature',
    'digest': 'signature', 'mac': 'signature',
    'csrf': 'csrf', 'xsrf': 'csrf',
    'otp': 'otp', 'totp': 'otp', 'mfa': 'otp',
    'session': 'session',
    'nonce': 'nonce',
    'reset': 'reset', 'recovery': 'reset',
    'webhook': 'webhook',
    'invite': 'invite',
    'verification': 'verification',
}
term_word_re = re.compile(r'[a-z][a-z0-9]*')
nullish_re = re.compile(r'^(?:null|undefined|true|false|0|1|NaN|Number\.NaN|""|\'\'|``)$')
length_re = re.compile(r'\b(?:length|byteLength|size)\b')
string_literal_re = re.compile(r'''(["'`])(?:\\.|(?!\1).)*?\1''')
comparison_token_re = re.compile(
    string_literal_re.pattern
    + rf'|(?P<compare>{compare_re.pattern})'
    + r'|(?P<boolean>&&(?![=])|\|\|(?![=]))'
    + r'|(?P<conditional>(?<!\?)\?(?![.?])|:)'
    + r'|(?P<open>[\[(])|(?P<close>[\])])|(?P<separator>[;{}])'
)
keywords = {
    'if', 'return', 'const', 'let', 'var', 'true', 'false', 'null', 'undefined',
    'await', 'async', 'function', 'typeof', 'instanceof', 'new', 'this',
}


def split_identifier_terms(text):
    text = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', ' ', text)
    text = re.sub(r'[_\-.]+', ' ', text)
    return text


def strip_string_literals(text):
    # Replace the *contents* of string/template literals with an empty pair of
    # quotes so a sensitive word that only ever appears inside a literal (e.g.
    # an allow-list like `new Set(["completion_token", ...])`) cannot taint a
    # variable name.  This mirrors the Go fix in #54 for the same flat-taint
    # bug class, and kills the "file-wide name taint via literal contents"
    # false positive described in #61.
    return string_literal_re.sub(lambda m: m.group(1) * 2, text)


def identifier_terms(identifier):
    return term_word_re.findall(split_identifier_terms(identifier).lower())


def identifier_is_sensitive(terms):
    for idx, term in enumerate(terms):
        if term in STRONG_TERMS:
            follower = terms[idx + 1] if idx + 1 < len(terms) else ''
            if follower not in METADATA_TERMS:
                return True
            continue
        if term in WEAK_TERMS and any(
            other_idx != idx and other in QUALIFIER_TERMS
            for other_idx, other in enumerate(terms)
        ):
            return True
    return False


def sensitive_families(text):
    # Concept families implied by the *qualified* identifiers in an operand's
    # code text, string-literal contents stripped first.  Empty => not
    # sensitive.  Each identifier is judged on its own terms, so
    # `req.headers.authorization` is sensitive (STRONG) while `parser.token`
    # and `cache.key` are not (WEAK without a qualifier).
    code = strip_string_literals(text)
    fams = set()
    if re.search(r'\bx\s+signature\b', split_identifier_terms(code).lower()):
        fams.add('signature')
    for ident in identifier_re.findall(code):
        terms = identifier_terms(ident)
        if not identifier_is_sensitive(terms):
            continue
        for word in terms:
            fam = TERM_FAMILY.get(word)
            if fam:
                fams.add(fam)
    return fams


def term_families(text):
    # Every concept family named ANYWHERE in the operand, qualified or not.
    # Not a sensitivity signal on its own; used only to tell whether two
    # name-sensitive operands talk about the SAME secret concept (issue #61):
    # `doneToken !== sessionNonce` is token-vs-nonce, a public correlation
    # check, even though sessionNonce alone is a qualified (sensitive) name.
    norm = split_identifier_terms(strip_string_literals(text)).lower()
    return {TERM_FAMILY[w] for w in term_word_re.findall(norm) if w in TERM_FAMILY}


def strip_line_comments(line: str) -> str:
    out = []
    quote = ''
    escape = False
    idx = 0
    while idx < len(line):
        ch = line[idx]
        if quote:
            out.append(ch)
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == quote:
                quote = ''
            idx += 1
            continue
        if ch in ('"', "'", '`'):
            quote = ch
            out.append(ch)
            idx += 1
            continue
        if ch == '/' and idx + 1 < len(line) and line[idx + 1] == '/':
            break
        out.append(ch)
        idx += 1
    return ''.join(out)


def code_line(source_line):
    stripped = source_line.strip()
    if not stripped or stripped.startswith(("//", "/*", "*")):
        return ""
    return re.sub(r'/\*.*?\*/', '', strip_line_comments(source_line))


def statement_from(code_lines, idx, max_lines=8):
    parts = []
    paren_balance = 0
    brace_balance = 0
    saw_code = False
    for line_idx in range(idx, min(len(code_lines), idx + max_lines)):
        current = code_lines[line_idx].strip()
        if not current:
            if parts:
                break
            continue
        parts.append(current)
        saw_code = True
        paren_balance += current.count('(') - current.count(')')
        brace_balance += current.count('{') - current.count('}')
        if line_idx > idx and paren_balance <= 0 and brace_balance <= 0:
            break
        if (';' in current or current.endswith('{')) and paren_balance <= 0 and brace_balance <= 0:
            break
    return ' '.join(parts) if saw_code else ""


def operand_identifiers(operand):
    # Ordinary quoted text cannot read a local variable. Preserve template
    # literals conservatively: their ${...} expressions can read secrets.
    code = string_literal_re.sub(
        lambda match: match.group() if match.group(1) == '`' else '', operand
    )
    return {
        token
        for token in identifier_re.findall(code)
        if token not in keywords
    }


def is_sensitive_text(text):
    return bool(sensitive_families(text))


CONTINUATION_TAIL = ('=', '(', '[', ',', '&&', '||', '?', ':', '+', '=>', '.')
CONTINUATION_HEAD = ('.', '?', ':', ')', ']', '&&', '||', '+', '===', '!==', '==', '!=')


def statement_start(code_lines, index):
    # Walk upward over physical lines that belong to the same statement as
    # lines[index] (assignment/paren/operator continuations) to recover the
    # left operand of a comparison whose operator starts a continuation line.
    start = index
    for _ in range(8):
        if start <= 0:
            break
        prev = code_lines[start - 1].strip()
        cur = code_lines[start].strip()
        if not prev:
            break
        if prev.endswith(CONTINUATION_TAIL) or cur.startswith(CONTINUATION_HEAD):
            start -= 1
            continue
        break
    return start


def open_jsx_tag(prefix):
    """Recognize an unfinished JSX tag, excluding ordinary less-than operands."""
    match = open_jsx_tag_re.search(prefix)
    if not match:
        return ''
    before = prefix[:match.start()].rstrip()
    if before and before[-1] not in '=([{,:?;>&|' and not re.search(r'\b(?:return|yield)\s*$', before):
        return ''
    return match.group()


call_head_re = re.compile(
    r'\s*(?:await\s+)?(?:new\s+)?[A-Za-z_$][\w$]*(?:\s*(?:\?\.|!?\.)\s*[A-Za-z_$][\w$]*)*'
    r'\s*(?:<[^<>()]*>\s*)?(?:\?\.\s*)?\('
)
chained_call_re = re.compile(r'\s*(?:\?\.|!?\.)\s*[A-Za-z_$][\w$]*\s*(?:<[^<>()]*>\s*)?(?:\?\.\s*)?\(')
call_tail_re = re.compile(r'\s*!?\s*(?:(?:as|satisfies)\s+[\w$.<>\[\]|&, ]+)?')
# An equality's left operand runs back to the statement start, so it can carry
# `return`, `yield` or assignment heads (`const ok = result.type`).
member_read_re = re.compile(
    r'(?:(?:return|yield)\s+|(?:(?:const|let|var)\s+)?[A-Za-z_$][\w$]*\s*=\s*)*'
    r'\(*\s*(?P<root>[A-Za-z_$][\w$]*)(?P<chain>(?:\s*(?:\?\.|!?\.)\s*[A-Za-z_$][\w$]*)+)\s*\)*'
)


def is_call_result(expr):
    """Whether an assignment's value is exactly the return value of a call.

    `await api.open(x)`, `new Client(x)`, `make(x).build()` and TypeScript
    `... as T` qualify; member reads of a result (`login(x).accessToken`),
    operators and anything else after the call do not.
    """
    match = call_head_re.match(expr)
    if not match:
        return False
    position = match.end() - 1
    while True:
        depth, close = 0, -1
        for index in range(position, len(expr)):
            if expr[index] == '(':
                depth += 1
            elif expr[index] == ')':
                depth -= 1
                if depth == 0:
                    close = index
                    break
        if close < 0:
            return False
        chained = chained_call_re.match(expr, close + 1)
        if not chained:
            return call_tail_re.fullmatch(expr, close + 1) is not None
        position = chained.end() - 1


def call_result_metadata_read(operand, call_results):
    """`result.type` where `result` only ever holds a call's return value (GH #181, #185).

    The call's arguments or callee name may name a secret
    (`openAuthSessionAsync(authorization.authorize_url)`), which is why the
    result is tracked at all, but a METADATA member of the returned object is
    its public discriminant, not that secret. Aliases of a secret
    (`result = authorization`) never qualify. A member whose own name carries
    secret vocabulary (`result.authTokenId`) is still reported by name.
    """
    read = member_read_re.fullmatch(operand)
    if not read or read.group('root') not in call_results:
        return False
    terms = identifier_terms(identifier_re.findall(read.group('chain'))[-1])
    return bool(terms) and terms[-1] in METADATA_TERMS


def collect_sensitive_bindings(lines, code_lines):
    """Locals assigned secret material, and those that only hold call results.

    Returns (sensitive_vars, call_results). A name lands in call_results when
    every assignment that made it sensitive was exactly a call expression and
    the name itself carries no secret vocabulary.
    """
    sensitive_vars, call_vars, alias_vars = set(), set(), set()
    # Carry unfinished tags over physical lines. Attribute names are DOM
    # properties, not assignments to JavaScript locals. Keep assignments inside
    # their {...} expressions eligible, including nested assignment expressions.
    tag_prefixes, tag = [], ''
    for code in code_lines:
        tag_prefixes.append(tag)
        tag = open_jsx_tag(tag + ' ' + strip_string_literals(code))
    for idx, code in enumerate(code_lines):
        stripped = code.strip()
        if not stripped or '=>' in stripped:
            continue
        statement = statement_from(code_lines, idx, max_lines=5)
        if not statement or safe_compare_re.search(statement):
            continue
        statement = strip_string_literals(statement)
        for match in assignment_head_re.finditer(statement):
            prefix = tag_prefixes[idx] + ' ' + statement[:match.start()]
            tag = open_jsx_tag(prefix)
            if tag and tag.count('{') == tag.count('}'):
                continue
            name = match.group('name')
            expr = statement[match.end():].split(';', 1)[0]
            # String contents and JSX attribute names cannot taint locals;
            # real assignment expressions still propagate secret material.
            named = bool(sensitive_families(name))
            if named or sensitive_families(expr):
                sensitive_vars.add(name)
                if not named and is_call_result(expr):
                    call_vars.add(name)
                else:
                    alias_vars.add(name)
    return sensitive_vars, frozenset(call_vars - alias_vars)


def clean_operand_text(operand):
    clean = operand.strip()
    clean = re.sub(r'^(?:if|while)\s*\(\s*', '', clean)
    # Boolean boundaries are resolved before classifying a comparison (GH #135).
    # Truncating both operands at the first connective can replace the LEFT
    # operand with an unrelated earlier term, and also splits quoted text.
    boundary = next((match.start() for match in comparison_token_re.finditer(clean)
                     if match.lastgroup == 'separator' and match.group() in ';{'), len(clean))
    clean = clean[:boundary].strip()
    while clean and clean[-1] in ';{}){':
        clean = clean[:-1].strip()
    return clean


def operand_is_nullish_or_shape_check(operand):
    clean = clean_operand_text(operand)
    # Only the complete unary identifier/member expression reveals a type.
    # A compound expression such as typeof value + password still leaks a
    # secret through equality and must keep the ordinary sensitivity checks.
    if re.fullmatch(r'typeof\s+[A-Za-z_$][\w$]*(?:\s*(?:\?\.|\.)\s*[A-Za-z_$][\w$]*)*', clean):
        return True
    if nullish_re.match(clean):
        return True
    if length_re.search(clean):
        return True
    if re.match(r'^[0-9]+(?:\.[0-9]+)?$', clean):
        return True
    return False


def comparison_operands(statement: str) -> Iterable[tuple[int, str, str]]:
    """Bound each equality's operands before sensitivity checks (GH #135)."""
    tokens = []
    depth = 0
    for match in comparison_token_re.finditer(statement):
        kind = match.lastgroup
        if kind is None:  # A quoted literal, not code punctuation.
            continue
        tokens.append((match, depth))
        if kind == 'open':
            depth += 1
        elif kind == 'close':
            depth -= 1

    for index, (comparison, level) in enumerate(tokens):
        if comparison.lastgroup != 'compare':
            continue
        start, end = 0, len(statement)
        # A connective in a nested operand, e.g. (secret || fallback), is not
        # a boundary of the surrounding equality. Quotes are skipped above.
        for previous, previous_level in reversed(tokens[:index]):
            kind = previous.lastgroup
            if (kind == 'separator'
                    or (kind in {'boolean', 'conditional'} and previous_level <= level)
                    or (kind == 'open' and previous_level < level)):
                start = previous.end()
                break
        for following, following_level in tokens[index + 1:]:
            kind = following.lastgroup
            if (kind == 'separator'
                    or (kind in {'boolean', 'conditional'} and following_level <= level)
                    or (kind == 'close' and following_level <= level)):
                end = following.start()
                break
        left = statement[start:comparison.start()]
        right = statement[comparison.end():end]
        # Equality binds more tightly than assignment. A leading simple
        # destination is not a compared value: `token = typeof value ===
        # "string"` compares only the type. Peel only proven identifier/member
        # assignment prefixes, including chains. Never search inside an
        # operand: nested assignments and regex text such as /x=y/ must remain
        # intact. Complex destinations stay conservative rather than guessed.
        while assignment := assignment_prefix_re.match(left):
            left = left[assignment.end():]
        if left.strip() and right.strip():
            yield comparison.start(), left, right


def playwright_response_ranges(text):
    """Public metadata of real, unrebound Playwright response callback bindings.

    File-wide alias names are not proof that a callback's Response is a secret.
    Keep that conservative taint for its contents; only method/URL metadata
    gets a scoped exception, with fixture provenance and no shadowed URL.
    """
    source, code = javascript_lexical_views(text)
    imports = re.finditer(
        r'\bimport\s*\{([^}]+)\}\s*from\s*([\'"])@playwright/test\2', source
    )
    if not any(code[match.start():match.start() + 6] == 'import'
               and 'test' in (name.strip() for name in match.group(1).split(','))
               for match in imports):
        return []
    from ubs_core.analyzers.taint_js import _function_scopes

    _root, scopes = _function_scopes(source, code)
    shadowed_url = bool(re.search(
        r'\b(?:const|let|var|class|function)\s+URL\b|\bURL\s*=(?!=)'
        r'|\bimport\b[^;]*\bURL\b', code
    )) or any('URL' in names for scope in scopes for names, *_ in scope.params)
    ranges = []
    for scope in scopes:
        if len(scope.params) != 1:
            continue
        names, rest, default, _span = scope.params[0]
        if len(names) != 1 or rest or default is not None:
            continue
        if code[_span[0]:_span[1]].lstrip().startswith(('{', '[')):
            continue
        name = names[0]
        prefix_start = max(0, scope.start - 256)
        call = re.search(
            r'\b([A-Za-z_$][\w$]*)\s*\.\s*(?:waitForResponse\s*\(\s*'
            r'|(?:on|once)\s*\(([^,()]*)\,\s*)$',
            code[prefix_start:scope.start],
        )
        if not call:
            continue
        if call.group(2) is not None:
            event_start, event_end = call.span(2)
            event = source[prefix_start + event_start:prefix_start + event_end].strip()
            if event not in {'"response"', "'response'"}:
                continue
        receiver = call.group(1)
        parent = scope.parent
        fixture = None
        while parent:
            prefix = code[max(0, parent.start - 512):parent.start]
            # Test callbacks receive the actual page fixture. Ordinary helpers
            # or similarly named methods do not establish this provenance.
            if any(receiver in bindings for bindings, *_ in parent.params):
                if (receiver in parent.params[0][0]
                        and re.search(r'\btest\s*\([^;]*,\s*$', prefix)):
                    fixture = parent
                break
            parent = parent.parent
        if fixture is None:
            continue
        if (re.search(rf'\b{re.escape(receiver)}\s*=(?!=|>)',
                      code[fixture.body_start:fixture.body_end])
                or re.search(rf'\b{re.escape(name)}\s*=(?!=|>)',
                             code[scope.body_start:scope.body_end])):
            continue
        # A nested function can shadow the Response parameter. Its body is not
        # evidence about the surrounding callback's public metadata.
        cursor = scope.body_start
        for child in sorted(scope.children, key=lambda item: item.start):
            ranges.append((cursor, child.start, name, not shadowed_url, scope.body_start))
            cursor = child.end
        ranges.append((cursor, scope.body_end, name, not shadowed_url, scope.body_start))
    return ranges


def response_metadata_read(operand, names, path_names):
    operand = operand.strip().removesuffix(';').strip()
    operand = re.sub(r'^(?:return|yield)\s+', '', operand)
    operand = re.sub(r'^(?:if|while)\s*\(', '(', operand)
    for name in names:
        root = re.escape(name)
        if re.fullmatch(rf'\(*\s*{root}\s*\.\s*url\s*\(\s*\)\s*\)*', operand):
            return True
        if re.fullmatch(rf'\(*\s*{root}\s*\.\s*request\s*\(\s*\)\s*\.\s*method\s*\(\s*\)\s*\)*', operand):
            return True
        if name in path_names and re.fullmatch(
                rf'\(*\s*new\s+URL\s*\(\s*{root}\s*\.\s*url\s*\(\s*\)\s*\)\s*\.\s*pathname\s*\)*', operand):
            return True
    return False


def callback_parameter_ranges(text, sensitive_vars):
    """Independent callback bindings, limited to unreassigned direct reads.

    A file-wide alias such as `r = await login(secret)` says nothing about
    `rows.filter(r => r.status === "sent")`. Defaults, destructuring, writes
    and secret-bearing callback inputs do not establish an independent value.
    Method calls and computed/compound reads retain conservative taint below.
    """
    if not sensitive_vars:
        return []
    from ubs_core.analyzers.taint_js import _function_scopes

    source, code = javascript_lexical_views(text)
    root, _scopes = _function_scopes(source, code)
    ranges = []
    input_contexts = {}

    def input_context(scope):
        """Resolve callback input names in their enclosing lexical binding.

        A local `w = world()` does not inherit another function's `w = secret`.
        Retain captured aliases and propagate local secret assignments before
        deciding whether the callback receives a potentially secret value.
        """
        if scope in input_contexts:
            return input_contexts[scope]
        active = set(input_context(scope.parent)) if scope.parent else set()
        own_code = scope.code[scope.body_start:scope.body_end]
        local_names = set()
        for declaration in re.finditer(r'\b(const|let|var)\s+([A-Za-z_$][\w$]*)', own_code):
            before = own_code[:declaration.start()]
            # A block/loop-local let or const cannot shadow a captured binding
            # throughout the function. Retain taint when that scope is unclear.
            if (declaration.group(1) == 'var'
                    or all(before.count(opening) == before.count(closing)
                           for opening, closing in (('{', '}'), ('(', ')'), ('[', ']')))):
                local_names.add(declaration.group(2))
        active.difference_update(local_names)
        for bindings, _rest, _default, _span in scope.params:
            active.difference_update(bindings)
            # Unknown incoming arguments keep the incumbent's conservative
            # classification; this is only a local declaration shadow repair.
            active.update(set(bindings) & sensitive_vars)
        own_lines = own_code.splitlines()
        local_sensitive, _call_results = collect_sensitive_bindings(own_lines, own_lines)
        active.update(local_sensitive)
        assignments = [(match.group('name'), own_code[match.end():].split(';', 1)[0])
                       for match in assignment_head_re.finditer(own_code)]
        changed = True
        while changed:
            changed = False
            for name, expression in assignments:
                if name not in active and operand_identifiers(expression) & active:
                    active.add(name)
                    changed = True
        input_contexts[scope] = frozenset(active)
        return input_contexts[scope]

    def visit(scope, inherited, bound):
        names = set(inherited)
        bound = set(bound)
        inline_callback = scope is not root and not (scope.name or scope.method)
        for bindings, _rest, _default, _span in scope.params:
            names.difference_update(bindings)
            # This repair handles inline callback bindings. Named functions
            # keep the existing call-result metadata policy; changing it here
            # would introduce unrelated key-id false positives.
            if inline_callback:
                bound.update(bindings)
        # Named functions/methods have separately resolved callers. Keep their
        # existing conservative treatment; only inline callbacks qualify here.
        if inline_callback:
            prefix_start = scope.parent.body_start
            nesting = {')': 0, ']': 0, '}': 0}
            pairs = {'(': ')', '[': ']', '{': '}'}
            for index in range(scope.start - 1, prefix_start - 1, -1):
                char = code[index]
                if char in nesting:
                    nesting[char] += 1
                elif char in pairs:
                    closing = pairs[char]
                    if nesting[closing]:
                        nesting[closing] -= 1
                    elif char == '{':
                        prefix_start = index + 1
                        break
                elif char == ';' and not any(nesting.values()):
                    prefix_start = index + 1
                    break
            # Balanced object literals belong to the receiver/arguments; a
            # closing brace alone is not a statement boundary.
            prefix = source[prefix_start:scope.start]
            secret_input = (is_sensitive_text(prefix)
                            or bool(operand_identifiers(prefix) & input_context(scope.parent)))
            if not secret_input:
                for bindings, rest, default, span in scope.params:
                    pattern = code[span[0]:span[1]].strip()
                    if (len(bindings) == 1 and not rest and default is None
                            and re.fullmatch(r'[A-Za-z_$][\w$]*(?:\s*\??\s*:[\s\S]+)?', pattern)):
                        names.add(bindings[0])
        body = code[scope.body_start:scope.body_end]
        for name in tuple(names):
            target = rf'(?<![\w$.]){re.escape(name)}\b'
            member = r'(?:\s*\.\s*[A-Za-z_$][\w$]*|\s*\[[^\]\n]*\])*'
            if re.search(target + member + r'\s*(?:[+*/%&|^?-]*=(?!=|>)|\+\+|--)', body):
                names.discard(name)
            elif re.search(target + r'\s*[,}\]][^;\n]*=(?!=|>)', body):
                names.discard(name)
            elif re.search(r'(?:\+\+|--)\s*' + target, body):
                names.discard(name)
            # Calls/aliases can mutate an object without spelling a direct
            # write. Do not declare its later fields independent in that case.
            elif (re.search(target + member + r'\s*\(', body)
                  or re.search(target + r'\s*[,)]', body)
                  or re.search(r'(?<![=!<>])=\s*' + target, body)):
                names.discard(name)
        cursor = scope.body_start
        for child in sorted(scope.children, key=lambda item: item.start):
            ranges.append((cursor, child.start, frozenset(names), scope.body_start, frozenset(bound)))
            visit(child, names, bound)
            cursor = child.end
        ranges.append((cursor, scope.body_end, frozenset(names), scope.body_start, frozenset(bound)))

    visit(root, set(), set())
    return ranges


def unsafe_secret_compare(statement, sensitive_vars, *, call_results=frozenset(),
                          comparison_start=0, comparison_limit=None,
                          response_ranges=(), parameter_ranges=(), source_offset=0):
    if safe_compare_re.search(statement):
        return False
    # Match within each term, never across &&/||. An exempt comparison only
    # exempts that term; later terms may still compare actual secret values.
    for offset, left, right in comparison_operands(statement):
        if offset < comparison_start:
            continue
        if comparison_limit is not None and offset >= comparison_limit:
            continue
        independent = set()
        comparison_call_results = call_results
        for start, end, names, body, bound in parameter_ranges:
            if start <= source_offset + offset < end:
                independent.update(names)
                # A new parameter cannot inherit the old variable's evidence
                # that its value was exclusively a call result, either.
                comparison_call_results = call_results - bound
                if names and source_offset + offset - len(left) < body <= source_offset + offset:
                    left = statement[body - source_offset:offset]
        public = [(name, paths, body) for start, end, name, paths, body in response_ranges
                  if start <= source_offset + offset < end]
        for name, paths, body in public:
            # A concise callback may share the comparison's physical line.
            # Recover its operand from the real body boundary, rather than
            # treating the call/arrow prefix as part of the compared value.
            if source_offset < body <= source_offset + offset:
                callback_left = statement[body - source_offset:offset]
                if response_metadata_read(callback_left, {name}, {name} if paths else set()):
                    left = callback_left
                    break
        if unsafe_secret_operands(left, right, sensitive_vars, comparison_call_results,
                                  frozenset(name for name, _, _ in public),
                                  frozenset(name for name, paths, _ in public if paths),
                                  frozenset(independent)):
            return True
    return False


def operand_tainted(operand, sensitive_vars, call_results=frozenset(), independent=frozenset()):
    identifiers = operand_identifiers(operand)
    read = member_read_re.fullmatch(operand)
    scalar = re.fullmatch(r'(?:(?:return|yield)\s+)?\(*\s*([A-Za-z_$][\w$]*)\s*\)*', operand)
    root = read.group('root') if read else scalar.group(1) if scalar else None
    if root in independent:
        identifiers.discard(root)
    return (bool(identifiers & sensitive_vars)
            and not call_result_metadata_read(operand, call_results))


def unsafe_secret_operands(left, right, sensitive_vars, call_results=frozenset(),
                           response_names=frozenset(), path_names=frozenset(), independent=frozenset()):
    left_metadata = response_metadata_read(left, response_names, path_names)
    right_metadata = response_metadata_read(right, response_names, path_names)
    left = clean_operand_text(left)
    right = clean_operand_text(right)
    if operand_is_nullish_or_shape_check(left) or operand_is_nullish_or_shape_check(right):
        return False

    left_fams = sensitive_families(left)
    right_fams = sensitive_families(right)
    left_taint = (operand_tainted(left, sensitive_vars, call_results, independent)
                  and not left_metadata)
    right_taint = (operand_tainted(right, sensitive_vars, call_results, independent)
                   and not right_metadata)
    left_sensitive = bool(left_fams) or left_taint
    right_sensitive = bool(right_fams) or right_taint

    if not (left_sensitive or right_sensitive):
        return False

    # When BOTH operands carry secret vocabulary in their identifier *names*
    # (no data-flow taint from an assigned secret), require that they name the
    # SAME secret concept.  A genuine timing-attack self-comparison uses one
    # concept on both sides (userToken === validToken; authorization ===
    # expectedToken).  Comparing two *different* concepts (doneToken !==
    # sessionNonce) is almost always an unrelated/public value such as a
    # correlation nonce, not a real secret check -- so it is not flagged.
    # See issue #61.
    left_all = term_families(left)
    right_all = term_families(right)
    if left_all and right_all and not (left_taint or right_taint):
        return bool(left_all & right_all)

    return True


def scan_file(path: Path, sample_root: Path) -> list[tuple[str, int, str]]:
    """Per-file body of the heredoc walk: [(rel_path, line, code_text), ...]."""
    issues: list[tuple[str, int, str]] = []
    if path.suffix.lower() not in exts:
        return issues
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return issues
    lines = text.splitlines()
    source_index = SourceSuppressions('javascript').index(path, text)
    # Statement lookahead revisits each physical line. Keep its exact lexical
    # view only for this file; the shared index owns suppression separately.
    # Scope coordinates are absolute. Blank comments without shortening the
    # line so a later comparison cannot appear inside an earlier callback.
    lexical_source, _lexical_code = javascript_lexical_views(text)
    code_lines = lexical_source.splitlines()
    sensitive_vars, call_results = collect_sensitive_bindings(lines, code_lines)
    response_ranges = playwright_response_ranges(text)
    parameter_ranges = callback_parameter_ranges(text, sensitive_vars)
    line_offsets = []
    offset = 0
    for line in text.splitlines(keepends=True):
        line_offsets.append(offset)
        offset += len(line)
    seen_lines = set()
    for idx, code in enumerate(code_lines):
        stripped = code.strip()
        if not stripped or ('==' not in stripped and '!=' not in stripped):
            continue
        prefix = ''
        if compare_re.match(stripped):
            # An operator may start a continuation line. Recover its real left
            # operand, but do not re-report comparisons from the prefix.
            start = statement_start(code_lines, idx)
            prefix = ' '.join(line.strip() for line in code_lines[start:idx])
            if prefix:
                prefix += ' '
        statement = prefix + statement_from(code_lines, idx)
        # Lookahead completes a multiline operand, but a comparison on a later
        # physical line must be reported there, not on this line as well.
        if not statement or not unsafe_secret_compare(
            statement, sensitive_vars, call_results=call_results,
            comparison_start=len(prefix), comparison_limit=len(prefix) + len(stripped),
            response_ranges=response_ranges,
            parameter_ranges=parameter_ranges,
            source_offset=line_offsets[idx] + len(code) - len(code.lstrip()) - len(prefix)
        ):
            continue
        if idx in seen_lines or source_index.is_suppressed(idx + 1, _RULE):
            continue
        seen_lines.add(idx)
        try:
            rel = path.relative_to(sample_root)
        except ValueError:
            rel = path
        issues.append((str(rel), idx + 1, stripped.replace('\t', ' ')))
    return issues


def collect_issues(root: Path) -> list[tuple[str, int, str]]:
    issues: list[tuple[str, int, str]] = []
    if root.is_file():
        candidates = [root]
        sample_root = root.parent
    else:
        candidates = []
        sample_root = root
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for fname in filenames:
                candidates.append(Path(dirpath) / fname)

    for path in candidates:
        issues.extend(scan_file(path, sample_root))
    return issues


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    issues = collect_issues(root)
    print(len(issues))
    for entry in issues[:25]:
        print('\t'.join(str(part) for part in entry))
    return 0


_KIND = "unsafe_secret_compare"
_RULE = f"javascript.ctcompare.{_KIND}"
_MESSAGE = "Secret, signature, or token compared with ==/!= without timing-safe equality"


def run(ctx: RunContext) -> Iterable[dict]:
    cwd = Path.cwd()
    for path in ctx.files:
        for rel, line, _sample in scan_file(path, cwd):
            yield {
                "rule": _RULE,
                "path": rel,
                "line": line,
                "col": 1,
                "layer": "ctcompare",
                "lang": "javascript",
                "severity": "critical",
                "message": _MESSAGE,
            }


_POSITIVE_SRC = """export function nonceReplayCheck(sessionNonce: string, expectedNonce: string): boolean {
  return sessionNonce === expectedNonce;
}

export function doneTokenCheck(doneAuthToken: string, expectedAuthToken: string): boolean {
  if (doneAuthToken !== expectedAuthToken) {
    return false;
  }
  return true;
}
"""


def _selftest_positive() -> None:
    for statement in ("return sessionNonce === expectedNonce;", "if (doneAuthToken !== expectedAuthToken) {"):
        sensitive_vars, call_results = collect_sensitive_bindings([statement], [code_line(statement)])
        assert unsafe_secret_compare(statement, sensitive_vars, call_results=call_results), statement


def _selftest_suppression() -> None:
    lines = [
        "export function verifyToken(authToken: string, expectedAuthToken: string): boolean {",
        "  if (authToken !== expectedAuthToken) { // ubs:ignore -- deliberate: not a secret comparison",
        "    return false;",
        "  }",
        "  return true;",
        "}",
    ]
    with tempfile.TemporaryDirectory(prefix="ubs_core_ctcompare_js_") as tmp:
        target = Path(tmp) / "suppressed.ts"
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert scan_file(target, Path(tmp)) == []


def _selftest_safe_compare_negative() -> None:
    lines = [
        "import crypto from 'crypto';",
        "export function safeCheck(left: string, right: string): boolean {",
        "  return crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));",
        "}",
    ]
    with tempfile.TemporaryDirectory(prefix="ubs_core_ctcompare_js_") as tmp:
        target = Path(tmp) / "safe.ts"
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert scan_file(target, Path(tmp)) == []


def _selftest_run(tmp_prefix: str = "ubs_core_ctcompare_js_") -> None:
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "leaky.ts"
        target.write_text(_POSITIVE_SRC, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert len(findings) == 2, findings
    assert findings[0]["rule"] == "javascript.ctcompare.unsafe_secret_compare"
    assert findings[0]["line"] == 2
    assert findings[1]["line"] == 6
    assert findings[0]["severity"] == "critical"


def _selftest_main_dialect(tmp_prefix: str = "ubs_core_ctcompare_js_") -> None:
    import contextlib
    import io

    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        target = Path(tmp) / "leaky.ts"
        target.write_text(_POSITIVE_SRC, encoding="utf-8")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            old_argv = sys.argv
            sys.argv = ["ctcompare_js", str(tmp)]
            try:
                assert main() == 0
            finally:
                sys.argv = old_argv
    lines_out = stdout.getvalue().splitlines()
    assert lines_out[0] == "2", lines_out
    assert lines_out[1].startswith("leaky.ts\t2\t"), lines_out


def _selftest_boolean_operand_boundaries() -> None:
    # GH #135: the secret-named call is not an operand of the typeof check.
    for connective in ('||', '&&'):
        for operator in ('===', '!==', '==', '!='):
            for statement in (
                f'if (!isValidSecret(secret) {connective} typeof envelope {operator} "string") return false;',
                f'if (typeof envelope {operator} "string" {connective} !isValidSecret(secret)) return false;',
                f'if (ready {connective} !isValidSecret(secret) {connective} typeof envelope {operator} "string") return false;',
            ):
                assert not unsafe_secret_compare(statement, set()), statement
    # A tainted value in another term must not taint the comparison either.
    statement = 'if (cachedValue || typeof envelope !== "string") return false;'
    assert not unsafe_secret_compare(statement, {'cachedValue'}), statement


def _selftest_later_boolean_comparisons() -> None:
    for connective in ('||', '&&'):
        for prefix in (
            'ready',
            'typeof envelope !== "string"',
            'expectedSignature.byteLength !== SIGNATURE_BYTES',
            'secret === undefined',
            'doneToken !== sessionNonce',
        ):
            statement = f'if ({prefix} {connective} expectedSignature !== actualSignature) return false;'
            assert unsafe_secret_compare(statement, set()), statement
        statement = f'if (ready {connective} cachedValue === suppliedValue) return false;'
        assert unsafe_secret_compare(statement, {'cachedValue'}), statement


def _selftest_quoted_boolean_text() -> None:
    # Splitting quoted ||/&& would expose secret words as identifiers.
    for literal in ('"public || secret"', "'public && secret'", '`public || secret`',
                    r'"public \" || secret"'):
        statement = f'if (kind === {literal} && state !== "ready") return false;'
        assert not unsafe_secret_compare(statement, set()), statement
    statement = 'if (kind === "public || secret" && expectedSignature !== actualSignature) return false;'
    assert unsafe_secret_compare(statement, set()), statement


def _selftest_boolean_exemptions() -> None:
    for prop in ('length', 'byteLength', 'size'):
        for connective in ('||', '&&'):
            for operands in (f'expectedSignature.{prop} !== SIGNATURE_BYTES',
                             f'SIGNATURE_BYTES !== expectedSignature.{prop}'):
                statement = f'if (!isValidSecret(secret) {connective} {operands}) return false;'
                assert not unsafe_secret_compare(statement, set()), statement
    for value in ('null', 'undefined', 'true', 'false', '0', '1', '42', '""'):
        statement = f'if (ready && secret !== {value}) return false;'
        assert not unsafe_secret_compare(statement, set()), statement
    for function in ('timingSafeEqual', 'crypto.timingSafeEqual', 'safeEqual',
                     'safeCompare', 'constantTimeEqual', 'compareDigest',
                     'verifyWebhookSignature', 'subtle.verify', 'crypto.subtle.verify'):
        statement = f'if (expectedSignature.byteLength !== SIGNATURE_BYTES || !{function}(expectedSignature, actualSignature)) return false;'
        assert not unsafe_secret_compare(statement, set()), statement


def _selftest_envelope_guard_regression() -> None:
    source = '''function isValidSecret(secret: Uint8Array | undefined): boolean {
  return secret !== undefined && secret.byteLength > 0;
}

export function verifyEnvelope(
  envelope: string | null | undefined,
  secret: Uint8Array | undefined,
): boolean {
  if (!isValidSecret(secret) || typeof envelope !== "string") return false;
  return envelope.length > 0;
}

if (
  expectedSignature.byteLength !== SIGNATURE_BYTES ||
  !timingSafeEqual(expectedSignature, actualSignature)
) {
  return undefined;
}
'''
    with tempfile.TemporaryDirectory(prefix="ubs_core_ctcompare_js_") as tmp:
        target = Path(tmp) / "envelope.ts"
        target.write_text(source, encoding="utf-8")
        assert collect_issues(Path(tmp)) == []
        assert list(run(RunContext(lang="javascript", files=[target]))) == []


def _selftest_nested_boolean_operands() -> None:
    for statement in (
        'return (secret || fallback) === supplied;',
        'return supplied === (secret || fallback);',
        'if (ready && (expectedSignature || fallback) !== actualSignature) return false;',
        'if (typeof envelope !== "string" || ((expectedSignature || fallback) !== actualSignature)) return false;',
    ):
        assert unsafe_secret_compare(statement, set()), statement
    statement = 'if (kind === "expectedSignature !== actualSignature" || state === "ready") return false;'
    assert not unsafe_secret_compare(statement, set()), statement


def _selftest_multiline_boolean_locations() -> None:
    source = '''if (
  typeof envelope !== "string" ||
  expectedSignature !== actualSignature
) {
  return false;
}
if (kind === "public" || expectedSignature !== actualSignature) return false;
'''
    with tempfile.TemporaryDirectory(prefix="ubs_core_ctcompare_js_") as tmp:
        target = Path(tmp) / "unsafe.ts"
        target.write_text(source, encoding="utf-8")
        findings = list(run(RunContext(lang="javascript", files=[target])))
    assert [f["line"] for f in findings] == [3, 7], findings
    assert all(f["rule"] == "javascript.ctcompare.unsafe_secret_compare" for f in findings)


def _selftest_leading_operator_continuations() -> None:
    for operator in ('===', '!==', '==', '!='):
        source = f'''if (expectedSignature
    {operator} actualSignature) return false;
const matches = expectedSignature
    {operator} supplied;
if (!isValidSecret(secret) || typeof envelope
    {operator} "string") return false;
if (expectedSignature !== actualSignature &&
    expectedSignature.length
    {operator} 32) return false;
'''
        with tempfile.TemporaryDirectory(prefix="ubs_core_ctcompare_js_") as tmp:
            target = Path(tmp) / "continued.ts"
            target.write_text(source, encoding="utf-8")
            findings = list(run(RunContext(lang="javascript", files=[target])))
        assert [f["line"] for f in findings] == [2, 4, 7], (operator, findings)


def _selftest_literal_and_conditional_operands() -> None:
    # A quoted route segment does not read the unrelated secret-bearing local.
    for quote in ('"', "'"):
        statement = f'url.pathname === {quote}/api/org/link{quote}'
        assert not unsafe_secret_compare(statement, {'org', 'link'}), statement
    assert unsafe_secret_compare('alias === supplied', {'alias'})
    assert unsafe_secret_compare('`${alias}` === supplied', {'alias'})
    # Secret-bearing work in another conditional arm is not an operand.
    for statement in (
        'cookie !== null ? verifyToken(secret, cookie) : null',
        'session.org === undefined ? publicValue : secret',
        'typeof claims.nonce !== "string"',
    ):
        assert not unsafe_secret_compare(statement, {'session', 'claims'}), statement
    # Neither conditional arm, nested expressions nor optional/nullish access
    # may hide a real comparison. The original unsafe cases remain findings.
    for statement in (
        'ready ? expectedSignature === supplied : false',
        'ready ? false : expectedSignature === supplied',
        'expectedSignature === (ready ? actualSignature : backupSignature)',
        '(expectedSignature ?? backupSignature) === supplied',
        'ctx?.expectedSignature === supplied',
        'typeof claims.nonce !== "string" || expectedSignature !== supplied',
        'typeof value + password === supplied',
        'typeof value + ":" + authToken === supplied',
    ):
        assert unsafe_secret_compare(statement, {'claims'}), statement


SELF_TESTS: tuple[tuple[str, callable], ...] = (
    ("literal_and_conditional_operands", _selftest_literal_and_conditional_operands),
    ("positive_detects_secret_compare", _selftest_positive),
    ("ubs_ignore_suppresses", _selftest_suppression),
    ("timing_safe_equal_negative", _selftest_safe_compare_negative),
    ("run_finds_unsafe_compares", _selftest_run),
    ("main_reproduces_count_dialect", _selftest_main_dialect),
    ("boolean_operands_stay_in_their_clause", _selftest_boolean_operand_boundaries),
    ("later_boolean_comparisons_are_checked", _selftest_later_boolean_comparisons),
    ("quoted_boolean_text_is_not_a_boundary", _selftest_quoted_boolean_text),
    ("boolean_length_and_safe_compare_exemptions", _selftest_boolean_exemptions),
    ("issue_135_envelope_guard_is_clean", _selftest_envelope_guard_regression),
    ("nested_boolean_operands_keep_their_secrets", _selftest_nested_boolean_operands),
    ("multiline_boolean_findings_keep_their_line", _selftest_multiline_boolean_locations),
    ("leading_operator_continuations_keep_the_left_operand", _selftest_leading_operator_continuations),
)

register(Analyzer(layer="ctcompare", lang="javascript", name="ctcompare_js", run=run, selftests=SELF_TESTS))
