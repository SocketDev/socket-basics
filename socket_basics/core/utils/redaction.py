"""Masking for finding fields that would otherwise reproduce a credential.

A finding needs to say *where* a credential is, not *what* it is. Everything a
connector puts on an alert travels further than the scanned checkout: it is
written to the facts file in the workspace, uploaded to Socket, rendered in the
dashboard, and pasted into whichever notifiers are configured. Anything copied
verbatim out of the source line is therefore copied into all of those places,
so the copy has to be masked at the point the alert is built rather than at
each destination.

Two passes are available:

``scrub_tokens``
    Always safe to run. Masks only strings matching a well-known credential
    format (AWS key IDs, GitHub tokens, PEM private key bodies, and so on),
    which are specific enough that a match is not a guess.

``redact_literals``
    For findings whose whole subject is a hardcoded credential. Masks the body
    of every string literal on the line, keeping the assignment target and the
    surrounding syntax so the finding is still readable.

``redact_snippet`` composes them, ``redact_message`` removes values interpolated
into rule messages, and ``is_credential_finding`` decides which rules get the
second pass.
"""

import re
from typing import Any, Mapping

__all__ = [
    "mask_value",
    "scrub_tokens",
    "redact_literals",
    "redact_snippet",
    "redact_message",
    "redact_dataflow_trace",
    "is_credential_finding",
]

# Below this length the revealed head and tail are a large enough fraction of
# the value to narrow it down, so short values are masked in full.
_MIN_LENGTH_FOR_PARTIAL_REVEAL = 16
_DEFAULT_REVEAL = 4

# At or above this length a bound metavariable value is specific enough that
# replacing it anywhere in a message is safe; below it, the replace is anchored
# to non-word boundaries instead.
_MIN_STANDALONE_METAVAR_LENGTH = 8


def mask_value(value: Any, reveal: int = _DEFAULT_REVEAL,
               min_length: int = _MIN_LENGTH_FOR_PARTIAL_REVEAL) -> str:
    """Mask a credential, keeping enough shape to tell two findings apart.

    Values at least ``min_length`` long keep ``reveal`` leading and trailing
    characters; shorter ones are masked completely. The asterisk run matches
    the original length so the result still lines up with the source.
    """
    text = value if isinstance(value, str) else str(value or '')
    if not text:
        return text
    if len(text) < min_length or len(text) <= reveal * 2:
        return '*' * len(text)
    return f"{text[:reveal]}{'*' * (len(text) - 2 * reveal)}{text[-reveal:]}"


# Formats distinctive enough that a match is a credential rather than a string
# that happens to look like one. Each pattern captures the secret in group 1;
# fixed vendor prefixes stay outside the group because they identify the key
# type without disclosing anything.
_TOKEN_PATTERNS = (
    # AWS access key IDs (AKIA/ASIA/ABIA/ACCA/A3T + 16 chars).
    re.compile(r'\b((?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})\b'),
    # GitHub personal access, OAuth, user-to-server, server-to-server and
    # refresh tokens.
    re.compile(r'\b(gh[pousr]_[A-Za-z0-9]{20,255})\b'),
    re.compile(r'\b(github_pat_[A-Za-z0-9_]{20,255})\b'),
    # Stripe secret, restricted and publishable keys.
    re.compile(r'\b((?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,})\b'),
    # Slack bot/user/app/refresh tokens and legacy workspace tokens.
    re.compile(r'\b(xox[abeoprs]-[A-Za-z0-9-]{10,})\b'),
    # Google API keys.
    re.compile(r'\b(AIza[A-Za-z0-9_\-]{35})\b'),
    # OpenAI-style project and user keys.
    re.compile(r'\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b'),
    # npm and PyPI upload tokens.
    re.compile(r'\b(npm_[A-Za-z0-9]{36})\b'),
    re.compile(r'\b(pypi-[A-Za-z0-9_\-]{16,})\b'),
    # Twilio account SIDs and API keys.
    re.compile(r'\b((?:AC|SK)[0-9a-fA-F]{32})\b'),
    # SendGrid.
    re.compile(r'\b(SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})\b'),
    # JSON Web Tokens: the payload segment carries the claims.
    re.compile(r'\b(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*)'),
    # Credentials embedded in a URL's authority section.
    re.compile(r'://[^\s:/@]+:([^\s/@]+)@'),
)

# PEM private keys are masked as a block: the base64 body is the key material
# and its line structure carries nothing worth keeping.
_PEM_BLOCK = re.compile(
    r'(-----BEGIN [A-Z ]*PRIVATE KEY-----)(.*?)(-----END [A-Z ]*PRIVATE KEY-----)',
    re.DOTALL,
)

# Quoted string literals, including escaped quotes. Covers the single, double
# and backtick forms the bundled rules match across languages.
_STRING_LITERAL = re.compile(
    r"""(?P<quote>["'`])(?P<body>(?:\\.|(?!(?P=quote))[^\\])*)(?P=quote)""",
    re.DOTALL,
)

# Fallback for unquoted forms such as ``password: hunter2`` in config-style
# sources, used only when a credential finding has no string literal to mask.
#
# Which operator binds decides whether a value reaches the literal pass, and
# three things have to hold at once:
#
#  - Only a whole operator counts. Stopping on the first character of ``:=`` or
#    ``==`` leaves the rest of it heading the value, which then does not look
#    quoted, so a Go short declaration would be starred out whole. A comparison
#    assigns nothing and does not match here at all.
#  - The last operator on the line binds. Taking the colon of
#    ``password: str = "..."`` leaves ``str = "..."`` as the value, so an
#    annotated declaration -- ordinary Python and TypeScript -- would never
#    reach the literal pass.
#  - An operator inside a string literal is not an operator. The ``:`` in
#    ``url = "https://..."`` would otherwise bind and star out the URL.
#
# A single regex cannot express the third, so ``_split_assignment`` walks the
# matches and skips the ones a literal covers.
_ASSIGNMENT_OPERATOR = re.compile(r':=|(?<![=!<>:])=(?!=)|(?<!:):(?!:)')

# Comment markers, used to mask text after the value on a credential line. A
# marker inside a string literal is not a comment, so callers check the spans.
_COMMENT_MARKER = re.compile(r'(?:#|//|--)')

# Statement separator. A line can carry more than one assignment, and only one
# operator binds per statement.
_STATEMENT_SEPARATOR = re.compile(r';')

# An assigned value that *opens* with a call is an expression rather than a bare
# credential, so the literal pass handles it instead of the unquoted fallback.
# Anchored deliberately: matching a call anywhere would let a trailing comment
# such as ``# see get_secret()`` disable masking for the value in front of it.
_CALL_EXPRESSION = re.compile(r'^[\w.\[\]]+\s*\(')

# A value that opens a string literal, allowing the usual raw/bytes/format/
# unicode prefixes. The prefix has to be recognized here: treating ``r"""...``
# as unquoted stars the opening line, which removes the quotes the rest of the
# snippet is measured against.
_LITERAL_OPENER = re.compile(r'^(?:rb|br|rf|fr|r|b|u|f)?(?P<quote>["\'`])', re.IGNORECASE)

# Interpolation placeholders: f-strings, template literals, shell-style.
_INTERPOLATION = re.compile(r'\$?\{[^}]*\}')

# Rule-name fragments whose finding *is* the credential. ``hardcoded-ip`` and
# the password-policy rules deliberately do not appear: their snippets are
# logic, and masking them would remove the reason the finding was raised.
#
# ``plain-text-password`` does stay, even though the rule it names mostly
# matches password *handling* rather than a literal. One of its patterns is a
# comparison against a hardcoded string, and no ``hardcoded-*`` rule covers that
# shape, so dropping it here is the difference between masking a password and
# publishing one. Keeping the handling snippets readable is the job of the
# expression carve-out in ``redact_literals``, not of this list.
_CREDENTIAL_RULE_FRAGMENTS = (
    'hardcoded-secret',
    'hardcoded-credential',
    'hardcoded-password',
    'hardcoded-key',
    'hardcoded-token',
    'default-credentials',
    'plain-text-password',
    'empty-password',
    'weak-jwt-secret',
    'private-key',
    'api-key',
)


def _mask_match(match: 're.Match[str]') -> str:
    """Replace a pattern's captured secret in place, leaving its prefix intact."""
    whole = match.group(0)
    secret = match.group(1)
    if not secret:
        return whole
    secret_start, secret_end = match.span(1)
    match_start = match.start(0)
    relative_start = secret_start - match_start
    relative_end = secret_end - match_start
    return f"{whole[:relative_start]}{mask_value(secret)}{whole[relative_end:]}"


def scrub_tokens(text: Any) -> str:
    """Mask well-known credential formats anywhere in ``text``."""
    if not isinstance(text, str) or not text:
        return text if isinstance(text, str) else ''

    scrubbed = _PEM_BLOCK.sub(
        lambda m: f"{m.group(1)}\n{'*' * 32}\n{m.group(3)}", text
    )
    for pattern in _TOKEN_PATTERNS:
        scrubbed = pattern.sub(_mask_match, scrubbed)
    return scrubbed


def _split_assignment(code: str, offset: int, in_literal) -> 'tuple[str, str, str] | None':
    """Split a statement at the assignment operator that binds, if it has one.

    Returns ``(head, value, trailing_whitespace)``, where ``head`` runs through
    the operator and any space after it. Operators covered by a string literal
    are skipped, and the last of the rest wins.
    """
    chosen = None
    for match in _ASSIGNMENT_OPERATOR.finditer(code):
        if in_literal(offset + match.start()):
            continue
        chosen = match
    if chosen is None:
        return None

    rest = code[chosen.end():]
    value = rest.lstrip()
    if not value:
        return None
    head = code[:chosen.end()] + rest[:len(rest) - len(value)]
    stripped = value.rstrip()
    return head, stripped, value[len(stripped):]


def _split_statements(code: str, offset: int, in_literal) -> 'list[tuple[str, int]]':
    """Split code on statement separators, keeping each separator as a piece.

    One operator binds per statement, so a line carrying more than one has to be
    handled a statement at a time: in ``a = hunter2; password = x`` the last
    operator is the second, which would leave the first value in the head.
    """
    pieces: 'list[tuple[str, int]]' = []
    start = 0
    for separator in _STATEMENT_SEPARATOR.finditer(code):
        if in_literal(offset + separator.start()):
            continue
        pieces.append((code[start:separator.start()], offset + start))
        pieces.append((separator.group(0), offset + separator.start()))
        start = separator.end()
    pieces.append((code[start:], offset + start))
    return pieces


def _mask_statement(code: str, offset: int, in_literal) -> str:
    """Mask the assigned value in a single statement."""
    split = _split_assignment(code, offset, in_literal)
    if not split:
        return code
    head, value, trailing = split

    # A value that opens with a call is code rather than a credential:
    # ``request.form.get('password')`` is the finding, and starring it leaves
    # nothing to act on. A quoted value is the literal pass's job -- but only
    # where the quote opens a literal that pass can find. A snippet cut mid
    # string has an opening quote and no closing one, so nothing matches and
    # the value would survive untouched.
    opener = _LITERAL_OPENER.match(value)
    opens_literal = bool(opener) and in_literal(
        offset + len(head) + opener.start('quote')
    )
    if opens_literal or _CALL_EXPRESSION.match(value):
        return code

    # Anything else is masked whole. Where the value ends is unknowable here,
    # and measuring it together with what follows would reveal the head of a
    # short credential.
    return f"{head}{'*' * len(value)}{trailing}"


def _mask_code(code: str, offset: int, in_literal) -> str:
    """Mask the assigned value in every statement on one line of code."""
    return ''.join(
        piece if piece == ';' else _mask_statement(piece, piece_offset, in_literal)
        for piece, piece_offset in _split_statements(code, offset, in_literal)
    )


def _split_comment(line: str, offset: int, in_literal) -> 'tuple[str, str, str]':
    """Split a line into code, comment marker and comment text.

    The marker is kept so the masked line still reads as commented. A marker
    inside a string literal is part of the value, not a comment.
    """
    for marker in _COMMENT_MARKER.finditer(line):
        if in_literal(offset + marker.start()):
            continue
        return line[:marker.start()], marker.group(0), line[marker.end():]
    return line, '', ''


def redact_literals(text: Any) -> str:
    """Mask the body of every string literal, keeping the surrounding syntax.

    ``API_KEY = "sk_live_abc123"`` becomes ``API_KEY = "****************"``:
    the name, the operator and the line all survive, which is what makes the
    finding actionable, while the value does not.

    Where the shape of the value is not recognized the whole value is masked
    rather than guessed at, so a subscript, a ternary or a prefixed literal
    (``f"..."``, ``r'...'``) loses more of the line than a plain assignment
    does. That direction is deliberate: the rule ID, file and line still
    identify the finding, and the alternative is leaving a credential in place.
    """
    if not isinstance(text, str) or not text:
        return text if isinstance(text, str) else ''

    def _mask_literal(match: 're.Match[str]') -> str:
        body = match.group('body')
        if not body:
            return match.group(0)
        quote = match.group('quote')
        if '\n' in body or _INTERPOLATION.search(body):
            # A body that spans lines, or that interpolates, is a block of
            # content rather than one opaque value. The head-and-tail reveal
            # measures the whole thing, so the literal text around a placeholder
            # inflates the length and buys a reveal the bare value would not get
            # -- ``f"{b}_SuperSecret123!"`` would show ``123!``. Mask every line
            # and keep the line breaks, so the snippet still shows where the
            # literal starts and ends.
            masked = '\n'.join('*' * len(segment) for segment in body.split('\n'))
        else:
            masked = mask_value(body)
        return f'{quote}{masked}{quote}'

    # Literal spans are measured over the whole snippet, not line by line. A
    # literal can span lines, and a ``#`` or ``--`` on its second line is part
    # of the value; reading it as a comment and starring the rest of that line
    # can drop the closing quote, after which the literal pass no longer matches
    # and the opening line's credential survives.
    spans = [match.span() for match in _STRING_LITERAL.finditer(text)]

    def in_literal(position: int) -> bool:
        return any(start <= position < end for start, end in spans)

    masked_lines = []
    offset = 0
    for line in text.split('\n'):
        # The comment comes off first. Everything below reasons about where the
        # value ends, and a comment can hold anything the value can -- including
        # an operator later in the line than the real one, which would bind and
        # leave the credential sitting in the head.
        code, marker, comment = _split_comment(line, offset, in_literal)
        masked_lines.append(
            f"{_mask_code(code, offset, in_literal)}{marker}{'*' * len(comment)}"
        )
        offset += len(line) + 1
    return _STRING_LITERAL.sub(_mask_literal, '\n'.join(masked_lines))


def is_credential_finding(rule_id: Any, metadata: Mapping[str, Any] | None = None) -> bool:
    """Report whether a rule's match is itself a credential.

    A rule can state this directly with a ``redact`` metadata key, which is how
    custom rules opt in or out; otherwise the rule name decides.
    """
    if isinstance(metadata, Mapping) and 'redact' in metadata:
        declared = metadata.get('redact')
        if isinstance(declared, str):
            return declared.strip().lower() in ('1', 'true', 'yes', 'on')
        return bool(declared)

    name = str(rule_id or '').lower()
    return any(fragment in name for fragment in _CREDENTIAL_RULE_FRAGMENTS)


def redact_snippet(text: Any, credential_finding: bool = False) -> str:
    """Mask a snippet before it is attached to an alert.

    ``credential_finding`` adds the string-literal pass on top of the token
    scrub that every snippet receives.
    """
    scrubbed = scrub_tokens(text)
    if credential_finding:
        scrubbed = redact_literals(scrubbed)
    return scrubbed


def redact_message(text: Any, metavars: Any = None,
                   credential_finding: bool = False) -> str:
    """Mask credentials interpolated into a scanner rule's message.

    OpenGrep expands metavariables before returning a result. For credential
    findings, mask every expanded metavariable that appears in the message;
    the connector cannot reliably identify which metavariable held the secret.
    Well-known token formats are scrubbed from every message independently.
    """
    redacted = scrub_tokens(text)
    if not credential_finding or not isinstance(metavars, Mapping):
        return redacted

    values = set()
    for details in metavars.values():
        if not isinstance(details, Mapping):
            continue
        value = details.get('abstract_content')
        if isinstance(value, str) and value:
            values.add(value)

    for value in sorted(values, key=len, reverse=True):
        if len(value) >= _MIN_STANDALONE_METAVAR_LENGTH:
            # Long enough to be specific to itself.
            redacted = redacted.replace(value, mask_value(value))
        else:
            # A short bound value is also an ordinary substring, and an
            # unanchored replace masks every occurrence rather than the one
            # that is the credential: "a" turns "secret a is bad" into
            # "secret * is b*d". Requiring a non-word character on each side
            # keeps the credential masked without touching words that merely
            # contain it. Skipping short values outright is not an option --
            # a short credential still has to be masked.
            redacted = re.sub(
                rf'(?<!\w){re.escape(value)}(?!\w)',
                mask_value(value),
                redacted,
            )
    return redacted


def redact_dataflow_trace(trace: Any, credential_finding: bool = False) -> Any:
    """Mask the code fragments carried by a taint-mode dataflow trace.

    Each step quotes a source line, so a step gets the same treatment the
    snippet does: the token scrub always, and the string-literal pass when the
    rule's match is a credential. A taint rule reaches this for a credential
    only by declaring ``redact`` in its metadata, since none of the bundled
    credential rules are taint-mode, but the trace must not be the one field
    that keeps the value when one does.
    """
    if not isinstance(trace, dict):
        return trace

    def _mask(step: Any) -> None:
        if isinstance(step, dict) and step.get('content'):
            step['content'] = redact_snippet(step['content'], credential_finding)

    for key in ('source', 'sink'):
        _mask(trace.get(key))
    intermediates = trace.get('intermediates')
    if isinstance(intermediates, list):
        for step in intermediates:
            _mask(step)
    return trace
