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
# The operator alternation is what keeps a quoted value out of this branch. A
# bare ``[=:]`` stops on the first character of ``:=`` or ``==`` and leaves the
# rest of the operator at the head of the value, which no longer looks quoted,
# so a Go short declaration or a comparison would be starred out whole instead
# of going to the literal pass. ``=`` and ``:`` are matched only where they are
# not part of a longer operator, and a comparison assigns nothing, so it does
# not match here at all.
_UNQUOTED_ASSIGNMENT = re.compile(
    r'^(?P<head>[^=:]*(?::=|=(?!=)|:(?!:))\s*)(?P<body>\S.*?)(?P<tail>\s*)$'
)

# Rule-name fragments whose finding *is* the credential. ``hardcoded-ip`` and
# the password-policy rules deliberately do not appear: their snippets are
# logic, and masking them would remove the reason the finding was raised.
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


def redact_literals(text: Any) -> str:
    """Mask the body of every string literal, keeping the surrounding syntax.

    ``API_KEY = "sk_live_abc123"`` becomes ``API_KEY = "****************"``:
    the name, the operator and the line all survive, which is what makes the
    finding actionable, while the value does not.
    """
    if not isinstance(text, str) or not text:
        return text if isinstance(text, str) else ''

    def _mask_literal(match: 're.Match[str]') -> str:
        body = match.group('body')
        if not body:
            return match.group(0)
        quote = match.group('quote')
        return f'{quote}{mask_value(body)}{quote}'

    # Mask unquoted assignments line by line before processing literals. A
    # quoted value is left for the literal pass, while an unquoted value is
    # masked even if another line or a trailing comment contains quoted text.
    masked_lines = []
    for line in text.split('\n'):
        match = _UNQUOTED_ASSIGNMENT.match(line)
        body = match.group('body') if match else ''
        if match and not body.lstrip().startswith(('"', "'", '`')):
            # If quoted text appears later in an unquoted value, mask the whole
            # body. Measuring that combined text could otherwise make a short
            # credential eligible for a partial reveal.
            masked_body = (
                '*' * len(body) if _STRING_LITERAL.search(body) else mask_value(body)
            )
            masked_lines.append(
                f"{match.group('head')}{masked_body}{match.group('tail')}"
            )
        else:
            masked_lines.append(line)
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
        redacted = redacted.replace(value, mask_value(value))
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
