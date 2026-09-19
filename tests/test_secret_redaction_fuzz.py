"""Generated-snippet coverage for credential masking.

The hand-written cases in ``test_secret_redaction`` assert the shapes someone
thought of. Every gap found in review was a shape nobody thought of, so this
generates them instead: assignment operators, quote styles and prefixes,
terminated and unterminated literals, comments, statement separators, and
nesting, combined at random and checked against one invariant.

    A credential in the input never survives to the output.

The seed is fixed so a failure is reproducible. Raise ``ITERATIONS`` locally, or
run ``.context/fuzz_redaction.py`` for a longer sweep, when changing masking.
"""

import random

from socket_basics.core.utils.redaction import redact_snippet

ITERATIONS = 20_000
SEED = 1337

SHORT_SECRET = "hunter2"
LONG_SECRET = "Sup3rS3cr3tValue99xyz"

TARGETS = [
    "password", "api_key", "DB_PASSWORD", "user.password", "apiKey",
    "self.password", "PASSWORD", "password: str", "const password: string",
    "creds['db']", "x",
]
OPERATORS = ["=", ":", ":=", "==", "!=", " = ", ": "]
QUOTES = ['"', "'", "`", '"""', "'''"]
PREFIXES = ["", "r", "f", "b", "u", "rb", "R", "F"]
COMMENT_MARKERS = ["#", "//", "--"]
COMMENT_BODIES = [
    "note", "see x = y", "ratio a:b", 'a "quoted" note', 'unbalanced " quote',
    "cf. k=v", "see get_secret()", "",
]
WRAPPERS = [
    "{value}", "get_secret({value})", "a if b else {value}",
    "{value} + other", "other + {value}", "[{value}]", "f({value}, x)",
]
BARE_VALUES = [
    "{secret}", "{secret}=suffix", "prefix:{secret}", "prefix;{secret}",
    "prefix;{secret}=suffix", "{secret}(arg)",
    'prefix"decoy"{secret}', 'r""{secret}',
]


def _value(rng, secret, allow_bare=True):
    # A bare token inside a call argument or a comparison is a variable
    # reference in any real language, not a credential, so it is not generated
    # there -- it would report a leak that cannot occur in a real snippet.
    choices = ["quoted", "quoted", "quoted", "wrapped"]
    if allow_bare:
        choices.append("bare")
    style = rng.choice(choices)
    if style == "bare":
        return rng.choice(BARE_VALUES).format(secret=secret)
    if style == "wrapped":
        return rng.choice(WRAPPERS).format(value=_value(rng, secret, allow_bare=False))
    body = secret
    if rng.random() < 0.25:
        body = "{x}_" + secret          # interpolation inflates the length
    if rng.random() < 0.2:
        # The secret goes on either side of the break: a continuation line is
        # exactly where masking that stops at the opener's line loses it.
        body = (secret + "\nsecond line" if rng.random() < 0.5
                else "first line\n" + secret)
    quote = rng.choice(QUOTES)
    terminated = rng.random() < 0.8
    return rng.choice(PREFIXES) + quote + body + (quote if terminated else "")


def _statement(rng, secret):
    operator = rng.choice(OPERATORS)
    comparison = "==" in operator or "!=" in operator
    return rng.choice(TARGETS) + operator + _value(rng, secret, allow_bare=not comparison)


def _snippet(rng, secret):
    parts = [_statement(rng, secret)]
    if rng.random() < 0.25:
        decoy = rng.choice(["b = 1", "other = x", f"a = {secret}"])
        parts = [parts[0], decoy] if rng.random() < 0.5 else [decoy, parts[0]]
    line = "; ".join(parts)
    if rng.random() < 0.4:
        line += f"  {rng.choice(COMMENT_MARKERS)} {rng.choice(COMMENT_BODIES)}"
    if rng.random() < 0.15:
        line = f"def f():\n    {line}\n    return None"
    if rng.random() < 0.1:
        line = "   " + line + "   "
    return line


def test_a_generated_credential_never_survives_masking():
    rng = random.Random(SEED)
    for _ in range(ITERATIONS):
        secret = rng.choice([SHORT_SECRET, LONG_SECRET])
        snippet = _snippet(rng, secret)
        masked = redact_snippet(snippet, credential_finding=True)
        assert secret not in masked, f"leaked\n  in : {snippet!r}\n  out: {masked!r}"


def test_a_generated_credential_is_never_partly_revealed():
    # The head-and-tail reveal is deliberate for a plain value, but it must not
    # expose a recognizable run of a credential that was masked another way.
    rng = random.Random(SEED + 1)
    for _ in range(ITERATIONS):
        snippet = _snippet(rng, LONG_SECRET)
        masked = redact_snippet(snippet, credential_finding=True)
        for fragment in (LONG_SECRET[:8], LONG_SECRET[-8:]):
            assert fragment not in masked, (
                f"partial reveal\n  in : {snippet!r}\n  out: {masked!r}"
            )


def test_generated_non_credential_snippets_are_untouched():
    # Masking must not reach a finding whose match is ordinary code.
    rng = random.Random(SEED + 2)
    for _ in range(ITERATIONS // 4):
        snippet = _snippet(rng, "ordinary_identifier")
        assert redact_snippet(snippet, credential_finding=False) == snippet
