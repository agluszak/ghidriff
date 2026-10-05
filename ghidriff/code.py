"""Shared views of decompiled C, without claiming semantic equivalence."""

import re


# Skip quoted text and comments before identifying the function's opening brace.
_TOKENS = re.compile(
    r'(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)|'
    r'(?P<quoted>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|'
    r'(?P<brace>\{)|(?P<integer>\b(?:uint|int)\b)'
)


def decompilation_parts(code):
    """Return declaration and body lines; incomplete fragments remain body evidence.

    Warnings before the declaration are retained in the original decompilation,
    but are not part of the prototype. The body starts after the opening brace,
    matching Ghidriff's historical signature-free comparison view.
    """
    text = ''.join(code) if isinstance(code, (list, tuple)) else code or ''
    for token in _TOKENS.finditer(text):
        if token.lastgroup != 'brace':
            continue
        header = text[:token.start()]
        header = _TOKENS.sub(
            lambda match: ' ' if match.lastgroup == 'comment' else match.group(),
            header,
        ).strip()
        if '(' not in header or re.match(r'^(?:if|for|while|switch|else)\b', header):
            return [], text.splitlines(True)
        return (header + '\n').splitlines(True), text[token.end():].splitlines(True)
    return [], text.splitlines(True)


def body_change_kind(old, new):
    """Describe a narrow spelling delta, never suppress it from the code diff.

    Only exact int/uint token substitutions qualify. Width changes, variable
    renaming, casts added/removed, operators and literals remain distinct.
    Signedness can change actual instructions and behavior.
    """
    if old == new:
        return None

    def integer_spelling(lines):
        return _TOKENS.sub(
            lambda match: 'int' if match.lastgroup == 'integer' else match.group(),
            ''.join(lines),
        )

    return 'scalar-signedness' if integer_spelling(old) == integer_spelling(new) else 'body'
