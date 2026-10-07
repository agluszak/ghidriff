"""Pure decompiled-text comparison. Results are evidence, not equivalence proofs."""

from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
import difflib
import re


_LEXICAL = re.compile(
    r'(?P<comment>//[^\n]*|/\*[\s\S]*?(?:\*/|\Z))|'
    r'(?P<quoted>"(?:\\[\s\S]|[^"\\])*(?:"|\Z)|\'(?:\\[\s\S]|[^\'\\])*(?:\'|\Z))'
)


def code_tokens(text: str) -> Iterator[tuple[str, str]]:
    """Yield code, comment and quoted spans, keeping multiline lexical state."""
    end = 0
    for token in _LEXICAL.finditer(text):
        if token.start() != end:
            yield 'code', text[end : token.start()]
        assert token.lastgroup is not None
        yield token.lastgroup, token.group()
        end = token.end()
    if end != len(text):
        yield 'code', text[end:]


def rewrite_code(text: str, transform: Callable[[str], str]) -> str:
    """Transform code spans only; literals and comments retain their contents."""
    return ''.join(transform(part) if kind == 'code' else part for kind, part in code_tokens(text))


def code_only(text: str) -> str:
    """Mask non-code without changing offsets or line numbers."""
    return ''.join(part if kind == 'code' else re.sub(r'[^\n]', ' ', part) for kind, part in code_tokens(text))


def decompilation_parts(code):
    """Split the inferred declaration from the body; fragments remain body evidence.

    Leading warnings remain in the full text. The body starts after the opening
    brace, matching Ghidriff's historical signature-free view.
    """
    text = ''.join(code) if isinstance(code, (list, tuple)) else code or ''
    opening = code_only(text).find('{')
    if opening == -1:
        return [], text.splitlines(True)
    header = ''.join(' ' if kind == 'comment' else part for kind, part in code_tokens(text[:opening])).strip()
    if '(' not in header or re.match(r'^(?:if|for|while|switch|else)\b', header):
        return [], text.splitlines(True)
    return (header + '\n').splitlines(True), text[opening + 1 :].splitlines(True)


def body_change_kind(old, new):
    """Tag exact int/uint substitutions without suppressing their difference."""
    if old == new:
        return None

    def spelling(lines):
        return rewrite_code(''.join(lines), lambda text: re.sub(r'\b(?:uint|int)\b', 'int', text))

    return 'scalar-signedness' if spelling(old) == spelling(new) else 'body'


@dataclass(frozen=True)
class TextComparison:
    """Both views and their findings, produced from the same normalized text."""

    orig: tuple[str, ...]
    recomp: tuple[str, ...]
    signature_diff: tuple[str, ...]
    body_diff: tuple[str, ...]
    full_diff: tuple[str, ...]
    similarity: float
    change_kind: str | None


def compare_code(orig: Sequence[str], recomp: Sequence[str], fromfile='orig', tofile='recomp') -> TextComparison:
    """Compare complete normalized functions; caller owns contextual preparation."""
    orig_signature, orig_body = decompilation_parts(orig)
    recomp_signature, recomp_body = decompilation_parts(recomp)
    return TextComparison(
        tuple(orig),
        tuple(recomp),
        tuple(difflib.unified_diff(orig_signature, recomp_signature, fromfile=fromfile, tofile=tofile)),
        tuple(difflib.unified_diff(orig_body, recomp_body, fromfile=fromfile, tofile=tofile)),
        tuple(difflib.unified_diff(orig, recomp, fromfile=fromfile, tofile=tofile, n=1000)),
        round(difflib.SequenceMatcher(None, orig_body, recomp_body).ratio(), 2),
        body_change_kind(orig_body, recomp_body),
    )


# Ghidra's default names for things without a user or analysis name:
# LAB_00401000, DAT_00601000, FUN_00401000 (also inside PTR_DAT_... and
# _DAT_...). A preceding letter or digit means it is part of a longer
# identifier; a following word character means the hex run is not the end.
DEFAULT_LABEL = re.compile(r'(?<![0-9A-Za-z])(LAB|DAT|SUB|UNK|EXT|FUN|OFF)_([0-9a-fA-F]+)(?![0-9A-Za-z_])')
ADDRESS_LABEL = re.compile(
    r'(?<![0-9A-Za-z_])'
    r'(?:(switchD|switchdataD)_([0-9a-fA-F]+)((?:_caseD_\d+|_default)?)'
    r'|(joined_r0x|code_r0x)([0-9a-fA-F]+))'
    r'(?![0-9A-Za-z_])'
)
# A single-bit test has the same zero/nonzero result whether Ghidra
# renders it as a shift-and-one or as a mask. Do not rewrite the value of
# the expression itself: outside a zero comparison it is 0/1 vs 0/mask.
ZERO_BIT_TEST = re.compile(
    r'(?P<prefix>\(\s*)(?P<operand>\*\([^()]*\)\([^()]*\)|\*[A-Za-z_]\w*|[A-Za-z_]\w*)'
    r'\s*>>\s*(?P<shift>0x[0-9a-fA-F]+|\d+)\s*&\s*1'
    r'(?P<tail>\)\s*(?:==|!=)\s*0)(?![\w])'
)

# A four-byte load has the same zero test whether typed int or uint.
# Restrict this to the load in an explicit zero equality; never rewrite
# ordering, arithmetic, returned values, declarations or other widths.
ZERO_WORD_LOAD = re.compile(
    r'\*\((?:uint|int)\s*\*\)\s*'
    r'(?P<pointer>\([^()\n]+\)|[A-Za-z_]\w*)'
    r'(?P<comparison>\s*(?:==|!=)\s*0)(?![\w])'
)

# PE export annotations are loader metadata, including wrapped decorated names.
# Export identity is compared structurally by the caller, not as body comments.
EXPORT_COMMENT = re.compile(r'/\*\s*(?:(?:0x)?[0-9a-fA-F]+\s+|RVA\s+)\d+\s+[^*]+\*/')
# Decompiler warnings locate themselves by address ("Could not recover
# jumptable at 0x...", "Removing unreachable block (ram,0x...)").
WARNING_COMMENT = re.compile(r'/\* WARNING: ')
WARNING_ADDRESS = re.compile(r'(?<![0-9A-Za-z_])0x[0-9a-fA-F]+(?![0-9A-Za-z_])')
STACK_RETURN_ADDRESS = re.compile(r'(?P<prefix>\s*uStack_[0-9a-fA-F]+ = )(?P<address>0x[0-9a-fA-F]+)(?P<suffix>;\s*)')
SIMPLE_EQUALITY = re.compile(
    r'^(\s*(?:return\s+|if\s*\(\s*))'
    r'((?:[A-Za-z]+Var\d+|param_\d+|local_[0-9a-fA-F]+))\s*'
    r'(==|!=)\s*((?:[A-Za-z]+Var\d+|param_\d+|local_[0-9a-fA-F]+))'
    r'(\s*(?:;|\)).*)$'
)
LOCAL_STEP = re.compile(
    r'^(?P<indent>[ \t]*)(?P<name>[A-Za-z]+Var\d+) = '
    r'(?P=name) [+-] (?:0x[0-9a-fA-F]+|\d+);\n?$'
)
AUTO_TEMP = re.compile(r'\b([A-Za-z]+Var)\d+\b')
AUTO_TEMP_DECL = re.compile(r'^\s*[^=();]+?\b([A-Za-z]+Var\d+);\s*$')

DEFAULT_PARAMETER = re.compile(r'\bparam_(\d+)\b')


def normalize_auto_temporaries(code: list) -> None:
    """Name Ghidra temporaries by first use, without changing their dataflow.

    Only declared auto names participate. Parameters, stack locations and
    user symbols retain their identities. Sorting declarations is safe:
    they have no effects, and Ghidra orders them by its arbitrary names.
    """
    masked = code_only(''.join(code)).splitlines(True)
    try:
        start = next(i for i, line in enumerate(masked) if line.strip() == '{') + 1
        end = next(i for i in range(start, len(masked)) if not masked[i].strip())
    except StopIteration:
        return

    declarations = {}
    for i in range(start, end):
        match = AUTO_TEMP_DECL.fullmatch(masked[i])
        if match is not None:
            declarations[match.group(1)] = i
    if not declarations:
        return

    names = {}
    counts = Counter()

    def rename(match: re.Match) -> str:
        name = match.group(0)
        if name not in declarations:
            return name
        if name not in names:
            prefix = match.group(1)
            names[name] = f'{prefix}{counts[prefix]}'
            counts[prefix] += 1
        return names[name]

    code[end + 1 :] = rewrite_code(''.join(code[end + 1 :]), lambda text: AUTO_TEMP.sub(rename, text)).splitlines(True)
    for name in declarations:
        if name not in names:
            prefix = AUTO_TEMP.fullmatch(name).group(1)
            names[name] = f'{prefix}{counts[prefix]}'
            counts[prefix] += 1

    declared_indices = set(declarations.values())
    first = min(declared_indices)
    ordered = sorted(
        (rewrite_code(code[i], lambda text: AUTO_TEMP.sub(lambda m: names[m.group(0)], text)) for i in declared_indices),
        key=lambda line: line.strip(),
    )
    remaining = [code[i] for i in range(start, end) if i not in declared_indices]
    remaining[first - start : first - start] = ordered
    code[start:end] = remaining


def declared_parameter_positions(code):
    """Default parameter names numbered by their position after any receiver.

    Ghidra numbers an inferred parameter by its slot, counting the ECX input
    of a member function whose prototype is not committed, but numbers a
    committed prototype's explicit parameters after its automatic ``this``.
    The declaration order is the identity both renderings share.
    """
    header = ''.join(decompilation_parts(code)[0])
    opening = header.find('(')
    closing = header.rfind(')')
    if opening == -1 or closing < opening:
        return {}
    names = DEFAULT_PARAMETER.findall(header[opening + 1 : closing])
    return {f'param_{number}': f'param{index}' for index, number in enumerate(names)}


# An unannotated prototype is Ghidra's default convention, which is __cdecl.
DEFAULT_CONVENTION = re.compile(r'(?<![\w])__cdecl\s+')


def normalize_code(code, entry_address=None, stack_setup=False):
    """Apply the generic spelling policy in place; leave meaningful differences."""
    matches = {}
    positions = declared_parameter_positions(code)

    def rename(match):
        labels = matches.setdefault(match.group(1), {})
        name = match.group(0)
        if name not in labels:
            labels[name] = f'{match.group(1)}_{len(labels)}'
        return labels[name]

    def address_label(match):
        prefix = match.group(1) or match.group(4)
        address = match.group(2) or match.group(5)
        labels = matches.setdefault(prefix, {})
        if address not in labels:
            labels[address] = len(labels)
        separator = '' if prefix.endswith('0x') else '_'
        return f'{prefix}{separator}{labels[address]}{match.group(3) or ""}'

    def equality(match):
        left, right = sorted((match.group(2), match.group(4)))
        return f'{match.group(1)}{left} {match.group(3)} {right}{match.group(5)}'

    def bit_test(match):
        value = match.group('shift')
        shift = int(value, 16 if value.startswith('0x') else 10)
        if shift >= 32:
            return match.group()
        return f'{match.group("prefix")}{match.group("operand")} & {1 << shift:#x}{match.group("tail")}'

    def spelling(text):
        lines = text.splitlines(True)
        for i, line in enumerate(lines):
            if stack_setup and entry_address is not None:
                address = STACK_RETURN_ADDRESS.fullmatch(line)
                if address is not None and entry_address <= int(address.group('address'), 16) < entry_address + 0x80:
                    line = address.group('prefix') + 'RETADDR' + address.group('suffix')
            line = DEFAULT_LABEL.sub(rename, line)
            line = ADDRESS_LABEL.sub(address_label, line)
            line = SIMPLE_EQUALITY.sub(equality, line)
            line = ZERO_BIT_TEST.sub(bit_test, line)
            line = ZERO_WORD_LOAD.sub(lambda m: f'*(uint *){m.group("pointer")}{m.group("comparison")}', line)
            lines[i] = DEFAULT_PARAMETER.sub(
                lambda match: positions.get(match.group(0), f'param{int(match.group(1)) - 1}'), line
            )
        return ''.join(lines)

    parts = []
    removed_comment = False
    for kind, text in code_tokens(''.join(code)):
        if kind == 'code':
            if removed_comment and text.startswith('\n'):
                text = text[1:]
            removed_comment = False
            text = spelling(text)
        elif kind == 'comment':
            if EXPORT_COMMENT.fullmatch(text):
                # Consume the comment-only line too, so absence is identical.
                if parts and not parts[-1].split('\n')[-1].strip():
                    parts[-1] = parts[-1].rstrip(' \t')
                removed_comment = bool(parts and parts[-1].endswith('\n'))
                continue
            lines = []
            for line in text.splitlines(True):
                if WARNING_COMMENT.search(line):
                    line = WARNING_ADDRESS.sub('ADDR', line)
                lines.append(line)
            text = ''.join(lines)
        parts.append(text)
    text = ''.join(parts)
    opening = code_only(text).find('{')
    if opening != -1:
        text = DEFAULT_CONVENTION.sub('', text[:opening]) + text[opening:]
    code[:] = text.splitlines(True)
    normalize_auto_temporaries(code)
    code[:] = rewrite_code(
        ''.join(code), lambda text: ''.join(SIMPLE_EQUALITY.sub(equality, line) for line in text.splitlines(True))
    ).splitlines(True)

    # Only consecutive constant steps of distinct generated locals commute.
    # Mask comments/literals before recognizing statements; writes and other
    # expressions remain barriers.
    masked = code_only(''.join(code)).splitlines(True)
    i = 0
    while i < len(code):
        first = LOCAL_STEP.fullmatch(masked[i])
        if first is None:
            i += 1
            continue
        j = i + 1
        names = {first.group('name')}
        while j < len(code):
            following = LOCAL_STEP.fullmatch(masked[j])
            if following is None or following.group('indent') != first.group('indent') or following.group('name') in names:
                break
            names.add(following.group('name'))
            j += 1
        if j - i > 1:
            code[i:j] = sorted(code[i:j], key=lambda line: line.split(' =', 1)[0].strip())
        i = j
