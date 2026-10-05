"""Regression evidence for the shared text comparison policy; no Ghidra runtime."""

from dataclasses import FrozenInstanceError

import pytest

from ghidriff.code import compare_code, normalize_code

pytestmark = pytest.mark.fast


def normalized(text):
    lines = text.splitlines(True)
    normalize_code(lines)
    return lines


@pytest.mark.parametrize(
    'literal',
    [
        'FUN_deadbeef',
        'DAT_12345678',
        'joined_r0x00403000',
        'param_1',
        '0x1000  123  exported_name',
        '/* WARNING: 0x1000 */',
        'escaped \\" FUN_deadbeef',
    ],
)
def test_identifier_normalization_preserves_quoted_contents(literal):
    text = f'void f(void)\n{{\n  use("{literal}");\n}}\n'
    assert f'"{literal}"' in ''.join(normalized(text))


def test_different_quoted_auto_labels_remain_body_differences():
    old = normalized('void f(void)\n{\n  use("FUN_deadbeef");\n}\n')
    new = normalized('void f(void)\n{\n  use("FUN_12345678");\n}\n')
    comparison = compare_code(old, new)
    assert comparison.body_diff
    assert comparison.similarity < 1
    assert comparison.change_kind == 'body'


def test_multiline_comments_do_not_rename_identifiers_or_consume_label_numbers():
    text = (
        'void f(void)\n{\n  /* DAT_deadbeef\n  FUN_deadbeef param_1\n'
        '  iVar1 = iVar1 + 1;\n  */\n  DAT_12345678 = FUN_12345678(param_1);\n}\n'
    )
    result = ''.join(normalized(text))
    assert '/* DAT_deadbeef\n  FUN_deadbeef param_1\n  iVar1 = iVar1 + 1;\n  */' in result
    assert 'DAT_0 = FUN_0(param0);' in result


def test_comments_do_not_determine_auto_temporary_first_use():
    text = 'void f(void)\n{\n  int iVar7;\n  int iVar9;\n\n  /* iVar9 */\n  iVar7 = get();\n  iVar9 = iVar7 + 1;\n}\n'
    result = ''.join(normalized(text))
    assert '/* iVar9 */' in result
    assert 'iVar0 = get();' in result
    assert 'iVar1 = iVar0 + 1;' in result


def test_declaration_comments_preserve_unbound_auto_names():
    text = 'void f(void)\n{\n  int iVar7; // iVar99\n\n  iVar7 = get();\n}\n'
    result = ''.join(normalized(text))
    assert 'int iVar0; // iVar99' in result
    assert 'iVar0 = get();' in result


@pytest.mark.parametrize(
    'body',
    [
        '  if ((*(uint *)p >> 6 & 1) == 0) return 0;\n',
        '  if (*(uint *)p < 18) return 0;\n',
        '  return x*x + y*y + z*z + w*w;\n',
        '  iVar7 = get();\n  iVar9 = get();\n  return iVar9 == iVar7;\n',
        '  use("FUN_deadbeef", param_1);\n',
    ],
)
def test_normalization_is_idempotent(body):
    first = normalized('int f(int param_1)\n{\n  int iVar7;\n  int iVar9;\n\n' + body + '}\n')
    second = first.copy()
    normalize_code(second)
    assert second == first


def test_signature_only_change_has_one_body_score_and_separate_declaration_diff():
    old = normalized('void f(uint param_1)\n{\n  use(param_1);\n}\n')
    new = normalized('void f(int param_1)\n{\n  use(param_1);\n}\n')
    result = compare_code(old, new)
    assert result.signature_diff
    assert not result.body_diff
    assert result.similarity == 1
    assert result.full_diff
    with pytest.raises(FrozenInstanceError):
        result.similarity = 0
    old.append('changed after comparison\n')
    assert result.orig[-1] == '}\n'


@pytest.mark.parametrize(
    'old,new,kind',
    [
        ('*(uint *)p < 18', '*(int *)p < 18', 'scalar-signedness'),
        ('*(uint *)p < 18', '*(byte *)p < 18', 'body'),
        ('*(uint *)p < 18', '*(uint *)p < 19', 'body'),
        ('(uint)x < 18', 'x < 18', 'body'),
        ('x*x + y*y + z*z + w*w', 'z*z + y*y + x*x + w*w', 'body'),
    ],
)
def test_meaningful_differences_remain_visible(old, new, kind):
    result = compare_code(
        normalized('int f(void)\n{\n  return ' + old + ';\n}\n'), normalized('int f(void)\n{\n  return ' + new + ';\n}\n')
    )
    assert result.body_diff
    assert result.change_kind == kind
