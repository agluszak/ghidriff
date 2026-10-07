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


@pytest.mark.parametrize('annotation', [
    '/* 100213a0  1112  ?getModelViewScaleType@srGERD@@ */',
    '/* RVA  1112\n                       ?getModelViewScaleType@srGERD@@ */',
    '/* RVA  1088  ?getMatrix@srGERD@@\n                        */',
])
def test_pe_export_annotations_do_not_change_body(annotation):
    plain = 'void f(void)\n{\n  return;\n}\n'
    annotated = plain.replace('  return;', '                    ' + annotation + '\n  return;')
    assert normalized(annotated) == normalized(plain)


def test_export_like_literal_and_unrelated_comment_remain():
    text = 'void f(void)\n{\n  /* RVA explains a meaningful fact */\n  use("RVA 1112 ?export");\n}\n'
    assert '/* RVA explains a meaningful fact */' in ''.join(normalized(text))
    assert '"RVA 1112 ?export"' in ''.join(normalized(text))


@pytest.mark.parametrize('comparison', ['==', '!='])
def test_same_width_word_zero_test_ignores_signedness(comparison):
    old = normalized(f'void f(void)\n{{\n  if (*(uint *)(this + 0x24) {comparison} 0) act();\n}}\n')
    new = normalized(f'void f(void)\n{{\n  if (*(int *)(this + 0x24) {comparison} 0) act();\n}}\n')
    assert old == new


@pytest.mark.parametrize('expression', [
    '*(TYPE *)p < 15', '*(TYPE *)p != 1', '*(TYPE *)p + 2',
    '*(TYPE *)p', '*(TYPE *)(p + 4) >= 0',
])
def test_word_signedness_remains_outside_zero_equality(expression):
    old = normalized('int f(void)\n{\n  return ' + expression.replace('TYPE', 'int') + ';\n}\n')
    new = normalized('int f(void)\n{\n  return ' + expression.replace('TYPE', 'uint') + ';\n}\n')
    assert compare_code(old, new).body_diff


def test_bool_value_is_not_normalized_into_a_zero_test():
    old = normalized('int f(void)\n{\n  return *(byte *)p != 0;\n}\n')
    new = normalized('int f(void)\n{\n  return *(byte *)p;\n}\n')
    assert compare_code(old, new).body_diff


def test_parameters_are_numbered_by_declaration_after_the_receiver():
    # Uncommitted retail prototype: the ECX input occupies slot 1.
    old = normalized(
        'void __thiscall F(void *this,int param_2,int *param_3)\n{\n  G(param_2,*param_3);\n}\n'
    )
    # Committed recomp prototype: explicit parameters follow the automatic this.
    new = normalized(
        'void __thiscall F(void *this,int param_1,int *param_2)\n{\n  G(param_1,*param_2);\n}\n'
    )
    comparison = compare_code(old, new)
    assert not comparison.body_diff
    assert not comparison.signature_diff


def test_parameters_without_receiver_keep_their_order():
    lines = normalized('int F(int param_1,int param_2)\n{\n  return param_2 - param_1;\n}\n')
    assert 'return param1 - param0;' in ''.join(lines)


def test_unannotated_prototype_is_the_default_convention():
    old = normalized('void F(int param_1)\n{\n  G(param_1);\n}\n')
    new = normalized('void __cdecl F(int param_1)\n{\n  G(param_1);\n}\n')
    assert not compare_code(old, new).signature_diff


def test_other_conventions_remain_signature_differences():
    old = normalized('void __stdcall F(int param_1)\n{\n  G(param_1);\n}\n')
    new = normalized('void F(int param_1)\n{\n  G(param_1);\n}\n')
    assert compare_code(old, new).signature_diff
