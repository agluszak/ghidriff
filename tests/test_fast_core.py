import argparse
from collections import Counter
import inspect
import logging
from pathlib import Path
import sys
from threading import Lock
from types import ModuleType, SimpleNamespace

import pytest

from ghidriff import DecompileResult, FunctionMatch, GhidraDiffEngine, get_parser
from ghidriff.decomp_correlate import decomp_correlate
from ghidriff.implied_matches import find_implied_matches
from ghidriff.utils import get_pe_extra_data


pytestmark = pytest.mark.fast


def test_summary_is_boolean_flag():
    parser = get_parser()

    args = parser.parse_args(["old.bin", "new.bin", "--summary"])

    assert args.summary is True


def test_summary_defaults_false():
    parser = get_parser()

    args = parser.parse_args(["old.bin", "new.bin"])

    assert args.summary is False


def test_ghidra_args_parse_typed_values_and_dash_prefixed_jvm_args():
    parser = argparse.ArgumentParser()
    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    args = parser.parse_args([
        "--max-ram-percent",
        "75.5",
        "--jvm-args=-Xmx8G",
        "--jvm-args=-Dfoo=bar",
        "--decompiler-timeout",
        "120",
    ])

    assert args.max_ram_percent == 75.5
    assert args.jvm_args == ["-Xmx8G", "-Dfoo=bar"]
    assert args.decompiler_timeout == 120


def test_remove_code_sig_always_returns_list_of_strings():
    code = "int demo(void)\n{\n  return 1;\n}\n"

    stripped = GhidraDiffEngine.remove_code_sig(None, code)
    failed = GhidraDiffEngine.remove_code_sig(None, "Failed to decompile demo")
    missing = GhidraDiffEngine.remove_code_sig(None, None)

    assert stripped == ["\n", "  return 1;\n", "}\n"]
    assert failed == ["Failed to decompile demo"]
    assert missing == []


class _FakeDecompiledFunction:
    def getC(self):
        return 'int demo(void) { return 1; }'


class _FakeDecompileResults:
    def __init__(self, completed, message='', timed_out=False, cancelled=False):
        self.completed = completed
        self.message = message
        self.timed_out = timed_out
        self.cancelled = cancelled

    def getErrorMessage(self):
        return self.message

    def decompileCompleted(self):
        return self.completed

    def isTimedOut(self):
        return self.timed_out

    def isCancelled(self):
        return self.cancelled

    def getDecompiledFunction(self):
        return _FakeDecompiledFunction()


def test_completed_decompile_keeps_code_when_ghidra_reports_a_warning():
    result = GhidraDiffEngine._read_decompile_results(
        _FakeDecompileResults(True, 'Could not recover jumptable')
    )

    assert result.completed
    assert result.error is None
    assert result.warnings == ('Could not recover jumptable',)
    assert result.code == 'int demo(void) { return 1; }'


def test_incomplete_decompile_returns_structured_failure():
    result = GhidraDiffEngine._read_decompile_results(
        _FakeDecompileResults(False, timed_out=True)
    )

    assert not result.completed
    assert result.timed_out
    assert result.error == 'Decompiler did not complete'
    assert result.code == ''


def test_pe_extra_data_rejects_non_pe_file(tmp_path: Path):
    not_a_pe = tmp_path / "not-a-pe.bin"
    not_a_pe.write_text("not a PE")

    with pytest.raises(Exception):
        get_pe_extra_data(not_a_pe)


def test_ghidra_application_info_falls_back_to_launcher_app_info():
    launcher = SimpleNamespace(
        _layout=None,
        app_info=SimpleNamespace(
            version="12.1.4",
            build_date="2026-Mar-03 1410 EST",
            release_name="PUBLIC",
        ),
    )

    app_info = GhidraDiffEngine.get_ghidra_application_info(launcher)

    assert app_info.applicationVersion == "12.1.4"
    assert app_info.applicationBuildDate == "2026-Mar-03 1410 EST"
    assert app_info.applicationReleaseName == "PUBLIC"


class _FakeBody:
    numAddresses = 8


class _FakeFunc:
    body = _FakeBody()

    def getSignature(self, include_namespace):
        return 'void demo(void)'


class _FakeFunctionManager:
    def getFunctionAt(self, address):
        return _FakeFunc()


class _FakeProgram:
    functionManager = _FakeFunctionManager()


class _FakeSymbol:
    address = "0x1000"
    program = _FakeProgram()
    referenceCount = 1

    def getName(self, include_namespace=False):
        return 'demo'


class _FastEngine(GhidraDiffEngine):
    def find_matches(self, p1, p2):
        return [[], [], []]


def test_base_engine_can_be_used_with_supplied_pairs():
    assert not inspect.isabstract(GhidraDiffEngine)


def test_broad_hash_matches_still_get_diffed_for_small_function_changes():
    engine = object.__new__(_FastEngine)
    engine.min_func_len = 8

    old = _FakeSymbol()
    new = _FakeSymbol()
    assert GhidraDiffEngine.syms_need_diff(
        engine,
        old,
        new,
        ["StructuralGraphHash"],
        [],
    ) is True
    assert GhidraDiffEngine.syms_need_decomp(
        engine,
        old,
        new,
        ["StructuralGraphHash"],
    ) is True


def test_exact_instruction_matches_still_get_deep_diffed():
    engine = object.__new__(_FastEngine)
    engine.min_func_len = 10

    assert GhidraDiffEngine.syms_need_diff(
        engine,
        _FakeSymbol(),
        _FakeSymbol(),
        ["ExactInstructionsFunctionHasher"],
        [],
    ) is True


def test_exact_byte_matches_skip_decompilation_but_not_metadata_diffing():
    engine = object.__new__(_FastEngine)
    engine.min_func_len = 10
    old = _FakeSymbol()
    new = _FakeSymbol()

    assert GhidraDiffEngine.syms_need_diff(
        engine,
        old,
        new,
        ["ExactBytesFunctionHasher"],
        [],
    ) is False
    assert GhidraDiffEngine.syms_need_decomp(
        engine,
        old,
        new,
        ["ExactBytesFunctionHasher"],
    ) is False

    new.referenceCount = 2
    assert GhidraDiffEngine.syms_need_diff(
        engine,
        old,
        new,
        ["ExactBytesFunctionHasher"],
        [],
    ) is True


class _FakeCodeUnit:
    mnemonicString = 'RET'

    def __str__(self):
        return 'RET'

    def getMnemonicString(self):
        return self.mnemonicString


class _FakeListing:
    def getCodeUnits(self, body, forward):
        return [_FakeCodeUnit()]


class _FakeCachedFunction:
    external = False
    parameterCount = 0
    body = _FakeBody()

    def __init__(self, program):
        self.program = program

    def getProgram(self):
        return self.program

    def getBody(self):
        return self.body

    def getCalledFunctions(self, monitor):
        return []

    def getCallingFunctions(self, monitor):
        return []

    def getSignature(self, include_namespace):
        return 'void demo(void)'


class _FakeCachedFunctionManager:
    def __init__(self, program):
        self.function = _FakeCachedFunction(program)

    def getFunctionAt(self, address):
        return self.function


class _FakeCachedProgram:
    def __init__(self):
        self.functionManager = _FakeCachedFunctionManager(self)
        self.listing = _FakeListing()

    def getDomainFile(self):
        return None

    def getListing(self):
        return self.listing


class _FakeNamespace:
    def toString(self):
        return 'Global'


class _FakeCachedSymbol:
    iD = 1
    address = '0x1000'
    symbolType = 'function'
    source = 'USER_DEFINED'
    external = False
    referenceCount = 0

    def __init__(self, program):
        self.program = program

    def getName(self, include_namespace=False):
        return 'demo'

    def getParentNamespace(self):
        return _FakeNamespace()

    def getReferenceCount(self):
        return self.referenceCount

    def getAddress(self):
        return self.address

    def getSymbolType(self):
        return self.symbolType


class _FakeBasicBlockModel:
    def __init__(self, program, include_externals):
        pass

    def getCodeBlocksContaining(self, body, monitor):
        return []


def test_enhance_sym_lazily_adds_decompiler_fields(monkeypatch):
    symbol_module = ModuleType('ghidra.program.model.symbol')
    symbol_module.SymbolType = SimpleNamespace(FUNCTION='function')
    task_module = ModuleType('ghidra.util.task')
    task_module.ConsoleTaskMonitor = object
    block_module = ModuleType('ghidra.program.model.block')
    block_module.BasicBlockModel = _FakeBasicBlockModel
    monkeypatch.setitem(sys.modules, 'ghidra.program.model.symbol', symbol_module)
    monkeypatch.setitem(sys.modules, 'ghidra.util.task', task_module)
    monkeypatch.setitem(sys.modules, 'ghidra.program.model.block', block_module)

    engine = object.__new__(_FastEngine)
    engine.esym_memo = {}
    engine.esym_memo_lock = Lock()
    engine.logger = logging.getLogger('test')
    engine.decompile_func = lambda program, function, timeout: DecompileResult(
        True, False, False, None, (), 'int demo(void) { return 1; }'
    )
    symbol = _FakeCachedSymbol(_FakeCachedProgram())

    cheap = engine.enhance_sym(symbol, get_decomp_info=False)
    enriched = engine.enhance_sym(symbol, get_decomp_info=True)

    assert cheap is enriched
    assert enriched['code'] == 'int demo(void) { return 1; }'
    assert enriched['decomp_completed'] is True
    assert enriched['instructions'] == ['RET']
    assert enriched['mnemonics'] == ['RET']


class _FakePairFunction:
    def __init__(self, entry):
        self.entry = entry
        self.symbol = f'symbol:{entry}'

    def getEntryPoint(self):
        return self.entry

    def getSymbol(self):
        return self.symbol


class _FakePairFunctionManager:
    def __init__(self, entries):
        self.functions = {entry: _FakePairFunction(entry) for entry in entries}

    def getFunctionAt(self, address):
        return self.functions.get(address)


class _FakeAddressSpace:
    def getAddress(self, offset):
        return f'0x{offset:x}'


class _FakeAddressFactory:
    def getAddress(self, address):
        return address

    def getDefaultAddressSpace(self):
        return _FakeAddressSpace()


class _FakePairProgram:
    def __init__(self, entries):
        self.manager = _FakePairFunctionManager(entries)

    def getAddressFactory(self):
        return _FakeAddressFactory()

    def getFunctionManager(self):
        return self.manager


def test_resolve_function_matches_preserves_provenance():
    assert FunctionMatch('0x1000', '0x2000', 'reccmp').provenance == ('reccmp',)
    engine = object.__new__(_FastEngine)
    old = _FakePairProgram(['0x1000'])
    new = _FakePairProgram(['0x2000'])

    resolved = engine.resolve_function_matches(
        old,
        new,
        [FunctionMatch(0x1000, '0x2000', ('reccmp', 'symbol'))],
    )

    assert resolved == [['symbol:0x1000', 'symbol:0x2000', ['reccmp', 'symbol']]]


def test_resolve_function_matches_rejects_missing_and_duplicate_pairs():
    engine = object.__new__(_FastEngine)
    old = _FakePairProgram(['0x1000'])
    new = _FakePairProgram(['0x2000', '0x3000'])

    with pytest.raises(ValueError, match='does not resolve'):
        engine.resolve_function_matches(old, new, [FunctionMatch('0x9999', '0x2000')])

    with pytest.raises(ValueError, match='one-to-one'):
        engine.resolve_function_matches(
            old,
            new,
            [FunctionMatch('0x1000', '0x2000'), FunctionMatch('0x1000', '0x3000')],
        )


def test_diff_pairs_routes_matches_through_standard_pipeline():
    engine = object.__new__(_FastEngine)
    matches = [FunctionMatch('0x1000', '0x2000')]
    calls = []
    engine.diff_bins = lambda old, new, **kwargs: calls.append((old, new, kwargs)) or {'functions': {}}

    result = engine.diff_pairs('old.exe', 'new.exe', matches, force_diff=True)

    assert result == {'functions': {}}
    assert calls == [('old.exe', 'new.exe', {
        'ignore_FUN': False,
        'force_diff': True,
        'function_matches': matches,
    })]


class _FakeCorrelationAddressSet:
    def __init__(self):
        self.addresses = set()

    def contains(self, address):
        return address in self.addresses

    def add(self, address):
        self.addresses.add(address)


class _FakeCorrelationFunction:
    def __init__(self, address):
        self.address = address

    def getEntryPoint(self):
        return self.address

    def getSymbol(self):
        return self.address


class _FakeDecompCorrelationEngine:
    def __init__(self, code):
        self.code = code
        self.calls = Counter()
        self.logger = logging.getLogger('test')

    def enhance_sym(self, symbol, get_decomp_info=False):
        self.calls[symbol] += 1
        return {'code': self.code[symbol], 'decomp_completed': True}

    def remove_code_sig(self, code):
        return code.split('{', 1)[-1].splitlines(True)


def test_decomp_correlate_groups_unique_normalized_decompilations():
    p1_funcs = [_FakeCorrelationFunction(address) for address in ('old-unique', 'old-dup-1', 'old-dup-2')]
    p2_funcs = [_FakeCorrelationFunction(address) for address in ('new-unique', 'new-dup-1', 'new-dup-2')]
    engine = _FakeDecompCorrelationEngine({
        'old-unique': 'old_signature {\n  return 1;\n}',
        'new-unique': 'new_signature {\n  return 1;\n}',
        'old-dup-1': 'a {\n  return 2;\n}',
        'old-dup-2': 'b {\n  return 2;\n}',
        'new-dup-1': 'c {\n  return 2;\n}',
        'new-dup-2': 'd {\n  return 2;\n}',
    })
    matches = {}
    p1_matches = _FakeCorrelationAddressSet()
    p2_matches = _FakeCorrelationAddressSet()

    decomp_correlate(engine, matches, p1_funcs, p2_funcs, p1_matches, p2_matches)

    assert matches == {('old-unique', 'new-unique'): {'Decomp Match': 1}}
    assert engine.calls == Counter({func.getEntryPoint(): 1 for func in p1_funcs + p2_funcs})


class _FakeRefType:
    def isCall(self):
        return True

    def isData(self):
        return False


class _FakeMemoryAddress:
    def __init__(self, value):
        self.value = value

    def isMemoryAddress(self):
        return True

    def __hash__(self):
        return hash(self.value)

    def __eq__(self, other):
        return isinstance(other, _FakeMemoryAddress) and self.value == other.value


class _FakeReference:
    def __init__(self, ref_type, from_address, to_address):
        self.ref_type = ref_type
        self.from_address = from_address
        self.to_address = to_address

    def getReferenceType(self):
        return self.ref_type

    def getFromAddress(self):
        return self.from_address

    def getToAddress(self):
        return self.to_address


class _FakeTargetFunction:
    def isThunk(self):
        return False


class _FakeImpliedFunctionManager:
    def getFunctionAt(self, address):
        return _FakeTargetFunction()


class _FakeReferenceManager:
    def __init__(self, refs=None, destination_refs=None):
        self.refs = refs or []
        self.destination_refs = destination_refs or {}

    def getReferenceSourceIterator(self, body, forward):
        return range(len(self.refs))

    def getReferencesFrom(self, address):
        if isinstance(address, int):
            return [self.refs[address]]
        return self.destination_refs.get(address, [])


class _FakeImpliedProgram:
    def __init__(self, ref_manager):
        self.ref_manager = ref_manager
        self.function_manager = _FakeImpliedFunctionManager()

    def getReferenceManager(self):
        return self.ref_manager

    def getFunctionManager(self):
        return self.function_manager


class _FakeImpliedFunction:
    def __init__(self, program):
        self.program = program

    def getProgram(self):
        return self.program

    def getBody(self):
        return object()


class _FakeAddressRange:
    def __init__(self, address):
        self.address = address

    def getMinAddress(self):
        return self.address


class _FakeAddressCorrelation:
    def __init__(self):
        self.calls = []

    def getCorrelatedDestinationRange(self, address, monitor):
        self.calls.append(address)
        return _FakeAddressRange(f'dest-{address}')


def test_find_implied_matches_reuses_address_correlation():
    ref_type = _FakeRefType()
    src_refs = [
        _FakeReference(ref_type, 'src-1', _FakeMemoryAddress('old-target-1')),
        _FakeReference(ref_type, 'src-2', _FakeMemoryAddress('old-target-2')),
    ]
    dst_refs = {
        'dest-src-1': [_FakeReference(ref_type, 'dest-src-1', _FakeMemoryAddress('new-target-1'))],
        'dest-src-2': [_FakeReference(ref_type, 'dest-src-2', _FakeMemoryAddress('new-target-2'))],
    }
    src_func = _FakeImpliedFunction(_FakeImpliedProgram(_FakeReferenceManager(src_refs)))
    dst_func = _FakeImpliedFunction(_FakeImpliedProgram(_FakeReferenceManager(destination_refs=dst_refs)))
    correlations = []

    def correlation_factory(source, destination):
        correlation = _FakeAddressCorrelation()
        correlations.append(correlation)
        return correlation

    implied = find_implied_matches(
        src_func,
        dst_func,
        correlation_factory=correlation_factory,
        monitor=object(),
    )

    assert len(correlations) == 1
    assert correlations[0].calls == ['src-1', 'src-2']
    assert set(implied) == {
        (_FakeMemoryAddress('old-target-1'), _FakeMemoryAddress('new-target-1'), 'FUNCTION'),
        (_FakeMemoryAddress('old-target-2'), _FakeMemoryAddress('new-target-2'), 'FUNCTION'),
    }


class _FakeSymbolTable:
    def __init__(self, count):
        self.numSymbols = count


class _FakePreflightProgram:
    def __init__(self, name, language_id, symbol_count):
        self.name = name
        self.languageID = language_id
        self._symbol_table = _FakeSymbolTable(symbol_count)

    def getSymbolTable(self):
        return self._symbol_table


def test_preflight_rejects_language_mismatch_with_actionable_error():
    engine = object.__new__(_FastEngine)

    with pytest.raises(ValueError, match="Language mismatch"):
        GhidraDiffEngine.check_diff_preconditions(
            engine,
            _FakePreflightProgram("old", "x86:LE:64:default", 100),
            _FakePreflightProgram("new", "ARM:LE:32:v8", 100),
        )


def test_preflight_rejects_large_symbol_count_mismatch_with_actionable_error():
    engine = object.__new__(_FastEngine)

    with pytest.raises(ValueError, match="Symbol counts"):
        GhidraDiffEngine.check_diff_preconditions(
            engine,
            _FakePreflightProgram("old", "x86:LE:64:default", 100),
            _FakePreflightProgram("new", "x86:LE:64:default", 5000),
        )


class _FakeDomainFile:
    def __init__(self, file_id):
        self._file_id = file_id

    def getFileID(self):
        return self._file_id


class _FakeKeyedProgram:
    def __init__(self, name, file_id):
        self.name = name
        self._domain_file = _FakeDomainFile(file_id)

    def getDomainFile(self):
        return self._domain_file


def test_program_key_distinguishes_same_named_programs():
    p1 = _FakeKeyedProgram('same.exe', 'file-id-old')
    p2 = _FakeKeyedProgram('same.exe', 'file-id-new')

    assert GhidraDiffEngine._program_key(p1) != GhidraDiffEngine._program_key(p2)


def test_program_key_stable_for_same_program():
    p1 = _FakeKeyedProgram('same.exe', 'file-id-old')

    assert GhidraDiffEngine._program_key(p1) == GhidraDiffEngine._program_key(p1)


def test_program_key_falls_back_to_object_identity():
    p1 = SimpleNamespace(name='same.exe', getDomainFile=lambda: None)
    p2 = SimpleNamespace(name='same.exe', getDomainFile=lambda: None)

    assert GhidraDiffEngine._program_key(p1) == GhidraDiffEngine._program_key(p1)
    assert GhidraDiffEngine._program_key(p1) != GhidraDiffEngine._program_key(p2)


def test_normalize_ghidra_decomp_renames_every_label_on_a_line():
    code = [
        "  DAT_00601000 = FUN_00401000(DAT_00601004, PTR_DAT_00601008);\n",
        "  if (DAT_00601004 != 0) goto LAB_00401020;\n",
        "  rc_MyDAT_00ff(_DAT_00601000);\n",
    ]

    GhidraDiffEngine.normalize_ghidra_decomp(None, code)

    assert code == [
        "  DAT_0 = FUN_0(DAT_1, PTR_DAT_2);\n",
        "  if (DAT_1 != 0) goto LAB_0;\n",
        "  rc_MyDAT_00ff(_DAT_0);\n",
    ]


def test_normalize_ghidra_decomp_export_comment_and_warning_addresses():
    code = [
        '                    /* 0x1000  1941  ?srAssertSetFunc@@YAXP6AXPBD0J0@Z@Z */\n',
        '                    /* 0x14950  726\n',
        '                       ?dump@srStatisticsManager@@QAEXXZ\n',
        '                    /* WARNING: Could not recover jumptable at 0x1000e862. Too many branches */\n',
        '  return 0x1000;\n',
    ]

    GhidraDiffEngine.normalize_ghidra_decomp(None, code)

    assert code == [
        '                    /* RVA  1941  ?srAssertSetFunc@@YAXP6AXPBD0J0@Z@Z */\n',
        '                    /* RVA  726\n',
        '                       ?dump@srStatisticsManager@@QAEXXZ\n',
        '                    /* WARNING: Could not recover jumptable at ADDR. Too many branches */\n',
        '  return 0x1000;\n',
    ]


def test_normalize_ghidra_decomp_address_labels():
    code = [
        'switchD_00401000_caseD_1: goto joined_r0x00402000;\n',
        'switchD_00401000_default: goto code_r0x00403000;\n',
        'switchD_00401100_caseD_2: switchdataD_00404000;\n',
        'switchD_00401000_caseD_3: joined_r0x00402000;\n',
    ]

    GhidraDiffEngine.normalize_ghidra_decomp(None, code)

    assert code == [
        'switchD_0_caseD_1: goto joined_r0x0;\n',
        'switchD_0_default: goto code_r0x0;\n',
        'switchD_1_caseD_2: switchdataD_0;\n',
        'switchD_0_caseD_3: joined_r0x0;\n',
    ]


def test_normalize_ghidra_decomp_orders_simple_equality():
    code = [
        '  return iVar2 == iVar1;\n',
        '  if (z != a) {\n',
        '  return a == iVar1;\n',
        '  return read_value() == iVar1;\n',
        '  if (*p == value) {\n',
    ]

    GhidraDiffEngine.normalize_ghidra_decomp(None, code)

    assert code == [
        '  return iVar1 == iVar2;\n',
        '  if (a != z) {\n',
        '  return a == iVar1;\n',
        '  return read_value() == iVar1;\n',
        '  if (*p == value) {\n',
    ]
