import logging
import sys
from types import ModuleType, SimpleNamespace

import pytest

from ghidriff import GhidraDiffEngine


pytestmark = pytest.mark.fast


class _Engine(GhidraDiffEngine):
    def find_matches(self, p1, p2):
        return [[], [], []]


class _CodeUnit:
    mnemonicString = 'RET'

    def __str__(self):
        return 'RET'

    def getMnemonicString(self):
        return 'RET'

    def getReferencesFrom(self):
        return []


class _Listing:
    def getCodeUnits(self, body, forward):
        return [_CodeUnit()]


class _BasicBlockModel:
    def __init__(self, program, include_externals):
        pass

    def getCodeBlocksContaining(self, body, monitor):
        return [object()]


class _Body:
    numAddresses = 1


class _Function:
    external = False
    parameterCount = 0
    body = _Body()

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

    def getSignature(self, include_calling_convention):
        return 'int demo(void)'


class _Program:
    def __init__(self):
        self.functionManager = self
        self.function = _Function(self)

    def getFunctionAt(self, address):
        return self.function

    def getListing(self):
        return _Listing()

    def getDomainFile(self):
        return None


class _Symbol:
    iD = 1
    address = 0x1000
    symbolType = 'function'
    source = 'IMPORTED'
    external = False

    def __init__(self, program):
        self.program = program

    def getName(self, qualified=False):
        return 'demo'

    def getReferenceCount(self):
        return 0

    def getParentNamespace(self):
        return SimpleNamespace(toString=lambda: 'Global')

    def getAddress(self):
        return self.address

    def getSymbolType(self):
        return 'Function'


@pytest.fixture
def fake_ghidra(monkeypatch):
    symbol_module = ModuleType('ghidra.program.model.symbol')
    symbol_module.SymbolType = SimpleNamespace(FUNCTION='function')
    task_module = ModuleType('ghidra.util.task')
    task_module.ConsoleTaskMonitor = object
    block_module = ModuleType('ghidra.program.model.block')
    block_module.BasicBlockModel = _BasicBlockModel
    monkeypatch.setitem(sys.modules, 'ghidra.program.model.symbol', symbol_module)
    monkeypatch.setitem(sys.modules, 'ghidra.util.task', task_module)
    monkeypatch.setitem(sys.modules, 'ghidra.program.model.block', block_module)


def test_enhance_sym_adds_decompiler_fields_to_a_cached_cheap_record(fake_ghidra):
    engine = object.__new__(_Engine)
    engine.esym_memo = {}
    engine.decompiler_timeout = 60
    engine.logger = logging.getLogger('test')
    engine.decompile_func = lambda program, function, timeout: (None, 'int demo(void) { return 1; }')
    symbol = _Symbol(_Program())

    cheap = engine.enhance_sym(symbol, get_decomp_info=False)
    enriched = engine.enhance_sym(symbol, get_decomp_info=True)

    assert cheap['code'] == ''
    assert enriched['code'] == 'int demo(void) { return 1; }'
    assert enriched['instructions'] == ['RET']
    assert enriched['mnemonics'] == ['RET']
    assert engine.enhance_sym(symbol, get_decomp_info=True) is enriched
