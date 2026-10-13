import importlib
import sys
from types import ModuleType

import pytest


pytestmark = pytest.mark.fast


@pytest.fixture
def correlators(monkeypatch):
    match_module = ModuleType('ghidra.app.plugin.match')
    match_module.FunctionHasher = object
    for name in ('ghidra', 'ghidra.app', 'ghidra.app.plugin'):
        monkeypatch.setitem(sys.modules, name, ModuleType(name))
    monkeypatch.setitem(sys.modules, 'ghidra.app.plugin.match', match_module)
    # setitem makes monkeypatch drop the stubbed import again after the test.
    monkeypatch.setitem(sys.modules, 'ghidriff.correlators', None)
    del sys.modules['ghidriff.correlators']
    return importlib.import_module('ghidriff.correlators')


class _Signature:
    def toString(self):
        return 'int demo(void)'


class _Name(str):
    def toString(self):
        return str(self)


class _Func:
    name = 'demo'

    def __init__(self, called, calling):
        self.called = [_Name(name) for name in called]
        self.calling = [_Name(name) for name in calling]

    def getCalledFunctions(self, monitor):
        return self.called

    def getCallingFunctions(self, monitor):
        return self.calling

    def getSignature(self):
        return _Signature()


def test_sig_calling_called_hasher_uses_the_callers(correlators):
    def hasher(func):
        return correlators.SigCallingCalledHasher.hash(correlators.SigCallingCalledHasher, func, None)

    same_callers = hasher(_Func(['puts'], ['main']))
    other_callers = hasher(_Func(['puts'], ['init']))

    assert same_callers == hasher(_Func(['puts'], ['main']))
    assert same_callers != other_callers
