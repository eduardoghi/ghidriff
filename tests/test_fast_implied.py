import logging

import pytest

from ghidriff import implied_matches


pytestmark = pytest.mark.fast


class _RefType:
    def isCall(self):
        return False


class _Ref:
    def getReferenceType(self):
        return _RefType()


class _RefManager:
    def __init__(self, sources):
        self.sources = sources

    def getReferenceSourceIterator(self, body, forward):
        return iter(self.sources)

    def getReferencesFrom(self, addr):
        return [_Ref()]


class _Program:
    def __init__(self, sources=(), functions=None):
        self.ref_manager = _RefManager(list(sources))
        self.functionManager = self
        self.functions = functions or {}

    def getReferenceManager(self):
        return self.ref_manager

    def getFunctionAt(self, addr):
        return self.functions.get(addr)


class _Func:
    def __init__(self, entry, program=None, callers=()):
        self.entry = entry
        self.program = program
        self.callers = list(callers)

    def getProgram(self):
        return self.program

    def getBody(self):
        return None

    def getEntryPoint(self):
        return self.entry

    def getCallingFunctions(self, monitor):
        return self.callers


def test_find_implied_matches_builds_one_correlation_per_pair(monkeypatch):
    built = []
    monkeypatch.setattr(implied_matches, 'address_correlation', lambda src, dst: built.append((src, dst)))
    src = _Func(0x10, _Program(sources=[0x11, 0x12, 0x13]))
    dst = _Func(0x20, _Program())

    implied_matches.find_implied_matches(src, dst)

    assert built == [(src, dst)]


def test_correlate_implied_matches_checks_each_accepted_match_once(monkeypatch):
    p1 = _Program()
    p2 = _Program()
    caller1 = _Func(0x100, p1)
    caller2 = _Func(0x200, p2)
    p1.functions = {0x100: caller1}
    p2.functions = {0x200: caller2}
    missing1 = _Func(0x110, p1, callers=[caller1])
    missing2 = _Func(0x120, p1, callers=[caller1])
    missing3 = _Func(0x210, p2, callers=[caller2])
    matches = {(0x50, 0x60): {'SymbolsHash': 1}, (0x100, 0x200): {'SymbolsHash': 1}}

    checked = []
    monkeypatch.setattr(implied_matches, 'find_implied_matches', lambda f1, f2: checked.append((f1, f2)) or [])

    implied_matches.correlate_implied_matches(
        matches, [missing1, missing2], [missing3], set(), set(), p1, p2, 2, None, logging.getLogger('test'))

    assert checked == [(caller1, caller2)]


def test_implied_match_needs_both_functions_unmatched(monkeypatch):
    p1 = _Program()
    p2 = _Program()
    caller1 = _Func(0x100, p1)
    caller2 = _Func(0x200, p2)
    p1.functions = {0x100: caller1}
    p2.functions = {0x200: caller2}
    missing1 = _Func(0x110, p1, callers=[caller1])
    missing2 = _Func(0x210, p2, callers=[caller2])
    matches = {(0x100, 0x200): {'SymbolsHash': 1}}
    implied = [(0x110, 0x200, 'FUNCTION'), (0x110, 0x210, 'FUNCTION')]
    monkeypatch.setattr(implied_matches, 'find_implied_matches', lambda f1, f2: implied)

    implied_matches.correlate_implied_matches(
        matches, [missing1], [missing2], set(), set(), p1, p2, 1, None, logging.getLogger('test'))

    assert set(matches) == {(0x100, 0x200), (0x110, 0x210)}
