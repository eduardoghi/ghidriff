import argparse
import logging
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from ghidriff import GhidraDiffEngine, get_parser
from ghidriff.utils import get_pe_download_name, get_pe_extra_data


pytestmark = pytest.mark.fast


class _PlanEngine:
    get_import_plan_options = GhidraDiffEngine.get_import_plan_options
    get_project_program_name = GhidraDiffEngine.get_project_program_name
    gen_proj_bin_name_from_path = GhidraDiffEngine.gen_proj_bin_name_from_path


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


def test_import_plan_arg_validates_json(tmp_path: Path):
    import_plan = tmp_path / "import-plan.json"
    import_plan.write_text('{"defaults": {"language": "x86:LE:64:default"}}')
    parser = argparse.ArgumentParser()
    GhidraDiffEngine.add_ghidra_args_to_parser(parser)

    args = parser.parse_args(["--import-plan", str(import_plan)])

    assert args.import_plan == str(import_plan)


def test_import_plan_rejects_unknown_keys():
    with pytest.raises(argparse.ArgumentTypeError, match="unexpected"):
        GhidraDiffEngine.validate_import_plan({"defaults": {"bad": "value"}})


def test_import_plan_merges_defaults_and_path_specific_options(tmp_path: Path):
    binary_path = tmp_path / "old.bin"
    binary_path.write_bytes(b"old")
    engine = _PlanEngine()
    engine.import_plan = GhidraDiffEngine.load_import_plan({
        "defaults": {
            "loader": "ghidra.app.util.opinion.BinaryLoader",
            "language": "x86:LE:64:default",
        },
        "imports": {
            "old.bin": {
                "compiler": "gcc",
                "program_name": "old-program",
            },
        },
    })

    options = GhidraDiffEngine.get_import_plan_options(engine, binary_path)

    assert options == {
        "loader": "ghidra.app.util.opinion.BinaryLoader",
        "language": "x86:LE:64:default",
        "compiler": "gcc",
        "program_name": "old-program",
    }
    assert GhidraDiffEngine.get_project_program_name(engine, binary_path) == "old-program"


def test_import_plan_compiler_requires_language(tmp_path: Path):
    binary_path = tmp_path / "old.bin"
    binary_path.write_bytes(b"old")
    engine = SimpleNamespace()
    engine.import_plan = GhidraDiffEngine.load_import_plan({})

    with pytest.raises(ValueError, match="compiler requires a language"):
        GhidraDiffEngine.import_program_with_plan(
            engine,
            project=None,
            program_path=binary_path,
            import_options={"compiler": "gcc"},
        )


def test_project_spec_accepts_gpr_path():
    spec = GhidraDiffEngine.normalize_project_spec(
        Path("/tmp/projects/sample.gpr"),
        "ghidriff",
    )

    assert spec.project_location == Path("/tmp/projects")
    assert spec.project_name == "sample"
    assert spec.gpr_path == Path("/tmp/projects/sample.gpr")
    assert spec.was_gpr_path is True


def test_project_spec_rejects_custom_name_with_gpr_path():
    with pytest.raises(ValueError, match="Cannot use --project-name"):
        GhidraDiffEngine.normalize_project_spec(
            Path("/tmp/projects/sample.gpr"),
            "custom",
        )


def test_project_spec_preserves_directory_project_options():
    spec = GhidraDiffEngine.normalize_project_spec(
        Path("/tmp/projects"),
        "custom",
    )

    assert spec.project_location == Path("/tmp/projects")
    assert spec.project_name == "custom"
    assert spec.gpr_path == Path("/tmp/projects/custom.gpr")
    assert spec.was_gpr_path is False


def test_remove_code_sig_always_returns_list_of_strings():
    code = "int demo(void)\n{\n  return 1;\n}\n"

    stripped = GhidraDiffEngine.remove_code_sig(None, code)
    failed = GhidraDiffEngine.remove_code_sig(None, "Failed to decompile demo")
    missing = GhidraDiffEngine.remove_code_sig(None, None)

    assert stripped == ["\n", "  return 1;\n", "}\n"]
    assert failed == ["Failed to decompile demo"]
    assert missing == []


class _FakeAddress:
    def __init__(self, offset, memory=True):
        self.offset = offset
        self.memory = memory

    def isMemoryAddress(self):
        return self.memory

    def getOffset(self):
        return self.offset


class _FakeRef:
    def __init__(self, address):
        self.address = address

    def getToAddress(self):
        return self.address


class _FakeCodeUnit:
    def __init__(self, text, refs=()):
        self.text = text
        self.refs = list(refs)

    def __str__(self):
        return self.text

    def getReferencesFrom(self):
        return self.refs


def test_mask_code_unit_hides_moved_addresses():
    call = _FakeCodeUnit("CALL 0x00401a2c", [_FakeRef(_FakeAddress(0x401a2c))])
    load = _FakeCodeUnit("MOV EDX,dword ptr [0x446D8514]", [_FakeRef(_FakeAddress(0x446d8514))])

    assert GhidraDiffEngine.mask_code_unit(call) == "CALL ADDR"
    assert GhidraDiffEngine.mask_code_unit(load) == "MOV EDX,dword ptr [ADDR]"


class _FakeScalar:
    def __init__(self, value):
        self.value = value

    def getUnsignedValue(self):
        return self.value


class _FakeSpace:
    def getAddress(self, value):
        return value


class _FakeMemory:
    def contains(self, address):
        return 0x44000000 <= address < 0x45000000


class _FakeAddressFactory:
    def getDefaultAddressSpace(self):
        return _FakeSpace()


class _FakeMemoryProgram:
    def getMemory(self):
        return _FakeMemory()

    def getAddressFactory(self):
        return _FakeAddressFactory()


class _FakeInstruction(_FakeCodeUnit):
    def __init__(self, text, operands):
        super().__init__(text)
        self.operands = operands

    def getProgram(self):
        return _FakeMemoryProgram()

    def getNumOperands(self):
        return len(self.operands)

    def getOpObjects(self, index):
        return self.operands[index]


def test_mask_code_unit_hides_unreferenced_scalar_addresses():
    handler = _FakeInstruction("PUSH 0x4401439a", [[_FakeScalar(0x4401439a)]])
    constant = _FakeInstruction("PUSH 0x12", [[_FakeScalar(0x12)]])

    assert GhidraDiffEngine.mask_code_unit(handler) == "PUSH ADDR"
    assert GhidraDiffEngine.mask_code_unit(constant) == "PUSH 0x12"


def test_mask_code_unit_keeps_constants_and_stack_offsets():
    constant = _FakeCodeUnit("MOV dword ptr [RBP + -0x4],0xc")
    stack = _FakeCodeUnit("MOV EAX,dword ptr [EBP + -0x24]", [_FakeRef(_FakeAddress(-0x24, memory=False))])
    other = _FakeCodeUnit("MOV EAX,0x4012", [_FakeRef(_FakeAddress(0x401a2c))])

    assert GhidraDiffEngine.mask_code_unit(constant) == "MOV dword ptr [RBP + -0x4],0xc"
    assert GhidraDiffEngine.mask_code_unit(stack) == "MOV EAX,dword ptr [EBP + -0x24]"
    assert GhidraDiffEngine.mask_code_unit(other) == "MOV EAX,0x4012"


def _minimal_pe(export_name: bytes, characteristics: int = 0x2022, pe32_plus: bool = True) -> bytes:
    """Build a PE with one section that holds an export directory naming export_name."""

    opt_size = 240 if pe32_plus else 224
    section_rva, section_raw = 0x1000, 0x200
    image = bytearray(section_raw + 0x200)
    image[0:2] = b'MZ'
    struct.pack_into('<I', image, 60, 0x40)
    struct.pack_into('<4sHHIIIHH', image, 0x40, b'PE\0\0', 0x8664, 1, 0x12345678, 0, 0, opt_size, characteristics)
    opt = 0x40 + 24
    struct.pack_into('<H', image, opt, 0x20b if pe32_plus else 0x10b)
    struct.pack_into('<I', image, 0x40 + 0x50, 0x3000)
    struct.pack_into('<H', image, opt + 68, 3)
    struct.pack_into('<II', image, opt + (112 if pe32_plus else 96), section_rva, 40)
    struct.pack_into('<8sIIII', image, opt + opt_size, b'.edata', 0x200, section_rva, 0x200, section_raw)
    struct.pack_into('<I', image, section_raw + 12, section_rva + 40)
    image[section_raw + 40:section_raw + 40 + len(export_name) + 1] = export_name + b'\0'
    return bytes(image)


@pytest.mark.parametrize('pe32_plus', [True, False])
def test_pe_extra_data_reads_export_name(tmp_path: Path, pe32_plus: bool):
    pe = tmp_path / 'archiveint.x64.10.0.19041.3803'
    pe.write_bytes(_minimal_pe(b'archiveint.dll', pe32_plus=pe32_plus))

    info = get_pe_extra_data(pe)

    assert info['export_name'] == 'archiveint.dll'
    assert info['characteristics'] & 0x2000
    assert info['timestamp'] == 0x12345678


def test_pe_download_name_restores_missing_extension():
    dll = {'characteristics': 0x2022, 'subsystem': 3, 'export_name': 'archiveint.dll'}
    exe = {'characteristics': 0x0022, 'subsystem': 3, 'export_name': None}
    driver = {'characteristics': 0x0022, 'subsystem': 1, 'export_name': None}

    assert get_pe_download_name('archiveint', dll) == 'archiveint.dll'
    assert get_pe_download_name('ntdll.dll.mui', dll) == 'ntdll.dll'
    assert get_pe_download_name('notepad.exe', exe) == 'notepad.exe'
    assert get_pe_download_name('notepad', exe) == 'notepad.exe'
    assert get_pe_download_name('mydriver', driver) == 'mydriver.sys'
    assert get_pe_download_name('other', {**dll, 'export_name': 'unrelated.dll'}) == 'other.dll'


def test_pe_extra_data_rejects_non_pe_file(tmp_path: Path):
    not_a_pe = tmp_path / "not-a-pe.bin"
    not_a_pe.write_text("not a PE")

    with pytest.raises(Exception):
        get_pe_extra_data(not_a_pe)


def test_ghidra_application_info_falls_back_to_launcher_app_info():
    launcher = SimpleNamespace(
        _layout=None,
        app_info=SimpleNamespace(
            version="12.0.4",
            build_date="2026-Mar-03 1410 EST",
            release_name="PUBLIC",
        ),
    )

    app_info = GhidraDiffEngine.get_ghidra_application_info(launcher)

    assert app_info.applicationVersion == "12.0.4"
    assert app_info.applicationBuildDate == "2026-Mar-03 1410 EST"
    assert app_info.applicationReleaseName == "PUBLIC"


class _FakeBody:
    numAddresses = 8


class _FakeFunc:
    body = _FakeBody()


class _FakeFunctionManager:
    def getFunctionAt(self, address):
        return _FakeFunc()


class _FakeProgram:
    functionManager = _FakeFunctionManager()


class _FakeSymbol:
    address = "0x1000"
    program = _FakeProgram()
    referenceCount = 1


class _FastEngine(GhidraDiffEngine):
    def find_matches(self, p1, p2):
        return [[], [], []]


def test_broad_hash_matches_still_get_diffed_for_small_function_changes():
    engine = object.__new__(_FastEngine)
    engine.min_func_len = 8

    assert GhidraDiffEngine.syms_need_diff(
        engine,
        _FakeSymbol(),
        _FakeSymbol(),
        ["StructuralGraphHash"],
        [],
    ) is True


def test_exact_instruction_matches_can_skip_deeper_diff_when_metadata_matches():
    engine = object.__new__(_FastEngine)
    engine.min_func_len = 10

    assert GhidraDiffEngine.syms_need_diff(
        engine,
        _FakeSymbol(),
        _FakeSymbol(),
        ["ExactInstructionsFunctionHasher"],
        [],
    ) is False


class _FakeListing:
    def __init__(self, lines):
        self.lines = lines

    def getCodeUnits(self, body, forward):
        return [_FakeCodeUnit(line) for line in self.lines]


class _FakeBodyProgram:
    def __init__(self, program_id, lines):
        self.program_id = program_id
        self.listing = _FakeListing(lines)
        self.functionManager = self

    def getFunctionAt(self, address):
        return _FakeBodyFunc(self)

    def getUniqueProgramID(self):
        return self.program_id

    def getListing(self):
        return self.listing


class _FakeBodyFunc:
    body = _FakeBody()

    def __init__(self, program):
        self.program = program

    def getProgram(self):
        return self.program

    def getBody(self):
        return self.body


class _FakeBodySymbol:
    address = "0x1000"
    referenceCount = 1

    def __init__(self, program):
        self.program = program

    def getProgram(self):
        return self.program

    def getID(self):
        return 1


def test_name_matches_get_diffed_when_a_constant_changes():
    engine = object.__new__(_FastEngine)
    engine.min_func_len = 10
    old = _FakeBodySymbol(_FakeBodyProgram(1, ["MOV dword ptr [RBP + -0x4],0x0", "RET"]))
    new = _FakeBodySymbol(_FakeBodyProgram(2, ["MOV dword ptr [RBP + -0x4],0xc", "RET"]))

    assert GhidraDiffEngine.syms_need_diff(engine, old, new, ["SymbolsHash"], []) is True


def test_name_matches_skip_diff_when_instructions_match():
    engine = object.__new__(_FastEngine)
    engine.min_func_len = 10
    old = _FakeBodySymbol(_FakeBodyProgram(1, ["MOV dword ptr [RBP + -0x4],0x0", "RET"]))
    new = _FakeBodySymbol(_FakeBodyProgram(2, ["MOV dword ptr [RBP + -0x4],0x0", "RET"]))

    assert GhidraDiffEngine.syms_need_diff(engine, old, new, ["SymbolsHash"], []) is False


def test_pairs_sent_by_the_mask_check_are_dropped_when_only_the_address_changed():
    engine = object.__new__(_FastEngine)
    engine.min_func_len = 10
    old = _FakeBodySymbol(_FakeBodyProgram(1, ["adrp x0,0x22d710000", "RET"]))
    new = _FakeBodySymbol(_FakeBodyProgram(2, ["adrp x0,0x22db58000", "RET"]))

    assert GhidraDiffEngine.syms_need_diff(engine, old, new, ["SymbolsHash"], []) is True
    assert engine.only_moved(old, new, _moved_esym(), _moved_esym(), ["address"])
    assert not engine.only_moved(old, new, _moved_esym(), _moved_esym(), ["code", "address"])


def test_default_names_that_follow_the_address_count_as_moved():
    engine = object.__new__(_FastEngine)
    engine.min_func_len = 10
    old = _FakeBodySymbol(_FakeBodyProgram(1, ["adrp x0,0x22d710000", "RET"]))
    new = _FakeBodySymbol(_FakeBodyProgram(2, ["adrp x0,0x22db58000", "RET"]))
    GhidraDiffEngine.syms_need_diff(engine, old, new, ["SymbolsHash"], [])
    esym = _moved_esym('FUN_1f1d4db60', calling=['FUN_1f1d00000', 'main'])
    esym2 = _moved_esym('FUN_1f1e4db60', calling=['FUN_1f1e00000', 'main'])
    renamed = _moved_esym('FUN_1f1e4db60', calling=['init', 'main'])

    assert engine.only_moved(old, new, esym, esym2, ['name', 'fullname', 'sig', 'address', 'calling'])
    assert not engine.only_moved(old, new, esym, renamed, ['name', 'fullname', 'sig', 'address', 'calling'])


def test_pairs_diffed_for_other_reasons_keep_address_only_changes():
    engine = object.__new__(_FastEngine)
    old = _FakeBodySymbol(_FakeBodyProgram(1, ["RET"]))
    new = _FakeBodySymbol(_FakeBodyProgram(2, ["RET"]))

    assert not engine.only_moved(old, new, _moved_esym(), _moved_esym(), ["address"])


def _moved_esym(name='_cc_demo', calling=()):
    return {'fullname': name, 'sig': f'undefined {name}(void)', 'calling': list(calling), 'called': []}


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
        'uVar3 = func_0x0001f2769220(func_0x0001f2769300, func_0x0001f2769220);\n',
    ]

    GhidraDiffEngine.normalize_ghidra_decomp(None, code)

    assert code == [
        'switchD_0_caseD_1: goto joined_r0x0;\n',
        'switchD_0_default: goto code_r0x0;\n',
        'switchD_1_caseD_2: switchdataD_0;\n',
        'switchD_0_caseD_3: joined_r0x0;\n',
        'uVar3 = func_0x0(func_0x1, func_0x0);\n',
    ]


def test_default_analysis_options_apply_without_program_options():
    engine = object.__new__(_FastEngine)
    engine.program_options = None

    assert not engine.user_set_analysis_option('Decompiler Parameter ID')


def test_program_options_override_default_analysis_options():
    engine = object.__new__(_FastEngine)
    engine.program_options = {'program_options': {'Analyzers': {'Decompiler Parameter ID': False}}}

    assert engine.user_set_analysis_option('Decompiler Parameter ID')
    assert not engine.user_set_analysis_option('Shared Return Calls.Assume Contiguous Functions Only')


def _slight_mod(diff_type, old_called, new_called):
    def esym(name, called):
        return {'name': name, 'fullname': name, 'external': False, 'called': called, 'calling': ['main']}

    return {'old': esym('FUN_00401000', old_called), 'new': esym('FUN_00402000', new_called), 'diff_type': diff_type}


def test_fun_callee_renames_are_hidden_from_slight_mods():
    modified = _slight_mod(['called'], ['FUN_00401100', 'puts'], ['FUN_00402100', 'puts'])

    assert GhidraDiffEngine._is_generated_name_noise(modified, {'called'})


def test_real_callee_changes_stay_in_slight_mods():
    removed = _slight_mod(['called'], ['FUN_00401100', 'puts'], ['FUN_00402100'])
    added = _slight_mod(['called'], ['FUN_00401100'], ['FUN_00402100', 'puts'])

    assert not GhidraDiffEngine._is_generated_name_noise(removed, {'called'})
    assert not GhidraDiffEngine._is_generated_name_noise(added, {'called'})


def test_file_log_level_is_independent_of_console_level(tmp_path: Path):
    engine = object.__new__(_FastEngine)
    engine.logger = engine.setup_logger('WARNING')
    log_path = tmp_path / 'ghidriff.log'

    engine.add_log_to_path(log_path, 'DEBUG')
    try:
        engine.logger.debug('debug line')
    finally:
        for handler in list(engine.logger.handlers):
            engine.logger.removeHandler(handler)
            handler.close()

    assert 'debug line' in log_path.read_text()


def test_project_location_rejects_hidden_path_elements(tmp_path: Path):
    GhidraDiffEngine.check_project_location(tmp_path / 'ghidra_projects' / 'ghidriff')

    with pytest.raises(ValueError, match=r'\.cache'):
        GhidraDiffEngine.check_project_location(tmp_path / '.cache' / 'ghidra_projects')


def test_side_by_side_files_do_not_overwrite_same_named_functions(tmp_path: Path):
    def mod(fullname, address):
        def esym(code):
            return {'name': 'Create', 'fullname': fullname, 'address': address, 'code': code}

        return {'old': esym('int a;\n'), 'new': esym('int b;\n'), 'diff_type': ['code']}

    pdiff = {
        'functions': {'added': [], 'deleted': [],
                      'modified': [mod('TOrder::Create', '00401000'), mod('TItem::Create', '00402000')]},
        'html_credits': '',
    }
    engine = object.__new__(_FastEngine)
    engine.logger = logging.getLogger('test')

    engine.dump_pdiff_to_path('old-new', pdiff, tmp_path, side_by_side=True,
                              write_diff=False, write_json=False, write_matches=False)

    assert len(list((tmp_path / 'sxs_html').glob('*.md'))) == 2


def test_mermaid_flowchart_labels_new_function_with_its_param_count():
    def esym(paramcount):
        return {'fullname': 'TOrder::Post', 'paramcount': paramcount}

    pdiff = {
        'old_meta': {'Program Name': 'old.bpl'},
        'new_meta': {'Program Name': 'new.bpl'},
        'functions': {
            'added': [],
            'deleted': [],
            'modified': [{'old': esym(1), 'new': esym(2), 'diff_type': ['code'], 'b_ratio': 0.5}],
        },
    }
    engine = object.__new__(_FastEngine)

    flowchart = engine.gen_mermaid_diff_flowchart(pdiff)

    assert 'TOrderPost-2-new' in flowchart
    assert 'TOrderPost-1-new' not in flowchart


def test_mermaid_flowchart_lists_exactly_max_section_funcs():
    pdiff = {
        'old_meta': {'Program Name': 'old.bpl'},
        'new_meta': {'Program Name': 'new.bpl'},
        'functions': {
            'added': [{'fullname': f'Added{i}'} for i in range(5)],
            'deleted': [],
            'modified': [],
        },
    }
    engine = object.__new__(_FastEngine)

    flowchart = engine.gen_mermaid_diff_flowchart(pdiff, max_section_funcs=2)

    assert 'Added1' in flowchart
    assert 'Added2' not in flowchart
    assert '3_more_added_funcs_omitted' in flowchart


def _md_esym(name):
    return {'name': name, 'fullname': name, 'parent': 'Global', 'refcount': 1, 'length': 10, 'called': [],
            'calling': [], 'paramcount': 0, 'address': '00401000', 'sig': f'void {name}(void)', 'code': '',
            'instructions': [], 'mnemonics': [], 'blocks': [], 'sym_type': 'Function', 'sym_source': 'IMPORTED',
            'external': False}


def _md_modified(name, diff_type):
    return {'old': _md_esym(name), 'new': _md_esym(name), 'diff': '-int a;\n+int b;\n', 'diff_type': diff_type,
            'ratio': 0.5, 'i_ratio': 0.5, 'm_ratio': 0.5, 'b_ratio': 0.5, 'match_types': ['SymbolsHash']}


def _gen_md(modified, max_section_funcs):
    pdiff = {
        'functions': {'added': [], 'deleted': [], 'modified': modified},
        'old_meta': {'Program Name': 'old.bin'},
        'new_meta': {'Program Name': 'new.bin'},
        'program_options': {},
        'stats': {'first_matches': {}, 'match_types': {}, 'func_match_overall_percent': '100%',
                  'match_func_similarity_percent': '50%'},
        'strings': {'added': [], 'deleted': []},
        'md_credits': '',
    }
    engine = object.__new__(_FastEngine)
    engine.logger = logging.getLogger('test')
    engine.args = None
    return engine.gen_diff_md(pdiff, max_section_funcs=max_section_funcs)


def test_modified_section_limit_counts_only_functions_with_code_changes():
    md = _gen_md([_md_modified('a', ['code']), _md_modified('b', ['refcount']), _md_modified('c', ['code']),
                  _md_modified('d', ['code'])], max_section_funcs=2)

    assert 'Max Modified Section Functions Reached Error' in md
    assert '\n1 Functions Ommited...' in md


def test_modified_section_limit_ignores_trailing_functions_without_code_changes():
    md = _gen_md([_md_modified('a', ['code']), _md_modified('b', ['refcount'])], max_section_funcs=1)

    assert 'Max Modified Section Functions Reached Error' not in md


def test_slight_mods_limit_counts_only_functions_the_section_would_show():
    md = _gen_md([_md_modified('a', ['code']), _md_modified('b', ['refcount']), _md_modified('c', ['code']),
                  _md_modified('x', ['address'])], max_section_funcs=2)

    assert 'Max Modified (No Code Changes) Section Functions Reached Error' in md
    assert md.count('Functions Ommited...') == 1
    assert '\n1 Functions Ommited...' in md
