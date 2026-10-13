import argparse
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
