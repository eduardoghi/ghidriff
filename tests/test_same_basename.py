from pathlib import Path
import json
import shutil

import pytest

from ghidriff import get_parser, VersionTrackingDiff, GhidraDiffEngine

SYMBOLS_DIR = 'symbols'
BINS_DIR = 'bins'


@pytest.mark.forked
def test_same_basename_binaries_get_separate_decompiler_pools(shared_datadir: Path):
    """
    Regression test: two inputs with the same filename must not share a
    decompiler pool. The pool used to be keyed by prog.name, so diffing
    e.g. old/Wiz8.exe vs new/Wiz8.exe silently decompiled old-side functions
    against the new program's bytes.

    Here two different afd.sys builds are copied under the same basename, then
    a function decompiled through the engine is compared against a control
    DecompInterface bound directly to the old program.
    """

    test_name = 'same-basename'
    output_path = shared_datadir / test_name
    output_path.mkdir(exist_ok=True, parents=True)
    symbols_path = shared_datadir / SYMBOLS_DIR
    bins_path = shared_datadir / BINS_DIR
    ghidra_project_path = output_path / 'ghidra_projects'
    ghidra_project_path.mkdir(exist_ok=True, parents=True)

    # two different builds under the same basename
    old_dir = output_path / 'old'
    new_dir = output_path / 'new'
    old_dir.mkdir(exist_ok=True)
    new_dir.mkdir(exist_ok=True)
    old_bin_path = old_dir / 'afd.sys'
    new_bin_path = new_dir / 'afd.sys'
    shutil.copyfile(bins_path / 'afd.sys.x64.10.0.22621.1028', old_bin_path)
    shutil.copyfile(bins_path / 'afd.sys.x64.10.0.22621.1415', new_bin_path)

    parser = get_parser()
    GhidraDiffEngine.add_ghidra_args_to_parser(parser)
    args = parser.parse_args([
        '-s', str(symbols_path),
        str(old_bin_path.absolute()),
        str(new_bin_path.absolute()),
        '--no-threaded',
        '-p',
        str(ghidra_project_path.absolute())])

    binary_paths = [old_bin_path, new_bin_path]
    project_name = f'{args.project_name}-same-basename'
    engine_log_path = output_path / parser.get_default('log_path')

    engine = VersionTrackingDiff(args=args,
                                 verbose=True,
                                 threaded=args.threaded,
                                 max_ram_percent=args.max_ram_percent,
                                 print_jvm_flags=args.print_flags,
                                 jvm_args=args.jvm_args,
                                 force_analysis=args.force_analysis,
                                 force_diff=args.force_diff,
                                 verbose_analysis=args.va,
                                 no_symbols=args.no_symbols,
                                 engine_log_path=engine_log_path,
                                 engine_log_level=args.log_level,
                                 engine_file_log_level=args.file_log_level,
                                 )

    engine.setup_project(binary_paths, args.project_location, project_name, args.symbols_path)
    engine.analyze_project()

    p1_name = engine.gen_proj_bin_name_from_path(old_bin_path)
    p2_name = engine.gen_proj_bin_name_from_path(new_bin_path)

    p1 = engine.project.openProgram('/', p1_name, True)
    p2 = engine.project.openProgram('/', p2_name, True)

    try:
        # the collision setup: same program name, different programs
        assert p1.name == p2.name == 'afd.sys'

        engine.setup_decompliers(p1, p2)
        try:
            # buggy keying collapses both programs into one pool
            assert len(engine.decompilers) == 2

            func1 = p1.getFunctionManager().getFunctions(True).next()

            error, code = engine.decompile_func(p1, func1, timeout=60)
            assert error == ''
            assert code

            # control: a dedicated decompiler bound to p1 directly
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            control = DecompInterface()
            control.openProgram(p1)
            try:
                expected = control.decompileFunction(
                    func1, 60, ConsoleTaskMonitor()).getDecompiledFunction().getC()
            finally:
                control.closeProgram()

            assert code == expected
        finally:
            engine.shutdown_decompilers(p1, p2)
    finally:
        engine.project.close(p1)
        engine.project.close(p2)

    pdiff = engine.diff_bins(old_bin_path, new_bin_path)
    pdiff_json = json.dumps(pdiff)
    engine.validate_diff_json(pdiff_json)

    diff_name = f"{old_bin_path.name}-{new_bin_path.name}_diff"
    engine.dump_pdiff_to_path(diff_name,
                              pdiff,
                              output_path,
                              side_by_side=args.side_by_side,
                              max_section_funcs=args.max_section_funcs,
                              md_title=args.md_title)

    assert len(pdiff['functions']['modified']) == 12
    assert len(pdiff['functions']['added']) == 28
    assert len(pdiff['functions']['deleted']) == 0
