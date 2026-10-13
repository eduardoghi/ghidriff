import hashlib
from pathlib import Path
from struct import unpack
from functools import lru_cache


@lru_cache(None)
def sha1_file(path: str) -> str:
    # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
    # BUF_SIZE is totally arbitrary, change for your app!
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    path = Path(path)

    sha1 = hashlib.sha1()

    with path.open('rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha1.update(data)

    return f'{sha1.hexdigest()}'


# get pe data for url gen
# https://github.com/m417z/winbindex/blob/gh-pages/data/extract_data_from_pe_files.py
def get_pe_extra_data(path: Path):

    path = Path(path)

    with path.open('rb') as handle:
        # Get PE offset (@60, DWORD) from DOS header
        handle.seek(60, 0)
        offset = handle.read(4)
        offset = unpack('<I', offset)[0]

        handle.seek(offset + 4, 0)
        word = handle.read(2)
        machine = unpack('<H', word)[0]

        handle.seek(offset + 8, 0)
        dword = handle.read(4)
        timestamp = unpack('<I', dword)[0]

        handle.seek(offset + 0x50, 0)
        dword = handle.read(4)
        image_size = unpack('<I', dword)[0]

        handle.seek(offset + 6, 0)
        num_sections = unpack('<H', handle.read(2))[0]
        handle.seek(offset + 20, 0)
        opt_size, characteristics = unpack('<HH', handle.read(4))

        opt = offset + 24
        handle.seek(opt, 0)
        magic = unpack('<H', handle.read(2))[0]
        handle.seek(opt + 68, 0)
        subsystem = unpack('<H', handle.read(2))[0]

        export_name = None
        handle.seek(opt + (112 if magic == 0x20b else 96), 0)
        export_rva = unpack('<I', handle.read(4))[0]
        if export_rva:
            handle.seek(opt + opt_size, 0)
            sections = [unpack('<8sIIII', handle.read(40)[:24]) for _ in range(num_sections)]
            export_offset = rva_to_offset(sections, export_rva)
            if export_offset is not None:
                # The Name RVA sits 12 bytes into IMAGE_EXPORT_DIRECTORY.
                handle.seek(export_offset + 12, 0)
                name_offset = rva_to_offset(sections, unpack('<I', handle.read(4))[0])
                if name_offset is not None:
                    handle.seek(name_offset, 0)
                    export_name = handle.read(256).split(b'\0', 1)[0].decode('ascii', 'replace') or None

    return {
        'machine': machine,
        'timestamp': timestamp,
        'image_size': image_size,
        'characteristics': characteristics,
        'subsystem': subsystem,
        'export_name': export_name,
    }


def rva_to_offset(sections, rva):
    """Map an RVA to a file offset through (name, vsize, vaddr, raw_size, raw_ptr) section tuples."""

    for _name, virtual_size, virtual_address, raw_size, raw_pointer in sections:
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            return raw_pointer + rva - virtual_address
    return None


PE_EXTENSIONS = {'.dll', '.exe', '.sys', '.efi', '.ocx', '.cpl', '.drv', '.scr', '.ax', '.acm', '.tsp', '.ime'}


def get_pe_download_name(filename: str, pe_info: dict) -> str:
    """
    Return the file name the Microsoft symbol server stores a PE under.

    OriginalFilename from the version resource can lack the extension ("archiveint" for
    archiveint.dll) or carry ".mui". The export directory name is used when it matches,
    otherwise the extension comes from the DLL flag and the subsystem.
    """

    name = filename[:-4] if filename.lower().endswith('.mui') else filename
    if Path(name).suffix.lower() in PE_EXTENSIONS:
        return name

    export_name = pe_info.get('export_name')
    if export_name and Path(export_name).stem.lower() == name.lower():
        return export_name

    if pe_info.get('characteristics', 0) & 0x2000:
        return f'{name}.dll'
    if pe_info.get('subsystem') == 1:
        return f'{name}.sys'
    return f'{name}.exe'


def get_microsoft_download_url(filename, timestamp, virtual_size):

    assert filename is not None
    assert timestamp is not None
    assert virtual_size is not None

    timestamp = format(timestamp, '08X')
    virtual_size = format(virtual_size, 'X')

    return f'https://msdl.microsoft.com/download/symbols/{filename}/{timestamp}{virtual_size}/{filename}'


# utils from PyGhidra

def get_private_class(path: str):
    from java.lang import ClassLoader
    from jpype import JClass

    gcl = ClassLoader.getSystemClassLoader()
    return JClass(path, loader=gcl)


def set_field(cls, fname, value, obj=None):
    cls = cls.class_
    field = cls.getDeclaredField(fname)
    field.setAccessible(True)
    field.set(obj, value)
    field.setAccessible(False)
