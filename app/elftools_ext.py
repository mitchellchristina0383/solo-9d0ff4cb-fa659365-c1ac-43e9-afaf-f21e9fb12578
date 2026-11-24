"""ELF 解析：Build ID 读取、x86-64/调试信息校验、地址 -> 函数 + 源码行还原。

使用 pyelftools 纯 Python 实现，不依赖外部 addr2line 进程，便于在服务内做
只读缓存并保证查询期间文件集合不变（快照语义由 elfstore 保证）。
"""
from __future__ import annotations

import bisect
import io
import os
from dataclasses import dataclass
from typing import Optional

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


class ELFValidationError(Exception):
    """ELF 不满足入库条件（不是 ELF、非 x86-64、缺 Build ID 或缺调试信息）。"""


@dataclass(frozen=True)
class FrameSymbol:
    function: Optional[str]
    file: Optional[str]
    line: Optional[int]

    def resolved(self) -> bool:
        return self.function is not None or self.file is not None


def _read_build_id(elf: ELFFile) -> Optional[str]:
    for section in elf.iter_sections():
        # SHT_NOTE，类型为 NT_GNU_BUILD_ID(3)
        if section["sh_type"] != "SHT_NOTE":
            continue
        for note in section.iter_notes():
            if note["n_type"] == "NT_GNU_BUILD_ID":
                return note["n_desc"].lower()
    return None


def _has_debug_info(elf: ELFFile) -> bool:
    # .debug_info 为标准 DWARF 节；gcc 压缩后可能叫 .zdebug_info
    return elf.get_section_by_name(".debug_info") is not None or elf.get_section_by_name(
        ".zdebug_info"
    ) is not None


def inspect_blob(blob: bytes) -> tuple[str, bool]:
    """校验上传内容，返回 (build_id, has_debug_info)。

    任何不满足条件的情况都抛 ELFValidationError，由批量接口整批退回。
    """
    try:
        elf = ELFFile(io.BytesIO(blob))
    except ELFError as exc:
        raise ELFValidationError(f"不是合法 ELF 文件: {exc}") from exc

    # pyelftools 把 e_machine 解码为枚举名字符串
    if elf["e_machine"] != "EM_X86_64":
        raise ELFValidationError(f"仅接受 x86-64 (EM_X86_64) ELF，实际为 {elf['e_machine']}")

    build_id = _read_build_id(elf)
    if not build_id:
        raise ELFValidationError("ELF 缺少 GNU Build ID 标识")

    if not _has_debug_info(elf):
        raise ELFValidationError("ELF 缺少 DWARF 调试信息 (.debug_info)")

    return build_id, True


# ---------------------------------------------------------------------------
# 地址符号化
# ---------------------------------------------------------------------------


def _line_entry_filename(line_program, file_index: int) -> Optional[str]:
    """兼容 DWARF v4/v5 的行表文件名提取。

    pyelftools 把行程序状态里的 file、以及 file_entry 的 dir_index 都统一成
    1 基索引（0 表示无文件/当前目录 comp_dir），include_directory[0] 即 comp_dir。
    """
    file_entries = line_program["file_entry"]
    if file_index <= 0 or file_index > len(file_entries):
        return None
    file_entry = file_entries[file_index - 1]
    name = file_entry.name
    if isinstance(name, bytes):
        name = name.decode("utf-8", "replace")

    dir_index = file_entry["dir_index"]
    includes = line_program["include_directory"]
    directory = ""
    if 0 < dir_index <= len(includes):
        directory = includes[dir_index - 1]
    if isinstance(directory, dict):  # 个别版本返回 FileEntry 风格对象
        directory = directory.get("name", b"")
    if isinstance(directory, bytes):
        directory = directory.decode("utf-8", "replace")
    return os.path.join(directory, name) if directory else name


@dataclass
class _LineHit:
    address: int
    file: Optional[str]
    line: Optional[int]


@dataclass
class _CUUnit:
    low: int
    high: int
    cu: object
    line_hits: list[_LineHit]  # 仅本 CU 的行状态，按 address 升序
    line_addresses: list[int]


@dataclass
class _ParsedELF:
    """单个 ELF 的只读解析结果，可被多线程共享。"""

    build_id: str
    cu_units: list[_CUUnit]  # 按 low 升序
    symtab: list[tuple[int, int, str]]  # (low, high, name) 按 low 升序

    def _find_cu(self, address: int) -> Optional[_CUUnit]:
        lows = [u.low for u in self.cu_units]
        idx = bisect.bisect_right(lows, address) - 1
        if idx >= 0:
            unit = self.cu_units[idx]
            if unit.low <= address < unit.high:
                return unit
        return None

    def lookup_line(self, address: int) -> tuple[Optional[str], Optional[int]]:
        # 先定位 CU，再在该 CU 的行表内取最近行状态，
        # 避免跨函数间隙命中其它编译单元（如 stdio.h）的行。
        unit = self._find_cu(address)
        if unit is None or not unit.line_hits:
            return None, None
        idx = bisect.bisect_right(unit.line_addresses, address) - 1
        if idx < 0:
            return None, None
        hit = unit.line_hits[idx]
        if hit.line in (None, 0):
            return hit.file, None
        return hit.file, hit.line

    def lookup_function(self, address: int) -> Optional[str]:
        # 1) DWARF DIE 上的子程序名（含 static/inline 信息更全）
        unit = self._find_cu(address)
        if unit is not None:
            name = self._find_subprogram(unit.cu, address)
            if name is not None:
                return name
        # 2) 退回符号表
        lows = [s[0] for s in self.symtab]
        idx = bisect.bisect_right(lows, address) - 1
        if idx >= 0:
            low, high, name = self.symtab[idx]
            if low <= address < high:
                return name
        return None

    @staticmethod
    def _find_subprogram(cu, address: int) -> Optional[str]:
        for die in cu.iter_DIEs():
            if die.tag not in ("DW_TAG_subprogram", "DW_TAG_inlined_subroutine"):
                continue
            low = die.attributes.get("DW_AT_low_pc")
            if low is None:
                continue
            low_val = low.value
            high_val = _die_high_pc(die, low_val)
            if low_val <= address < high_val:
                name_attr = die.attributes.get("DW_AT_name")
                if name_attr is not None:
                    return name_attr.value.decode("utf-8", "replace")
        return None


def _die_high_pc(die, low_val: int) -> int:
    high = die.attributes.get("DW_AT_high_pc")
    if high is None:
        return low_val
    # constant 类 DW_FORM_data* 表示相对 low_pc 的偏移，其余为绝对地址
    if high.form.startswith("DW_FORM_data") or high.form in (
        "DW_FORM_const1u",
        "DW_FORM_const2u",
        "DW_FORM_const4u",
        "DW_FORM_const8u",
        "DW_FORM_const1s",
        "DW_FORM_const2s",
        "DW_FORM_const4s",
        "DW_FORM_const8s",
        "DW_FORM_udata",
        "DW_FORM_sdata",
    ):
        return low_val + high.value
    return high.value


def _cu_bounds(dwarf, cu, line_hits: list[_LineHit]) -> Optional[tuple[int, int]]:
    """取 CU 地址覆盖区间；依次尝试 low_pc/high_pc、DW_AT_ranges、行表退化。"""
    top = cu.get_top_DIE()
    low_attr = top.attributes.get("DW_AT_low_pc")
    if low_attr is not None:
        return low_attr.value, _die_high_pc(top, low_attr.value)
    ranges_attr = top.attributes.get("DW_AT_ranges")
    if ranges_attr is not None:
        try:
            ranges = dwarf.range_lists().get_range_list_at_offset(ranges_attr.value, cu)
            lows, highs = [], []
            base = 0
            for rng in ranges:
                if rng.is_base_address:
                    base = rng.base_address
                    continue
                lows.append(rng.begin_or_value + (base if rng.is_offset else 0))
                highs.append(rng.end_or_value + (base if rng.is_offset else 0))
            if lows:
                return min(lows), max(highs)
        except Exception:
            pass
    if line_hits:
        return line_hits[0].address, line_hits[-1].address + 1
    return None


def _parse_file(path: str, build_id: str) -> _ParsedELF:
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        if not elf.has_dwarf_info():
            raise ELFValidationError("ELF 缺少 DWARF 调试信息")
        dwarf = elf.get_dwarf_info()

        cu_units: list[_CUUnit] = []
        for cu in dwarf.iter_CUs():
            line_hits: list[_LineHit] = []
            line_program = dwarf.line_program_for_CU(cu)
            if line_program is not None:
                # 只收集真实行状态；end_sequence 仅标记行程序区间结束，
                # 本身不代表源码行，不能参与最近地址匹配。
                for entry in line_program.get_entries():
                    state = entry.state
                    if state is None or state.end_sequence:
                        continue
                    file_name = _line_entry_filename(line_program, state.file)
                    line_hits.append(
                        _LineHit(state.address, file_name, state.line or None)
                    )
            line_hits.sort(key=lambda h: h.address)
            bounds = _cu_bounds(dwarf, cu, line_hits)
            if bounds is None:
                continue
            low, high = bounds
            cu_units.append(
                _CUUnit(
                    low=low,
                    high=high,
                    cu=cu,
                    line_hits=line_hits,
                    line_addresses=[h.address for h in line_hits],
                )
            )

        symtab: list[tuple[int, int, str]] = []
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                value = symbol["st_value"]
                size = symbol["st_size"]
                if value == 0 or not symbol.name:
                    continue
                symtab.append((value, value + max(size, 1), symbol.name))

    cu_units.sort(key=lambda u: u.low)
    symtab.sort(key=lambda s: s[0])
    return _ParsedELF(build_id=build_id, cu_units=cu_units, symtab=symtab)


class Symbolizer:
    """按文件路径惰性解析并缓存 _ParsedELF。

    缓存键带发布版本，文件一旦发布即不可变，因此缓存可长期复用。
    """

    def __init__(self) -> None:
        self._cache: dict[str, _ParsedELF] = {}

    def symbolize(self, path: str, build_id: str, address: int) -> FrameSymbol:
        parsed = self._cache.get(build_id)
        if parsed is None:
            parsed = _parse_file(path, build_id)
            self._cache[build_id] = parsed
        function = parsed.lookup_function(address)
        file, line = parsed.lookup_line(address)
        return FrameSymbol(function=function, file=file, line=line)

    def evict(self, build_id: str) -> None:
        self._cache.pop(build_id, None)
