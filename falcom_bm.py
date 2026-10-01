#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""falcom_bm - Falcom 图片容器 (._bm) 与归档 (.na/.ni) 解包/封包工具。

支持:
  * ._bm  -> BMP      (BZip mode2 解压)
  * BMP   -> ._bm     (BZip mode2 压缩, 沿用模板的块划分)
  * .na/.ni 归档      (Falcom NNI 归档, 内含 zlib 压缩的 BMP)

算法参考来源
------------
BZip mode 2 的位流布局与压缩器决策逻辑移植自:

    Aureole-Suite/Falcompress  (MIT OR Apache-2.0)
    https://github.com/Aureole-Suite/Falcompress
    src/bzip/decompress.rs
    src/bzip/compress/mode2.rs

该实现对 ._bm 内嵌的位流布局与压缩器决策逻辑（包括"首字仅用高 8 位"
的首字对齐、长度/偏移的位分配、终止序列）给出了可直接对照的准确描述，
本文件的 compress() / decompress() 即据此以 Python 重新实现。

.na/.ni 归档的 TOC/名称表反混淆与 zlib 条目解析参考:

    Kyuuhachi  "Ys I/II/Origin/VI extractor"
    https://gist.github.com/Kyuuhachi/42b6acd38a99f7cc8d924286617a9c02

详见 README.md
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import zlib

__version__ = "1.0"

# ---------------------------------------------------------------------------
# Falcom BZip, mode 2
# ---------------------------------------------------------------------------

_MAX_CHUNK = 0xFFFF


def _repeat(out: bytearray, count: int, offset: int) -> None:
    """从输出缓冲回退 offset 字节处复制 count 字节（LZ 回退）。"""
    if not 1 <= offset <= len(out):
        raise ValueError("回退越界: offset=%d, 已输出=%d" % (offset, len(out)))
    src = len(out) - offset
    for _ in range(count):
        out.append(out[src])
        src += 1


class _BitReader:
    """mode2 位流读取器。

    首个 u16 只使用高 8 位，其后每个 u16 使用全部 16 位。
    """

    __slots__ = ("data", "pos", "word", "mask")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 2
        self.word = data[0] | (data[1] << 8)
        self.mask = 0x0100

    def bit(self) -> bool:
        if self.mask == 0:
            p = self.pos
            self.word = self.data[p] | (self.data[p + 1] << 8)
            self.pos = p + 2
            self.mask = 1
        value = (self.word & self.mask) != 0
        self.mask = (self.mask << 1) & 0xFFFF
        return value

    def read_bits(self, n: int) -> int:
        value = 0
        for _ in range(n & 7):
            value = (value << 1) | (1 if self.bit() else 0)
        for _ in range(n >> 3):
            value = (value << 8) | self.data[self.pos]
            self.pos += 1
        return value

    def count(self) -> int:
        if self.bit():
            return 2
        if self.bit():
            return 3
        if self.bit():
            return 4
        if self.bit():
            return 5
        if self.bit():
            return 6 + self.read_bits(3)
        return 14 + self.read_bits(8)


def decompress(data: bytes, out: bytearray) -> None:
    """解压一块 mode2 数据，结果追加到 out。"""
    br = _BitReader(data)
    while True:
        if not br.bit():
            out.append(data[br.pos])
            br.pos += 1
        elif not br.bit():
            offset = br.read_bits(8)
            _repeat(out, br.count(), offset)
        else:
            value = br.read_bits(13)
            if value == 0:
                return
            if value == 1:
                n = br.read_bits(12) if br.bit() else br.read_bits(4)
                value = data[br.pos]
                br.pos += 1
                out.extend(bytes([value]) * (14 + n))
            else:
                _repeat(out, br.count(), value)


class _BitWriter:
    __slots__ = ("out", "anchor", "mask")

    def __init__(self, out: bytearray) -> None:
        self.out = out
        self.anchor = len(out)
        out.extend(b"\x00\x00")
        self.mask = 0x0080

    def bit(self, value) -> bool:
        self.mask = (self.mask << 1) & 0xFFFF
        if self.mask == 0:
            self.anchor = len(self.out)
            self.out.extend(b"\x00\x00")
            self.mask = 1
        if value:
            if self.mask < 256:
                self.out[self.anchor] |= self.mask
            else:
                self.out[self.anchor + 1] |= self.mask >> 8
        return bool(value)

    def bits(self, n: int, value: int) -> None:
        if value >= (1 << n):
            raise ValueError("bits(%d, %d): 值超出位宽" % (n, value))
        for k in range((n >> 3) << 3, n)[::-1]:
            self.bit((value >> k) & 1)
        for k in range(0, n >> 3)[::-1]:
            self.out.append((value >> (k << 3)) & 0xFF)

    def byte(self, value: int) -> None:
        self.out.append(value & 0xFF)


def _count_equal(data: bytes, i: int, j: int, limit: int) -> int:
    """比较 data[i:] 与 data[j:] 前 limit 字节的相同数量。"""
    n = min(limit, len(data) - i, len(data) - j)
    k = 0
    step = 32
    while k + step <= n:
        if data[i + k:i + k + step] == data[j + k:j + k + step]:
            k += step
        else:
            break
    while k < n and data[i + k] == data[j + k]:
        k += 1
    return k


class _Digraphs:
    """双字节对索引，用于查找最长匹配。"""

    WINDOW = 0x1FFF
    SLOTS = 0x2000
    NONE = 0xFFFF

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.head = [self.NONE] * 0x10000
        self.nxt = [self.NONE] * self.SLOTS
        self.tail = [self.NONE] * 0x10000

    def _key(self, p: int) -> int:
        d = self.data
        b2 = d[p + 1] if p + 1 < len(d) else 0
        return d[p] | (b2 << 8)

    def advance(self) -> None:
        if self.pos >= self.WINDOW:
            prev = self.pos - self.WINDOW
            self.head[self._key(prev)] = self.nxt[prev % self.SLOTS]
        key = self._key(self.pos)
        if self.head[key] == self.NONE:
            self.head[key] = self.pos & 0xFFFF
        else:
            self.nxt[self.tail[key]] = self.pos & 0xFFFF
        self.tail[key] = self.pos % self.SLOTS
        self.nxt[self.pos % self.SLOTS] = self.NONE
        self.pos += 1

    def find(self, best_len: int, best_pos: int):
        p = self.head[self._key(self.pos)]
        d = self.data
        while p != self.NONE:
            length = _count_equal(d, self.pos + 2, p + 2, 267) + 2
            if length >= best_len:
                best_len, best_pos = length, p
            p = self.nxt[p % self.SLOTS]
        return best_len, best_pos


def compress(data: bytes) -> bytes:
    """压缩一块数据为 mode2 格式（单块，长度须 < 65535）。"""
    if len(data) >= _MAX_CHUNK:
        raise ValueError("单块过大: %d 字节（上限 %d）" % (len(data), _MAX_CHUNK - 1))

    out = bytearray()
    bw = _BitWriter(out)
    dig = _Digraphs(data)
    pos = 0
    end = len(data)

    while pos < end:
        run_len = _count_equal(data, pos, pos + 1, 0xFFE) + 1
        if run_len < 14:
            run_len = 1
        run_pos = pos
        if run_len < 64 and pos + 3 < end:
            run_len, run_pos = dig.find(run_len, run_pos)

        if bw.bit(run_len > 1):
            if run_pos == pos:
                run_len = min(run_len, ((1 << 12) - 1) + 14)
                bw.bit(True)
                bw.bits(13, 1)
                n = run_len - 14
                if bw.bit(n >= 16):
                    bw.bits(12, n)
                else:
                    bw.bits(4, n)
                bw.byte(data[pos])
            else:
                run_len = min(run_len, ((1 << 8) - 1) + 14)
                off = pos - run_pos
                if bw.bit(off >= 256):
                    bw.bits(13, off)
                else:
                    bw.bits(8, off)

                m = run_len
                if m >= 3:
                    bw.bit(False)
                if m >= 4:
                    bw.bit(False)
                if m >= 5:
                    bw.bit(False)
                if m >= 6:
                    bw.bit(False)
                if bw.bit(m < 14):
                    if m >= 6:
                        bw.bits(3, m - 6)
                else:
                    bw.bits(8, m - 14)
        else:
            bw.byte(data[pos])

        for _ in range(run_len):
            pos += 1
            dig.advance()

    bw.bit(True)
    bw.bit(True)
    bw.bits(13, 0)
    return bytes(out)


# ---------------------------------------------------------------------------
# ._bm 容器
# ---------------------------------------------------------------------------

HEADER_SIZE = 8
_BMP_OFFSET_FLAGS = 2      # BMP 头的"文件大小"字段偏移
_BMP_OFFSET_RASTER = 34    # BMP 头的"像素数据大小"字段偏移


def unpack_container(data: bytes):
    """解析 ._bm 容器。

    返回 (header_size, total_size, chunks, tail)
    chunks: [(压缩数据, 后续标志字节或 None), ...]
    """
    header = struct.unpack_from("<I", data, 0)[0]
    total = struct.unpack_from("<I", data, 4)[0]
    pos = header
    chunks = []
    while pos < len(data):
        size = struct.unpack_from("<H", data, pos)[0]
        if size < 2:
            raise ValueError("块长度非法: %d @ %d" % (size, pos))
        comp = data[pos + 2:pos + size]
        pos += size
        if pos >= len(data):
            chunks.append((comp, None))
            break
        flag = data[pos]
        pos += 1
        chunks.append((comp, flag))
        if flag == 0:
            break
    return header, total, chunks, data[pos:]


def pack_container(chunks, tail: bytes, total: int, header: int = HEADER_SIZE) -> bytes:
    body = bytearray()
    for comp, flag in chunks:
        body += struct.pack("<H", len(comp) + 2)
        body += comp
        if flag is not None:
            body += bytes([flag])
    return struct.pack("<I", header) + struct.pack("<I", total) + bytes(body) + tail


def chunk_output_sizes(chunks):
    sizes = []
    for comp, _ in chunks:
        buf = bytearray()
        decompress(comp, buf)
        sizes.append(len(buf))
    return sizes


def decode_bm(data: bytes) -> bytes:
    _, _, chunks, _ = unpack_container(data)
    out = bytearray()
    for comp, _ in chunks:
        decompress(comp, out)
    return bytes(out)


def _fix_bmp_header(bmp: bytearray) -> None:
    """让 BMP 头的两个大小字段与当前数据长度自洽。"""
    length = len(bmp)
    offset = struct.unpack_from("<I", bmp, 10)[0]
    struct.pack_into("<I", bmp, _BMP_OFFSET_FLAGS, length)
    struct.pack_into("<I", bmp, _BMP_OFFSET_RASTER, length - offset)


def encode_bm(bmp: bytes, template: bytes, fit_header: bool = True) -> bytes:
    """把 BMP 封回 ._bm，沿用 template 的块划分与尾部数据。"""
    header, total, chunks, tail = unpack_container(template)
    sizes = chunk_output_sizes(chunks)

    data = bytearray(bmp)
    need = sum(sizes)
    if len(data) != need:
        if not fit_header:
            raise ValueError(
                "BMP 长度 %d 与模板解压长度 %d 不一致（可加 --fit-header 自动适配）"
                % (len(data), need))
        if len(data) > need:
            data = data[:need]
        else:
            data += b"\x00" * (need - len(data))
        _fix_bmp_header(data)

    parts = []
    pos = 0
    for size in sizes:
        parts.append(bytes(data[pos:pos + size]))
        pos += size

    new_chunks = []
    for part, (_, flag) in zip(parts, chunks):
        new_chunks.append((compress(part), flag))
    return pack_container(new_chunks, tail, total, header)


# ---------------------------------------------------------------------------
# .na / .ni 归档
# ---------------------------------------------------------------------------

_NA_KEY = 0x7C53F961
_NA_MUL = 0x3D09


def _na_deobfuscate(data: bytes) -> bytes:
    key = _NA_KEY
    out = bytearray(len(data))
    for i, byte in enumerate(data):
        key = (key * _NA_MUL) & 0xFFFFFFFF
        out[i] = (byte - (key >> 16)) & 0xFF
    return bytes(out)


class Archive:
    """Falcom NNI 归档（.na + .ni）。"""

    def __init__(self, na_path: str) -> None:
        base = os.path.splitext(na_path)[0]
        self.na = open(base + ".na", "rb").read()
        ni = open(base + ".ni", "rb").read()
        magic, toc_len, name_len, _ = struct.unpack_from("<4sIII", ni, 0)
        if magic != b"NNI\x00":
            raise ValueError("不是 NNI 归档: %r" % magic)
        toc = _na_deobfuscate(ni[16:16 + toc_len * 16])
        names = _na_deobfuscate(ni[16 + toc_len * 16: 16 + toc_len * 16 + name_len])
        self.entries = []
        for _, size, offset, name_pos in struct.iter_unpack("<IIII", toc):
            end = names.find(b"\x00", name_pos)
            raw = names[name_pos:end]
            try:
                name = raw.decode("cp932")
            except UnicodeDecodeError:
                name = raw.decode("latin-1")
            self.entries.append((name, size, offset))

    def read(self, entry) -> bytes:
        _, size, offset = entry
        return self.na[offset:offset + size]

    def data(self, entry) -> bytes:
        """读取并解压（.Z 条目自动 zlib 解压）。"""
        name, _, _ = entry
        raw = self.read(entry)
        if name.upper().endswith(".Z"):
            expected = struct.unpack_from("<I", raw, 4)[0]
            raw = zlib.decompress(raw[8:])
            if len(raw) != expected:
                raise ValueError("解压长度不符: %s" % name)
        return raw

    @staticmethod
    def output_name(entry) -> str:
        """条目落盘时使用的名称；.Z 条目去掉 .Z 后缀。"""
        name = entry[0].replace("\\", "/")
        if name.upper().endswith(".Z"):
            name = name[:-2]
        return name


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _write_png(bmp: bytes, path: str) -> bool:
    try:
        from PIL import Image
        import io as _io
        Image.open(_io.BytesIO(bmp)).save(path)
        return True
    except Exception:
        return False


def cmd_extract(args) -> int:
    for src in args.input:
        data = open(src, "rb").read()
        bmp = decode_bm(data)
        dst = args.output or os.path.splitext(src)[0] + ".bmp"
        if len(args.input) > 1 and args.output:
            os.makedirs(args.output, exist_ok=True)
            dst = os.path.join(args.output,
                               os.path.splitext(os.path.basename(src))[0] + ".bmp")
        os.makedirs(os.path.dirname(os.path.abspath(dst)) or ".", exist_ok=True)
        open(dst, "wb").write(bmp)
        line = "%-28s -> %-28s %d 字节" % (os.path.basename(src),
                                           os.path.basename(dst), len(bmp))
        if args.png:
            png = os.path.splitext(dst)[0] + ".png"
            line += "  " + ("+png" if _write_png(bmp, png) else "(png 失败)")
        print(line)
    return 0


def cmd_pack(args) -> int:
    for src in args.input:
        if not args.template:
            template_path = os.path.splitext(src)[0] + "._bm"
        else:
            template_path = args.template
        if not os.path.exists(template_path):
            print("找不到模板: %s" % template_path, file=sys.stderr)
            return 2
        bmp = open(src, "rb").read()
        if bmp[:2] != b"BM":
            print("不是 BMP: %s" % src, file=sys.stderr)
            return 2
        out = encode_bm(bmp, open(template_path, "rb").read(),
                        fit_header=args.fit_header)
        os.makedirs(args.output or ".", exist_ok=True)
        dst = os.path.join(args.output or ".",
                           os.path.basename(os.path.splitext(src)[0]) + "._bm")
        open(dst, "wb").write(out)
        print("%-28s -> %-28s %d 字节" % (os.path.basename(src),
                                          os.path.basename(dst), len(out)))
    return 0


def cmd_batch_extract(args) -> int:
    src_dir, out_dir = args.directory, args.output
    os.makedirs(out_dir, exist_ok=True)
    names = sorted(f for f in os.listdir(src_dir) if f.endswith("._bm"))
    print("解包 %d 个文件 -> %s\n" % (len(names), out_dir))
    for name in names:
        data = open(os.path.join(src_dir, name), "rb").read()
        bmp = decode_bm(data)
        base = name[:-4]
        open(os.path.join(out_dir, base + ".bmp"), "wb").write(bmp)
        extra = ""
        if args.png:
            if _write_png(bmp, os.path.join(out_dir, base + ".png")):
                extra = " +png"
        print("  %-24s %7d 字节%s" % (name, len(bmp), extra))
    return 0


def cmd_batch_pack(args) -> int:
    bmp_dir, tpl_dir, out_dir = args.directory, args.template_dir, args.output
    os.makedirs(out_dir, exist_ok=True)
    names = sorted(f for f in os.listdir(bmp_dir) if f.lower().endswith(".bmp"))
    print("封包 %d 个文件 -> %s\n" % (len(names), out_dir))
    failed = 0
    for name in names:
        base = os.path.splitext(name)[0]
        tpl = os.path.join(tpl_dir, base + "._bm")
        if not os.path.exists(tpl):
            print("  %-24s 跳过（无模板 %s）" % (base, base + "._bm"))
            failed += 1
            continue
        bmp = open(os.path.join(bmp_dir, name), "rb").read()
        try:
            out = encode_bm(bmp, open(tpl, "rb").read(), fit_header=args.fit_header)
        except ValueError as exc:
            print("  %-24s 失败: %s" % (base, exc))
            failed += 1
            continue
        open(os.path.join(out_dir, base + "._bm"), "wb").write(out)
        print("  %-24s %7d -> %7d 字节" % (base, len(bmp), len(out)))
    if failed:
        print("\n%d 个未处理" % failed)
    return 0


def cmd_verify(args) -> int:
    """解包后再封包，检查是否能还原（无损校验）。"""
    bad = 0
    for src in args.input:
        raw = open(src, "rb").read()
        bmp = decode_bm(raw)
        rebuilt = encode_bm(bmp, raw)
        ok = rebuilt == raw
        print("%-28s 解压 %7d  重建 %7d  %s"
              % (os.path.basename(src), len(bmp), len(rebuilt),
                 "完全一致" if ok else "不一致"))
        if not ok:
            bad += 1
    return 1 if bad else 0


def cmd_archive_list(args) -> int:
    arc = Archive(args.path)
    print("%s: %d 个条目\n" % (os.path.basename(args.path), len(arc.entries)))
    pattern = args.filter.lower() if args.filter else None
    for name, size, offset in arc.entries:
        if pattern and pattern not in name.lower():
            continue
        print("  %-46s %10d  @%d" % (name, size, offset))
    return 0


def cmd_archive_extract(args) -> int:
    arc = Archive(args.path)
    os.makedirs(args.output, exist_ok=True)
    pattern = args.filter.lower() if args.filter else None
    count = 0
    for entry in arc.entries:
        name, size, _ = entry
        if pattern and pattern not in name.lower():
            continue
        try:
            data = arc.data(entry)
        except Exception as exc:
            print("  失败 %-40s %s" % (name, exc))
            continue
        logical = name.replace("\\", "/")
        out_name = logical[:-2] if logical.upper().endswith(".Z") else logical
        if args.keep_ext:
            out_name = logical
        dst = os.path.join(args.output, out_name)
        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
        open(dst, "wb").write(data)
        mark = "" if out_name == logical else " -> %s" % out_name
        print("  %-46s %10d%s" % (logical, size, mark))
        count += 1
    print("\n提取 %d 个文件 -> %s" % (count, args.output))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="falcom_bm",
        description="Falcom 图片容器 (._bm) 与归档 (.na/.ni) 解包/封包工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  falcom_bm.py extract bk1p._bm\n"
               "  falcom_bm.py extract ./bmp -o ./out --png\n"
               "  falcom_bm.py pack edited.bmp --template bk1p._bm -o ./new\n"
               "  falcom_bm.py batch-pack ./edited --template-dir ./bmp -o ./new\n"
               "  falcom_bm.py verify bk1p._bm\n"
               "  falcom_bm.py archive-list data_ys1.na --filter bk\n",
    )
    parser.add_argument("--version", action="version",
                        version="falcom_bm %s" % __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("extract", help="._bm -> .bmp（支持传入目录批量）")
    p.add_argument("input", nargs="+", help="._bm 文件或目录")
    p.add_argument("-o", "--output", help="输出文件或目录")
    p.add_argument("--png", action="store_true", help="同时输出 PNG（需 Pillow）")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("pack", help=".bmp -> ._bm")
    p.add_argument("input", nargs="+", help="BMP 文件")
    p.add_argument("--template", help="原始 ._bm（默认取同名 ._bm）")
    p.add_argument("-o", "--output", help="输出目录")
    p.add_argument("--no-fit-header", dest="fit_header", action="store_false",
                   help="长度不一致时报错，不自动修正 BMP 头")
    p.set_defaults(func=cmd_pack, fit_header=True)

    p = sub.add_parser("batch-extract", help="批量 ._bm -> .bmp")
    p.add_argument("directory", help="含 ._bm 的目录")
    p.add_argument("-o", "--output", required=True, help="输出目录")
    p.add_argument("--png", action="store_true", help="同时输出 PNG")
    p.set_defaults(func=cmd_batch_extract)

    p = sub.add_parser("batch-pack", help="批量 .bmp -> ._bm")
    p.add_argument("directory", help="含 .bmp 的目录")
    p.add_argument("--template-dir", required=True, help="含原始 ._bm 的目录")
    p.add_argument("-o", "--output", required=True, help="输出目录")
    p.add_argument("--no-fit-header", dest="fit_header", action="store_false",
                   help="长度不一致时报错")
    p.set_defaults(func=cmd_batch_pack, fit_header=True)

    p = sub.add_parser("verify", help="解包再封包，校验无损还原")
    p.add_argument("input", nargs="+", help="._bm 文件")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("archive-list", help="列出 .na/.ni 归档内容")
    p.add_argument("path", help=".na 文件路径")
    p.add_argument("--filter", help="只显示名称含该子串的条目")
    p.set_defaults(func=cmd_archive_list)

    p = sub.add_parser("archive-extract", help="提取 .na/.ni 归档")
    p.add_argument("path", help=".na 文件路径")
    p.add_argument("-o", "--output", required=True, help="输出目录")
    p.add_argument("--filter", help="只提取名称含该子串的条目")
    p.add_argument("--keep-ext", action="store_true",
                   help="保留 .Z 后缀（默认：解压后去掉）")
    p.set_defaults(func=cmd_archive_extract)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # extract 允许传目录
    if args.command == "extract":
        expanded = []
        for item in args.input:
            if os.path.isdir(item):
                expanded += [os.path.join(item, f)
                             for f in sorted(os.listdir(item)) if f.endswith("._bm")]
            else:
                expanded.append(item)
        args.input = expanded
        if not args.input:
            print("没有找到 ._bm 文件", file=sys.stderr)
            return 2
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
