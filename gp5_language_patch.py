#!/usr/bin/env python3
"""GP-5 USB V1.0.6 language-mask patch. Tested on one Chinese-market GP-5. Python 3.9+, no dependencies.

This edits a local file only. It neither connects to nor flashes a pedal.
Only the exact analysed official firmware is accepted. No CRC checks are disabled.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

OFFICIAL_SHA256 = "259ac4e77d3df792ff48e55feff52427ff2ea9ed63cb65785360a23a10dbaf42"
FILE_SIZE = 2094404
MAIN_START = 0xA43DC
PATCH_OFFSET = MAIN_START + 0x53A8
BEFORE = bytes.fromhex("04000057")  # NDS32: LWI r0,[r0+348]
AFTER = bytes.fromhex("44000003")   # NDS32: MOVI r0,#3
EXPECTED_LAYOUT = (
    ("c", 0x200000, 0, 49992),
    ("g", 0x240000, 49992, 348200),
    ("f", 0x280000, 398192, 274404),
    ("b", 0, 672596, 1237352),
    ("e", 0x190000, 1909948, 184320),
)


def crc16_modbus(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
    return crc


def valeton_crc(data):
    crc = crc16_modbus(data)
    return ((crc & 0xFF) << 8) | (crc >> 8)


def layout(data):
    if (len(data) != FILE_SIZE or data[:4] != b"HTFW"
            or data[12:28].split(b"\0", 1)[0] != b"GP-5"
            or data[0x1C:0x20] != b"V\x01\x00\x06"
            or data[0x21] != 0 or data[0x22] != 5
            or struct.unpack_from("<I", data, 8)[0] != len(data)):
        raise ValueError("Нужен распакованный официальный GP-5 USB V1.0.6, 2094404 байт.")
    blocks = []
    for i, expected in enumerate(EXPECTED_LAYOUT):
        toc = 0x38 + i * 16
        stored, reserved, tag, address, offset, size = struct.unpack_from("<HBBIII", data, toc)
        if (chr(tag), address, offset, size) != expected or reserved != 0:
            raise ValueError("Таблица блоков отличается от исследованной прошивки.")
        start = 0x88 + offset
        blocks.append((toc, chr(tag), start, size, stored))
    return blocks


def validate(data):
    blocks = layout(data)
    for _, tag, start, size, stored in blocks:
        if stored != valeton_crc(memoryview(data)[start:start + size]):
            raise ValueError("CRC блока %s не совпадает." % tag)
    if struct.unpack_from("<H", data, 4)[0] != valeton_crc(memoryview(data)[6:]):
        raise ValueError("CRC всего файла не совпадает.")
    return blocks


def repair_crc(data):
    # Block CRCs belong to the outer CRC input, so the outer CRC is updated last.
    for toc, _, start, size, _ in layout(data):
        struct.pack_into("<H", data, toc, valeton_crc(memoryview(data)[start:start + size]))
    struct.pack_into("<H", data, 4, valeton_crc(memoryview(data)[6:]))


def classify(data):
    validate(data)
    digest = hashlib.sha256(data).hexdigest()
    if digest == OFFICIAL_SHA256:
        if data[PATCH_OFFSET:PATCH_OFFSET + 4] != BEFORE:
            raise ValueError("Неожиданная инструкция в официальной прошивке.")
        return "official"
    if data[PATCH_OFFSET:PATCH_OFFSET + 4] == AFTER:
        restored = bytearray(data)
        restored[PATCH_OFFSET:PATCH_OFFSET + 4] = BEFORE
        repair_crc(restored)
        if hashlib.sha256(restored).hexdigest() == OFFICIAL_SHA256:
            return "experimental-language-mask-3"
    raise ValueError("Неизвестный SHA-256. Этот патчер не поддерживает другие модификации.")


def describe(data):
    kind = classify(data)
    return {
        "kind": kind, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "header_version": "V1.0.6", "crc_ok": True,
        "blocks": [{"tag": tag, "size": size, "crc": "0x%04x" % stored, "crc_ok": True}
                   for _, tag, _, size, stored in layout(data)],
        "patch_file_offset": "0x%x" % PATCH_OFFSET,
        "patch_main_offset": "0x53a8", "original_bytes": BEFORE.hex(),
        "patched_bytes": AFTER.hex(),
        "hardware_verified": True,
        "hardware_verification_scope": "Одна китайская GP-5: English сохраняется после перезапуска; iOS Suite также на английском.",
        "note": "Маска 3 разрешает языки 0 и 1. Проверено на одной GP-5; другие экземпляры не проверены."
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("patch", "verify", "restore"))
    parser.add_argument("firmware", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    try:
        if args.firmware.stat().st_size != FILE_SIZE:
            raise ValueError("Неподходящий размер файла.")
        data = args.firmware.read_bytes()
        kind = classify(data)
        if args.command == "verify":
            if args.output:
                raise ValueError("verify не создаёт файл; убери -o.")
            print(json.dumps(describe(data), ensure_ascii=False, indent=2))
            return 0
        if not args.output:
            raise ValueError("Укажи отдельный выходной файл через -o.")
        if args.output.resolve() == args.firmware.resolve():
            raise ValueError("Входной и выходной файлы должны отличаться.")
        expected = "official" if args.command == "patch" else "experimental-language-mask-3"
        if kind != expected:
            raise ValueError("patch требует оригинал, restore требует файл этого патчера.")
        result = bytearray(data)
        result[PATCH_OFFSET:PATCH_OFFSET + 4] = AFTER if args.command == "patch" else BEFORE
        repair_crc(result)
        info = describe(result)
        # Exclusive creation preserves existing files, including the original firmware.
        with args.output.open("xb") as f:
            f.write(result)
        info["output"] = str(args.output.resolve())
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print("Ошибка: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
