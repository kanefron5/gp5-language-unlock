#!/usr/bin/env python3
"""Valeton GP-5 diagnostics for macOS, Python 3.9+, standard library only.

Commands:
  python3 gp5_diag.py check /path/to/firmware.bin
  python3 gp5_diag.py native-crc /path/to/firmware.bin
  python3 gp5_diag.py native-probe /path/to/firmware.bin
  python3 gp5_diag.py native-flash /path/to/firmware.bin --bootloader
  python3 gp5_diag.py ports
  python3 gp5_diag.py native-scan --name GP-5
  python3 gp5_diag.py logs
  python3 gp5_diag.py capture /path/to/firmware.bin

Nonstandard install: put --app '/path/Valeton Suite.app' BEFORE the command.
capture launches the official GUI. Reproduce the error there, then press
Ctrl+C in this terminal AFTER any active transfer has completed or failed.
Ctrl+C stops collection; it does not terminate Valeton Suite.

Native ABI recovered by static analysis of the official macOS Suite 2.1.0
and 1.0.9 libraries (arm64). native-crc needs 2.1.0: 1.0.9 has no exported
checkCrc function. Native commands are restricted to the analysed hashes.
native-flash explicitly calls deviceStartUpdate after three native checks.
Other commands never call firmware-writing entries. Native flashing is
experimental. Official V1.0.6 was flashed successfully in the supplied Claude report
with --announce-version V999 --version-reject-ok. The language-mask patch was also flashed successfully on the same GP-5.
Device English persists after reboot, and iOS Suite also uses English.
native-probe has been tested
on macOS ARM64 with the user's GP-5. Firmware success requires terminal
native status 0, followed by checking the installed version on the device.
"""

import argparse
import codecs
import ctypes as C
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import queue
import shutil
import struct
import subprocess
import sys
import tempfile
import time

DIAG_VERSION = "0.20-block-crc"

LIB_HASHES = {
    "8c3b0ae683eb51275c197e5b3b4ebea9a3ba4e8f57e8abc7820747a10bd1d222": "2.1.0",
    "dc1fec60a5d5295cf09d8c51516ed63238273c8981b3defea82e88ca729a42ca": "1.0.9",
}
DEFAULT_APP = Path("/Applications/Valeton Suite.app")
MAX_FIRMWARE = 64 * 1024 * 1024


def emit(value):
    print(json.dumps(value, ensure_ascii=False, indent=2), flush=True)


def require_mac():
    if sys.platform != "darwin":
        raise RuntimeError("Эта команда требует macOS.")


def app_info(app):
    app = app.expanduser().resolve()
    info = app / "Contents/Info.plist"
    if not info.is_file():
        raise RuntimeError(f"Приложение не найдено: {app}. Используй --app перед командой.")
    with info.open("rb") as f:
        metadata = plistlib.load(f)
    lib = app / "Contents/Frameworks/5868USB.dylib"
    return app, metadata, lib


def crc16_modbus(data):
    table = []
    for value in range(256):
        crc = value
        for _ in range(8):
            crc = (crc >> 1) ^ (0xA001 if crc & 1 else 0)
        table.append(crc)
    crc = 0xFFFF
    for value in data:
        crc = (crc >> 8) ^ table[(crc ^ value) & 0xFF]
    return crc


def firmware_block_info(data):
    """Validate uncompressed HTFW component CRCs, including locally patched files."""
    errors, blocks = [], []
    if data[0x21] != 0:
        return blocks, ["Сжатый контейнер не поддерживается проверкой CRC блоков."]
    count = data[0x22]
    payload = 0x38 + count * 16
    if not 1 <= count <= 32 or payload > len(data):
        return blocks, ["Некорректная таблица блоков HTFW."]
    end_previous = payload
    for index in range(count):
        stored, reserved, tag, address, offset, size = struct.unpack_from("<HBBIII", data, 0x38 + index * 16)
        start, end = payload + offset, payload + offset + size
        name = chr(tag) if 32 <= tag < 127 else "0x%02x" % tag
        if size == 0 or start < end_previous or end > len(data):
            errors.append("Некорректные границы блока %s." % name)
            continue
        end_previous = end
        crc = crc16_modbus(memoryview(data)[start:end])
        calculated = ((crc & 0xff) << 8) | (crc >> 8)
        ok = stored == calculated
        blocks.append({"tag": name, "address": "0x%x" % address,
                       "file_offset": start, "size": size,
                       "crc_stored": "0x%04x" % stored,
                       "crc_calculated": "0x%04x" % calculated, "crc_ok": ok})
        if not ok:
            errors.append("CRC блока %s не совпадает." % name)
    if end_previous != len(data):
        errors.append("Блоки HTFW не покрывают полезные данные файла.")
    return blocks, errors


def firmware_info(path):
    path = path.expanduser().resolve()
    if not path.is_file():
        raise RuntimeError(f"Файл не найден: {path}")
    if path.stat().st_size > MAX_FIRMWARE:
        raise RuntimeError("Файл больше 64 MiB; ожидается распакованный .bin GP-5.")
    data = path.read_bytes()
    result = {"path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    errors = []
    if len(data) < 0x94 or data[:4] != b"HTFW":
        result.update(valid=False, errors=["Нет заголовка HTFW либо файл слишком короткий. Нужен .bin, не ZIP."])
        return result
    declared = struct.unpack_from("<I", data, 8)[0]
    model = data[12:28].split(b"\0", 1)[0].decode("ascii", "replace")
    stored = struct.unpack_from("<H", data, 4)[0]
    # Valeton checkCrc uses CRC16 tables with the two accumulator bytes
    # swapped relative to conventional Modbus numeric presentation.
    crc = crc16_modbus(memoryview(data)[6:])
    calculated = ((crc & 0xFF) << 8) | (crc >> 8)
    if declared != len(data):
        errors.append("Размер файла отличается от размера в заголовке.")
    if model != "GP-5":
        errors.append(f"В заголовке другая модель: {model!r}.")
    if stored != calculated:
        errors.append("CRC не совпадает.")
    blocks, block_errors = firmware_block_info(data)
    errors.extend(block_errors)
    # 5868USB getVersionStringForFilePath: header byte 0x1c ('V' or 'B')
    # followed by three decimal numbers from 0x1d..0x1f, joined with dots.
    prefix = "V" if data[0x1c] == 0x56 else "B"
    header_version = f"{prefix}{data[0x1d]}.{data[0x1e]}.{data[0x1f]}"
    result.update(magic="HTFW", model=model, version_tag=data[0x90:0x94].decode("ascii", "replace"),
                  header_version=header_version,
                  declared_size=declared, crc_stored=f"0x{stored:04x}",
                  crc_calculated=f"0x{calculated:04x}", crc_ok=stored == calculated,
                  blocks=blocks, block_crc_ok=not block_errors,
                  valid=not errors, errors=errors)
    return result


def load_native(app):
    require_mac()
    _, metadata, libpath = app_info(app)
    digest = hashlib.sha256(libpath.read_bytes()).hexdigest()
    if digest not in LIB_HASHES:
        raise RuntimeError("Неизвестная сборка 5868USB.dylib. Нативные вызовы отключены: "
                           f"Suite {metadata.get('CFBundleShortVersionString')}, SHA-256 {digest}. "
                           "Команды check, ports, logs и capture доступны.")
    return C.CDLL(str(libpath))


def native_worker(app, mode, firmware=None, name="GP-5"):
    lib = load_native(app)
    if mode == "crc":
        if not hasattr(lib, "checkCrc"):
            raise RuntimeError("В Suite 1.0.9 функция checkCrc не экспортируется. "
                               "Для native-crc нужен Suite 2.1.0; команда check работает и без него.")
        check = lib.checkCrc
        check.argtypes = [C.c_char_p]
        check.restype = C.c_int
        code = check(os.fsencode(firmware.expanduser().resolve()))
        emit({"function": "checkCrc", "return_code": code,
              "meaning": {0: "CRC совпадает", -1: "CRC не совпадает", -2: "Размер не совпадает"}.get(code, "Неизвестный код")})
        return 0 if code == 0 else 1
    callback_type = C.CFUNCTYPE(None, C.POINTER(C.c_int), C.c_int)
    for function in ("scanInDevice", "scanOutDevice"):
        results = []
        errors = []

        @callback_type
        def callback(indices, count):
            if count < 0 or count > 4096 or (count and not indices):
                errors.append("Неверные аргументы callback")
                return
            # The library frees this array immediately after callback returns.
            results.append([indices[i] for i in range(count)])

        scan = getattr(lib, function)
        scan.argtypes = [C.c_char_p, callback_type]
        scan.restype = None
        scan(name.encode("utf-8"), callback)
        emit({"function": function, "exact_name_filter": name, "matching_indices": results,
              "callback_received": bool(results), "errors": errors})
    return 0


def run_native(args):
    require_mac()
    mode = "crc" if args.command == "native-crc" else "scan"
    if mode == "crc":
        info = firmware_info(args.firmware)
        emit(info)
        if not info["valid"]:
            return 1
    command = [sys.executable, str(Path(__file__).resolve()), "--app", str(args.app),
               "_native", "--mode", mode]
    if mode == "crc":
        command += ["--firmware", str(args.firmware.expanduser().resolve())]
    else:
        command += ["--name", args.name]
    native_env = os.environ.copy()
    if mode == "scan":
        # HTFileLog resets its logfile on first use. Give this diagnostic
        # process its own temp directory to preserve the GUI's existing log.
        folder = output_dir()
        private_temp = folder / "native-temp"
        private_temp.mkdir()
        native_env["TMPDIR"] = str(private_temp) + "/"
        print(f"Нативные логи: {private_temp / 'HTCache/logfile.txt'}", flush=True)
    try:
        result = subprocess.run(command, timeout=30, env=native_env)
    except subprocess.TimeoutExpired:
        print("Нативный вызов не завершился за 30 секунд. Диагностический процесс остановлен.", file=sys.stderr)
        return 1
    if result.returncode < 0:
        print(f"Нативная библиотека завершилась по сигналу {-result.returncode}; родительский скрипт продолжил работу.", file=sys.stderr)
    return 0 if result.returncode == 0 else 1


# The official bridge posts Dart_CObject arrays, rather than calling the
# Python callbacks directly. This minimal receiver implements only the
# observed Dart_PostCObject entry, with the verified Dart API v2 layout.
class DartArray(C.Structure):
    _fields_ = [("length", C.c_ssize_t), ("values", C.POINTER(C.c_void_p))]


class DartValue(C.Union):
    _fields_ = [("integer", C.c_int64), ("int32", C.c_int32),
                ("boolean", C.c_bool), ("string", C.c_char_p),
                ("array", DartArray), ("reserved", C.c_byte * 40)]


class DartObject(C.Structure):
    _fields_ = [("kind", C.c_int32), ("value", DartValue)]


def decode_dart_object(address, depth=0):
    if not address or depth > 8:
        raise ValueError("Invalid Dart object graph")
    obj = C.cast(address, C.POINTER(DartObject)).contents
    if obj.kind == 0:
        return None
    if obj.kind == 1:
        return obj.value.boolean
    if obj.kind == 2:
        return obj.value.int32
    if obj.kind == 3:
        return obj.value.integer
    if obj.kind == 5:
        return (obj.value.string or b"").decode("utf-8", "replace")
    if obj.kind == 6:
        array = obj.value.array
        if not 0 <= array.length <= 65536 or (array.length and not array.values):
            raise ValueError("Invalid Dart array")
        return [decode_dart_object(array.values[i], depth + 1) for i in range(array.length)]
    raise ValueError(f"Unsupported Dart_CObject kind {obj.kind}")


class DartReceiver:
    def __init__(self, lib):
        self.events = queue.Queue(maxsize=4096)
        self.dropped = 0
        callback_type = C.CFUNCTYPE(C.c_bool, C.c_int64, C.c_void_p)

        @callback_type
        def post(port, message):
            try:
                event = {"time": dt.datetime.now().astimezone().isoformat(),
                         "native_port": port, "event": decode_dart_object(message)}
                self.events.put_nowait(event)
                return True
            except queue.Full:
                self.dropped += 1
                return False
            except Exception as error:
                try:
                    self.events.put_nowait({"dart_decode_error": str(error)})
                except queue.Full:
                    self.dropped += 1
                return False

        class Entry(C.Structure):
            _fields_ = [("name", C.c_char_p), ("function", C.c_void_p)]

        class API(C.Structure):
            _fields_ = [("major", C.c_int32), ("minor", C.c_int32),
                        ("functions", C.POINTER(Entry))]

        self.callback = post
        self.entries = (Entry * 2)(Entry(b"Dart_PostCObject", C.cast(post, C.c_void_p).value), Entry(None, None))
        self.api = API(2, 0, self.entries)
        lib.InitDartApiDL.argtypes = [C.c_void_p]
        lib.InitDartApiDL.restype = C.c_ssize_t
        code = lib.InitDartApiDL(C.byref(self.api))
        if code != 0:
            raise RuntimeError(f"InitDartApiDL: {code}")

    def drain(self):
        result = []
        while True:
            try:
                result.append(self.events.get_nowait())
            except queue.Empty:
                return result


def decode_gp5_single_packet(event):
    """Decode a complete one-packet nibble SysEx with CRC-8/poly 0x07."""
    if event.get("direction") != "RX" or not isinstance(event.get("hex"), str):
        return None
    try:
        frame = bytes.fromhex(event["hex"])
    except ValueError:
        return None
    if not frame.startswith(b"\xf0") or not frame.endswith(b"\xf7"):
        return None
    nib = frame[1:-1]
    if len(nib) % 2 or any(v > 15 for v in nib):
        return None
    raw = bytes((nib[i] << 4) | nib[i + 1] for i in range(0, len(nib), 2))
    if len(raw) < 4 or raw[1:3] != b"\x01\x00" or len(raw) != raw[3] + 4:
        return None
    crc = 0
    for value in raw[1:]:
        crc ^= value
        for _ in range(8):
            crc = ((crc << 1) ^ (0x07 if crc & 0x80 else 0)) & 0xff
    return raw[4:] if crc == raw[0] else None


def announcement_info(info, tag):
    if tag is None:
        return info
    if len(tag) != 4 or tag[0] != "V" or any(c not in "0123456789" for c in tag[1:]):
        raise RuntimeError("--announce-version: нужен тег V и три цифры, например V107.")
    return dict(info, version_tag=tag)


def suite_bootloader_handshake(lib, device, info, midi, receiver, record, enter_only=False, reject_ok=False):
    """Repeat the observed Suite requests; ACK is transport status only."""
    lib.sendMidiMessage.argtypes = [C.c_void_p, C.c_int32, C.c_void_p, C.c_int32, C.c_int32]
    lib.sendMidiMessage.restype = None
    def request(command, data, message_type, accepts):
        # Drain already queued frames before submitting a new request.
        for event in receiver.drain() + midi.drain():
            record(event)
        buffer = C.create_string_buffer(data) if data else None
        record({"suite_handshake_tx": {"command": f"0x{command:02x}", "type": f"0x{message_type:02x}", "data_hex": data.hex()}})
        lib.sendMidiMessage(device, command, buffer, len(data), message_type)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            midi.pump(0.005)
            events = receiver.drain() + midi.drain()
            for event in events:
                record(event)
            for event in events:
                payload = decode_gp5_single_packet(event)
                if payload is not None and accepts(payload):
                    record({"suite_handshake_rx": {"command": f"0x{command:02x}", "payload_hex": payload.hex()}})
                    return payload
            time.sleep(0.001)
        raise RuntimeError(f"Нет ожидаемого ответа на 0x{command:02x}. Передача прошивки не запускалась.")
    # HTMessage::sendMidiMessage chooses state 4 (wait ACK) for type 0x11,
    # state 5 (wait matching command response) for other request types.
    # The 0x30 response has data, so an ACK-only request would block 0x69.
    mode = request(0x30, b"", 0x12, lambda p: p.startswith(b"\x11\x30"))
    if enter_only:
        if mode != b"\x11\x30\x01\x00":
            raise RuntimeError(f"Для --enter-update нужен обычный рабочий режим GP-5; получен ответ {mode.hex()}. Передача не запускалась.")
        ack = request(0x6f, b"", 0x11, lambda p: len(p) == 3 and p[:2] == b"\x14\x08")
        if ack[2] != 0:
            raise RuntimeError(f"После 0x6f получен ACK {ack[2]}. Передача прошивки не запускалась.")
        midi.pump(0.05)
        for event in receiver.drain() + midi.drain():
            record(event)
        record({"enter_update_command_acknowledged": True, "note": "Ожидается USB-переподключение; ACK сам по себе не подтверждает режим загрузчика."})
        return
    if mode != b"\x11\x30\x01\x01":
        raise RuntimeError(f"Ответ режима {mode.hex()} отличается от наблюдавшегося загрузчика. Включи режим обновления вручную; передача не запускалась.")
    version = info["version_tag"].encode("ascii") + b"\0"
    if len(version) != 5:
        raise RuntimeError("Для эксперимента нужен тег версии из четырёх ASCII-символов.")
    ack = request(0x69, version, 0x11, lambda p: len(p) == 3 and p[:2] == b"\x14\x08")
    if ack[2] != 0 and not reject_ok:
        raise RuntimeError(f"После 0x69 получен ACK {ack[2]}. Передача прошивки не запускалась.")
    if reject_ok:
        # Suite 2.1.0 (_HomePageState.startUpdateFirmware -> waitVersion,
        # handelSendMessageReponseAck 0x2c5e70) starts the update only when
        # 5868USB reports status 3 (RET_SEND_FAILED after 10 rejects) for 0x69.
        if ack[2] == 0:
            raise RuntimeError("0x69 принят (ACK 0), а для этого эксперимента нужен отказ, как ждёт Suite. Передача не запускалась.")
        final, deadline = None, time.monotonic() + 15.0
        while final is None and time.monotonic() < deadline:
            midi.pump(0.005)
            for event in receiver.drain() + midi.drain():
                record(event)
                m = event.get("event")
                if isinstance(m, list) and len(m) == 6 and m[:2] == [3, 103] and m[3] == 0x69:
                    final = m[5]
            time.sleep(0.001)
        record({"version_reject_final_status": final})
        if final != 3:
            raise RuntimeError(f"Итоговый статус 0x69 = {final}, ожидался 3. Передача не запускалась.")
    midi.pump(0.05)
    for event in receiver.drain() + midi.drain():
        record(event)
    record({"suite_handshake_completed": True, "note": "ACK 0 подтверждает обмен; совместимость и успешная запись этим не доказаны."})


VERSION_PROBE_STRINGS = ("V106", "V1.0.6", "V103", "V1.0.3", "V107", "V1.0.7", "V100", "V999")


def version_probe(lib, device, midi, receiver, record, expected_mode, strings=VERSION_PROBE_STRINGS):
    """Send only 0x30 and 0x69 variants. No 0x60/0x61, no deviceStartUpdate.

    5868USB 2.1.0 (HTDevice::reciveACKData 0xa1870, HTMessage::setMessageState
    0xac9bc, HTDevice::timerCallback 0xa1088): ACK byte 0 -> outgoing status 2;
    nonzero ACK or timeout -> resend, after 10 failures outgoing status 3
    (log RET_SEND_FAILED). Suite 2.1.0 Dart treats status 3 for 0x69 as success.
    """
    lib.sendMidiMessage.argtypes = [C.c_void_p, C.c_int32, C.c_void_p, C.c_int32, C.c_int32]
    lib.sendMidiMessage.restype = None
    def pump_collect(seconds, stop=None):
        events, deadline = [], time.monotonic() + seconds
        while time.monotonic() < deadline:
            midi.pump(0.005)
            batch = receiver.drain() + midi.drain()
            for event in batch:
                record(event)
            events += batch
            if stop and any(stop(e) for e in batch):
                break
            time.sleep(0.001)
        return events
    for event in receiver.drain() + midi.drain():
        record(event)
    record({"version_probe_tx": {"command": "0x30", "type": "0x12"}})
    lib.sendMidiMessage(device, 0x30, None, 0, 0x12)
    events = pump_collect(5.0, lambda e: (decode_gp5_single_packet(e) or b"").startswith(b"\x11\x30"))
    modes = [p for p in (decode_gp5_single_packet(e) for e in events) if p and p.startswith(b"\x11\x30")]
    if not modes:
        raise RuntimeError("Нет ответа на 0x30. Проба остановлена.")
    if modes[-1] != expected_mode:
        raise RuntimeError(f"Ответ режима {modes[-1].hex()}, ожидался {expected_mode.hex()}. Проба остановлена.")
    pump_collect(0.3)
    summary = []
    for text in strings:
        data = text.encode("ascii") + b"\0"
        buffer = C.create_string_buffer(data)
        record({"version_probe_tx": {"command": "0x69", "string": text, "data_hex": data.hex()}})
        lib.sendMidiMessage(device, 0x69, buffer, len(data), 0x11)
        def done(e):
            m = e.get("event")
            return isinstance(m, list) and len(m) == 6 and m[:2] == [3, 103] and m[3] == 0x69
        events = pump_collect(8.0, done)
        acks = [p[2] for p in (decode_gp5_single_packet(e) for e in events)
                if p and len(p) == 3 and p[:2] == b"\x14\x08"]
        finals = [e["event"][5] for e in events if done(e)]
        item = {"string": text, "ack_bytes": acks, "outgoing_status": finals[-1] if finals else None}
        summary.append(item)
        record({"version_probe_result": item,
                "meaning": "status 2 = ACK 00; status 3 = 10 отказов/таймаутов (RET_SEND_FAILED)"})
        if not finals and not acks:
            record({"version_probe_stopped": "Нет ответа; дальнейшие строки не отправлялись."})
            break
        pump_collect(0.3)
    record({"version_probe_summary": summary})
    return summary


def native_probe_worker(args):
    # New device-facing ABIs have been inspected on ARM64 Suite 2.1.0 only.
    if platform.machine().lower() not in ("arm64", "aarch64"):
        raise RuntimeError("native-probe пока поддерживает только Python ARM64 на Apple Silicon.")
    _, metadata, path = app_info(args.app)
    if hashlib.sha256(path.read_bytes()).hexdigest() != next(iter(LIB_HASHES)):
        raise RuntimeError("native-probe требует проверенную библиотеку Suite 2.1.0.")
    info = firmware_info(args.firmware)
    announce_version = getattr(args, "announce_version", None)
    handshake_info = announcement_info(info, announce_version)
    if announce_version and not (args.enter_update or args.suite_handshake):
        raise RuntimeError("--announce-version требует --enter-update либо --suite-handshake.")
    if not info["valid"]:
        emit(info)
        return 1
    if os.environ.get("GP5_TX_REQUIRED") == "1":
        trace_path = Path(os.environ.get("GP5_TX_LOG", ""))
        if not trace_path.is_file() or '"hook_loaded"' not in trace_path.read_text():
            raise RuntimeError("macOS не загрузила MIDI-трассировщик. Запись не запускалась.")
    lib = load_native(args.app)
    receiver = DartReceiver(lib)
    midi = MidiPorts()
    device = None
    flash = args.command == "_flash"
    terminal_status = None
    last_progress_print = 0.0
    def record(event):
        nonlocal terminal_status, last_progress_print
        message = event.get("event")
        if flash and isinstance(message, list) and len(message) == 7 and message[:2] == [2, 104]:
            status, sent, total, stage = message[3:]
            if status in (0, -1):
                terminal_status = status
            now = time.monotonic()
            if status != 1 or now - last_progress_print >= 1:
                emit({"firmware_progress": {"status": status, "total_packets": total,
                                            "sent_packets": sent, "stage": stage}})
                last_progress_print = now
        elif not flash or event.get("direction") != "RX":
            emit(event)
        with (args.output / "native-probe.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    try:
        if announce_version:
            record({"announcement_override": {"command": "0x69", "file_version": info.get("version_tag"),
                    "announced_version": announce_version, "firmware_file_modified": False}})
        ports = midi.snapshot()
        record({"ports": ports})
        sources = [p for p in ports if p["direction"] == "source"]
        destinations = [p for p in ports if p["direction"] == "destination"]
        # No unchecked index is passed into connectDevice, which indexes its
        # JUCE port arrays without bounds validation.
        if len(sources) != 1 or len(destinations) != 1:
            raise RuntimeError("Для native-probe оставь ровно один MIDI source и destination: GP-5. Другие MIDI-устройства отключи.")
        lib.connectDevice.argtypes = [C.c_int32, C.c_int32, C.c_char_p,
                                      C.c_int64, C.c_int64, C.c_int64]
        lib.connectDevice.restype = C.c_void_p
        lib.registerSendPort.argtypes = [C.c_void_p, C.c_int64]
        lib.registerSendPort.restype = None
        lib.isRealFirmware.argtypes = [C.c_void_p, C.c_char_p]
        lib.isRealFirmware.restype = C.c_int32
        lib.isRealFirmwareWithDeviceName.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p]
        lib.isRealFirmwareWithDeviceName.restype = C.c_int32
        lib.checkCrc.argtypes, lib.checkCrc.restype = [C.c_char_p], C.c_int32
        lib.disConnectDevice.argtypes, lib.disConnectDevice.restype = [C.c_void_p], None
        # Last three values are opaque callback IDs echoed in posted events,
        # not C callback pointers; confirmed in all three bridge lambdas.
        # Third string is copied from the observed Suite FFI invocation.
        # It is not a verified model-name parameter.
        device = lib.connectDevice(0, 0, b"97", 101, 102, 103)
        record({"function": "connectDevice", "device": hex(device or 0)})
        if not device:
            raise RuntimeError("connectDevice вернул NULL.")
        lib.registerSendPort(device, 1)
        midi.start_receiving()
        for event in midi.sync_receivers(ports):
            record(event)
        cf = midi.cf
        cf.CFRunLoopRunInMode.argtypes = [C.c_void_p, C.c_double, C.c_bool]
        cf.CFRunLoopRunInMode.restype = C.c_int32
        run_mode = C.c_void_p.in_dll(cf, "kCFRunLoopDefaultMode")
        filename = os.fsencode(args.firmware.expanduser().resolve())
        started = time.monotonic()
        next_check = 0.0
        previous = None
        if args.enter_update:
            preflight = {"checkCrc": lib.checkCrc(filename),
                         "isRealFirmware": lib.isRealFirmware(device, filename),
                         "isRealFirmwareWithDeviceName_GP5": lib.isRealFirmwareWithDeviceName(device, filename, b"GP-5")}
            record({"before_enter_update_preflight": preflight})
            if any(value != 0 for value in preflight.values()):
                raise RuntimeError("Проверка файла не пройдена. Переход в загрузчик не запускался.")
            original_endpoints = {p["endpoint"] for p in ports}
            suite_bootloader_handshake(lib, device, handshake_info, midi, receiver, record, enter_only=True)
            lib.disConnectDevice(device)
            device = None
            deadline = time.monotonic() + 10.0
            last_inventory = ports
            ready_since = None
            while time.monotonic() < deadline:
                midi.pump(0.05)
                ports = midi.snapshot()
                if ports != last_inventory:
                    record({"ports_after_enter_update": ports})
                    last_inventory = ports
                for event in midi.sync_receivers(ports) + receiver.drain() + midi.drain():
                    record(event)
                sources = [p for p in ports if p["direction"] == "source"]
                destinations = [p for p in ports if p["direction"] == "destination"]
                new_pair = len(sources) == len(destinations) == 1 and all(
                    p["endpoint"] not in original_endpoints for p in ports)
                if new_pair:
                    if ready_since is None:
                        ready_since = time.monotonic()
                    if time.monotonic() - ready_since >= 0.5:
                        break
                else:
                    ready_since = None
                time.sleep(0.001)
            else:
                raise RuntimeError("После 0x6f новые MIDI-порты загрузчика не появились. Передача прошивки не запускалась.")
            device = lib.connectDevice(0, 0, b"97", 101, 102, 103)
            record({"function": "connectDevice_after_enter_update", "device": hex(device or 0)})
            if not device:
                raise RuntimeError("Не удалось подключиться после USB-переподключения. Передача не запускалась.")
            lib.registerSendPort(device, 1)
        if getattr(args, "version_probe", False):
            in_boot = args.enter_update or args.bootloader
            strings = tuple(x for x in (args.probe_strings or "").split(",") if x) or VERSION_PROBE_STRINGS
            if any(len(x) > 16 or not x.isascii() or not x.isprintable() for x in strings):
                raise RuntimeError("--probe-strings: короткие ASCII-строки через запятую.")
            version_probe(lib, device, midi, receiver, record,
                          b"\x11\x30\x01\x01" if in_boot else b"\x11\x30\x01\x00", strings)
            record({"probe_finished": True, "note": "Только 0x30/0x69; запись не запускалась."})
            return 0
        if flash:
            preflight = {"checkCrc": lib.checkCrc(filename),
                         "isRealFirmware": lib.isRealFirmware(device, filename),
                         "isRealFirmwareWithDeviceName_GP5": lib.isRealFirmwareWithDeviceName(device, filename, b"GP-5")}
            record({"flash_preflight": preflight})
            if any(value != 0 for value in preflight.values()):
                raise RuntimeError("Нативная проверка отклонила файл. Запись не запущена.")
            if args.suite_handshake or args.enter_update:
                suite_bootloader_handshake(lib, device, handshake_info, midi, receiver, record,
                                           reject_ok=getattr(args, "version_reject_ok", False))
            lib.deviceProcessCallback.argtypes = [C.c_void_p, C.c_int64]
            lib.deviceProcessCallback.restype = C.c_int32
            lib.deviceStartUpdate.argtypes = [C.c_void_p, C.c_char_p]
            lib.deviceStartUpdate.restype = C.c_int32
            code = lib.deviceProcessCallback(device, 104)
            record({"function": "deviceProcessCallback", "return_code": code})
            if code != 0:
                raise RuntimeError("Не удалось подключить события прогресса. Запись не запущена.")
            # Firmware-writing is reachable only through the explicit
            # native-flash command, after all three native checks pass.
            import signal
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            code = lib.deviceStartUpdate(device, filename)
            record({"function": "deviceStartUpdate", "return_code": code,
                    "meaning": "0 = передача запущена; это не подтверждение завершения."})
            if code != 0:
                raise RuntimeError(f"deviceStartUpdate отказал: {code}")
            # The native method starts its own JUCE MultiTimer(2) at 1 ms.
            # CFRunLoop dispatches JUCE timer callbacks; do not tick manually.
            while terminal_status is None:
                cf.CFRunLoopRunInMode(run_mode, 0.005, False)
                for event in receiver.drain() + midi.drain():
                    record(event)
                time.sleep(0.001)
            record({"flash_finished": terminal_status == 0,
                    "native_terminal_status": terminal_status,
                    "note": "После успешной передачи версию нужно проверить на устройстве."})
            return 0 if terminal_status == 0 else 1
        if args.suite_handshake or args.enter_update:
            suite_bootloader_handshake(lib, device, handshake_info, midi, receiver, record)
        record({"probe": "Подключение и проверка файла без GUI; передача прошивки не запускается.",
                "suite_handshake_requested": args.suite_handshake or args.enter_update})
        started = time.monotonic()
        while time.monotonic() - started < args.seconds:
            cf.CFRunLoopRunInMode(run_mode, 0.05, False)
            for event in receiver.drain() + midi.drain():
                record(event)
            elapsed = time.monotonic() - started
            if elapsed >= next_check:
                current = {"checkCrc": lib.checkCrc(filename),
                           "isRealFirmware": lib.isRealFirmware(device, filename),
                           "isRealFirmwareWithDeviceName_GP5": lib.isRealFirmwareWithDeviceName(device, filename, b"GP-5")}
                if current != previous:
                    record({"elapsed_seconds": round(elapsed, 2), "native_checks": current,
                            "meaning": "0 = файл принят этой функцией; -1 = отклонён. Это не разрешение на запись."})
                    previous = current
                next_check = elapsed + 2.0
        record({"probe_finished": True, "dart_events_dropped": receiver.dropped,
                "midi_packets_dropped": midi.dropped_packets})
        return 0
    finally:
        if device:
            lib.disConnectDevice(device)
        midi.close()
        # receiver references must outlive native callbacks through disconnect.
        for event in receiver.drain():
            record(event)


TX_TRACE_SOURCE = r"""
#include <CoreMIDI/CoreMIDI.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <errno.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned captured = 0;
static void log_packet(const char *api, MIDIEndpointRef endpoint,
                       const unsigned char *bytes, size_t count,
                       OSStatus status, int protocol) {
    /* Bounded trace: first 2048 packets, no changes to transmitted buffers. */
    pthread_mutex_lock(&lock);
    const char *path = getenv("GP5_TX_LOG");
    if (!path || captured >= 2048) { pthread_mutex_unlock(&lock); return; }
    captured++;
    size_t size = count > 4096 ? 4096 : count;
    char hex[8193];
    const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; i++) {
        hex[2*i] = digits[bytes[i] >> 4];
        hex[2*i+1] = digits[bytes[i] & 15];
    }
    hex[2*size] = 0;
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    char line[8600];
    int length = snprintf(line, sizeof(line),
        "{\"direction\":\"TX\",\"api\":\"%s\",\"pid\":%d,\"endpoint\":%u,"
        "\"unix_time\":%lld.%09ld,\"status\":%d,\"protocol\":%d,"
        "\"length\":%zu,\"truncated\":%s,\"hex\":\"%s\"}\n",
        api, (int)getpid(), (unsigned)endpoint, (long long)ts.tv_sec, ts.tv_nsec,
        (int)status, protocol, count, size != count ? "true" : "false", hex);
    int fd = open(path, O_WRONLY|O_CREAT|O_APPEND, 0600);
    if (fd >= 0) {
        size_t sent = 0;
        while (sent < (size_t)length) {
            ssize_t n = write(fd, line + sent, (size_t)length - sent);
            if (n <= 0) break;
            sent += (size_t)n;
        }
        close(fd);
    }
    pthread_mutex_unlock(&lock);
}
__attribute__((constructor)) static void trace_loaded(void) {
    log_packet("hook_loaded", 0, (const unsigned char *)"", 0, 0, 0);
}
/* Experimental timing change only: retain the exact header and device ACK.
   Enabled solely by native-flash's explicit --header-delay-ms option. */
static void delay_block_header(const unsigned char *nibbles, size_t length,
                               MIDIEndpointRef endpoint) {
    const char *setting = getenv("GP5_HEADER_DELAY_MS");
    if (!setting || length != 36) return;
    unsigned char raw[18];
    for (size_t i = 0; i < 18; i++) {
        if (nibbles[2*i] > 15 || nibbles[2*i+1] > 15) return;
        raw[i] = (nibbles[2*i] << 4) | nibbles[2*i+1];
    }
    if (raw[1] != 1 || raw[2] != 0 || raw[3] != 14 ||
        raw[4] != 0x11 || raw[5] != 0x61) return;
    unsigned char crc = 0;
    for (size_t i = 1; i < 18; i++) {
        crc ^= raw[i];
        for (int j = 0; j < 8; j++)
            crc = (crc << 1) ^ ((crc & 0x80) ? 7 : 0);
    }
    if (crc != raw[0]) return;
    char *end; long ms = strtol(setting, &end, 10);
    if (*end || ms < 1 || ms > 2000) return;
    log_packet("header_delay_begin", endpoint, raw, sizeof(raw), (OSStatus)ms, 0);
    struct timespec remaining = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&remaining, &remaining) && errno == EINTR) {}
    log_packet("header_delay_done", endpoint, raw, sizeof(raw), (OSStatus)ms, 0);
}
static void delay_sysex_header(const unsigned char *bytes, size_t size,
                               MIDIEndpointRef endpoint) {
    if (size == 38 && bytes[0] == 0xf0 && bytes[37] == 0xf7)
        delay_block_header(bytes + 1, 36, endpoint);
}
static void delay_event_header(const MIDIEventList *list, MIDIEndpointRef endpoint) {
    unsigned char nibbles[36]; size_t used = 0; int started = 0;
    const MIDIEventPacket *p = &list->packet[0];
    for (UInt32 i = 0; i < list->numPackets; i++, p = MIDIEventPacketNext(p)) {
        if (p->wordCount > 1024) return;
        for (UInt32 j = 0; j + 1 < p->wordCount; ) {
            uint32_t a = p->words[j], b = p->words[j+1];
            if ((a >> 28) != 3) return;
            unsigned state = (a >> 20) & 15, count = (a >> 16) & 15;
            if (count > 6 || state > 3) return;
            if (state == 0 || state == 1) { used = 0; started = 1; }
            if (!started || used + count > sizeof(nibbles)) return;
            unsigned char bytes[6] = { a >> 8, a, b >> 24, b >> 16, b >> 8, b };
            memcpy(nibbles + used, bytes, count); used += count;
            if (state == 0 || state == 3) {
                delay_block_header(nibbles, used, endpoint); started = 0;
            }
            j += 2;
        }
    }
}
static OSStatus trace_send(MIDIPortRef port, MIDIEndpointRef endpoint,
                           const MIDIPacketList *list) {
    const MIDIPacket *before = &list->packet[0];
    for (UInt32 i = 0; i < list->numPackets; i++, before = MIDIPacketNext(before))
        delay_sysex_header(before->data, before->length, endpoint);
    OSStatus result = MIDISend(port, endpoint, list);
    const MIDIPacket *p = &list->packet[0];
    for (UInt32 i = 0; i < list->numPackets; i++) {
        log_packet("MIDISend", endpoint, p->data, p->length, result, 0);
        p = MIDIPacketNext(p);
    }
    return result;
}
static OSStatus trace_event_send(MIDIPortRef port, MIDIEndpointRef endpoint,
                                 const MIDIEventList *list) {
    if (getenv("GP5_HEADER_DELAY_MS")) delay_event_header(list, endpoint);
    /* Alternative CoreMIDI transport for complete group-zero SysEx7 only.
       Reassemble exactly the same bytes; other UMP messages use the original API. */
    if (getenv("GP5_LEGACY_MIDI")) {
        union { MIDIPacketList list; unsigned char storage[8192]; } legacy;
        MIDIPacket *tail = MIDIPacketListInit(&legacy.list);
        unsigned char bytes[4096]; size_t used = 0; int started = 0, valid = 1;
        const MIDIEventPacket *event = &list->packet[0];
        for (UInt32 i = 0; i < list->numPackets && valid;
             i++, event = MIDIEventPacketNext(event)) {
            if (event->wordCount > 1024 || event->wordCount % 2) { valid = 0; break; }
            for (UInt32 j = 0; j < event->wordCount; j += 2) {
                uint32_t a = event->words[j], b = event->words[j+1];
                unsigned state = (a >> 20) & 15, count = (a >> 16) & 15;
                if ((a >> 28) != 3 || ((a >> 24) & 15) != 0 ||
                    state > 3 || count > 6) { valid = 0; break; }
                if (state == 0 || state == 1) {
                    if (started) { valid = 0; break; }
                    used = 0; bytes[used++] = 0xf0; started = 1;
                }
                if (!started || used + count + 1 > sizeof(bytes)) { valid = 0; break; }
                unsigned char data[6] = { a >> 8, a, b >> 24, b >> 16, b >> 8, b };
                for (unsigned k = 0; k < count; k++) {
                    if (data[k] > 127) { valid = 0; break; }
                    bytes[used++] = data[k];
                }
                if (!valid) break;
                if (state == 0 || state == 3) {
                    bytes[used++] = 0xf7;
                    tail = MIDIPacketListAdd(&legacy.list, sizeof(legacy), tail,
                                             event->timeStamp, used, bytes);
                    if (!tail) { valid = 0; break; }
                    started = 0;
                }
            }
        }
        if (valid && !started && legacy.list.numPackets) {
            OSStatus result = MIDISend(port, endpoint, &legacy.list);
            const MIDIPacket *p = &legacy.list.packet[0];
            for (UInt32 i = 0; i < legacy.list.numPackets; i++, p = MIDIPacketNext(p))
                log_packet("legacy:MIDISend", endpoint, p->data, p->length, result, 0);
            return result;
        }
        /* No partial conversion is sent. */
    }
    OSStatus result = MIDISendEventList(port, endpoint, list);
    const MIDIEventPacket *p = &list->packet[0];
    for (UInt32 i = 0; i < list->numPackets; i++) {
        /* UMP words serialized in network order for offline SysEx7 decoding. */
        unsigned char data[4096];
        UInt32 count = p->wordCount > 1024 ? 1024 : p->wordCount;
        for (UInt32 j = 0; j < count; j++) {
            uint32_t word = p->words[j];
            data[4*j] = word >> 24; data[4*j+1] = word >> 16;
            data[4*j+2] = word >> 8; data[4*j+3] = word;
        }
        log_packet("MIDISendEventList", endpoint, data, count * 4, result, list->protocol);
        p = MIDIEventPacketNext(p);
    }
    return result;
}
static OSStatus trace_sysex(MIDISysexSendRequest *request) {
    /* Copy before call, as the asynchronous API may advance the request. */
    unsigned char data[4096];
    size_t length = request->bytesToSend;
    size_t kept = length > sizeof(data) ? sizeof(data) : length;
    MIDIEndpointRef endpoint = request->destination;
    memcpy(data, request->data, kept);
    delay_sysex_header(data, kept, endpoint);
    OSStatus result = MIDISendSysex(request);
    log_packet("MIDISendSysex", endpoint, data, length, result, 0);
    return result;
}
/* Dart FFI resolves these exports through dlsym. Wrap only inspected ABIs;
   the original functions receive unchanged arguments and return unchanged
   results. The capture launcher enables this only for known Suite 2.1.0. */
typedef int32_t (*PathCheckFn)(const char *);
typedef int32_t (*DevicePathFn)(void *, const char *);
typedef int32_t (*DeviceNamedPathFn)(void *, const char *, const char *);
typedef void *(*ConnectFn)(int32_t, int32_t, const char *, int64_t, int64_t, int64_t);
static PathCheckFn real_crc;
static DevicePathFn real_firmware, real_start;
static DeviceNamedPathFn real_named_firmware;
static ConnectFn real_connect;
typedef void (*DisconnectFn)(void *);
typedef int32_t (*ConnectedCheckFn)(void *);
static DisconnectFn real_disconnect;
static ConnectedCheckFn real_connected_check;
static void *active_device;
static pthread_mutex_t lifecycle_lock = PTHREAD_MUTEX_INITIALIZER;
typedef struct GP5DartObject GP5DartObject;
struct GP5DartObject {
    int32_t type;
    union {
        bool boolean;
        int32_t int32;
        int64_t int64;
        struct { intptr_t length; GP5DartObject **values; } array;
        unsigned char padding[40];
    } value;
};
typedef struct { const char *name; void *function; } GP5DartEntry;
typedef struct { int32_t major, minor; GP5DartEntry *functions; } GP5DartAPI;
typedef bool (*PostObjectFn)(int64_t, GP5DartObject *);
typedef intptr_t (*InitAPIFn)(void *);
static PostObjectFn real_post_object;
static InitAPIFn real_init_api;
static bool trace_post_object(int64_t port, GP5DartObject *object) {
    if (object && object->type == 6 && object->value.array.length >= 0 &&
        object->value.array.length <= 32) {
        char line[2048]; struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
        size_t length = (size_t)snprintf(line, sizeof(line),
            "{\"direction\":\"NATIVE\",\"api\":\"native:Dart_PostCObject\",\"pid\":%d,"
            "\"unix_time\":%lld.%09ld,\"native_port\":%lld,\"event\":[",
            (int)getpid(), (long long)ts.tv_sec, ts.tv_nsec, (long long)port);
        for (intptr_t i = 0; i < object->value.array.length; i++) {
            GP5DartObject *item = object->value.array.values[i];
            if (item && (item->type == 1 || item->type == 2 || item->type == 3)) {
                int64_t value = item->type == 3 ? item->value.int64 :
                                item->type == 2 ? item->value.int32 : item->value.boolean;
                length += (size_t)snprintf(line + length, sizeof(line) - length,
                                          "%s%lld", i ? "," : "", (long long)value);
            } else {
                length += (size_t)snprintf(line + length, sizeof(line) - length,
                                          "%snull", i ? "," : "");
            }
        }
        length += (size_t)snprintf(line + length, sizeof(line) - length, "]}\n");
        pthread_mutex_lock(&lock);
        const char *path = getenv("GP5_TX_LOG");
        if (path && captured < 2048) {
            captured++;
            int fd = open(path, O_WRONLY|O_CREAT|O_APPEND, 0600);
            if (fd >= 0) {
                size_t sent = 0;
                while (sent < length) {
                    ssize_t n = write(fd, line + sent, length - sent);
                    if (n <= 0) break;
                    sent += (size_t)n;
                }
                close(fd);
            }
        }
        pthread_mutex_unlock(&lock);
    }
    return real_post_object(port, object);
}
static intptr_t trace_init_api(void *data) {
    GP5DartAPI *api = (GP5DartAPI *)data;
    if (!api || api->major != 2 || !api->functions) return real_init_api(data);
    size_t count = 0;
    while (count < 1024 && api->functions[count].name) count++;
    if (count == 1024) return real_init_api(data);
    GP5DartEntry *entries = calloc(count + 1, sizeof(*entries));
    if (!entries) return real_init_api(data);
    memcpy(entries, api->functions, (count + 1) * sizeof(*entries));
    for (size_t i = 0; i < count; i++) {
        if (!strcmp(entries[i].name, "Dart_PostCObject") && entries[i].function) {
            real_post_object = (PostObjectFn)entries[i].function;
            entries[i].function = (void *)trace_post_object;
        }
    }
    GP5DartAPI copy = *api; copy.functions = entries;
    /* InitDartApiDL resolves these entries into globals during the call. */
    intptr_t result = real_init_api(&copy);
    free(entries);
    return result;
}
static void log_native(const char *api, const char *text, int result) {
    const char *safe = text ? text : "";
    log_packet(api, 0, (const unsigned char *)safe, strlen(safe), result, 0);
}
static int32_t trace_crc(const char *path) {
    int32_t result = real_crc(path);
    log_native("native:checkCrc", path, result);
    return result;
}
static int32_t trace_firmware(void *device, const char *path) {
    int32_t result = real_firmware(device, path);
    log_native("native:isRealFirmware", path, result);
    return result;
}
static int32_t trace_named_firmware(void *device, const char *path, const char *name) {
    int32_t result = real_named_firmware(device, path, name);
    log_native("native:isRealFirmwareWithDeviceName:name", name, result);
    log_native("native:isRealFirmwareWithDeviceName", path, result);
    return result;
}
static int32_t trace_start(void *device, const char *path) {
    int32_t result = real_start(device, path);
    log_native("native:deviceStartUpdate", path, result);
    return result;
}
static void *trace_connect(int32_t input, int32_t output, const char *name,
                           int64_t incoming, int64_t process, int64_t state) {
    pthread_mutex_lock(&lifecycle_lock);
    void *result = real_connect(input, output, name, incoming, process, state);
    active_device = result;
    pthread_mutex_unlock(&lifecycle_lock);
    log_native("native:connectDevice:name", name, result ? 0 : -1);
    return result;
}
static void trace_disconnect(void *device) {
    pthread_mutex_lock(&lifecycle_lock);
    if (active_device == device) active_device = NULL;
    real_disconnect(device);
    pthread_mutex_unlock(&lifecycle_lock);
    log_native("native:disConnectDevice", "", 0);
}
static int32_t trace_connected_check(void *device) {
    pthread_mutex_lock(&lifecycle_lock);
    /* Crash report: the Suite timer checks a disconnected HTDevice whose
       MIDI input at +0x128 is null. This export normally returns 0 on every
       path. Do not dereference objects already retired by disConnectDevice. */
    if (!device || device != active_device) {
        pthread_mutex_unlock(&lifecycle_lock);
        log_native("native:checkDeviceConnecting:retired_skipped", "", 0);
        return 0;
    }
    void *midi_input = NULL;
    memcpy(&midi_input, (const unsigned char *)device + 0x128, sizeof(midi_input));
    if (!midi_input) {
        pthread_mutex_unlock(&lifecycle_lock);
        log_native("native:checkDeviceConnecting:null_input_skipped", "", 0);
        return 0;
    }
    int32_t result = real_connected_check(device);
    pthread_mutex_unlock(&lifecycle_lock);
    return result;
}
static void *trace_dlsym(void *handle, const char *name) {
    void *result = dlsym(handle, name);
    if (!result || !getenv("GP5_TRACE_NATIVE") || !name) return result;
    if (!strcmp(name, "checkCrc")) {
        real_crc = (PathCheckFn)result; result = (void *)trace_crc;
    } else if (!strcmp(name, "isRealFirmware")) {
        real_firmware = (DevicePathFn)result; result = (void *)trace_firmware;
    } else if (!strcmp(name, "isRealFirmwareWithDeviceName")) {
        real_named_firmware = (DeviceNamedPathFn)result; result = (void *)trace_named_firmware;
    } else if (!strcmp(name, "deviceStartUpdate")) {
        real_start = (DevicePathFn)result; result = (void *)trace_start;
    } else if (!strcmp(name, "connectDevice")) {
        real_connect = (ConnectFn)result; result = (void *)trace_connect;
    } else if (!strcmp(name, "disConnectDevice")) {
        real_disconnect = (DisconnectFn)result; result = (void *)trace_disconnect;
    } else if (!strcmp(name, "checkDeviceConnecting")) {
        real_connected_check = (ConnectedCheckFn)result; result = (void *)trace_connected_check;
    } else if (!strcmp(name, "InitDartApiDL")) {
        real_init_api = (InitAPIFn)result; result = (void *)trace_init_api;
    } else return result;
    log_native("native:lookup", name, 0);
    return result;
}
#define INTERPOSE(replacement, original) \
    __attribute__((used)) static const struct { const void *new_fn; const void *old_fn; } \
    replace_##original __attribute__((section("__DATA,__interpose"))) = \
    { (const void *)(replacement), (const void *)(original) };
INTERPOSE(trace_send, MIDISend)
INTERPOSE(trace_event_send, MIDISendEventList)
INTERPOSE(trace_sysex, MIDISendSysex)
INTERPOSE(trace_dlsym, dlsym)
"""


def build_tx_trace(folder):
    source = folder / "gp5-midi-trace.c"
    output = folder / "gp5-midi-trace.dylib"
    source.write_text(TX_TRACE_SOURCE)
    command = ["/usr/bin/xcrun", "clang", "-dynamiclib", "-arch", "arm64",
               "-mmacosx-version-min=11.0", "-O2", "-framework", "CoreMIDI",
               "-Wno-deprecated-declarations", str(source), "-o", str(output)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=45)
    (folder / "trace-build.log").write_text(result.stdout + result.stderr)
    if result.returncode != 0:
        raise RuntimeError("Не удалось собрать MIDI-трассировщик. Нужны установленные Xcode Command Line Tools. Подробности в trace-build.log; запись не запускалась.")
    return output


def run_probe(args):
    require_mac()
    announce_version = getattr(args, "announce_version", None)
    if announce_version and not (args.enter_update or args.suite_handshake):
        raise RuntimeError("--announce-version требует --enter-update либо --suite-handshake.")
    header_delay = getattr(args, "header_delay_ms", 0)
    if not 0 <= header_delay <= 2000:
        raise RuntimeError("--header-delay-ms: допустимо 0..2000 миллисекунд.")
    if header_delay and args.command != "native-flash":
        raise RuntimeError("--header-delay-ms используется только с native-flash.")
    if args.command == "native-flash" and not (args.bootloader or args.enter_update):
        raise RuntimeError("Укажи --enter-update для перехода из рабочего режима либо --bootloader, если загрузчик включён вручную.")
    if getattr(args, "version_reject_ok", False):
        if args.command != "native-flash" or not announce_version:
            raise RuntimeError("--version-reject-ok только для native-flash вместе с --announce-version.")
    if getattr(args, "version_probe", False):
        if args.command != "native-probe":
            raise RuntimeError("--version-probe только для native-probe.")
        if announce_version or args.suite_handshake or header_delay or getattr(args, "legacy_midi", False):
            raise RuntimeError("--version-probe не сочетается с другими экспериментами.")
    info = firmware_info(args.firmware)
    announcement_info(info, announce_version)
    emit(info)
    if not info["valid"]:
        return 1
    _, metadata, _ = app_info(args.app)
    if subprocess.run(["/usr/bin/pgrep", "-x", metadata["CFBundleExecutable"]], capture_output=True).returncode == 0:
        raise RuntimeError("Закрой Valeton Suite перед нативной командой.")
    folder = output_dir(args.output)
    private_temp = folder / "native-temp"
    private_temp.mkdir()
    env = dict(os.environ, TMPDIR=str(private_temp) + "/")
    env.pop("GP5_HEADER_DELAY_MS", None)
    env.pop("GP5_LEGACY_MIDI", None)
    legacy_midi = getattr(args, "legacy_midi", False)
    if args.trace_midi or header_delay or legacy_midi:
        hook = build_tx_trace(folder)
        inherited = env.get("DYLD_INSERT_LIBRARIES")
        env["DYLD_INSERT_LIBRARIES"] = str(hook) + (":" + inherited if inherited else "")
        env["GP5_TX_LOG"] = str(folder / "midi-tx.jsonl")
        env["GP5_TX_REQUIRED"] = "1"
        if header_delay:
            env["GP5_HEADER_DELAY_MS"] = str(header_delay)
        if legacy_midi:
            env["GP5_LEGACY_MIDI"] = "1"
    command = [sys.executable, str(Path(__file__).resolve()), "--app", str(args.app),
               "_flash" if args.command == "native-flash" else "_probe",
               str(args.firmware.expanduser().resolve()), "--output", str(folder),
               "--seconds", str(args.seconds)]
    if args.suite_handshake:
        command.append("--suite-handshake")
    if args.enter_update:
        command.append("--enter-update")
    if getattr(args, "bootloader", False):
        command.append("--bootloader")
    if getattr(args, "version_probe", False):
        command.append("--version-probe")
        if args.probe_strings:
            command += ["--probe-strings", args.probe_strings]
    if getattr(args, "version_reject_ok", False):
        command.append("--version-reject-ok")
    if announce_version:
        command += ["--announce-version", announce_version]
    print(f"GP-5 diagnostics {DIAG_VERSION}\nЛоги: {folder}", flush=True)
    if header_delay:
        print(f"Эксперимент: пауза {header_delay} мс перед каждым заголовком блока 0x61; содержимое пакетов и обработка отказа не изменяются.", flush=True)
    if legacy_midi:
        print("Эксперимент: полные SysEx7 передаются через MIDISend вместо MIDISendEventList, с сохранением байтов и timestamp.", flush=True)
    if announce_version:
        print(f"Эксперимент: в 0x69 объявляется {announce_version}; файл остаётся {info.get('version_tag')} без изменений SHA-256 и CRC из-за подмены объявляемой версии.", flush=True)
    # Separate process contains ctypes crashes; tee both diagnostics and
    # library output into the bundle. Only native-flash starts firmware writing.
    with (folder / "console.log").open("wb") as f:
        child = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while True:
            try:
                for line in child.stdout:
                    f.write(line)
                    f.flush()
                    print(line.decode("utf-8", "replace"), end="", flush=True)
                code = child.wait()
                break
            except KeyboardInterrupt:
                if args.command == "native-flash":
                    print("Передача продолжается. Ctrl+C не прерывает запись; дождись результата.", flush=True)
                    continue
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                code = child.returncode
                break
    (folder / "result.json").write_text(json.dumps({"exit_code": code, "firmware": info,
        "header_delay_ms": header_delay, "legacy_midi": legacy_midi,
        "announced_version": announce_version or info.get("version_tag")}, ensure_ascii=False, indent=2))
    archive = shutil.make_archive(str(folder), "zip", root_dir=folder)
    print(f"Готово: {archive}", flush=True)
    return 0 if code == 0 else 1


class MidiPorts:
    """CoreMIDI enumeration and optional passive input; never sends messages."""
    def __init__(self):
        require_mac()
        self.midi = C.CDLL("/System/Library/Frameworks/CoreMIDI.framework/CoreMIDI")
        self.cf = C.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        for name in ("MIDIGetNumberOfSources", "MIDIGetNumberOfDestinations"):
            function = getattr(self.midi, name)
            function.argtypes, function.restype = [], C.c_ulong
        for name in ("MIDIGetSource", "MIDIGetDestination"):
            function = getattr(self.midi, name)
            function.argtypes, function.restype = [C.c_ulong], C.c_uint32
        self.midi.MIDIObjectGetStringProperty.argtypes = [C.c_uint32, C.c_void_p, C.POINTER(C.c_void_p)]
        self.midi.MIDIObjectGetStringProperty.restype = C.c_int32
        self.cf.CFStringGetLength.argtypes, self.cf.CFStringGetLength.restype = [C.c_void_p], C.c_long
        self.cf.CFStringGetCString.argtypes = [C.c_void_p, C.c_void_p, C.c_long, C.c_uint32]
        self.cf.CFStringGetCString.restype = C.c_bool
        self.cf.CFRelease.argtypes, self.cf.CFRelease.restype = [C.c_void_p], None
        self.cf.CFRunLoopRunInMode.argtypes = [C.c_void_p, C.c_double, C.c_bool]
        self.cf.CFRunLoopRunInMode.restype = C.c_int32
        self.run_mode = C.c_void_p.in_dll(self.cf, "kCFRunLoopDefaultMode")
        self.packets = queue.Queue(maxsize=4096)
        self.dropped_packets = 0
        notify_type = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p)
        @notify_type
        def notify(message, _context):
            if message:
                try:
                    self.packets.put_nowait({"midi_notification": C.c_uint32.from_address(message).value,
                                            "time": dt.datetime.now().astimezone().isoformat()})
                except queue.Full:
                    self.dropped_packets += 1
        self.notify_callback = notify
        self.name_properties = [(name, C.c_void_p.in_dll(self.midi, name).value)
                                for name in ("kMIDIPropertyDisplayName", "kMIDIPropertyName")]
        self.cf.CFStringCreateWithCString.argtypes = [C.c_void_p, C.c_char_p, C.c_uint32]
        self.cf.CFStringCreateWithCString.restype = C.c_void_p
        self.midi.MIDIClientCreate.argtypes = [C.c_void_p, notify_type, C.c_void_p, C.POINTER(C.c_uint32)]
        self.midi.MIDIClientCreate.restype = C.c_int32
        self.midi.MIDIClientDispose.argtypes = [C.c_uint32]
        self.midi.MIDIClientDispose.restype = C.c_int32
        self.client = C.c_uint32()
        name = self.cf.CFStringCreateWithCString(None, b"GP5 Diagnostics", 0x08000100)
        try:
            status = self.midi.MIDIClientCreate(name, self.notify_callback, None, C.byref(self.client))
        finally:
            self.cf.CFRelease(name)
        if status:
            raise RuntimeError(f"MIDIClientCreate: {status}")
        self.port = C.c_uint32()
        self.connected_sources = set()
        self.read_callback = None
        self.pump(0.05)

    def pump(self, seconds):
        # CoreMIDI notifications run on the thread that created the client.
        # A sleeping capture loop leaves its endpoint inventory stale after
        # the pedal re-enumerates when entering the bootloader.
        self.cf.CFRunLoopRunInMode(self.run_mode, seconds, False)

    def start_receiving(self):
        callback_type = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p, C.c_void_p)
        align_packets = platform.machine().lower() in ("arm64", "aarch64")

        @callback_type
        def receive(packet_list, _context, source_context):
            # Apple MIDIServices.h: #pragma pack(4); packet offset=4,
            # timestamp offset=0, length offset=8, data offset=10.
            # MIDIPacketNext aligns to four bytes on ARM only.
            try:
                count = C.c_uint32.from_address(packet_list).value
                if count > 4096:
                    return
                address = packet_list + 4
                for _ in range(count):
                    timestamp = C.c_uint64.from_address(address).value
                    length = C.c_uint16.from_address(address + 8).value
                    payload = C.string_at(address + 10, length)
                    event = {"time": dt.datetime.now().astimezone().isoformat(),
                             "direction": "RX", "endpoint": source_context,
                             "host_timestamp": timestamp, "length": length,
                             "hex": payload.hex(" "),
                             "ascii": "".join(chr(v) if 32 <= v < 127 else "." for v in payload)}
                    try:
                        self.packets.put_nowait(event)
                    except queue.Full:
                        self.dropped_packets += 1
                    address += 10 + length
                    if align_packets:
                        address = (address + 3) & ~3
            except Exception as error:
                try:
                    self.packets.put_nowait({"raw_midi_error": str(error)})
                except queue.Full:
                    self.dropped_packets += 1

        self.read_callback = receive
        self.midi.MIDIInputPortCreate.argtypes = [C.c_uint32, C.c_void_p, callback_type,
                                                C.c_void_p, C.POINTER(C.c_uint32)]
        self.midi.MIDIInputPortCreate.restype = C.c_int32
        self.midi.MIDIPortConnectSource.argtypes = [C.c_uint32, C.c_uint32, C.c_void_p]
        self.midi.MIDIPortConnectSource.restype = C.c_int32
        self.midi.MIDIPortDisconnectSource.argtypes = [C.c_uint32, C.c_uint32]
        self.midi.MIDIPortDisconnectSource.restype = C.c_int32
        self.midi.MIDIPortDispose.argtypes = [C.c_uint32]
        self.midi.MIDIPortDispose.restype = C.c_int32
        name = self.cf.CFStringCreateWithCString(None, b"GP5 Passive RX", 0x08000100)
        try:
            status = self.midi.MIDIInputPortCreate(self.client, name, self.read_callback,
                                                 None, C.byref(self.port))
        finally:
            self.cf.CFRelease(name)
        if status:
            raise RuntimeError(f"MIDIInputPortCreate: {status}")

    def sync_receivers(self, ports):
        sources = [p for p in ports if p["direction"] == "source"]
        chosen = [p for p in sources if any(label in (p["name"] or "").lower()
                                            for label in ("gp-5", "gp5", "valeton", "hotone"))]
        if not chosen and len(sources) == 1:
            chosen = sources
        wanted = {p["endpoint"] for p in chosen}
        events = []
        for endpoint in self.connected_sources - wanted:
            status = self.midi.MIDIPortDisconnectSource(self.port, endpoint)
            events.append({"passive_disconnect": endpoint, "status": status})
            self.connected_sources.discard(endpoint)
        for endpoint in wanted - self.connected_sources:
            status = self.midi.MIDIPortConnectSource(self.port, endpoint, C.c_void_p(endpoint))
            events.append({"passive_connect": endpoint, "status": status})
            if status == 0:
                self.connected_sources.add(endpoint)
        if not wanted:
            events.append({"passive_rx": "Нет однозначного источника GP-5 для записи."})
        return events

    def drain(self):
        result = []
        while True:
            try:
                result.append(self.packets.get_nowait())
            except queue.Empty:
                return result

    def close(self):
        if self.port.value:
            self.midi.MIDIPortDispose(self.port)
            self.port.value = 0
        if self.client.value:
            self.midi.MIDIClientDispose(self.client)
            self.client.value = 0

    def snapshot(self):
        results = []
        for direction, count_name, getter_name in (
            ("source", "MIDIGetNumberOfSources", "MIDIGetSource"),
            ("destination", "MIDIGetNumberOfDestinations", "MIDIGetDestination"),
        ):
            for index in range(getattr(self.midi, count_name)()):
                endpoint = getattr(self.midi, getter_name)(index)
                name = None
                statuses = {}
                for property_name, property_value in self.name_properties:
                    text = C.c_void_p()
                    status = self.midi.MIDIObjectGetStringProperty(endpoint, property_value, C.byref(text))
                    statuses[property_name] = status
                    if status == 0 and text.value:
                        try:
                            buffer = C.create_string_buffer(self.cf.CFStringGetLength(text) * 4 + 1)
                            if self.cf.CFStringGetCString(text, buffer, len(buffer), 0x08000100):
                                name = buffer.value.decode("utf-8", "replace")
                        finally:
                            self.cf.CFRelease(text)
                    if name:
                        break
                results.append({"direction": direction, "index": index, "endpoint": endpoint,
                                "name": name, "name_status": statuses})
        return results


def log_candidates():
    roots = [Path(tempfile.gettempdir()), Path(os.environ.get("TMPDIR", "/tmp")),
             Path("/tmp"), Path("/private/tmp")]
    paths = [root / "HTCache/logfile.txt" for root in roots]
    # Candidate Dart log paths; existence is checked, never assumed.
    paths += [Path.home() / "Documents/midi_debug.log"]
    seen = set()
    for path in paths:
        path = path.resolve()
        if path not in seen:
            seen.add(path)
            yield path


def collect_logs(folder, prefix="current"):
    entries = []
    for index, path in enumerate(log_candidates()):
        try:
            if path.is_file():
                destination = folder / f"{prefix}-{index}-{path.name}"
                shutil.copy2(path, destination)
                entries.append({"source": str(path), "copy": destination.name, "size": destination.stat().st_size})
        except OSError as error:
            entries.append({"source": str(path), "error": str(error)})
    return entries


def output_dir(value=None):
    path = (value or Path.cwd() / ("gp5-diag-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f"))).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=False)
    return path


def capture(args):
    require_mac()
    if args.diagnostic_copy and not args.trace_midi:
        raise RuntimeError("--diagnostic-copy используется вместе с --trace-midi.")
    app, metadata, libpath = app_info(args.app)
    info = firmware_info(args.firmware)
    emit(info)
    if not info["valid"]:
        return 1
    executable = app / "Contents/MacOS" / metadata["CFBundleExecutable"]
    running = subprocess.run(["/usr/bin/pgrep", "-x", metadata["CFBundleExecutable"]], capture_output=True)
    if running.returncode == 0:
        raise RuntimeError("Сначала закрой Valeton Suite обычным способом, затем повтори capture.")
    folder = output_dir(args.output)
    env = dict(os.environ, NSUnbufferedIO="YES")
    diagnostic_app = None
    if args.trace_midi:
        hook = build_tx_trace(folder)
        inherited = env.get("DYLD_INSERT_LIBRARIES")
        env["DYLD_INSERT_LIBRARIES"] = str(hook) + (":" + inherited if inherited else "")
        env["GP5_TX_LOG"] = str(folder / "midi-tx.jsonl")
    if args.trace_midi and hashlib.sha256(libpath.read_bytes()).hexdigest() == next(iter(LIB_HASHES)):
        env["GP5_TRACE_NATIVE"] = "1"
    if args.diagnostic_copy:
        # Only this temporary copy is re-signed. Hardened Runtime in the
        # official binary suppresses DYLD injection; App Sandbox also restricts
        # writing the external trace. Keep OS security settings untouched.
        copy_root = Path(tempfile.mkdtemp(prefix="gp5-suite-trace-"))
        diagnostic_app = copy_root / app.name
        print(f"Создаю диагностическую копию Suite: {diagnostic_app}", flush=True)
        shutil.copytree(app, diagnostic_app, symlinks=True)
        entitlements = folder / "diagnostic-entitlements.plist"
        entitlements.write_bytes(plistlib.dumps({"com.apple.security.cs.allow-jit": True}))
        sign = subprocess.run(["/usr/bin/codesign", "--force", "--deep", "--sign", "-",
                               "--options", "0", "--entitlements", str(entitlements),
                               str(diagnostic_app)], capture_output=True, text=True, timeout=90)
        (folder / "diagnostic-codesign.log").write_text(sign.stdout + sign.stderr)
        if sign.returncode != 0:
            raise RuntimeError("Не удалось подписать диагностическую копию. Смотри diagnostic-codesign.log; приложение не запускалось.")
        verify = subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict",
                                 str(diagnostic_app)], capture_output=True, text=True, timeout=30)
        with (folder / "diagnostic-codesign.log").open("a") as f:
            f.write(verify.stdout + verify.stderr)
        if verify.returncode != 0:
            raise RuntimeError("Подпись диагностической копии не прошла проверку; приложение не запускалось.")
        executable = diagnostic_app / "Contents/MacOS" / metadata["CFBundleExecutable"]
    bundle = {"diagnostics_version": DIAG_VERSION,
              "started": dt.datetime.now().astimezone().isoformat(), "platform": platform.platform(),
              "python": sys.version, "app": str(app), "suite_version": metadata.get("CFBundleShortVersionString"),
              "library_sha256": hashlib.sha256(libpath.read_bytes()).hexdigest(), "firmware": info,
              "logs_before": collect_logs(folder, "before"),
              "diagnostic_app_copy": str(diagnostic_app) if diagnostic_app else None}
    (folder / "metadata.json").write_text(json.dumps(bundle, ensure_ascii=False, indent=2))
    def record_raw(events):
        if not events:
            return
        with (folder / "midi-raw.jsonl").open("a", encoding="utf-8") as f:
            for event in events:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
                if event.get("direction") == "RX":
                    print(f"MIDI RX [{event['endpoint']}] {event['hex'][:600]}", flush=True)
                else:
                    emit(event)

    midi = None
    raw_enabled = False
    print(f"GP-5 diagnostics {DIAG_VERSION}", flush=True)
    try:
        midi = MidiPorts()
    except (OSError, AttributeError, RuntimeError) as error:
        (folder / "midi-error.txt").write_text(str(error))
    if midi:
        try:
            midi.start_receiving()
            raw_enabled = True
            record_raw(midi.sync_receivers(midi.snapshot()))
        except (OSError, AttributeError, RuntimeError) as error:
            (folder / "midi-raw-error.txt").write_text(str(error))
            print(f"Пассивная запись MIDI недоступна: {error}", flush=True)
    transcript = (folder / "console.log").open("wb")
    app_process = subprocess.Popen([str(executable)], cwd=str(folder), env=env,
                                   stdout=transcript, stderr=subprocess.STDOUT,
                                   start_new_session=True)
    # Child retains its own file descriptor after collection ends. A pipe
    # would risk SIGPIPE in the still-running app when this script exits.
    transcript.close()
    console_reader = (folder / "console.log").open("rb")
    console_decoder = codecs.getincrementaldecoder("utf-8")("replace")
    log_file = (folder / "macos-unified.log").open("w")
    log_process = None
    try:
        log_process = subprocess.Popen(["/usr/bin/log", "stream", "--style", "compact", "--level", "debug",
                                        "--predicate", f"processIdentifier == {app_process.pid}"],
                                       stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True)
    except OSError as error:
        log_file.write(str(error))

    print(f"Логи: {folder}\nПовтори ошибку в открывшемся Valeton Suite.\n"
          "После завершения или отказа обновления нажми Ctrl+C здесь. Приложение останется открытым.", flush=True)
    previous = None
    trace_checked = not args.trace_midi
    trace_check_after = time.monotonic() + 2.0
    try:
        while True:
            if not trace_checked and time.monotonic() >= trace_check_after:
                trace_checked = True
                trace_path = folder / "midi-tx.jsonl"
                records = []
                if trace_path.is_file():
                    for line in trace_path.read_text().splitlines():
                        try:
                            records.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
                loaded = any(r.get("api") == "hook_loaded" and r.get("pid") == app_process.pid for r in records)
                bundle["suite_tx_hook_loaded"] = loaded
                print("Трассировщик TX загружен в Valeton Suite." if loaded else
                      "Трассировщик TX не загрузился в Valeton Suite. RX и обычные логи продолжают собираться; причина запуска будет в console.log.", flush=True)
            text = console_decoder.decode(console_reader.read())
            if text:
                print(text, end="", flush=True)
            if midi:
                try:
                    current = midi.snapshot()
                    if raw_enabled:
                        if current != previous:
                            record_raw(midi.sync_receivers(current))
                        record_raw(midi.drain())
                    if current != previous:
                        entry = {"time": dt.datetime.now().astimezone().isoformat(), "ports": current}
                        with (folder / "midi-ports.jsonl").open("a") as f:
                            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                        emit(entry)
                        previous = current
                except (OSError, RuntimeError) as error:
                    (folder / "midi-error.txt").write_text(str(error))
                    midi.close()
                    midi = None
            collect_logs(folder)
            if app_process.poll() is not None:
                print(console_decoder.decode(console_reader.read(), final=True), end="", flush=True)
                print(f"Valeton Suite завершился: {app_process.returncode}")
                break
            if midi:
                midi.pump(0.75)
            else:
                time.sleep(0.75)
    except KeyboardInterrupt:
        print("\nСбор остановлен. Valeton Suite не закрыт.")
    finally:
        if midi:
            midi.close()
            record_raw(midi.drain())
            bundle["raw_midi_dropped_packets"] = midi.dropped_packets
        bundle["passive_raw_midi_enabled"] = raw_enabled
        bundle["logs_after"] = collect_logs(folder, "after")
        bundle["app_pid"] = app_process.pid
        bundle["app_exit_code"] = app_process.poll()
        bundle["ended"] = dt.datetime.now().astimezone().isoformat()
        if log_process and log_process.poll() is None:
            log_process.terminate()
            try:
                log_process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                log_process.kill()
                log_process.wait(timeout=3)
        log_file.close()
        console_reader.close()
        (folder / "metadata.json").write_text(json.dumps(bundle, ensure_ascii=False, indent=2))
    archive = shutil.make_archive(str(folder), "zip", root_dir=folder)
    print(f"Готово: {archive}", flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--app", type=Path, default=DEFAULT_APP)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "native-crc", "capture"):
        command = sub.add_parser(name)
        command.add_argument("firmware", type=Path)
        if name == "capture":
            command.add_argument("--output", type=Path)
            command.add_argument("--trace-midi", action="store_true",
                                 help="Записать исходящие MIDI-пакеты Valeton Suite; требует Xcode Command Line Tools")
            command.add_argument("--diagnostic-copy", action="store_true",
                                 help="Для TX-трассы создать временную копию Suite с ad-hoc подписью без Hardened Runtime и App Sandbox; исходное приложение не изменяется")
    for name in ("native-probe", "_probe", "native-flash", "_flash"):
        probe = sub.add_parser(name)
        probe.add_argument("firmware", type=Path)
        probe.add_argument("--output", type=Path)
        probe.add_argument("--seconds", type=float, default=15.0)
        mode = probe.add_mutually_exclusive_group()
        mode.add_argument("--bootloader", action="store_true",
                           help="GP-5 уже вручную загружена в режим обновления")
        mode.add_argument("--enter-update", action="store_true",
                          help="Перейти из рабочего режима командой 0x6f, дождаться новых USB-портов и повторить запросы Suite 0x30/0x69")
        probe.add_argument("--trace-midi", action="store_true",
                           help="Записать исходящие CoreMIDI-пакеты; требует Xcode Command Line Tools")
        probe.add_argument("--header-delay-ms", type=int, default=0,
                           help="Эксперимент для native-flash: пауза 0..2000 мс перед каждым 0x61, включая повторы; автоматически включает TX-трассу")
        probe.add_argument("--legacy-midi", action="store_true",
                           help="Эксперимент: отправлять те же SysEx7 через MIDISend вместо UMP API; автоматически включает TX-трассу")
        probe.add_argument("--announce-version",
                           help="Эксперимент: заменить только тег версии в команде 0x69 (например V107); файл прошивки не меняется, нужен --enter-update или --suite-handshake")
        probe.add_argument("--version-probe", action="store_true",
                           help="Только native-probe: отправить 0x30 и серию 0x69 с разными строками версии и записать ACK; 0x60/0x61 и запись не выполняются. Без --enter-update/--bootloader проба идёт в рабочем режиме")
        probe.add_argument("--probe-strings",
                           help="Для --version-probe: свой список строк через запятую, например V110,V200")
        probe.add_argument("--version-reject-ok", action="store_true",
                           help="Только native-flash с --announce-version: как Suite 2.1.0, продолжать лишь после 10 отказов на 0x69 (статус 3)")
        probe.add_argument("--suite-handshake", action="store_true",
                           help="Эксперимент: перед передачей повторить запросы Suite 0x30 и 0x69 в уже включённом загрузчике")
    sub.add_parser("ports")
    scan = sub.add_parser("native-scan")
    scan.add_argument("--name", default="GP-5", help="Точное имя MIDI-порта из ports; сравнение без учёта регистра")
    sub.add_parser("logs")
    worker = sub.add_parser("_native", help="Внутренний изолированный процесс нативных вызовов")
    worker.add_argument("--mode", choices=("crc", "scan"), required=True)
    worker.add_argument("--firmware", type=Path)
    worker.add_argument("--name", default="GP-5")
    args = parser.parse_args()
    try:
        if args.command == "check":
            info = firmware_info(args.firmware)
            emit(info)
            return 0 if info["valid"] else 1
        if args.command in ("native-crc", "native-scan"):
            return run_native(args)
        if args.command in ("native-probe", "_probe", "native-flash", "_flash"):
            if not 1 <= args.seconds <= 60:
                raise RuntimeError("--seconds должен быть от 1 до 60.")
            if args.command in ("_probe", "_flash"):
                return native_probe_worker(args)
            return run_probe(args)
        if args.command == "ports":
            midi = MidiPorts()
            try:
                emit(midi.snapshot())
            finally:
                midi.close()
            return 0
        if args.command == "logs":
            require_mac()
            found = False
            for path in log_candidates():
                if path.is_file():
                    found = True
                    print(f"\n=== {path} ===")
                    # Read just the tail, not potentially huge historic logs.
                    with path.open("rb") as f:
                        f.seek(max(0, path.stat().st_size - 128 * 1024))
                        lines = f.read().decode("utf-8", "replace").splitlines()
                    print("\n".join(lines[-100:]))
            if not found:
                print("Файл лога пока не найден. Запусти capture и повтори ошибку.")
            return 0
        if args.command == "_native":
            return native_worker(args.app, args.mode, args.firmware, args.name)
        return capture(args)
    except (OSError, RuntimeError, ValueError, KeyError, AttributeError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

