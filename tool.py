#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import array
import binascii
import ctypes
import datetime
import json
import logging
import mmap
import os
import struct
import subprocess
import sys
import time
from binascii import hexlify
from ctypes import c_void_p, c_int
from dataclasses import dataclass
from enum import IntEnum
from io import BytesIO
from pathlib import Path
from struct import unpack
from typing import Optional

import usb.backend.libusb0
import usb.backend.libusb1
import usb.core
import usb.util


_IS_WINDOWS = sys.platform.startswith("win")
_IS_MACOS = sys.platform == "darwin"
_IS_LINUX = sys.platform.startswith("linux")

if _IS_WINDOWS:
    try:
        import ctypes.wintypes as _wt
        _WINTYPES_OK = True
    except Exception:
        _wt = None
        _WINTYPES_OK = False
else:
    _wt = None
    _WINTYPES_OK = False


_DEFAULT_DUMP_CHUNK = 128 if _IS_WINDOWS else 256
_DEFAULT_READ_DELAY = 0.02 if _IS_WINDOWS else 0.0

_CREATE_NO_WINDOW = 0x08000000

_USBSTOR_REG_PATH = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
_USBSTOR_REG_VALUE = "Start"

_state_dir_env = os.environ.get("TEMP") or os.environ.get("TMP") or "C:\\Windows\\Temp"
_GUARD_DIR = Path(_state_dir_env) / "kyocera_edl_guard"
_GUARD_STATE = _GUARD_DIR / "state.json"
_GUARD_PID = _GUARD_DIR / "guard.pid"
_GUARD_LOG = _GUARD_DIR / "guard.log"

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_OPEN_EXISTING = 3

_IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
_IOCTL_DISK_SET_DISK_ATTRIBUTES = 0x0007C0F0

_STORAGE_DEVICE_PROPERTY = 0
_PROPERTY_STANDARD_QUERY = 0
_BUS_TYPE_USB = 7

_DISK_ATTRIBUTE_OFFLINE = 0x00000001


_kernel32 = None
_ctypes_ready = False


if _IS_WINDOWS and _WINTYPES_OK:
    try:
        _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        class _STORAGE_PROPERTY_QUERY(ctypes.Structure):
            _fields_ = [
                ("PropertyId", _wt.DWORD),
                ("QueryType", _wt.DWORD),
                ("AdditionalParameters", ctypes.c_ubyte * 1),
            ]

        class _STORAGE_DEVICE_DESCRIPTOR(ctypes.Structure):
            _fields_ = [
                ("Version", _wt.DWORD),
                ("Size", _wt.DWORD),
                ("DeviceType", ctypes.c_ubyte),
                ("DeviceTypeModifier", ctypes.c_ubyte),
                ("RemovableMedia", ctypes.c_ubyte),
                ("CommandQueueing", ctypes.c_ubyte),
                ("VendorIdOffset", _wt.DWORD),
                ("ProductIdOffset", _wt.DWORD),
                ("ProductRevisionOffset", _wt.DWORD),
                ("SerialNumberOffset", _wt.DWORD),
                ("BusType", _wt.DWORD),
                ("RawPropertiesLength", _wt.DWORD),
                ("RawDeviceProperties", ctypes.c_ubyte * 1),
            ]

        class _SET_DISK_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("Version", _wt.DWORD),
                ("Persist", ctypes.c_ubyte),
                ("Reserved1", ctypes.c_ubyte * 3),
                ("Attributes", _wt.DWORD),
                ("AttributesMask", _wt.DWORD),
                ("Reserved2", _wt.DWORD * 4),
            ]

        _kernel32.CreateFileW.restype = _wt.HANDLE
        _kernel32.CreateFileW.argtypes = [
            _wt.LPCWSTR,
            _wt.DWORD,
            _wt.DWORD,
            _wt.LPVOID,
            _wt.DWORD,
            _wt.DWORD,
            _wt.HANDLE,
        ]
        _kernel32.DeviceIoControl.restype = _wt.BOOL
        _kernel32.DeviceIoControl.argtypes = [
            _wt.HANDLE,
            _wt.DWORD,
            _wt.LPVOID,
            _wt.DWORD,
            _wt.LPVOID,
            _wt.DWORD,
            ctypes.POINTER(_wt.DWORD),
            _wt.LPVOID,
        ]
        _kernel32.CloseHandle.restype = _wt.BOOL
        _kernel32.CloseHandle.argtypes = [_wt.HANDLE]

        _ctypes_ready = True
    except Exception:
        _ctypes_ready = False


def _ensure_guard_dir():
    try:
        _GUARD_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def _setup_logging(to_file=False):
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    root.addHandler(sh)
    if to_file:
        try:
            _ensure_guard_dir()
            fh = logging.FileHandler(_GUARD_LOG, mode="a", encoding="utf-8")
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except Exception:
            pass
    root.setLevel(logging.INFO)


def _is_admin():
    if not _IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _is_valid_handle(h):
    if h is None:
        return False
    try:
        v = int(h)
    except (ValueError, TypeError):
        return False
    if v in (0, -1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
        return False
    return True


def _open_physical_drive(n, write):
    path = f"\\\\.\\PhysicalDrive{n}"
    access = _GENERIC_READ | (_GENERIC_WRITE if write else 0)
    try:
        h = _kernel32.CreateFileW(
            path,
            access,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            None,
            _OPEN_EXISTING,
            0,
            None,
        )
    except Exception:
        return None
    if not _is_valid_handle(h):
        return None
    return h


def _close_handle(h):
    if h is None:
        return
    try:
        _kernel32.CloseHandle(h)
    except Exception:
        pass


def _query_bus_type(n):
    h = _open_physical_drive(n, write=False)
    if h is None:
        return None
    try:
        q = _STORAGE_PROPERTY_QUERY()
        q.PropertyId = _STORAGE_DEVICE_PROPERTY
        q.QueryType = _PROPERTY_STANDARD_QUERY

        buf_size = 1024
        buf = ctypes.create_string_buffer(buf_size)
        br = _wt.DWORD(0)

        ok = _kernel32.DeviceIoControl(
            h,
            _IOCTL_STORAGE_QUERY_PROPERTY,
            ctypes.byref(q),
            ctypes.sizeof(q),
            buf,
            buf_size,
            ctypes.byref(br),
            None,
        )
        if not ok:
            return None

        desc = ctypes.cast(buf, ctypes.POINTER(_STORAGE_DEVICE_DESCRIPTOR)).contents
        return int(desc.BusType)
    except Exception:
        return None
    finally:
        _close_handle(h)


def _set_disk_offline(n):
    h = _open_physical_drive(n, write=True)
    if h is None:
        return False
    try:
        sda = _SET_DISK_ATTRIBUTES()
        sda.Version = ctypes.sizeof(_SET_DISK_ATTRIBUTES)
        sda.Persist = 0
        sda.Attributes = _DISK_ATTRIBUTE_OFFLINE
        sda.AttributesMask = _DISK_ATTRIBUTE_OFFLINE
        br = _wt.DWORD(0)

        ok = _kernel32.DeviceIoControl(
            h,
            _IOCTL_DISK_SET_DISK_ATTRIBUTES,
            ctypes.byref(sda),
            ctypes.sizeof(sda),
            None,
            0,
            ctypes.byref(br),
            None,
        )
        return bool(ok)
    except Exception:
        return False
    finally:
        _close_handle(h)


def _force_offline_all_usb_disks():
    if not _IS_WINDOWS or not _ctypes_ready:
        return 0
    offline_count = 0
    for n in range(32):
        bt = _query_bus_type(n)
        if bt is None:
            continue
        if bt != _BUS_TYPE_USB:
            continue
        if _set_disk_offline(n):
            offline_count += 1
    return offline_count


def _process_alive(pid):
    if not pid or pid <= 0:
        return False
    if not _IS_WINDOWS:
        try:
            os.kill(int(pid), 0)
            return True
        except OSError:
            return False
    try:
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not h:
            return False
        try:
            code = ctypes.c_ulong()
            if kernel32.GetExitCodeProcess(h, ctypes.byref(code)):
                return code.value == STILL_ACTIVE
            return False
        finally:
            kernel32.CloseHandle(h)
    except Exception:
        return False


def _guard_read_pid():
    try:
        return int(_GUARD_PID.read_text().strip())
    except Exception:
        return None


def _guard_write_pid(pid):
    _ensure_guard_dir()
    try:
        _GUARD_PID.write_text(str(pid))
    except Exception:
        pass


def _guard_clear_pid():
    try:
        _GUARD_PID.unlink()
    except Exception:
        pass


def _guard_is_running():
    pid = _guard_read_pid()
    if pid is None:
        return False
    if _process_alive(pid):
        return True
    _guard_clear_pid()
    return False


def _guard_save_state(state):
    _ensure_guard_dir()
    try:
        _GUARD_STATE.write_text(json.dumps(state, indent=2))
    except Exception:
        pass


def _guard_load_state():
    try:
        return json.loads(_GUARD_STATE.read_text())
    except Exception:
        return {}


def _guard_clear_state():
    try:
        _GUARD_STATE.unlink()
    except Exception:
        pass


def _reg_read_usbstor_start():
    if not _IS_WINDOWS:
        return None
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _USBSTOR_REG_PATH) as k:
            v, _ = winreg.QueryValueEx(k, _USBSTOR_REG_VALUE)
            return int(v)
    except Exception:
        return None


def _reg_write_usbstor_start(value):
    if not _IS_WINDOWS:
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _USBSTOR_REG_PATH, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, _USBSTOR_REG_VALUE, 0, winreg.REG_DWORD, int(value))
        return True
    except Exception as e:
        logger.error(f"USBSTOR レジストリ書き込み失敗: {e}")
        return False


def _guard_apply_usbstor_disable():
    state = _guard_load_state()
    if "usbstor_original_start" not in state:
        orig = _reg_read_usbstor_start()
        state["usbstor_original_start"] = orig if orig is not None else 3
        _guard_save_state(state)
    ok = _reg_write_usbstor_start(4)
    if ok:
        logger.info("USBSTOR を無効化したよ (Start=4)")
    else:
        logger.error("USBSTOR の無効化に失敗したよ")
    return ok


def _guard_restore_usbstor():
    state = _guard_load_state()
    orig = state.get("usbstor_original_start")
    if orig is None:
        orig = 3
    ok = _reg_write_usbstor_start(int(orig))
    if ok:
        logger.info(f"USBSTOR を Start={orig} に戻したよ")
    else:
        logger.error("USBSTOR の復元に失敗したよ")
    return ok


def _kill_tree(pid):
    if not pid:
        return
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/F", "/T"],
            capture_output=True, timeout=8,
            creationflags=_CREATE_NO_WINDOW,
        )
    except Exception:
        pass


def _guard_worker_main():
    _setup_logging(to_file=True)
    _guard_write_pid(os.getpid())
    logger.info("=== MountGuard worker 開始 ===")

    if not _is_admin():
        logger.error("管理者権限が無いよ。worker を終了するね。")
        _guard_clear_pid()
        return 1

    if not _ctypes_ready:
        logger.error("ctypes の初期化に失敗したよ。worker を終了するね。")
        _guard_clear_pid()
        return 1

    logger.info("USBSTOR 無効化中…")
    _guard_apply_usbstor_disable()

    logger.info("USB ディスク監視ループ開始 (200ms間隔、純Python + ctypes)")

    error_count = 0
    silent_cycles = 0
    try:
        while True:
            try:
                count = _force_offline_all_usb_disks()
                if count > 0:
                    if silent_cycles > 20:
                        logger.info(f"USB ディスク {count} 台を offline にしたよ")
                    silent_cycles = 0
                else:
                    silent_cycles += 1
                    if silent_cycles == 200:
                        logger.info("USB ディスクはまだ見つかってないよ。監視は続けるね")
                        silent_cycles = 0
            except Exception as e:
                error_count += 1
                if error_count <= 3:
                    logger.error(f"offline ループ内エラー: {e}")
            time.sleep(0.2)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt で終了")
    finally:
        logger.info("MountGuard worker 終了")
        _guard_clear_pid()
    return 0


def _spawn_guard_elevated():
    if not _IS_WINDOWS:
        return False
    script = os.path.abspath(sys.argv[0])
    params = subprocess.list2cmdline([script, "--internal-guard-worker"])
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        return int(ret) > 32
    except Exception as e:
        logger.error(f"昇格起動失敗: {e}")
        return False


def spawn_guard():
    if not _IS_WINDOWS:
        return False
    if _guard_is_running():
        return True
    logger.info("MountGuard を昇格起動するよ。UAC を承認してね…")
    if not _spawn_guard_elevated():
        logger.error("MountGuard の昇格起動に失敗したよ")
        return False
    for _ in range(20):
        time.sleep(0.5)
        if _guard_is_running():
            logger.info(f"MountGuard 起動完了 (PID {_guard_read_pid()})")
            return True
    logger.error("MountGuard が起動しなかったよ。ログを見てね: " + str(_GUARD_LOG))
    return False


def stop_guard():
    if not _IS_WINDOWS:
        print("MountGuard: Windows 専用だよ")
        return
    if not _is_admin():
        print("MountGuard: 管理者権限が必要だよ。UAC を承認してね…")
        script = os.path.abspath(sys.argv[0])
        params = subprocess.list2cmdline([script, "guard-stop"])
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
        except Exception as e:
            print(f"昇格起動失敗: {e}")
        return

    _setup_logging(to_file=True)
    pid = _guard_read_pid()
    if not pid:
        print("MountGuard: 動作していないみたい")
        _guard_restore_usbstor()
        _guard_clear_state()
        return
    if not _process_alive(pid):
        print(f"MountGuard: PID {pid} は既に終了してるよ")
        _guard_clear_pid()
        _guard_restore_usbstor()
        _guard_clear_state()
        return
    print(f"MountGuard: PID {pid} を停止するね…")
    _kill_tree(pid)
    time.sleep(0.8)
    if _process_alive(pid):
        print(f"MountGuard: PID {pid} を停止できなかったよ")
        return
    _guard_clear_pid()
    print(f"MountGuard: PID {pid} を停止したよ")
    _guard_restore_usbstor()
    _guard_clear_state()
    print("MountGuard: USBSTOR を元に戻したよ")


def guard_status():
    if not _IS_WINDOWS:
        print("MountGuard: Windows 専用だよ")
        return
    pid = _guard_read_pid()
    if pid and _process_alive(pid):
        print(f"MountGuard: 動作中 (PID {pid})")
    else:
        print("MountGuard: 停止中")
        if pid:
            print(f"  (古いPIDファイル: {pid})")
    cur = _reg_read_usbstor_start()
    print(f"  USBSTOR 現在の Start: {cur}")
    st = _guard_load_state()
    orig = st.get("usbstor_original_start")
    if orig is not None:
        print(f"  USBSTOR 元の Start: {orig}")
    print(f"  ctypes 準備状態: {'OK' if _ctypes_ready else 'NG'}")
    print(f"  ログ: {_GUARD_LOG}")


def _find_libusb():
    if _IS_WINDOWS:
        name = "libusb-1.0.dll"
    elif _IS_MACOS:
        name = "libusb-1.0.dylib"
    else:
        name = "libusb-1.0.so"
    try:
        script_dir = Path(__file__).resolve().parent
        local = script_dir / name
        if local.exists():
            return str(local)
    except Exception:
        pass
    return name


ErrorDesc = {
    0x00: "Invalid command received in current state",
    0x01: "Protocol mismatch between host and target",
    0x02: "Invalid target protocol version",
    0x03: "Invalid host protocol version",
    0x04: "Invalid packet size received",
    0x05: "Unexpected image ID received",
    0x06: "Invalid image header size received",
    0x07: "Invalid image data size received",
    0x08: "Invalid image type received",
    0x09: "Invalid tranmission length",
    0x0A: "Invalid reception length",
    0x0B: "General transmission or reception error",
    0x0C: "Error while transmitting READ_DATA packet",
    0x0D: "Cannot receive specified number of program headers",
    0x0E: "Invalid data length received for program headers",
    0x0F: "Multiple shared segments found in ELF image",
    0x10: "Uninitialized program header location",
    0x11: "Invalid destination address",
    0x12: "Invalid data size received in image header",
    0x13: "Invalid ELF header received",
    0x14: "Unknown host error received in HELLO_RESP",
    0x15: "Timeout while receiving data",
    0x16: "Timeout while transmitting data",
    0x17: "Invalid mode received from host",
    0x18: "Invalid memory read access",
    0x19: "Host cannot handle read data size requested",
    0x1A: "Memory debug not supported",
    0x1B: "Invalid mode switch",
    0x1C: "Failed to execute command",
    0x1D: "Invalid parameter passed to command execution",
    0x1E: "Unsupported client command received",
    0x1F: "Invalid client command received for data response",
    0x20: "Failed to authenticate hash table",
    0x21: "Failed to verify hash for a given segment of ELF image",
    0x22: "Failed to find hash table in ELF image",
    0x23: "Target failed to initialize",
    0x24: "Failed to authenticate generic image",
    0x25: "Invalid ELF hash table size.  Too bit or small.",
    0x26: "Invalid IMG Hash Table Size",
    0x27: "Enumeration failed",
    0x28: "Hardware Bulk transfer error"
}


class SaharaCmd(IntEnum):
    HELLO_REQ = 0x1
    HELLO_RSP = 0x2
    READ_DATA = 0x3
    END_TRANSFER = 0x4
    DONE_REQ = 0x5
    DONE_RSP = 0x6
    RESET_REQ = 0x7
    RESET_RSP = 0x8
    MEMORY_DEBUG = 0x9
    MEMORY_READ = 0xA
    CMD_READY = 0xB
    SWITCH_MODE = 0xC
    EXECUTE_REQ = 0xD
    EXECUTE_RSP = 0xE
    EXECUTE_DATA = 0xF
    MEMORY_DEBUG_64BIT = 0x10
    MEMORY_READ_64BIT = 0x11
    MEMORY_READ_DATA_64BIT = 0x12
    RESET_STATE_MACHINE_ID = 0x13


class SaharaExecCmd(IntEnum):
    SERIAL_NUM_READ = 0x01


class SaharaMode(IntEnum):
    IMAGE_TX_PENDING = 0x0
    IMAGE_TX_COMPLETE = 0x1
    MEMORY_DEBUG = 0x2
    COMMAND = 0x3


@dataclass
class CmdHeader:
    cmd: SaharaCmd
    len: int


@dataclass
class SaharaPacket:
    cmd: SaharaCmd
    len: int

    def __repr__(self):
        return f"SAHARA_UNKNOWN_PKT(cmd={self.cmd}, len={self.len}"

    def __str__(self):
        return self.__repr__()


@dataclass
class HelloRequest(SaharaPacket):
    version: int
    version_supported: int
    cmd_packet_length: int
    mode: SaharaMode
    reserved1: int
    reserved2: int
    reserved3: int
    reserved4: int
    reserved5: int
    reserved6: int

    def __repr__(self):
        return (f"SAHARA_HELLO_REQ(cmd={self.cmd}, "
                f"len={self.len}, version={self.version}, "
                f"version_supported={self.version_supported}, "
                f"cmd_packet_length={self.cmd_packet_length}, "
                f"mode={self.mode})")


@dataclass
class ExecuteResponse(SaharaPacket):
    client_cmd: int
    data_len: int


@dataclass
class ImageEnd(SaharaPacket):
    image_id: int
    image_tx_status: int


def write_object(definition, *args):
    obj = {}
    object_size = 0
    data = b""
    i = 0
    for (name, stype) in definition:
        object_size += struct.calcsize(stype)
        arg = args[i]
        try:
            data += struct.pack(stype, arg)
        except Exception as e:
            print("Error:" + str(e))
            break
        i += 1
    obj['object_size'] = len(data)
    obj['raw_data'] = data
    return obj


class structhelper_io:
    pos = 0

    def __init__(self, data: BytesIO = None, direction='little'):
        self.data = data
        self.direction = direction

    def setdata(self, data, offset=0):
        self.pos = offset
        self.data = data

    def qword(self):
        return int.from_bytes(self.data.read(8), self.direction)

    def dword(self):
        return int.from_bytes(self.data.read(4), self.direction)

    def dwords(self, dwords=1):
        return [int.from_bytes(self.data.read(4), self.direction) for _ in range(dwords)]

    def short(self):
        return int.from_bytes(self.data.read(2), self.direction)

    def shorts(self, shorts):
        return [int.from_bytes(self.data.read(2), self.direction) for _ in range(shorts)]

    def bytes(self, rlen=1):
        dat = self.data.read(rlen)
        if dat == b'':
            return dat
        if rlen == 1:
            return dat[0]
        return dat

    def string(self, rlen=1):
        return self.data.read(rlen)

    def getpos(self):
        return self.data.tell()

    def seek(self, pos):
        self.data.seek(pos)


logger = logging.getLogger('kedl_tool')


class DeviceClass:

    def __init__(self, portconfig=None, devclass=-1):
        self.connected = False
        self.timeout = 1000
        self.maxsize = 512
        self.vid = None
        self.pid = None
        self.stopbits = None
        self.databits = None
        self.parity = None
        self.baudrate = None
        self.configuration = None
        self.device = None
        self.devclass = -1
        self.xmlread = True
        self.portconfig = portconfig

    def connect(self, options):
        raise NotImplementedError()

    def close(self, reset=False):
        raise NotImplementedError()

    def flush(self):
        raise NotImplementedError()

    def detectdevices(self):
        raise NotImplementedError()

    def getInterfaceCount(self):
        raise NotImplementedError()

    def setLineCoding(self, baudrate=None, parity=0, databits=8, stopbits=1):
        raise NotImplementedError()

    def setbreak(self):
        raise NotImplementedError()

    def setcontrollinestate(self, RTS=None, DTR=None, isFTDI=False):
        raise NotImplementedError()

    def write(self, command, pktsize=None):
        raise NotImplementedError()

    def usbwrite(self, data, pktsize=None):
        raise NotImplementedError()

    def usbread(self, resplen=None, timeout=0):
        raise NotImplementedError()

    def ctrl_transfer(self, bmRequestType, bRequest, wValue, wIndex, data_or_wLength):
        raise NotImplementedError()

    def usbreadwrite(self, data, resplen):
        raise NotImplementedError()

    def read(self, length=None, timeout=-1):
        if timeout == -1:
            timeout = self.timeout
        if length is None:
            length = self.maxsize
        return self.usbread(length, timeout)

    def rdword(self, count=1, little=False):
        rev = "<" if little else ">"
        value = self.usbread(4 * count)
        data = unpack(rev + "I" * count, value)
        if count == 1:
            return data[0]
        return data

    def rword(self, count=1, little=False):
        rev = "<" if little else ">"
        data = []
        for _ in range(count):
            v = self.usbread(2)
            if len(v) == 0:
                return data
            data.append(unpack(rev + "H", v)[0])
        if count == 1:
            return data[0]
        return data

    def rbyte(self, count=1):
        return self.usbread(count)

    def verify_data(self, data, pre="RX:"):
        if isinstance(data, bytes) or isinstance(data, bytearray):
            if data[:5] == b"<?xml":
                try:
                    rdata = b""
                    for line in data.split(b"\n"):
                        try:
                            rdata += line + b"\n"
                        except Exception:
                            v = hexlify(line)
                            logger.debug(pre + v.decode('utf-8'))
                    return rdata
                except Exception as err:
                    logger.debug(str(err))
        return data


MAX_PACKET_LEN = 4096

crcTbl = (
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78)


def serial16le(data):
    out = bytearray()
    out.append(data & 0xFF)
    out.append((data >> 8) & 0xFF)
    return out


def serial16(data):
    out = bytearray()
    out.append((data >> 8) & 0xFF)
    out.append(data & 0xFF)
    return out


def serial32le(data):
    out = bytearray()
    out += serial16le(data & 0xFFFF)
    out += serial16le((data >> 16) & 0xFFFF)
    return out


def crc16(iv, data):
    for byte in data:
        iv = ((iv >> 8) & 0xFFFF) ^ crcTbl[(iv ^ byte) & 0xFF]
    return ~iv & 0xFFFF


def serial32(data):
    out = bytearray()
    out += serial16((data >> 16) & 0xFFFF)
    out += serial16(data & 0xFFFF)
    return out


def escape(indata):
    outdata = bytearray()
    for i in range(0, len(indata)):
        buf = indata[i]
        if buf == 0x7e:
            outdata.append(0x7d)
            outdata.append(0x5e)
        elif buf == 0x7d:
            outdata.append(0x7d)
            outdata.append(0x5d)
        else:
            outdata.append(buf)
    return outdata


def unescape(indata):
    mescape = False
    out = bytearray()
    for buf in indata:
        if mescape:
            if buf == 0x5e:
                out.append(0x7e)
            elif buf == 0x5d:
                out.append(0x7d)
            else:
                logging.error("Fatal error unescaping buffer!")
                return None
            mescape = False
        else:
            if buf == 0x7d:
                mescape = True
            else:
                out.append(buf)
    if len(out) == 0:
        return None
    return out


def convert_cmdbuf(indata):
    crc16val = crc16(0xFFFF, indata)
    indata.extend(bytearray(serial16le(crc16val)))
    outdata = escape(indata)
    outdata.append(0x7E)
    return outdata


class hdlc:
    def __init__(self, cdc):
        self.cdc = cdc
        self.timeout = 1500

    def receive_reply(self, timeout=None):
        replybuf = bytearray()
        if timeout is None:
            timeout = self.timeout
        tmp = self.cdc.read(timeout=timeout)
        if tmp == bytearray():
            return b""
        if tmp == b"":
            return b""
        retry = 0
        while tmp[-1] != 0x7E:
            time.sleep(0.01)
            tmp += self.cdc.read(timeout=timeout)
            retry += 1
            if retry > 5:
                break
        replybuf.extend(tmp)
        data = unescape(replybuf)
        if len(data) > 3:
            if data[0] == 0x7E:
                data = data[1:]
            crc16val = crc16(0xFFFF, data[:-3])
            reccrc = int(data[-3]) + (int(data[-2]) << 8)
            if crc16val != reccrc:
                return -1
        else:
            time.sleep(0.01)
            data = self.cdc.read(timeout=timeout)
            if len(data) > 3:
                crc16val = crc16(0xFFFF, data[:-3])
                reccrc = int(data[-3]) + (int(data[-2]) << 8)
                if crc16val != reccrc:
                    return -1
                return data
        return data[:-3]

    def receive_reply_nocrc(self, timeout=None):
        replybuf = bytearray()
        if timeout is None:
            timeout = self.timeout
        tmp = self.cdc.read(timeout=timeout)
        if tmp == bytearray():
            return b""
        if tmp == b"":
            return b""
        retry = 0
        while tmp[-1] != 0x7E:
            tmp += self.cdc.read(timeout=timeout)
            retry += 1
            if retry > 5:
                break
        replybuf.extend(tmp)
        data = unescape(replybuf)
        if len(data) > 3:
            return data[:-3]
        else:
            time.sleep(0.5)
            data = self.cdc.read(timeout=timeout)
            if len(data) > 3:
                return data[:-3]
            else:
                return data

    def send_unframed_buf(self, outdata, prefixflag):
        if prefixflag:
            tmp = bytearray()
            tmp.append(0x7E)
            tmp.extend(outdata)
            outdata = tmp
        return self.cdc.write(outdata[:MAX_PACKET_LEN])

    def send_cmd_base(self, outdata, prefixflag, nocrc=False):
        if isinstance(outdata, str):
            outdata = bytes(outdata, 'utf-8')
        packet = convert_cmdbuf(bytearray(outdata))
        self.cdc.flush()
        if self.send_unframed_buf(packet, prefixflag):
            if nocrc:
                return self.receive_reply_nocrc()
            else:
                return self.receive_reply()
        return b""

    def send_cmd(self, outdata, nocrc=False):
        return self.send_cmd_base(outdata, 1, nocrc)

    def send_cmd_np(self, outdata, nocrc=False):
        return self.send_cmd_base(outdata, 0, nocrc)

    def show_errpacket(self, descr, pktbuf):
        if len(pktbuf) == 0:
            return
        logging.error("Error: %s " % descr)
        if pktbuf[1] == 0x0e:
            pktbuf[-4] = 0
            ret = self.receive_reply()
            errorcode = unpack("<I", ret[2:2 + 4])
            logging.error("Error code = %08x\n\n", errorcode)


USB_DIR_OUT = 0
USB_DIR_IN = 0x80

USB_TYPE_MASK = (0x03 << 5)
USB_TYPE_STANDARD = (0x00 << 5)
USB_TYPE_CLASS = (0x01 << 5)
USB_TYPE_VENDOR = (0x02 << 5)
USB_TYPE_RESERVED = (0x03 << 5)

USB_RECIP_MASK = 0x1f
USB_RECIP_DEVICE = 0x00
USB_RECIP_INTERFACE = 0x01
USB_RECIP_ENDPOINT = 0x02
USB_RECIP_OTHER = 0x03
USB_RECIP_PORT = 0x04
USB_RECIP_RPIPE = 0x05

MAX_USB_BULK_BUFFER_SIZE = 16384

CDC_CMDS = {
    "SEND_ENCAPSULATED_COMMAND": 0x00,
    "GET_ENCAPSULATED_RESPONSE": 0x01,
    "SET_COMM_FEATURE": 0x02,
    "GET_COMM_FEATURE": 0x03,
    "CLEAR_COMM_FEATURE": 0x04,
    "SET_LINE_CODING": 0x20,
    "GET_LINE_CODING": 0x21,
    "SET_CONTROL_LINE_STATE": 0x22,
    "SEND_BREAK": 0x23,
}


class usb_class(DeviceClass):

    def __init__(self, portconfig=None, devclass=-1, serial_number=None):
        super().__init__(portconfig, devclass)
        self.serial_number = serial_number
        self.EP_IN = None
        self.EP_OUT = None
        self.is_serial = False
        self.buffer = array.array('B', [0]) * 1048576
        self.claimed_interfaces = []
        self.backend = usb.backend.libusb1.get_backend(find_library=lambda x: _find_libusb())
        if self.backend is not None:
            try:
                self.backend.lib.libusb_set_option.argtypes = [c_void_p, c_int]
                self.backend.lib.libusb_set_option(self.backend.ctx, 1)
            except Exception:
                self.backend = None

    def getInterfaceCount(self):
        if self.vid is not None:
            self.device = usb.core.find(idVendor=self.vid, idProduct=self.pid, backend=self.backend)
            if self.device is None:
                logger.debug("デバイスが見つからないよ。接続されてる？")
                return False
            try:
                self.device.set_configuration()
            except Exception as err:
                logger.debug(str(err))
            self.configuration = self.device.get_active_configuration()
            logger.debug(2, self.configuration)
            return self.configuration.bNumInterfaces
        else:
            logger.error("デバイス未検出。接続されてる？")
        return 0

    def setLineCoding(self, baudrate=None, parity=0, databits=8, stopbits=1):
        sbits = {1: 0, 1.5: 1, 2: 2}
        dbits = {5, 6, 7, 8, 16}
        pmodes = {0, 1, 2, 3, 4}
        brates = {300, 600, 1200, 2400, 4800, 9600, 14400,
                  19200, 28800, 38400, 57600, 115200, 230400}

        if stopbits is not None:
            if stopbits not in sbits.keys():
                valid = ", ".join(str(k) for k in sorted(sbits.keys()))
                raise ValueError("Valid stopbits are " + valid)
            self.stopbits = stopbits
        else:
            self.stopbits = 0

        if databits is not None:
            if databits not in dbits:
                valid = ", ".join(str(d) for d in sorted(dbits))
                raise ValueError("Valid databits are " + valid)
            self.databits = databits
        else:
            self.databits = 0

        if parity is not None:
            if parity not in pmodes:
                valid = ", ".join(str(pm) for pm in sorted(pmodes))
                raise ValueError("Valid parity modes are " + valid)
            self.parity = parity
        else:
            self.parity = 0

        if baudrate is not None:
            if baudrate not in brates:
                brs = sorted(brates)
                dif = [abs(br - baudrate) for br in brs]
                best = brs[dif.index(min(dif))]
                raise ValueError("Invalid baudrates, nearest valid is {}".format(best))
            self.baudrate = baudrate

        linecode = [
            self.baudrate & 0xff,
            (self.baudrate >> 8) & 0xff,
            (self.baudrate >> 16) & 0xff,
            (self.baudrate >> 24) & 0xff,
            sbits[self.stopbits],
            self.parity,
            self.databits]

        txdir = 0
        req_type = 1
        recipient = 1
        req_type = (txdir << 7) + (req_type << 5) + recipient
        data = bytearray(linecode)
        wlen = self.device.ctrl_transfer(
            req_type, CDC_CMDS["SET_LINE_CODING"],
            data_or_wLength=data, wIndex=1)
        logger.debug("Linecoding set, {}b sent".format(wlen))

    def setbreak(self):
        txdir = 0
        req_type = 1
        recipient = 1
        req_type = (txdir << 7) + (req_type << 5) + recipient
        wlen = self.device.ctrl_transfer(
            bmRequestType=req_type, bRequest=CDC_CMDS["SEND_BREAK"],
            wValue=0, data_or_wLength=0, wIndex=1)
        logger.debug("Break set, {}b sent".format(wlen))

    def setcontrollinestate(self, RTS=None, DTR=None, isFTDI=False):
        ctrlstate = (2 if RTS else 0) + (1 if DTR else 0)
        if isFTDI:
            ctrlstate += (1 << 8) if DTR is not None else 0
            ctrlstate += (2 << 8) if RTS is not None else 0
        txdir = 0
        req_type = 2 if isFTDI else 1
        recipient = 0 if isFTDI else 1
        req_type = (txdir << 7) + (req_type << 5) + recipient

        wlen = self.device.ctrl_transfer(
            bmRequestType=req_type,
            bRequest=1 if isFTDI else CDC_CMDS["SET_CONTROL_LINE_STATE"],
            wValue=ctrlstate,
            wIndex=1,
            data_or_wLength=0)
        logger.debug("Linecoding set, {}b sent".format(wlen))

    def flush(self):
        return

    def connect(self, EP_IN=-1, EP_OUT=-1, portname: str = ""):
        if self.connected:
            self.close()
            self.connected = False
        self.device = None
        self.EP_OUT = None
        self.EP_IN = None
        self.claimed_interfaces = []
        devices = usb.core.find(find_all=True, backend=self.backend)
        for dev in devices:
            for usbid in self.portconfig:
                if dev.idProduct == usbid[1] and dev.idVendor == usbid[0]:
                    if self.serial_number is not None:
                        if dev.serial_number != self.serial_number:
                            continue
                    self.device = dev
                    self.vid = dev.idVendor
                    self.pid = dev.idProduct
                    self.serial_number = dev.serial_number
                    self.interface = usbid[2]
                    break
            if self.device is not None:
                break

        if self.device is None:
            logger.debug("デバイスが見つからないよ。接続されてる？")
            return False

        try:
            self.configuration = self.device.get_active_configuration()
        except usb.core.USBError as e:
            if e.strerror == "Configuration not set":
                self.device.set_configuration()
                self.configuration = self.device.get_active_configuration()
            if e.errno == 13:
                logger.error("Permission denied accessing {:04x}:{:04x}.".format(self.vid, self.pid))
                logger.info("udevルールを追加すると直るかも: sudo echo 'SUBSYSTEM==\"usb\",ATTRS{{idVendor}}==\"{:04x}\",ATTRS{{idProduct}}==\"{:04x}\",MODE=\"0666\"' >> /etc/udev/rules.d/99-edl.rules".format(self.vid, self.pid))
                self.backend = usb.backend.libusb0.get_backend()
                self.device = usb.core.find(idVendor=self.vid, idProduct=self.pid, backend=self.backend)
        if self.configuration is None:
            logger.error("デバイス構成を取得できなかったよ。")
            return False
        if self.interface > self.configuration.bNumInterfaces:
            print("インターフェース番号が変だよ、最大は %d だよ" % self.configuration.bNumInterfaces)
            return False
        for itf in self.configuration:
            if self.devclass == -1 or self.devclass == 0xFF:
                self.devclass = 0x02
            if itf.bInterfaceClass == self.devclass:
                if self.interface == -1 or self.interface == itf.bInterfaceNumber:
                    self.interface = itf
                    self.EP_OUT = EP_OUT
                    self.EP_IN = EP_IN
                    for ep in itf:
                        edir = usb.util.endpoint_direction(ep.bEndpointAddress)
                        if (edir == usb.util.ENDPOINT_OUT and EP_OUT == -1) or ep.bEndpointAddress == (EP_OUT & 0xF):
                            self.EP_OUT = ep
                        elif (edir == usb.util.ENDPOINT_IN and EP_IN == -1) or ep.bEndpointAddress == (EP_OUT & 0xF):
                            self.EP_IN = ep
                    break

        if self.EP_OUT is not None and self.EP_IN is not None:
            self.maxsize = self.EP_IN.wMaxPacketSize

            if _IS_WINDOWS:
                for itf in self.configuration:
                    ifnum = itf.bInterfaceNumber
                    try:
                        if self.device.is_kernel_driver_active(ifnum):
                            logger.debug(f"Interface {ifnum} のカーネルドライバをデタッチするね")
                            self.device.detach_kernel_driver(ifnum)
                    except Exception as err:
                        logger.debug(f"Interface {ifnum} detach 失敗: {err}")
                    try:
                        usb.util.claim_interface(self.device, ifnum)
                        self.claimed_interfaces.append(ifnum)
                        logger.debug(f"Interface {ifnum} を claim したよ")
                    except Exception as err:
                        logger.debug(f"Interface {ifnum} claim 失敗: {err}")
            else:
                try:
                    if self.device.is_kernel_driver_active(0):
                        logger.debug("カーネルドライバをデタッチするね")
                        self.device.detach_kernel_driver(0)
                except Exception as err:
                    logger.debug("カーネルドライバ対応してないみたい: " + str(err))

                try:
                    usb.util.claim_interface(self.device, 0)
                except Exception:
                    pass

            self.connected = True
            return True
        print("CDCインターフェース見つからなかったよ。ごめんね。")
        self.connected = False
        return False

    def close(self, reset=False):
        if self.connected:
            try:
                if reset:
                    self.device.reset()
            except Exception as err:
                logger.debug(str(err))

            if _IS_WINDOWS:
                try:
                    for ifnum in list(self.claimed_interfaces):
                        try:
                            usb.util.release_interface(self.device, ifnum)
                            logger.debug(f"Interface {ifnum} を release したよ")
                        except Exception as err:
                            logger.debug(f"Interface {ifnum} release 失敗: {err}")
                        try:
                            if not self.device.is_kernel_driver_active(ifnum):
                                self.device.attach_kernel_driver(ifnum)
                                logger.debug(f"Interface {ifnum} にカーネルドライバを戻したよ")
                        except Exception:
                            pass
                except Exception as err:
                    logger.debug(str(err))
                self.claimed_interfaces = []
            else:
                try:
                    if not self.device.is_kernel_driver_active(self.interface):
                        self.device.attach_kernel_driver(0)
                except Exception as err:
                    logger.debug(str(err))

            try:
                usb.util.dispose_resources(self.device)
            except Exception:
                pass

            try:
                del self.device
            except Exception:
                pass

            if reset:
                time.sleep(2)
            self.connected = False

    def write(self, command, pktsize=None):
        if pktsize is None:
            pktsize = MAX_USB_BULK_BUFFER_SIZE
        if isinstance(command, str):
            command = bytes(command, 'utf-8')
        pos = 0
        if command == b'':
            try:
                self.EP_OUT.write(b'')
            except usb.core.USBError as err:
                error = str(err.strerror)
                if "timeout" in error:
                    try:
                        self.EP_OUT.write(b'')
                    except Exception as err:
                        logger.debug(str(err))
                        return False
                return True
        else:
            i = 0
            while pos < len(command):
                try:
                    ctr = self.EP_OUT.write(command[pos:pos + pktsize])
                    if ctr <= 0:
                        logger.info(ctr)
                    pos += ctr
                except Exception as err:
                    logger.debug(str(err))
                    i += 1
                    if i == 3:
                        return False
        self.verify_data(bytearray(command), "TX:")
        return True

    def usbread(self, resplen=None, timeout=0) -> bytes:
        if timeout == 0:
            timeout = 1
        if resplen is None:
            resplen = self.maxsize
        if resplen <= 0:
            logger.info("Warning !")
        res = bytearray()
        buffer = self.buffer[:resplen]
        epr = self.EP_IN.read
        extend = res.extend
        while len(res) < resplen:
            try:
                resplen = epr(buffer, timeout)
                extend(buffer[:resplen])
                if resplen == self.EP_IN.wMaxPacketSize:
                    break
            except usb.core.USBError as e:
                if _IS_WINDOWS:
                    errno_val = getattr(e, 'errno', None)
                    try:
                        errstr = str(e.strerror) if e.strerror else ""
                    except Exception:
                        errstr = ""
                    if errno_val == 19 or "No such device" in errstr or "disconnected" in errstr.lower():
                        logger.error(f"USBデバイスが切断されたよ: {e}")
                        self.connected = False
                        return b""
                    if "timed out" in errstr or errno_val == 110:
                        if timeout is None:
                            return b""
                        if timeout == 10:
                            return b""
                        timeout += 1
                    elif "Overflow" in errstr or errno_val == 75:
                        logger.error("USB Overflow")
                        return b""
                    else:
                        logger.info(repr(e))
                        return b""
                else:
                    error = str(e.strerror)
                    if "timed out" in error:
                        if timeout is None:
                            return b""
                        if timeout == 10:
                            return b""
                        timeout += 1
                    elif "Overflow" in error:
                        logger.error("USB Overflow")
                        return b""
                    else:
                        logger.info(repr(e))
                        return b""

        return res[:resplen]

    def ctrl_transfer(self, bmRequestType, bRequest, wValue, wIndex, data_or_wLength):
        ret = self.device.ctrl_transfer(bmRequestType=bmRequestType, bRequest=bRequest, wValue=wValue, wIndex=wIndex,
                                        data_or_wLength=data_or_wLength)
        return ret[0] | (ret[1] << 8)

    class deviceclass:
        vid = 0
        pid = 0

        def __init__(self, vid, pid):
            self.vid = vid
            self.pid = pid

    def detectdevices(self):
        dev = usb.core.find(find_all=True, backend=self.backend)
        ids = [self.deviceclass(cfg.idVendor, cfg.idProduct) for cfg in dev]
        return ids

    def usbwrite(self, data, pktsize=None):
        if pktsize is None:
            pktsize = len(data)
        return self.write(data, pktsize)

    def usbreadwrite(self, data, resplen):
        self.usbwrite(data)
        res = self.usbread(resplen)
        return res


class DataError(Exception):
    ...


class CommandHandler:

    @staticmethod
    def parse_hello_req(data):
        if len(data) < 0xC * 0x4:
            raise DataError
        st = structhelper_io(BytesIO(data))
        return HelloRequest(
            cmd=SaharaCmd(st.dword()),
            len=st.dword(),
            version=st.dword(),
            version_supported=st.dword(),
            cmd_packet_length=st.dword(),
            mode=st.dword(),
            reserved1=st.dword(),
            reserved2=st.dword(),
            reserved3=st.dword(),
            reserved4=st.dword(),
            reserved5=st.dword(),
            reserved6=st.dword(),
        )

    @staticmethod
    def parse_execute_rsp(data):
        if len(data) < 0x4 * 0x4:
            raise DataError
        st = structhelper_io(BytesIO(data))
        return ExecuteResponse(
            cmd=SaharaCmd(st.dword()),
            len=st.dword(),
            client_cmd=st.dword(),
            data_len=st.dword(),
        )

    @staticmethod
    def parse_image_end(data):
        if len(data) < 0x4 * 0x4:
            raise DataError
        st = structhelper_io(BytesIO(data))
        return ImageEnd(
            cmd=SaharaCmd(st.dword()),
            len=st.dword(),
            image_id=st.dword(),
            image_tx_status=st.dword(),
        )

    def parse_pkt(self, data):
        if len(data) < 2 * 4:
            raise DataError
        st = structhelper_io(BytesIO(data))
        cmd = SaharaCmd(st.dword())
        if cmd == SaharaCmd.HELLO_REQ:
            return self.parse_hello_req(data)
        if cmd == SaharaCmd.EXECUTE_RSP:
            return self.parse_execute_rsp(data)
        if cmd == SaharaCmd.END_TRANSFER:
            return self.parse_image_end(data)
        return CmdHeader(cmd=cmd, len=st.dword())


class Sahara:

    def __init__(self, cdc) -> None:
        self._cdc = cdc
        self._ch = CommandHandler()
        self._version = 2
        self._pkt_size = None
        self._serial = None

    def connect(self) -> bool:
        v = self._cdc.read(length=0xC * 0x4, timeout=1)
        if len(v) > 1:
            pkt = self._ch.parse_pkt(v)
            if pkt.cmd == SaharaCmd.HELLO_REQ:
                self._pkt_size = pkt.cmd_packet_length
                self._version = pkt.version
                logger.debug(f"RX: {pkt}")
                if self.cmd_info(self._version):
                    logger.info(f'シリアル番号: {self._serial}')
                    return True
                return False
            else:
                logger.info(f"接続時にサポートしてないパケット来たよ: {pkt}")
                return False
        else:
            logger.info(f"接続時のデータが足りないよ: {v}")
            return False

    def disconnect(self) -> None:
        if self.cmd_reset():
            logger.info('Saharaをリセットしたよ、お疲れさま〜')
        else:
            logger.info('Saharaのリセットに失敗しちゃった')

    def cmd_hello(self, mode: SaharaMode, version_min: int = 1, max_cmd_len: int = 0, version: int = 2):
        cmd = SaharaCmd.HELLO_RSP
        length = 0x30
        payload = struct.pack("<IIIIIIIIIIII", cmd, length, version, version_min, max_cmd_len, mode, 1, 2, 3, 4, 5, 6)
        try:
            self._cdc.write(payload)
        except Exception as e:
            logger.error(str(e))
            return False
        return True

    def cmd_reset(self):
        try:
            self._cdc.write(struct.pack("<II", SaharaCmd.RESET_REQ, 0x8))
            logger.info("リセットコマンド送ったよ。デバイスが再起動するよ〜")
            time.sleep(0.1)
            return True
        except Exception as e:
            logger.debug(f"リセットでUSBが切れたよ（想定通り）: {e}")
            return True

    def get_rsp(self):
        try:
            data = self._cdc.read()
            if data == b'':
                return None
            return self._ch.parse_pkt(data)
        except Exception as e:
            logger.error(str(e))
            return None

    def enter_command_mode(self, version=2) -> bool:
        if not self.cmd_hello(SaharaMode.COMMAND, version=version):
            return False
        res = self.get_rsp()
        if res:
            if res.cmd == SaharaCmd.CMD_READY:
                return True
            logger.error(f"コマンドモードの応答が変だよ: {res}")
        else:
            logger.warning(f"コマンドモードの応答が空だよ: {res}")
        return False

    @staticmethod
    def get_error_desc(status):
        if status in ErrorDesc:
            return f'Error: {ErrorDesc[status]}'
        return 'Unknown error'

    def cmd_exec(self, mcmd):
        data = struct.pack("<III", SaharaCmd.EXECUTE_REQ, 0xC, mcmd)
        self._cdc.write(data)
        res = self.get_rsp()
        if res:
            if res.cmd == SaharaCmd.EXECUTE_RSP:
                data = struct.pack("<III", SaharaCmd.EXECUTE_DATA, 0xC, mcmd)
                self._cdc.write(data)
                payload = self._cdc.usbread(res.data_len)
                return payload
            elif res.cmd == SaharaCmd.END_TRANSFER:
                logger.error(self.get_error_desc(res.image_tx_status))
            else:
                logger.warning(f"対応してない応答: {res}")
            return None
        else:
            logger.warning(f"空の応答: {res}")
        return res

    def cmdexec_get_serial_num(self):
        res = self.cmd_exec(SaharaExecCmd.SERIAL_NUM_READ)
        logger.info(f'シリアル番号 (bytes): {res} [{hexlify(res)}]')
        return int.from_bytes(res, 'little')

    def cmd_modeswitch(self, mode):
        data = struct.pack("<III", SaharaCmd.SWITCH_MODE, 0xC, mode)
        self._cdc.write(data)

    def cmd_info(self, version) -> bool:
        if self.enter_command_mode(version=version):
            self._serial = self.cmdexec_get_serial_num()
            return True
        return False


class KyoceraSahara(Sahara):

    def drain_in(self, location: str, count: int = 0, attempts: int = 1, timeout: int = 1) -> Optional[bytes]:
        buffer = bytearray()
        for _ in range(attempts):
            try:
                buf = self._cdc.read(min(self._cdc.maxsize, count or self._cdc.maxsize), timeout)
            except Exception as e:
                logger.debug(str(e))
                break
            else:
                buffer.extend(buf)
        response = bytes(buffer)
        if response:
            logger.warning(f'{location} 排水 [{len(response)}]: {response}')
            return response
        return None

    def vendor_cmd_ab_clear_write_protect(self, lba: int, byte_count: int) -> bool:
        logger.debug(f'vendor_cmd_ab_clear_write_protect: lba:{lba} から {byte_count} バイトの書き込み保護を解除中')
        self.drain_in('pre')
        data = struct.pack("<IIII", 0xAB, 16, lba, byte_count)
        if not self._cdc.write(data):
            logger.error(f'データ送信に失敗したよ')
            return False
        resp = self._cdc.read(16)
        if len(resp) == 16:
            cmd_id = struct.unpack("<I", resp[0:4])[0]
            if cmd_id == 0xAC:
                logger.info('書き込み保護を解除したよ〜')
                return True
            elif cmd_id == 0x04:
                logger.error(f'書き込み保護解除エラー: {resp}')
                return False
            else:
                logger.warning(f'想定外の応答: {resp}')
                return False
        else:
            logger.error(f'エラー: {resp}')
        self.drain_in('post')
        return False

    A7_CHUNK_BYTES = 8 * 1024 * 1024
    A7_MS_PER_MB = 1500

    def vendor_cmd_a7_checksum(self, lba: int, byte_count: int) -> Optional[int]:
        logger.debug(f'vendor_cmd_a7_checksum: lba:{lba} から {byte_count} バイトを検証中')
        self.drain_in('pre')
        result = 0
        remaining = byte_count
        current_lba = lba
        while remaining > 0:
            chunk = min(remaining, self.A7_CHUNK_BYTES, 0xFFFFFFFF)
            chunk -= (chunk % 512)
            if chunk == 0:
                chunk = 512
            self.drain_in('process')
            data = struct.pack("<IIII", 0xA7, 16, current_lba, chunk)
            if not self._cdc.write(data):
                logger.error(f'データ送信に失敗したよ')
                return None
            rsp = self._cdc.read(20, timeout=max(3000, min(60000, int(1000 + (chunk / (1024 * 1024)) * self.A7_MS_PER_MB))))
            if len(rsp) == 20:
                rid, rlen, rsp_lba, rsp_bytes, rsp_sum = struct.unpack("<IIIII", rsp)
                if rid == 0xA8:
                    result = (result + rsp_sum) & 0xFFFFFFFF
                else:
                    logger.error(f'応答IDが変だよ: {rid} [{rsp}]')
                    return None
            elif len(rsp) == 16:
                logger.error(f'エラー: {rsp}')
                return None
            else:
                logger.error(f'応答長が変だよ: {len(rsp)}')
                return None
            sectors_advanced = (chunk + 511) // 512
            current_lba += sectors_advanced
            remaining -= sectors_advanced * 512
        self.drain_in('post')
        return result

    def vendor_cmd_b5_read_secureboot(self) -> Optional[bool]:
        logger.debug('vendor_cmd_b5_read_secureboot: SecureBoot状態を読み取り中')
        self.drain_in('pre')
        data = struct.pack("<II", 0xB5, 8)
        if not self._cdc.write(data):
            logger.error(f'データ送信に失敗したよ')
            return False
        resp = self._cdc.read(12)
        if len(resp) == 12:
            rid, rlen, sb_status = struct.unpack("<III", resp)
            if rid == 0xB6:
                return sb_status == 1
            else:
                logger.error(f'エラー: {resp}')
                return None
        logger.error(f'エラー: {resp}')
        return None

    def vendor_cmd_b9_read_raw(self, lba: int, sectors: int) -> Optional[bytes]:
        logger.debug(f'vendor_cmd_b9_read_raw: lba:{lba} から {sectors} セクタ読み取り中')
        self.drain_in('pre')
        data = struct.pack("<IIII", 0xB9, 16, lba, sectors)
        if not self._cdc.write(data):
            logger.error(f'データ送信に失敗したよ')
            return None
        total = sectors * 512
        first = True
        buf = bytearray()
        while len(buf) < total:
            tmp = self._cdc.read(min(self._cdc.maxsize, total))
            if _IS_WINDOWS:
                if not tmp:
                    if not self._cdc.connected:
                        logger.error('USBデバイスが切断されたよ。読み取りを中断するね。')
                        return None
                    continue
            if first and len(tmp) == 16:
                pkt = self._ch.parse_pkt(tmp)
                if pkt.cmd == SaharaCmd.END_TRANSFER:
                    logger.error(f'read_raw エラー: {pkt}')
                    return None
            first = False
            buf.extend(tmp)
        post = self.drain_in('post', 0)
        if post:
            if len(post) == 16:
                pkt = self._ch.parse_pkt(post)
                if pkt.cmd == SaharaCmd.END_TRANSFER:
                    logger.error(f'read_raw エラー: {pkt}')
                    return None
                else:
                    logger.warning(f'想定外の応答: {pkt}')
                    return None
        return bytes(buf)

    def vendor_cmd_a5_erase_region(self, lba: int, sectors: int) -> bool:
        logger.debug(f'vendor_cmd_a5_erase_region: lba:{lba} から {sectors} セクタ消去中')
        end_lba = int(lba) + int(sectors) - 1
        if end_lba < int(lba):
            logger.error("vendor_cmd_a5_erase_region: end_lba < start_lba になっちゃった")
            return False
        self.drain_in('pre')
        data = struct.pack("<IIII", 0xA5, 16, lba, sectors)
        if not self._cdc.write(data):
            logger.error(f'データ送信に失敗したよ')
            return False
        deadline = time.time() + 60.0
        while True:
            if time.time() >= deadline:
                logger.error("0xA5 後の 0xA6 待ちでタイムアウトしちゃった")
                return False
            hdr = self._cdc.read(16)
            rid, rlen, p2, p3 = struct.unpack("<IIII", hdr)
            code = rid & 0xFF
            logger.debug(f"[debug] 0xA5 応答: id=0x{rid:x} len={rlen} p2={p2} p3={p3}")
            if code == 0xA6 and rlen == 16:
                break
            if code == 0x04 and rlen == 16:
                status = p3
                if status != 0:
                    logger.error(f"0xA5でデバイスがエラー返してきたよ: status={status}")
                    return False
                continue
        return True

    BA_CHUNK_SIZE = 1048576

    def vendor_cmd_ba_write_raw(self, lba: int, data: bytes) -> bool:
        if len(data) % 512 != 0:
            logger.error("vendor_cmd_ba_write_raw: データ長は512の倍数じゃないとダメだよ")
            return False
        sectors = len(data) // 512
        logger.debug(f'vendor_cmd_ba_write_raw: lba:{lba} へ {len(data)} バイト ({sectors} セクタ) 書き込み中')

        self.drain_in('pre')
        payload = struct.pack("<IIII", 0xBA, 16, lba, sectors)
        if not self._cdc.write(payload):
            logger.error(f'データ送信に失敗したよ')
            return False

        try:
            resp = self._cdc.read(16)
        except Exception as e:
            logger.error(str(e))
            return False
        else:
            if len(resp) == 16:
                cmd_id, rlen, p2, p3 = struct.unpack("<IIII", resp)
                if cmd_id == 0x04 and p3 != 0x00:
                    logger.error(f'write_ba エラー: id=0x{cmd_id:x} len={rlen} p2=0x{p2:x} p3=0x{p3:x}')
                    return False
                logger.info(f'0xBA 準備OK hdr: id=0x{cmd_id:x} len={rlen} p2=0x{p2:x} p3=0x{p3:x}')

        sent = 0
        total = len(data)
        while sent < total:
            chunk_size = min(total - sent, self.BA_CHUNK_SIZE)
            actual = self._cdc.EP_OUT.write(data[sent:sent + chunk_size])
            if actual == chunk_size and chunk_size % self._cdc.EP_OUT.wMaxPacketSize == 0:
                self._cdc.EP_OUT.write(b'')
            sent += actual
            logger.debug(f'{sent}/{total} バイト送信済み')

        try:
            resp = self._cdc.read(timeout=6000)
        except Exception as e:
            logger.error(str(e))
            return False
        else:
            if len(resp) == 16:
                cmd_id, rlen, p2, p3 = struct.unpack("<IIII", resp)
                if cmd_id == 0x04:
                    logger.error(f'write_ba エラー: id=0x{cmd_id:x} len={rlen} p2=0x{p2:x} p3=0x{p3:x}')
                    return False
                logger.info(f'0xBB 準備OK hdr: id=0x{cmd_id:x} len={rlen} p2=0x{p2:x} p3=0x{p3:x}')
        return True


class Qdl:

    def __init__(self, vid: int, pid: int) -> None:
        self._vid = vid
        self._pid = pid
        self._cdc = None
        self._sahara = None
        self._parts = {}

    @property
    def partitions(self) -> dict:
        return dict(self._parts)

    def connect(self) -> bool:
        try:
            self._cdc = usb_class([[self._vid, self._pid, -1]])
            if self._cdc.connect(-1, -1, ''):
                logger.info('デバイスに繋がったよ〜')
                self._sahara = KyoceraSahara(self._cdc)
                resp = self._sahara.connect()
                if not resp:
                    self.disconnect()
                    return False
                return True
        except Exception as e:
            logger.debug(f"USB接続の例外: {e}")
        return False

    def disconnect(self) -> None:
        if self._sahara:
            self._sahara.disconnect()
        if self._cdc:
            try:
                self._cdc.close(True)
            except Exception as e:
                logger.debug(f"USB切断時の例外（想定内）: {e}")
        self._parts.clear()

    def partition_checksum(self, partition: str) -> Optional[int]:
        if partition in self._parts:
            return self._sahara.vendor_cmd_a7_checksum(
                self._parts[partition]["first_lba"],
                self._parts[partition]["sectors"] * 512
            )
        logger.error(f'そんなパーティション無いよ: {partition}')
        return None

    def erase_partition(self, partition: str) -> bool:
        if partition in self._parts:
            return self._sahara.vendor_cmd_a5_erase_region(
                self._parts[partition]["first_lba"],
                self._parts[partition]["sectors"]
            )
        logger.error(f'そんなパーティション無いよ: {partition}')
        return False

    def prepare_partition(self, partition: str) -> bool:
        if partition in self._parts:
            return self._sahara.vendor_cmd_ab_clear_write_protect(
                self._parts[partition]["first_lba"],
                self._parts[partition]["sectors"] * 512
            )
        logger.error(f'そんなパーティション無いよ: {partition}')
        return False

    def write_partition(self, partition: str, data: bytes, allow_padding: bool = False) -> bool:
        if partition in self._parts:
            if allow_padding:
                expected_size = self._parts[partition]["sectors"] * 512
                if len(data) < expected_size:
                    data = data.ljust(expected_size, b'\x00')
                    logger.info(f'パーティション {partition} を {len(data)} バイトにパディングしたよ')
            return self._sahara.vendor_cmd_ba_write_raw(
                self._parts[partition]["first_lba"],
                data
            )
        logger.error(f'そんなパーティション無いよ: {partition}')
        return False

    def read_gpt(self) -> int:
        self._parts.clear()
        boot_region = self._sahara.vendor_cmd_b9_read_raw(0, 34)
        if not boot_region or len(boot_region) < 1024:
            raise RuntimeError('ブートセクタ/GPTデータが読めなかったよ')

        gpt_hdr = boot_region[512:1024]
        if gpt_hdr[:8] != b'EFI PART':
            raise RuntimeError('LBA1にGPTシグネチャが無いよ')

        backup_gpt_lba = struct.unpack_from("<Q", gpt_hdr, 0x20)[0]
        total_sectors = backup_gpt_lba + 1
        logger.info('GPTから検出したeMMCの総セクタ数: %d', total_sectors)

        entries_lba = struct.unpack_from("<Q", gpt_hdr, 72)[0]
        entries_count = struct.unpack_from("<I", gpt_hdr, 80)[0]
        entry_size = struct.unpack_from("<I", gpt_hdr, 84)[0]
        entries_crc = struct.unpack_from("<I", gpt_hdr, 88)[0]

        entries_bytes = entries_count * entry_size
        if (entries_lba + (entries_bytes + 511) // 512) * 512 <= len(boot_region):
            entries_data = boot_region[entries_lba * 512:entries_lba * 512 + entries_bytes]
        else:
            entries_data = self._sahara.vendor_cmd_b9_read_raw(entries_lba, (entries_bytes + 511) // 512)

        if not entries_data:
            raise RuntimeError('GPTエントリ配列の読み込みに失敗したよ')

        calc_crc = binascii.crc32(entries_data[:entries_bytes]) & 0xFFFFFFFF
        if entries_crc != calc_crc:
            raise RuntimeError(f'GPTエントリのCRCが合わないよ r:{entries_crc:08X} c:{calc_crc:08X}')

        for i in range(entries_count):
            off = i * entry_size
            ent = entries_data[off:off + entry_size]
            if not ent or ent == b"\x00" * entry_size:
                continue
            first_lba = struct.unpack_from("<Q", ent, 32)[0]
            last_lba = struct.unpack_from("<Q", ent, 40)[0]
            attrs = struct.unpack_from("<Q", ent, 48)[0]
            name_utf16 = ent[56:56 + 72]
            try:
                name = name_utf16.decode("utf-16le").rstrip("\x00")
            except Exception:
                name = f'__unknown_partition_{i}__'
            sectors = (last_lba - first_lba + 1) if last_lba >= first_lba else 0
            self._parts[name] = {
                "index": i,
                "first_lba": first_lba,
                "last_lba": last_lba,
                "sectors": sectors,
                "attrs": attrs,
                "name": name,
            }
        return total_sectors

    def is_secureboot_enabled(self) -> bool:
        return self._sahara.vendor_cmd_b5_read_secureboot()

    def raw_dump_emmc(self, output_path: Path, total_sectors: int = 15269888,
                      chunk_size: int = 256, read_delay: float = 0.0):
        logger.info("eMMCの生ダンプ開始するよ〜")
        sectors_read = 0
        start_lba = 0

        with open(output_path, "wb") as f:
            while sectors_read < total_sectors:
                to_read = min(chunk_size, total_sectors - sectors_read)
                current_lba = start_lba + sectors_read

                print_progress(sectors_read, total_sectors, prefix="dump ", suffix=f"LBA:{current_lba}")

                chunk = self._sahara.vendor_cmd_b9_read_raw(current_lba, to_read)
                if chunk is None:
                    print()
                    logger.error(f"LBA {current_lba} で読み取り失敗。ダンプ中断するね。")
                    break

                f.write(chunk)
                sectors_read += to_read

                if _IS_WINDOWS:
                    if not self._cdc.connected:
                        print()
                        logger.error("USB接続が切れちゃった。ダンプ中断するね。")
                        break
                    if read_delay > 0:
                        time.sleep(read_delay)

        print()
        if sectors_read == total_sectors:
            logger.info(f"eMMC全体を {output_path} にダンプ完了！")
        else:
            logger.error(f"ダンプが不完全。セクタ {sectors_read} まで保存したよ。")

    def raw_write_emmc(self, input_path: Path, chunk_sectors: int = 2048, write_delay: float = 0.0):
        if not input_path.exists():
            logger.error(f"入力イメージが無いよ: {input_path}")
            return False

        file_size = input_path.stat().st_size
        if file_size % 512 != 0:
            logger.error("入力RAWイメージは512バイトの倍数じゃないとダメだよ")
            return False

        total_sectors = file_size // 512
        logger.info(f"eMMC全体リストア準備: {file_size} バイト ({total_sectors} セクタ)")

        self._sahara.vendor_cmd_ab_clear_write_protect(0, file_size)

        sectors_written = 0
        chunk_bytes = chunk_sectors * 512

        with open(input_path, "rb") as f:
            while sectors_written < total_sectors:
                current_lba = sectors_written
                data_chunk = f.read(chunk_bytes)
                if not data_chunk:
                    break

                actual_sectors = len(data_chunk) // 512
                print_progress(sectors_written, total_sectors, prefix="flash", suffix=f"LBA:{current_lba}")

                if not self._sahara.vendor_cmd_ba_write_raw(current_lba, data_chunk):
                    print()
                    logger.error(f"LBA {current_lba} で書き込み失敗。中断するね。")
                    return False

                sectors_written += actual_sectors

                if _IS_WINDOWS:
                    if not self._cdc.connected:
                        print()
                        logger.error("USB接続が切れちゃった。書き込み中断するね。")
                        return False
                    if write_delay > 0:
                        time.sleep(write_delay)

        print()
        if sectors_written == total_sectors:
            logger.info("eMMC全体のリストア完了！")
            return True
        else:
            logger.error("リストアが不完全で終わっちゃった")
            return False


def checksum_file(filepath: str, offset: int = 0, length: int = None) -> int:
    file_path = Path(filepath)
    file_size = file_path.stat().st_size

    if offset >= file_size:
        return 0

    if length is None:
        length = file_size - offset
    else:
        length = min(length, file_size - offset)

    if length == 0:
        return 0

    with open(filepath, 'rb') as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped_file:
            chunk_size = 65536
            checksum = 0
            pos = offset
            end = offset + length

            while pos < end:
                chunk_end = min(pos + chunk_size, end)
                chunk = mmapped_file[pos:chunk_end]

                i = 0
                chunk_len = len(chunk)
                while i + 4 <= chunk_len:
                    dword = int.from_bytes(chunk[i:i + 4], 'little')
                    checksum = (checksum + dword) & 0xFFFFFFFF
                    i += 4

                if chunk_end == end and i < chunk_len:
                    remaining = chunk_len - i
                    last_bytes = chunk[i:] + b'\x00' * (4 - remaining)
                    last_dword = int.from_bytes(last_bytes[:4], 'little')
                    mask = (1 << (remaining * 8)) - 1
                    checksum = (checksum + (last_dword & mask)) & 0xFFFFFFFF

                pos = chunk_end

    return checksum


WIDTH = 66


def _w(text):
    return sum(2 if ord(c) > 0x1100 else 1 for c in text)


def print_banner():
    print()
    print("+" + "-" * WIDTH + "+")
    title = "Kyocera EDL Tool  -  eMMC dump / flash / erase"
    pad = WIDTH - _w(title)
    left = pad // 2
    right = pad - left
    print("|" + " " * left + title + " " * right + "|")
    print("+" + "-" * WIDTH + "+")


def print_section(title):
    print()
    print(f"== {title} ==")
    print("-" * WIDTH)


def print_kv(key, value):
    print(f"   {key:<14}: {value}")


def print_progress(current, total, prefix="", suffix="", width=34):
    if total <= 0:
        return
    pct = current / total
    filled = int(width * pct)
    bar = "#" * filled + "." * (width - filled)
    line = f"  {prefix} |{bar}| {pct*100:6.2f}%  ({current}/{total})  {suffix}"
    print(line.ljust(120)[:120], end="\r", flush=True)


def print_table(parts):
    idx_w = 5
    name_w = 22
    lba_w = 24
    sec_w = 12
    attr_w = 18

    def sep(l, m, r, fill="-"):
        return l + m.join(fill * w for w in [idx_w, name_w, lba_w, sec_w, attr_w]) + r

    print(sep("+", "+", "+"))
    print(f"|{'Index':^{idx_w}}|{'Partition':^{name_w}}|{'LBA Range':^{lba_w}}|{'Sectors':^{sec_w}}|{'Attrs':^{attr_w}}|")
    print(sep("+", "+", "+"))
    for part in parts:
        lba_range = f"{part['first_lba']}-{part['last_lba']}"
        name = part['name'][:name_w - 1]
        print(f"|{part['index']:^{idx_w}}|{name:<{name_w}}|{lba_range:<{lba_w}}|{part['sectors']:<{sec_w}}|{part['attrs']:<{attr_w}}|")
    print(sep("+", "+", "+"))


def resolve_output_path(args, action: str, partition: Optional[str] = None) -> Optional[Path]:
    if action != "dump":
        return None

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if getattr(args, "full", False):
        default_name = f"{ts}_full_emmc.img"
    else:
        default_name = f"{ts}_{partition}.img"

    if args.output:
        p = Path(args.output)
        if p.is_dir():
            return p / default_name
        return p

    script_dir = Path(__file__).resolve().parent
    return script_dir / default_name


def handle_info(qdl: Qdl, args):
    print_section("Device Info")
    sb_enabled = qdl.is_secureboot_enabled()
    sb_status = "ON" if sb_enabled else "OFF"
    print_kv("SecureBoot", sb_status)

    total_sectors = qdl.read_gpt()
    print_kv("Total Sectors", f"{total_sectors}")
    print_kv("Disk Size", f"{total_sectors * 512 / (1024**3):.2f} GiB")
    print()

    print_section("Partition Table")
    print_table(list(qdl.partitions.values()))


def handle_dump(qdl: Qdl, args):
    output_img = resolve_output_path(args, "dump", args.partition)
    print_section("Dump")
    print_kv("Output", str(output_img))
    if _IS_WINDOWS:
        print_kv("Chunk", f"{args.chunk} sectors")
        print_kv("Delay", f"{args.delay:.3f} s")

    try:
        total_sectors = qdl.read_gpt()
    except Exception as e:
        logger.error(f"GPTの解析に失敗しちゃった: {e}")
        return

    if args.full:
        qdl.raw_dump_emmc(output_img, total_sectors=total_sectors,
                          chunk_size=args.chunk, read_delay=args.delay)
    else:
        if not args.partition:
            logger.error("--partition を指定するか、--full にしてね")
            return
        if args.partition not in qdl.partitions:
            logger.error(f"パーティション '{args.partition}' はGPTに無いよ")
            return
        part = qdl.partitions[args.partition]
        logger.info(f"パーティション '{args.partition}' ({part['sectors']} セクタ) をダンプ中…")

        chunk_size = args.chunk
        total = part["sectors"]
        done = 0
        buf = bytearray()
        while done < total:
            to_read = min(chunk_size, total - done)
            print_progress(done, total, prefix="dump ", suffix=f"LBA:{part['first_lba'] + done}")
            c = qdl._sahara.vendor_cmd_b9_read_raw(part["first_lba"] + done, to_read)
            if c is None:
                print()
                logger.error(f"LBA {part['first_lba'] + done} で読み取り失敗。中断するね。")
                return
            buf.extend(c)
            done += to_read
            if _IS_WINDOWS:
                if not qdl._cdc.connected:
                    print()
                    logger.error("USB接続が切れちゃった。ダンプ中断するね。")
                    return
                if args.delay > 0:
                    time.sleep(args.delay)
        print()
        output_img.write_bytes(bytes(buf))
        logger.info(f"パーティションを {output_img} にダンプしたよ〜")


def handle_flash(qdl: Qdl, args):
    input_file = Path(args.image)
    print_section("Flash")

    if not input_file.exists():
        logger.error(f"入力ファイルが無いよ: {input_file}")
        return

    print_kv("Input", str(input_file))

    try:
        qdl.read_gpt()
    except Exception as e:
        logger.error(f"GPTの解析に失敗: {e}")
        return

    if args.full:
        qdl.raw_write_emmc(input_file, write_delay=args.delay)
        return

    if not args.partition:
        logger.error("--partition を指定するか、--full にしてね")
        return

    if args.partition not in qdl.partitions:
        logger.error(f"パーティション '{args.partition}' はGPTに無いよ")
        return

    print_kv("Target", args.partition)
    data = input_file.read_bytes()

    if args.clear_wp:
        print_kv("Write-Protect", "解除を試みるよ")
        qdl.prepare_partition(args.partition)
    if args.erase:
        print_kv("Pre-Erase", "やるよ")
        qdl.erase_partition(args.partition)

    logger.info(f"{input_file.name} を '{args.partition}' に書き込み中…")
    if qdl.write_partition(args.partition, data, allow_padding=args.pad):
        logger.info("書き込み完了！やったね〜")
    else:
        logger.error("書き込み失敗しちゃった…")


def handle_erase(qdl: Qdl, args):
    print_section("Erase")
    qdl.read_gpt()
    if args.partition not in qdl.partitions:
        logger.error(f"パーティション '{args.partition}' はGPTに無いよ")
        return
    print_kv("Target", args.partition)
    logger.info(f"パーティション '{args.partition}' を消去中…")
    if qdl.erase_partition(args.partition):
        logger.info("消去完了！きれいになったよ〜")
    else:
        logger.error("消去失敗しちゃった…")


def handle_verify(qdl: Qdl, args):
    local_file = Path(args.image)
    print_section("Verify")

    if not local_file.exists():
        logger.error(f"ローカルファイルが無いよ: {local_file}")
        return

    qdl.read_gpt()
    if args.partition not in qdl.partitions:
        logger.error(f"パーティション '{args.partition}' はGPTに無いよ")
        return

    logger.info("チェックサムを計算中…")
    local_crc = checksum_file(str(local_file))
    remote_crc = qdl.partition_checksum(args.partition)

    print()
    print_kv("Local CRC", f"0x{local_crc:08X}")
    print_kv("Device CRC", f"0x{remote_crc:08X}" if remote_crc is not None else "取得失敗")
    print()
    if remote_crc is not None and local_crc == remote_crc:
        print("  [OK] チェックサム一致！検証パスしたよ〜")
    else:
        print("  [NG] チェックサムが合わないよ…注意してね")


def main():
    if "--internal-guard-worker" in sys.argv:
        sys.exit(_guard_worker_main())

    parser = argparse.ArgumentParser(
        prog="tool.py",
        description="Kyocera EDL フラッシュツール（Windows=MountGuard統合 / Linux=軽量モード）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  1. GPTマップとSecureBoot状態を見る:
     python tool.py info
  2. eMMC全体をダンプ:
     python tool.py dump --full -o full_emmc.img
  3. 単一パーティションをダンプ:
     python tool.py dump -p system
  4. 単一パーティションへ書き込み:
     python tool.py flash -p system -i system.img
  5. eMMC全体を書き戻す:
     python tool.py flash --full -i full_emmc.img
  6. パーティションを消去:
     python tool.py erase -p system
  7. MountGuard 手動起動 (Windowsのみ):
     python tool.py guard-start
  8. MountGuard 停止 (Windowsのみ):
     python tool.py guard-stop
  9. MountGuard 状態確認 (Windowsのみ):
     python tool.py guard-status

MountGuardについて:
  Windowsでは tool.py 起動時に自動で MountGuard が昇格起動します。
  UAC を承認すると、PC 再起動まで常駐し、USBSTOR を無効化＋USB ディスクを
  強制offline にして 0482:0a7f の自動マウントを防止します。
  停止したいときは guard-stop を実行してね。
  --no-guard を付けると MountGuard を起動せずに実行できます。

Linuxについて:
  Linuxでは MountGuard は一切起動せず
  軽量動作になります。
  インターフェース0のみ claim、余計な connected チェック無し、
  チャンク256セクタ、delay無し。
        """
    )
    parser.add_argument("--vid", type=lambda x: int(x, 16), default="0x0482",
                        help="USB Vendor ID (hex, 既定: 0x0482)")
    parser.add_argument("--pid", type=lambda x: int(x, 16), default="0x0a7f",
                        help="USB Product ID (hex, 既定: 0x0a7f)")
    parser.add_argument("--debug", action="store_true",
                        help="デバッグログを有効にするよ")
    parser.add_argument("--no-guard", action="store_true",
                        help="MountGuard を起動しないで実行するよ (Windowsのみ意味あり)")

    subparsers = parser.add_subparsers(dest="action", required=True,
                                       help="実行するコマンド")

    subparsers.add_parser(
        "info",
        help="デバイス状態とGPTパーティションマップを表示",
        description="SecureBootビットを確認し、GUIDパーティションテーブル(GPT)を読むよ。",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers.add_parser(
        "guard-start",
        help="MountGuard を手動で起動するよ (Windowsのみ)",
        description="MountGuard を昇格起動して常駐させるよ。",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers.add_parser(
        "guard-stop",
        help="MountGuard を停止して USBSTOR を復元するよ (Windowsのみ)",
        description="常駐している MountGuard を停止し、USBSTOR の Start 値を元に戻すよ。",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers.add_parser(
        "guard-status",
        help="MountGuard の状態を確認するよ (Windowsのみ)",
        description="MountGuard の稼働状態と USBSTOR の設定を表示するよ。",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    dump_parser = subparsers.add_parser(
        "dump",
        help="デバイスからデータを吸い出して保存するよ",
        description="Kyocera拡張SaharaコマンドでeMMCから読み出すよ。\nパーティション指定か、eMMC全体を選択できるよ。",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    dump_parser.add_argument("-o", "--output",
                             help="出力ファイルまたはディレクトリ。省略時は日時_名前で自動生成。")
    dump_parser.add_argument("-p", "--partition",
                             help="ダンプするパーティション名")
    dump_parser.add_argument("--full", action="store_true",
                             help="eMMC全体をダンプするよ")
    dump_parser.add_argument("--chunk", type=int, default=_DEFAULT_DUMP_CHUNK,
                             help=f"1回の読み出しセクタ数 (既定: {_DEFAULT_DUMP_CHUNK})")
    dump_parser.add_argument("--delay", type=float, default=_DEFAULT_READ_DELAY,
                             help=f"各読み出し後の待機秒 (Windowsのみ有効, 既定: {_DEFAULT_READ_DELAY})")

    flash_parser = subparsers.add_parser(
        "flash",
        help="ローカルイメージをパーティションまたはeMMC全体へ書き込むよ",
        description="ローカルのバイナリをデバイスのeMMCへ書き込むよ。",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    flash_parser.add_argument("-i", "--image", required=True,
                              help="書き込むイメージ/バイナリファイルのパス")
    flash_parser.add_argument("-p", "--partition",
                              help="書き込み先パーティション名 (--full時は不要)")
    flash_parser.add_argument("--full", action="store_true",
                              help="LBA0からeMMC全体を書き換えるよ")
    flash_parser.add_argument("--clear-wp", action="store_true",
                              help="書き込み前にハードウェア書き込み保護を解除してみるよ")
    flash_parser.add_argument("--erase", action="store_true",
                              help="書き込み前にブロックを消去するよ")
    flash_parser.add_argument("--pad", action="store_true",
                              help="入力ファイルをセクタ境界まで0埋めするよ")
    flash_parser.add_argument("--delay", type=float, default=_DEFAULT_READ_DELAY,
                              help=f"各書き込み後の待機秒 (Windowsのみ有効, 既定: {_DEFAULT_READ_DELAY})")

    erase_parser = subparsers.add_parser(
        "erase",
        help="指定パーティションを消去するよ",
        description="パーティションをゼロで埋めて消去するよ。",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    erase_parser.add_argument("-p", "--partition", required=True,
                              help="消去するパーティション名")

    verify_parser = subparsers.add_parser(
        "verify",
        help="パーティションとローカルイメージの整合性を検証するよ",
        description="ローカルファイルのチェックサムと、デバイス側で計算したパーティションのチェックサムを比較するよ。",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    verify_parser.add_argument("-p", "--partition", required=True,
                               help="検証するパーティション名")
    verify_parser.add_argument("-i", "--image", required=True,
                               help="比較対象のローカルイメージファイル")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    if args.action == "guard-start":
        if not _IS_WINDOWS:
            print("MountGuard: Windows 専用だよ")
            sys.exit(1)
        if _guard_is_running():
            print(f"MountGuard: 既に動作中 (PID {_guard_read_pid()})")
            sys.exit(0)
        if spawn_guard():
            print("MountGuard: 起動完了")
            sys.exit(0)
        print("MountGuard: 起動失敗")
        sys.exit(1)

    if args.action == "guard-stop":
        stop_guard()
        sys.exit(0)

    if args.action == "guard-status":
        guard_status()
        sys.exit(0)

    print_banner()
    print()
    print(f"  プラットフォーム: {'Windows' if _IS_WINDOWS else ('macOS' if _IS_MACOS else 'Linux')}")

    if _IS_WINDOWS and not args.no_guard:
        if _guard_is_running():
            print(f"  MountGuard: 既に稼働中 (PID {_guard_read_pid()})")
        else:
            print("  MountGuard: 起動中… (UACを承認してね)")
            if spawn_guard():
                print(f"  MountGuard: 起動完了 (PID {_guard_read_pid()})")
                print(f"  ログ: {_GUARD_LOG}")
            else:
                print("  MountGuard: 起動失敗。--no-guard で続行するか手動で起動してね")
    elif args.no_guard:
        print("  MountGuard: --no-guard 指定のため起動しないよ")

    print()
    print(f"  デバイス待ちだよ〜 (VID: 0x{args.vid:04x}, PID: 0x{args.pid:04x})")
    print(f"  デバイスを接続してね…")

    qdl = Qdl(args.vid, args.pid)
    dots = 0
    while not qdl.connect():
        dots = (dots + 1) % 4
        print(f"  まだ見つからないよ{'.' * dots}{' ' * (3 - dots)}", end="\r")
        time.sleep(2)

    print("\n  デバイス見つけた！ハンドシェイク完了〜          ")
    print()

    try:
        dispatch_map = {
            "info": handle_info,
            "dump": handle_dump,
            "flash": handle_flash,
            "erase": handle_erase,
            "verify": handle_verify,
        }
        dispatch_map[args.action](qdl, args)
    except KeyboardInterrupt:
        print("\n  中断されたよ、お疲れさま〜")
    except Exception as e:
        logger.error(f"想定外のエラー: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
    finally:
        qdl.disconnect()
        if _IS_WINDOWS and not args.no_guard:
            print()
            print("  MountGuard はバックグラウンドで動き続けるよ")
            print("  止めたいときは: python tool.py guard-stop")


if __name__ == '__main__':
    main()