#!/usr/bin/env python3
"""
Samsung UART dashboard (Main <-> WiFi)

Frame format (confirmed):
  SOF: d0 c0
  VER: 1 byte
  LEN: 1 byte (body length)
  BODY: CTR(6) | SEP(1) | PAYLOAD(...) | CHK(1) | EOF(1=e0)
  CHK: XOR of all bytes from d0 through end of payload (exclude CHK and EOF)

UI:
  Header (top):
    Appliance Type
    Platform Type
    Serial Number
    MAC
  Table (live):
    Field | Value
"""

import argparse
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, List

try:
    import serial  # pip install pyserial
except ImportError:
    print("Missing dependency: pyserial. Install with: pip install pyserial", file=sys.stderr)
    raise

# Optional rich UI (nicer live updating)
USE_RICH = False
try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
    USE_RICH = True
except Exception:
    USE_RICH = False

SOF0 = 0xD0
SOF1 = 0xC0
EOF_ = 0xE0

DOOR_ID_LABELS = {
    0x47: "Refrigerator Door",
    0x57: "Flex Zone Drawer",
    0x87: "Freezer Door",
}
DOOR_STATE_LABELS = {
    0x0F: "OPEN",
    0xF0: "CLOSED",
}


def xor_checksum(bs: bytes) -> int:
    x = 0
    for b in bs:
        x ^= b
    return x & 0xFF


def fmt_hex(bs: bytes, max_chars: int = 140) -> str:
    s = " ".join(f"{b:02x}" for b in bs)
    if len(s) > max_chars:
        return s[:max_chars] + " …"
    return s


def extract_ascii_runs(payload: bytes, min_len: int = 4) -> List[str]:
    printable = set(range(0x20, 0x7F))
    runs: List[str] = []
    cur = bytearray()
    for b in payload:
        if b in printable:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                runs.append(cur.decode(errors="replace"))
            cur.clear()
    if len(cur) >= min_len:
        runs.append(cur.decode(errors="replace"))
    return runs


def looks_like_platform(s: str) -> bool:
    # e.g., DA-REF-NORMAL-01011
    s = s.strip("\x00").strip()
    if len(s) < 8 or len(s) > 40:
        return False
    # strong signature you mentioned
    if s.startswith("DA-") and "-" in s:
        return True
    # other likely platform-ish formats
    if s.upper().startswith("DA-") or s.upper().startswith("RF-"):
        return True
    return False


def looks_like_serial(s: str) -> bool:
    s = s.strip("\x00").strip()
    if not (10 <= len(s) <= 24):
        return False
    # exclude platform
    if looks_like_platform(s):
        return False
    # serials: usually no spaces, mostly alnum (allow a few symbols)
    if any(ch.isspace() for ch in s):
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    if not all(ch in allowed for ch in s):
        return False
    return True


def looks_like_appliance_type(s: str) -> bool:
    s0 = s.strip("\x00").strip().lower()
    # be tolerant: user said they see "Refrigerator" in the log
    return ("refrigerator" in s0) or ("fridge" in s0) or ("refrig" in s0)


def mac_is_plausible(mac: bytes) -> bool:
    if len(mac) != 6:
        return False
    if mac == b"\x00" * 6 or mac == b"\xff" * 6:
        return False
    # reject 00:00:00:*:*:*
    if mac[0] == 0x00 and mac[1] == 0x00 and mac[2] == 0x00:
        return False
    # reject "payloadish" tiny-bytes candidate like 0b 02 04 05 0c 0d
    if all(b <= 0x0F for b in mac):
        return False
    # low-entropy rejection (common in bogus picks)
    if len(set(mac)) <= 2:
        return False
    return True


def find_mac_candidates(payload: bytes) -> List[bytes]:
    """
    Try several heuristics to find MAC candidates in a payload:
      - pattern: 0x06 followed by 6 bytes (from your earlier observation)
      - pattern: 0x82 0x06 followed by 6 bytes
      - raw scan: any 6-byte window that passes plausibility, but only if preceded by a marker byte
    """
    cands: List[bytes] = []

    # 0x82 0x06 <mac>
    for i in range(len(payload) - 8):
        if payload[i] == 0x82 and payload[i + 1] == 0x06:
            mac = payload[i + 2:i + 8]
            cands.append(mac)

    # 0x06 <mac>
    for i in range(len(payload) - 7):
        if payload[i] == 0x06:
            mac = payload[i + 1:i + 7]
            cands.append(mac)

    # conservative scan: look for <marker> <6 bytes> where marker is likely a tag
    likely_tags = {0x06, 0x16, 0x26, 0x82, 0x83, 0x84}
    for i in range(len(payload) - 7):
        if payload[i] in likely_tags:
            mac = payload[i + 1:i + 7]
            cands.append(mac)

    return cands


@dataclass
class Frame:
    ver: int
    ln: int
    ctr: bytes
    sep: int
    payload: bytes
    chk: int
    eof: int
    raw: bytes
    chk_calc: int
    chk_ok: bool
    eof_ok: bool


class SamsungParser:
    def __init__(self):
        self.buf = bytearray()

    def feed(self, data: bytes) -> None:
        self.buf.extend(data)
        if len(self.buf) > 300_000:
            self.buf = self.buf[-80_000:]

    def _find_sof(self) -> int:
        b = self.buf
        for i in range(len(b) - 1):
            if b[i] == SOF0 and b[i + 1] == SOF1:
                return i
        return -1

    def next_frame(self) -> Optional[Frame]:
        i = self._find_sof()
        if i < 0:
            if len(self.buf) > 1:
                self.buf = self.buf[-1:]
            return None

        if i > 0:
            del self.buf[:i]

        if len(self.buf) < 4:
            return None

        ver = self.buf[2]
        ln = self.buf[3]
        total = 4 + ln
        if len(self.buf) < total:
            return None

        raw = bytes(self.buf[:total])
        del self.buf[:total]

        body = raw[4:]
        if len(body) < 9:
            return None

        ctr = body[0:6]
        sep = body[6]
        payload = body[7:-2]
        chk = body[-2]
        eof = body[-1]

        chk_calc = xor_checksum(raw[:-2])
        chk_ok = (chk == chk_calc)
        eof_ok = (eof == EOF_)

        return Frame(
            ver=ver, ln=ln, ctr=ctr, sep=sep, payload=payload,
            chk=chk, eof=eof, raw=raw,
            chk_calc=chk_calc, chk_ok=chk_ok, eof_ok=eof_ok
        )


@dataclass
class DashboardState:
    # headline identity fields
    appliance_type: str = "Unknown"
    platform_type: str = "Unknown"
    serial_number: str = "Unknown"
    mac: str = "Unknown"

    # core stats
    frames_total: int = 0
    frames_bad_chk: int = 0
    frames_bad_eof: int = 0
    last_frame_time: float = 0.0

    # last frame info
    last_ver: Optional[int] = None
    last_len: Optional[int] = None
    last_sep: Optional[int] = None
    last_ctr: Optional[str] = None
    last_payload_hex: str = ""
    last_frame_hex: str = ""
    last_ascii_runs: str = ""

    # door states
    door_47: str = "Unknown"
    door_57: str = "Unknown"
    door_87: str = "Unknown"

    # telemetry
    telemetry_seen: int = 0
    last_tel_sig: str = ""
    last_tel_head: str = ""

    # wifi control
    last_wifi_ctl: str = ""

    # extras
    extra: Dict[str, str] = field(default_factory=dict)


def update_from_ascii(state: DashboardState, runs: List[str]) -> None:
    if runs:
        state.last_ascii_runs = " | ".join(repr(r.strip("\x00")) for r in runs[:3])

    # Prefer stronger matches for appliance_type
    for r in runs:
        s = r.strip("\x00").strip()
        if not s:
            continue

        # Appliance type (case-insensitive)
        if looks_like_appliance_type(s):
            state.appliance_type = s

        # Platform type
        if looks_like_platform(s):
            # don't stomp a previously found platform if this is less specific
            # but generally: keep the latest
            state.platform_type = s

        # Serial number
        if looks_like_serial(s):
            state.serial_number = s


def update_mac(state: DashboardState, payload: bytes) -> None:
    # Try candidates; accept the first that passes plausibility.
    for cand in find_mac_candidates(payload):
        if mac_is_plausible(cand):
            state.mac = ":".join(f"{b:02x}" for b in cand)
            return


def classify_and_update(state: DashboardState, fr: Frame) -> None:
    state.frames_total += 1
    state.last_frame_time = time.time()

    state.last_ver = fr.ver
    state.last_len = fr.ln
    state.last_sep = fr.sep
    state.last_ctr = fr.ctr.hex()

    state.last_payload_hex = fmt_hex(fr.payload, max_chars=220)
    state.last_frame_hex = fmt_hex(fr.raw, max_chars=260)

    if not fr.chk_ok:
        state.frames_bad_chk += 1
    if not fr.eof_ok:
        state.frames_bad_eof += 1

    # ASCII sniff + identity fields
    runs = extract_ascii_runs(fr.payload, min_len=4)
    if runs:
        update_from_ascii(state, runs)

    # MAC sniff (only update if we find a plausible one)
    update_mac(state, fr.payload)

    # Door event: 02 06 03 <ID> 01 <STATE>
    if len(fr.payload) == 6 and fr.payload[0:3] == bytes([0x02, 0x06, 0x03]) and fr.payload[4] == 0x01:
        door_id = fr.payload[3]
        st = fr.payload[5]
        door_name = DOOR_ID_LABELS.get(door_id, f"Door 0x{door_id:02x}")
        st_name = DOOR_STATE_LABELS.get(st, f"0x{st:02x}")

        label = f"{door_name}: {st_name} (raw=0x{st:02x})"

        if door_id == 0x47:
            state.door_47 = label
        elif door_id == 0x57:
            state.door_57 = label
        elif door_id == 0x87:
            state.door_87 = label
        else:
            state.extra[f"door_{door_id:02x}"] = label
        return

    # Telemetry signature: 15 05 1f ...
    if len(fr.payload) >= 3 and fr.payload[0:3] == bytes([0x15, 0x05, 0x1F]):
        state.telemetry_seen += 1
        state.last_tel_sig = f"15 05 1f (payload_len={len(fr.payload)}) ver=0x{fr.ver:02x} sep=0x{fr.sep:02x}"
        state.last_tel_head = fmt_hex(fr.payload[:40], max_chars=240)
        return

    # WiFi control class: payload[0]==0x94
    if len(fr.payload) >= 1 and fr.payload[0] == 0x94:
        state.last_wifi_ctl = fmt_hex(fr.payload, max_chars=240)
        return


def build_rows(state: DashboardState) -> List[Tuple[str, str]]:
    age = (time.time() - state.last_frame_time) if state.last_frame_time else 0.0
    rows = [
        ("frames_total", str(state.frames_total)),
        ("frames_bad_chk", str(state.frames_bad_chk)),
        ("frames_bad_eof", str(state.frames_bad_eof)),
        ("last_rx_age_s", f"{age:.2f}"),

        ("last_ver", f"0x{state.last_ver:02x}" if state.last_ver is not None else ""),
        ("last_len", str(state.last_len) if state.last_len is not None else ""),
        ("last_sep", f"0x{state.last_sep:02x}" if state.last_sep is not None else ""),
        ("last_ctr", state.last_ctr or ""),

        ("Refrigerator Door (0x47)", state.door_47),
        ("Flex Zone Drawer (0x57)", state.door_57),
        ("Freezer Door (0x87)", state.door_87),

        ("telemetry_seen", str(state.telemetry_seen)),
        ("last_telemetry_sig", state.last_tel_sig),
        ("last_telemetry_head", state.last_tel_head),

        ("last_wifi_ctl", state.last_wifi_ctl),

        ("last_ascii_runs", state.last_ascii_runs),
        ("last_payload_hex", state.last_payload_hex),
        ("last_frame_hex", state.last_frame_hex),
    ]
    for k in sorted(state.extra.keys()):
        rows.append((k, state.extra[k]))
    return rows


def render_simple(state: DashboardState, rows: List[Tuple[str, str]]) -> None:
    sys.stdout.write("\x1b[2J\x1b[H")  # clear + home
    sys.stdout.write("Samsung UART Dashboard (SOF d0 c0 / EOF e0)\n\n")

    sys.stdout.write(f"Appliance Type : {state.appliance_type}\n")
    sys.stdout.write(f"Platform Type  : {state.platform_type}\n")
    sys.stdout.write(f"Serial Number  : {state.serial_number}\n")
    sys.stdout.write(f"MAC Address    : {state.mac}\n\n")

    sys.stdout.write("-" * 100 + "\n")
    left_w = 28
    sys.stdout.write(f"{'Field':<{left_w}} | Value\n")
    sys.stdout.write("-" * 100 + "\n")
    for k, v in rows:
        v = (v or "").replace("\n", "\\n")
        if len(v) > 300:
            v = v[:300] + " …"
        sys.stdout.write(f"{k:<{left_w}} | {v}\n")
    sys.stdout.flush()


def build_rich_renderable(state: DashboardState, rows: List[Tuple[str, str]]):
    header = Text()
    header.append("Appliance Type: ", style="bold")
    header.append(state.appliance_type + "\n")
    header.append("Platform Type : ", style="bold")
    header.append(state.platform_type + "\n")
    header.append("Serial Number : ", style="bold")
    header.append(state.serial_number + "\n")
    header.append("MAC Address   : ", style="bold")
    header.append(state.mac)

    header_panel = Panel(header, title="Identity", expand=False)

    table = Table(title="Live Fields", show_lines=False)
    table.add_column("Field", style="bold", no_wrap=True)
    table.add_column("Value")
    for k, v in rows:
        v = (v or "").replace("\n", "\\n")
        table.add_row(k, v)

    grid = Table.grid(padding=(0, 1))
    grid.add_row(header_panel)
    grid.add_row(table)
    return grid


def read_replay_bytes(path: str) -> bytes:
    raw = open(path, "rb").read()
    # if it's mostly hex text, normalize to bytes
    asciiish = sum(1 for b in raw if 32 <= b <= 126 or b in (9, 10, 13)) / max(len(raw), 1)
    if asciiish > 0.95:
        s = raw.decode(errors="ignore")
        hexchars = "0123456789abcdefABCDEF"
        s2 = "".join(ch for ch in s if ch in hexchars)
        if len(s2) % 2 == 1:
            s2 = s2[:-1]
        try:
            return bytes.fromhex(s2)
        except Exception:
            return raw
    return raw


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/tty.usbserial-10")
    ap.add_argument("--baud", type=int, default=9600)
    ap.add_argument("--timeout", type=float, default=0.1)
    ap.add_argument("--refresh-ms", type=int, default=200)
    ap.add_argument("--replay", default="", help="Replay from a file instead of live serial")
    ap.add_argument("--no-rich", action="store_true", help="Force ANSI UI even if rich is installed")
    args = ap.parse_args()

    use_rich = USE_RICH and (not args.no_rich)

    parser = SamsungParser()
    state = DashboardState()

    ser = None
    replay = b""
    replay_pos = 0

    if args.replay:
        replay = read_replay_bytes(args.replay)
    else:
        try:
            ser = serial.Serial(
                port=args.port,
                baudrate=args.baud,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=args.timeout,
            )
        except Exception as e:
            print(f"Failed to open {args.port}: {e}", file=sys.stderr)
            return 2

    refresh_s = max(args.refresh_ms, 50) / 1000.0

    if use_rich:
        console = Console()
        with Live(build_rich_renderable(state, build_rows(state)),
                  console=console,
                  refresh_per_second=max(2, int(1 / refresh_s))) as live:
            try:
                while True:
                    if replay:
                        chunk = replay[replay_pos:replay_pos + 512]
                        replay_pos += len(chunk)
                        if chunk:
                            parser.feed(chunk)
                    else:
                        chunk = ser.read(4096)  # type: ignore
                        if chunk:
                            parser.feed(chunk)

                    while True:
                        fr = parser.next_frame()
                        if fr is None:
                            break
                        classify_and_update(state, fr)

                    live.update(build_rich_renderable(state, build_rows(state)))
                    time.sleep(refresh_s)
            except KeyboardInterrupt:
                return 0
            finally:
                if ser:
                    try:
                        ser.close()
                    except Exception:
                        pass
    else:
        try:
            while True:
                if replay:
                    chunk = replay[replay_pos:replay_pos + 512]
                    replay_pos += len(chunk)
                    if chunk:
                        parser.feed(chunk)
                else:
                    chunk = ser.read(4096)  # type: ignore
                    if chunk:
                        parser.feed(chunk)

                while True:
                    fr = parser.next_frame()
                    if fr is None:
                        break
                    classify_and_update(state, fr)

                render_simple(state, build_rows(state))
                time.sleep(refresh_s)
        except KeyboardInterrupt:
            return 0
        finally:
            if ser:
                try:
                    ser.close()
                except Exception:
                    pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
