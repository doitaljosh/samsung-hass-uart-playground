#!/usr/bin/env python3

# Samsung HASS UART Playground

import argparse
import time
from dataclasses import dataclass
from typing import Optional, List

import serial

SOF = 0x32
EOF = 0x34
MAX_PAYLOAD = 0x300  # observed firmware reject threshold

ACK = 0x06
NAK_SEQ = 0x15
NAK_VERIFY = 0x19

ESC = 0xB4  # compression escape marker


# ---------------- CRC / helpers ----------------

def crc16_ccitt(data: bytes, init: int = 0xFFFF) -> int:
    """CRC-16/CCITT (poly 0x1021, init 0xFFFF, no xorout)."""
    crc = init & 0xFFFF
    for b in data:
        crc ^= (b & 0xFF) << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def u24_to_be(x: int) -> bytes:
    x &= 0xFFFFFF
    return bytes([(x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF])


def parse_u24_be(b: bytes) -> int:
    return (b[0] << 16) | (b[1] << 8) | b[2]


def hex_bytes(s: str) -> bytes:
    s = s.strip().replace(" ", "").replace("_", "")
    if s == "":
        return b""
    if len(s) % 2 != 0:
        raise ValueError("Hex string must have even number of hex digits")
    return bytes.fromhex(s)


# ---------------- Frame ----------------

@dataclass
class Frame:
    src: int
    dst: int
    hdr: int
    cmd: int
    payload: bytes
    crc: int

    @property
    def hdr_hi(self) -> int:
        return (self.hdr >> 4) & 0xF

    @property
    def hdr_lo(self) -> int:
        return self.hdr & 0xF


def build_frame(src: int, dst: int, hdr: int, cmd: int, payload: bytes) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"Payload too large ({len(payload)} > {MAX_PAYLOAD})")

    buf = bytearray()
    buf.append(SOF)
    buf += u24_to_be(src)
    buf += u24_to_be(dst)
    buf.append(hdr & 0xFF)
    buf.append(cmd & 0xFF)
    buf += len(payload).to_bytes(2, "big")
    buf += payload

    # CRC over bytes after SOF through end of payload
    crc = crc16_ccitt(bytes(buf[1:]))
    buf += crc.to_bytes(2, "big")
    buf.append(EOF)
    return bytes(buf)


class StreamFramer:
    """Streaming framer for SOF/EOF + len + CRC scheme."""
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.in_frame = False
        self.buf = bytearray()
        self.payload_len: Optional[int] = None

    def feed(self, b: int) -> Optional[Frame]:
        b &= 0xFF

        if not self.in_frame:
            if b == SOF:
                self.in_frame = True
                self.buf = bytearray([SOF])
                self.payload_len = None
            return None

        self.buf.append(b)

        # Once we have header, parse payload length.
        # layout: [0]=SOF [1..3]=src [4..6]=dst [7]=hdr [8]=cmd [9..10]=len
        if self.payload_len is None and len(self.buf) >= 11:
            plen = int.from_bytes(self.buf[9:11], "big")
            if plen > MAX_PAYLOAD:
                self.reset()
                return None
            self.payload_len = plen

        if self.payload_len is None:
            return None

        total_len = 1 + 3 + 3 + 1 + 1 + 2 + self.payload_len + 2 + 1
        if len(self.buf) < total_len:
            return None

        pkt = bytes(self.buf[:total_len])
        self.reset()

        if pkt[-1] != EOF:
            return None

        src = parse_u24_be(pkt[1:4])
        dst = parse_u24_be(pkt[4:7])
        hdr = pkt[7]
        cmd = pkt[8]
        plen = int.from_bytes(pkt[9:11], "big")
        payload = pkt[11:11+plen]
        crc_rx = int.from_bytes(pkt[11+plen:13+plen], "big")
        crc_calc = crc16_ccitt(pkt[1:11+plen])
        if crc_calc != crc_rx:
            return None

        return Frame(src=src, dst=dst, hdr=hdr, cmd=cmd, payload=payload, crc=crc_rx)


def open_serial(port: str) -> serial.Serial:
    return serial.Serial(
        port=port,
        baudrate=115200,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_TWO,
        timeout=0.05,
        write_timeout=1.0,
    )


def fmt_frame(f: Frame) -> str:
    return (
        f"SRC=0x{f.src:06X} DST=0x{f.dst:06X} "
        f"HDR=0x{f.hdr:02X}(hi={f.hdr_hi:X},lo={f.hdr_lo:X}) "
        f"CMD=0x{f.cmd:02X} LEN={len(f.payload)} CRC=0x{f.crc:04X} "
        f"PAYLOAD={f.payload.hex()}"
    )


def read_frames(ser: serial.Serial, timeout_s: float) -> List[Frame]:
    fr = StreamFramer()
    out: List[Frame] = []
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        chunk = ser.read(1024)
        if not chunk:
            continue
        for bb in chunk:
            f = fr.feed(bb)
            if f is not None:
                out.append(f)
    return out


def send_frame_wait(
    ser: serial.Serial,
    pkt: bytes,
    timeout_s: float,
    expect_src: Optional[int] = None,
    expect_dst: Optional[int] = None,
) -> List[Frame]:
    ser.reset_input_buffer()
    ser.write(pkt)
    ser.flush()

    frames = read_frames(ser, timeout_s)
    if expect_src is None and expect_dst is None:
        return frames

    filtered = [
        f for f in frames
        if (expect_src is None or f.src == expect_src) and (expect_dst is None or f.dst == expect_dst)
    ]
    return filtered if filtered else frames


# ---------------- Compression (matches your decoder) ----------------
# Decoder semantics:
#  - literal byte != 0xB4 => output it
#  - 0xB4 0x00 => output literal 0xB4
#  - 0xB4 <offset!=0> <count> => copy <count> bytes from 256-byte ring at (hist_i - offset)

def compress_b4_lz(data: bytes, min_match: int = 4) -> bytes:
    out = bytearray()
    hist = bytearray([0] * 256)
    hist_i = 0

    def hist_put(b: int) -> None:
        nonlocal hist_i
        hist[hist_i] = b & 0xFF
        hist_i = (hist_i + 1) & 0xFF

    def hist_get(offset: int, count: int) -> bytes:
        start = (hist_i - offset) & 0xFF
        return bytes(hist[(start + k) & 0xFF] for k in range(count))

    i = 0
    n = len(data)

    # Build a searchable "window" of the last 255 bytes in history (oldest..newest)
    while i < n:
        best_len = 0
        best_off = 0

        max_len = min(255, n - i)
        window_len = 255
        window = bytes(hist[(hist_i - window_len + k) & 0xFF] for k in range(window_len))

        if max_len >= min_match:
            # try longer matches first, prefer closer matches via rfind
            for L in range(max_len, min_match - 1, -1):
                needle = data[i:i+L]
                pos = window.rfind(needle)
                if pos != -1:
                    match_start_index = (hist_i - 255 + pos) & 0xFF
                    off = (hist_i - match_start_index) & 0xFF
                    if 1 <= off <= 255:
                        best_len = L
                        best_off = off
                        break

        if best_len >= min_match:
            out.append(ESC)
            out.append(best_off)
            out.append(best_len)
            expanded = hist_get(best_off, best_len)
            for b in expanded:
                hist_put(b)
            i += best_len
        else:
            b = data[i]
            if b == ESC:
                out.append(ESC)
                out.append(0x00)
            else:
                out.append(b)
            hist_put(b)
            i += 1

    return bytes(out)


def chunk_bytes(b: bytes, size: int) -> List[bytes]:
    return [b[i:i+size] for i in range(0, len(b), size)]


# ---------------- CLI commands ----------------

def cmd_logmsg(args: argparse.Namespace) -> int:
    ser = open_serial(args.port)
    fr = StreamFramer()
    print(f"[logmsg] Listening on {args.port} @125000 8N2. Ctrl+C to stop.")
    try:
        while True:
            chunk = ser.read(2048)
            if not chunk:
                continue
            for bb in chunk:
                f = fr.feed(bb)
                if f is not None:
                    print(fmt_frame(f))
    except KeyboardInterrupt:
        return 0
    finally:
        ser.close()


def cmd_sendmsg(args: argparse.Namespace) -> int:
    src = int(args.src, 0) & 0xFFFFFF
    dst = int(args.dst, 0) & 0xFFFFFF
    cmd = int(args.cmd, 0) & 0xFF
    payload = hex_bytes(args.payload)

    hdr = ((args.hdr_hi & 0xF) << 4) | (args.hdr_lo & 0xF)
    pkt = build_frame(src, dst, hdr, cmd, payload)

    ser = open_serial(args.port)
    try:
        frames = send_frame_wait(
            ser, pkt,
            timeout_s=args.response_window,
            expect_src=dst if args.filter_reply else None,
            expect_dst=src if args.filter_reply else None,
        )
        print("[sendmsg] Sent:")
        print("  " + pkt.hex())
        print("[sendmsg] Received:")
        if not frames:
            print("  (no valid frames)")
            return 2
        for f in frames:
            print("  " + fmt_frame(f))
        return 0
    finally:
        ser.close()


def cmd_eraseflash(args: argparse.Namespace) -> int:
    """
    Fixed erase range: device firmware erases its own fixed region (e.g., 0x4000..0x60000).
    We therefore send cmd=erase_cmd with EMPTY payload (or optional payload if you force it).
    """
    src = int(args.src, 0) & 0xFFFFFF
    dst = int(args.dst, 0) & 0xFFFFFF
    cmd = int(args.cmd, 0) & 0xFF

    payload = b""  # fixed erase => no args
    hdr = ((args.hdr_hi & 0xF) << 4) | (args.hdr_lo & 0xF)
    pkt = build_frame(src, dst, hdr, cmd, payload)

    ser = open_serial(args.port)
    try:
        frames = send_frame_wait(
            ser, pkt,
            timeout_s=args.response_window,
            expect_src=dst if args.filter_reply else None,
            expect_dst=src if args.filter_reply else None,
        )
        print(f"[eraseflash] Sent erase cmd=0x{cmd:02X} (fixed range, empty payload)")
        ok = any((f.cmd == cmd and len(f.payload) >= 1 and f.payload[0] == ACK) for f in frames)
        for f in frames:
            print("  " + fmt_frame(f))
        return 0 if ok else 2
    finally:
        ser.close()


def cmd_writeflash(args: argparse.Namespace) -> int:
    """
    writeflash:
      - optional erase first (fixed range)
      - compress bin with B4-LZ (firmware decoder)
      - send cmd=data_cmd frames with payload chunks
      - header low nibble is 4-bit sequence counter; device ACKs with payload[0]==0x06
    """
    src = int(args.src, 0) & 0xFFFFFF
    dst = int(args.dst, 0) & 0xFFFFFF
    erase_cmd = int(args.erase_cmd, 0) & 0xFF
    data_cmd = int(args.data_cmd, 0) & 0xFF

    raw = open(args.file, "rb").read()
    print(f"[writeflash] Input: {args.file} size={len(raw)} bytes")

    if args.compress:
        comp = compress_b4_lz(raw, min_match=args.min_match)
        print(f"[writeflash] Compressed: {len(comp)} bytes (ratio={len(comp)/max(1,len(raw)):.3f})")
    else:
        comp = raw
        print("[writeflash] Compression disabled; sending raw bytes")

    ser = open_serial(args.port)
    try:
        # Optional fixed erase
        if not args.no_erase:
            hdr = ((args.hdr_hi & 0xF) << 4) | (args.erase_hdr_lo & 0xF)
            pkt = build_frame(src, dst, hdr, erase_cmd, b"")
            frames = send_frame_wait(
                ser, pkt,
                timeout_s=args.erase_window,
                expect_src=dst if args.filter_reply else None,
                expect_dst=src if args.filter_reply else None,
            )
            if not any((f.cmd == erase_cmd and len(f.payload) >= 1 and f.payload[0] == ACK) for f in frames):
                print("[writeflash] Erase did not ACK; abort.")
                for f in frames:
                    print("  " + fmt_frame(f))
                return 2
            print("[writeflash] Erase ACK.")

        # Stream data chunks
        chunk_len = min(args.chunk_len, MAX_PAYLOAD)
        chunks = chunk_bytes(comp, chunk_len)

        seq = args.seq_start & 0xF
        sent = 0
        retries_total = 0

        for idx, ch in enumerate(chunks):
            hdr = ((args.hdr_hi & 0xF) << 4) | (seq & 0xF)
            pkt = build_frame(src, dst, hdr, data_cmd, ch)

            ok = False
            attempt_used = 0
            for attempt in range(args.retries):
                attempt_used = attempt
                frames = send_frame_wait(
                    ser, pkt,
                    timeout_s=args.response_window,
                    expect_src=dst if args.filter_reply else None,
                    expect_dst=src if args.filter_reply else None,
                )
                if any((f.cmd == data_cmd and len(f.payload) >= 1 and f.payload[0] == ACK) for f in frames):
                    ok = True
                    break
                # NAK => retry same chunk/seq
                if any((f.cmd == data_cmd and len(f.payload) >= 1 and f.payload[0] == NAK_SEQ) for f in frames):
                    time.sleep(args.retry_delay)
                    continue
                time.sleep(args.retry_delay)

            if not ok:
                print(f"[writeflash] Chunk {idx+1}/{len(chunks)} failed (seq={seq}).")
                for f in frames:
                    print("  " + fmt_frame(f))
                return 2

            sent += len(ch)
            retries_total += attempt_used

            if args.progress:
                pct = 100.0 * sent / max(1, len(comp))
                print(f"[writeflash] {idx+1}/{len(chunks)} seq={seq} sent={sent}/{len(comp)} ({pct:.1f}%)")

            seq = (seq + 1) & 0xF

        print(f"[writeflash] Done. sent={sent} bytes, total_retries={retries_total}")
        return 0
    finally:
        ser.close()


def cmd_verifyflash(args: argparse.Namespace) -> int:
    """
    verifyflash:
      - compute CRC16-CCITT of local file
      - send verify command with payload:
          reserved[0..3] (default 00000000)
          length[4..7] u32 BE
          crc[8..9] u16 BE
      - device replies payload[0]==0x06 success or 0x19 failure (per RE)
    """
    src = int(args.src, 0) & 0xFFFFFF
    dst = int(args.dst, 0) & 0xFFFFFF
    cmd = int(args.cmd, 0) & 0xFF

    raw = open(args.file, "rb").read()
    length = len(raw)
    crc = crc16_ccitt(raw, 0xFFFF)

    reserved = b"\x00\x00\x00\x00" if not args.reserved else hex_bytes(args.reserved)
    if len(reserved) != 4:
        raise ValueError("--reserved must be exactly 4 bytes (8 hex chars)")

    payload = reserved + length.to_bytes(4, "big") + crc.to_bytes(2, "big")

    hdr = ((args.hdr_hi & 0xF) << 4) | (args.hdr_lo & 0xF)
    pkt = build_frame(src, dst, hdr, cmd, payload)

    ser = open_serial(args.port)
    try:
        frames = send_frame_wait(
            ser, pkt,
            timeout_s=args.response_window,
            expect_src=dst if args.filter_reply else None,
            expect_dst=src if args.filter_reply else None,
        )
        print(f"[verifyflash] file={args.file} len={length} crc=0x{crc:04X} cmd=0x{cmd:02X}")
        ok = any((f.cmd == cmd and len(f.payload) >= 1 and f.payload[0] == ACK) for f in frames)
        for f in frames:
            print("  " + fmt_frame(f))
        return 0 if ok else 2
    finally:
        ser.close()


# ---------------- main ----------------

def main() -> int:
    p = argparse.ArgumentParser(
        description="UART bus CLI @125000 8N2 (SOF=0x32, EOF=0x34, CRC16-CCITT)"
    )
    p.add_argument("--port", default="/dev/ttyUSB0", help="Serial port (default: /dev/ttyUSB0)")

    sub = p.add_subparsers(dest="subcmd", required=True)

    sp = sub.add_parser("logmsg", help="Parse received frames and print them")
    sp.set_defaults(func=cmd_logmsg)

    sp = sub.add_parser("sendmsg", help="Assemble and send a frame, then print response(s)")
    sp.add_argument("--src", default="0x000000", help="24-bit source address (you can set later)")
    sp.add_argument("--dst", required=True, help="24-bit destination board address")
    sp.add_argument("--cmd", required=True, help="Command byte (e.g. 0x40)")
    sp.add_argument("--payload", default="", help="Payload hex bytes (e.g. '0102A0FF')")
    sp.add_argument("--hdr-hi", type=int, default=0, help="Header high nibble (0-15)")
    sp.add_argument("--hdr-lo", type=int, default=0, help="Header low nibble (0-15)")
    sp.add_argument("--response-window", type=float, default=0.7, help="Seconds to wait for replies")
    sp.add_argument("--filter-reply", action="store_true",
                    help="Filter replies to only frames with src==dst and dst==src")
    sp.set_defaults(func=cmd_sendmsg)

    sp = sub.add_parser("eraseflash", help="Send fixed-range erase command (empty payload)")
    sp.add_argument("--src", default="0x000000", help="24-bit source address")
    sp.add_argument("--dst", required=True, help="24-bit destination board address")
    sp.add_argument("--cmd", default="0x20", help="Erase command byte (default 0x20)")
    sp.add_argument("--hdr-hi", type=int, default=0, help="Header high nibble (0-15)")
    sp.add_argument("--hdr-lo", type=int, default=0, help="Header low nibble (0-15)")
    sp.add_argument("--response-window", type=float, default=5.0, help="Seconds to wait for ACK")
    sp.add_argument("--filter-reply", action="store_true", help="Filter reply src/dst match")
    sp.set_defaults(func=cmd_eraseflash)

    sp = sub.add_parser("writeflash", help="(optional) fixed erase, then compress+stream bin via cmd 0x40")
    sp.add_argument("--src", default="0x000000", help="24-bit source address")
    sp.add_argument("--dst", required=True, help="24-bit destination board address")
    sp.add_argument("file", help="Uncompressed bin file to write")
    sp.add_argument("--erase-cmd", default="0x20", help="Erase command byte (default 0x20)")
    sp.add_argument("--data-cmd", default="0x40", help="Data command byte (default 0x40)")
    sp.add_argument("--no-erase", action="store_true", help="Skip erase step")
    sp.add_argument("--erase-window", type=float, default=8.0, help="Seconds to wait for erase ACK")
    sp.add_argument("--compress", action="store_true", help="Enable 0xB4 LZ-style compression")
    sp.add_argument("--min-match", type=int, default=4, help="Compression min match length (default 4)")
    sp.add_argument("--chunk-len", type=int, default=256, help=f"Chunk size (<= {MAX_PAYLOAD})")
    sp.add_argument("--seq-start", type=int, default=1, help="Initial seq nibble (0-15), default 1")
    sp.add_argument("--hdr-hi", type=int, default=0, help="Header high nibble (0-15)")
    sp.add_argument("--erase-hdr-lo", type=int, default=0, help="Low nibble for erase frame header")
    sp.add_argument("--response-window", type=float, default=0.7, help="Seconds to wait for per-chunk ACK")
    sp.add_argument("--retries", type=int, default=8, help="Retries per chunk")
    sp.add_argument("--retry-delay", type=float, default=0.03, help="Delay between retries (seconds)")
    sp.add_argument("--progress", action="store_true", help="Print progress per chunk")
    sp.add_argument("--filter-reply", action="store_true", help="Filter reply src/dst match")
    sp.set_defaults(func=cmd_writeflash)

    sp = sub.add_parser("verifyflash", help="Send verify request derived from local bin (len+CRC)")
    sp.add_argument("--src", default="0x000000", help="24-bit source address")
    sp.add_argument("--dst", required=True, help="24-bit destination board address")
    sp.add_argument("--cmd", default="0x50", help="Verify command byte (default 0x50)")
    sp.add_argument("file", help="Bin file to verify against")
    sp.add_argument("--reserved", default="", help="4 reserved bytes (8 hex chars), default 00000000")
    sp.add_argument("--hdr-hi", type=int, default=0, help="Header high nibble (0-15)")
    sp.add_argument("--hdr-lo", type=int, default=0, help="Header low nibble (0-15)")
    sp.add_argument("--response-window", type=float, default=1.2, help="Seconds to wait for response")
    sp.add_argument("--filter-reply", action="store_true", help="Filter reply src/dst match")
    sp.set_defaults(func=cmd_verifyflash)

    args = p.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
