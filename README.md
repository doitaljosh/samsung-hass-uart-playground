### Samsung HASS UART bus playground

A small Python command-line tool for talking to Samsung appliance boards over the HASS UART protocol at **125000 baud, 8N2**. It supports:

- Live bus logging with frame parsing + CRC validation
- Sending a single framed message and printing responses
- Fixed-range flash erase (device-side fixed erase region)
- Flash write (optional erase → optional compression → sequenced chunk stream)
- Flash verify (build verify request from a local `.bin` file)

This repo is designed for Linux (e.g., `/dev/ttyUSB0`) but works anywhere `pyserial` works.

---

## Protocol Summary (Wire Format)

Frames are encoded like this:

| Field | Size | Notes |
|------:|-----:|------|
| SOF | 1 | `0x32` |
| SRC | 3 | 24-bit big-endian source address |
| DST | 3 | 24-bit big-endian destination address |
| HDR | 1 | High + low nibble (often used for sequencing) |
| CMD | 1 | Command byte |
| LEN | 2 | Payload length, big-endian |
| PAYLOAD | N | `LEN` bytes |
| CRC16 | 2 | CRC-16/CCITT, poly `0x1021`, init `0xFFFF`, big-endian |
| EOF | 1 | `0x34` |

CRC is computed over everything **after SOF** through end of payload:

`SRC..DST..HDR..CMD..LEN..PAYLOAD`

# Clone and run:

```
git clone https://github.com/doitaljosh/samsung-hass-uart-playground.git
cd samsung-hass-uart-playground
python3 hass-uart.py
```

# Quick Start

1. Log bus traffic (decoded frames):

```
python3 hass-uart.py logmsg --port /dev/ttyUSB0
```
You'll see decoded frames like:
- SRC/DST (24-bit)
- Header high/low nibbles
- CMD byte
- Payload length + hex payload string
- CRC value

2. Send a single message:

```
python3 hass-uart.py sendmsg \
  --dst 0x123456 \
  --cmd 0x10 \
  --payload "DEADBEEF" \
  --hdr-lo 1

```
To ignore unrelated bus traffic and only show direct replies (matching ```src=dst``` and ```dst=src```), add:
```
--filter-reply
```

# Commands

`logmsg`
Continuously reads /dev/ttyUSB0, parses valid frames, and prints them.
```
python3 hass-uart.py logmsg --port /dev/ttyUSB0

```

`sendmsg`
Builds a frame from SRC/DST/CMD/PAYLOAD + HDR nibbles, sends it, then prints any valid response frames.
```
python3 hass-uart.py sendmsg --dst 0x123456 --cmd 0x40 --payload "01020304" --hdr-lo 2

```
Options:
`--src` (default `0x000000`)
`--dst` (required)
`--cmd` (required)
`--payload` hex string (optional)
`--hdr-hi`/`--hdr-lo` (optional)
`--response-window` seconds to listen for a reply message
`--filter-reply` to show only direct replies

`eraseflash`
Sends the fixed-range erase command.
This implementation deliberately uses empty payload because the device firmware performs an internal fixed erase range (e.g., starting at 0x4000 through its programmed region).
```
python3 hass-uart.py eraseflash --dst 0x123456
```
Options:
`--cmd` (default `0x20`)
`--hdr-hi`/`--hdr-lo`
`--response-window`
`--filter-reply`

`writeflash`
Streams a firmware file to flash:
1. (optional) send erase (cmd 0x20)
2. (optional) compress file using the firmware’s decoder-compatible scheme
3. send sequenced chunks using cmd 0x40 (sequence is the HDR low nibble (0–15, wraps))
```
python3 hass-uart.py writeflash --dst 0x123456 firmware.bin --compress --progress

```
Common options:
`--no-erase` : skip erase
`--compress` : enable compression (recommended if your device expects compressed payloads)
`--chunk-len` : payload size per frame (default 256, max 768)
`--seq-start` : starting sequence nibble (default 1)
`--retries`/`retry-delay` : retry behavior on NAK/timeouts
`--filter-reply` : only accept direct replies
ACK/NAK behavior:
- ACK payload byte `0x06` indicates success
- ACK payload byte `0x15` indicates sequence error/retry

`verifyflash`
Computes CRC16-CCITT from a local `.bin` file and sends a verify request

Payload laout:
- bytes `[0..3]` reserved (default `00 00 00 00`)
- bytes `[4..7]` length (u32 big-endian)
- bytes `[8..9]` expected CRC (u16 big-endian)

```
python3 hass-uart.py verifyflash --dst 0x123456 firmware.bin
```

Options:
`--cmd` (default `0x50`)
`--reserved` (8 hex chars, optional)
`--filter-reply`

Expected responses:
`0x06` = verify OK
`0x19` = verify failed (mismatch)

# Compression Format (B4-LZ)

When `--compress` is enabled, the tool uses a byte-oriented scheme compatible with the firmware’s decoder:

Literal byte `X` (`X != 0xB4`) → emit `X`
Literal `0xB4` → emit `0xB4 0x00`
Backref → emit `0xB4 <offset:1..255> <count:1..255>`

The device maintains a 256-byte rolling history buffer and for backrefs copies:

```
count bytes from (hist_index - offset) mod 256
```

# Notes/Tips

If multiple devices share the UART bus, use --filter-reply on commands to focus on replies addressed back to your SRC address.
If you don’t know the destination address yet, sniff with logmsg first and identify the target node.
If you see no replies, confirm:
- stop bits 2 (8N2)
- baud 125000
- TX/RX swapped correctly
- shared ground
- your adapter supports non-standard baud rates cleanly

# Safety/Disclaimer

This tool can erase/program flash on compatible targets. Use it only on boards you own or are explicitly authorized to modify, and verify your wiring and addressing before issuing erase/write commands.
