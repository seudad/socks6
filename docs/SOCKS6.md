# SOCKS6 Protocol Specification — Version 1

## Overview

SOCKS6 is a binary proxy protocol for TCP and UDP relaying. It is **not**
wire-compatible with SOCKS5 (RFC 1928). Only SOCKS6 clients and servers can
interoperate.

Key differences from SOCKS5:

| Property | SOCKS5 | SOCKS6 |
|---|---|---|
| Version byte | `0x05` | `0x06` |
| RSV byte in request/reply | present | removed |
| TLV options in request/reply | none | `OPTLEN + OPTIONS` appended |
| Transport assumption | raw TCP | designed for TLS / Reality tunnel |

## 1. Client Greeting

```
+------+----------+----------+
| VER  | NMETHODS | METHODS  |
+------+----------+----------+
| 0x06 |  uint8   | uint8[]  |
+------+----------+----------+
```

- `NMETHODS` — number of method identifiers in `METHODS` (1–255).
- Each byte in `METHODS` identifies an authentication method.

### Method Identifiers

| Value | Meaning |
|-------|---------|
| `0x00` | No authentication |
| `0x02` | Username / Password |
| `0xFF` | No acceptable methods (server only) |

## 2. Server Choice

```
+------+--------+
| VER  | METHOD |
+------+--------+
| 0x06 | uint8  |
+------+--------+
```

- If `METHOD == 0xFF` the server rejects the connection; no further data is
  exchanged and the TCP connection is closed.

## 3. Username / Password Authentication (METHOD `0x02`)

Identical to RFC 1929 sub-negotiation:

```
Client → Server:
+-----+------+----------+------+----------+
| VER | ULEN | USERNAME | PLEN | PASSWORD |
+-----+------+----------+------+----------+
| 0x01| uint8| bytes    | uint8| bytes    |
+-----+------+----------+------+----------+

Server → Client:
+-----+--------+
| VER | STATUS |
+-----+--------+
| 0x01| uint8  |
+-----+--------+
```

`STATUS == 0x00` means success; any other value means failure (connection closed).

## 4. Request

```
+------+-----+------+----------+----------+--------+---------+
| VER  | CMD | ATYP | DST.ADDR | DST.PORT | OPTLEN | OPTIONS |
+------+-----+------+----------+----------+--------+---------+
| 0x06 | u8  | u8   | variable | u16 BE   | u16 BE | TLV[]   |
+------+-----+------+----------+----------+--------+---------+
```

There is **no RSV** byte between `CMD` and `ATYP`.

### CMD Values

| Value | Meaning |
|-------|---------|
| `0x01` | CONNECT |
| `0x03` | UDP ASSOCIATE |

### ATYP / Address Encoding

| ATYP | Format |
|------|--------|
| `0x01` | IPv4 — 4 octets |
| `0x03` | Domain — 1 byte length + UTF-8 domain name (max 255 bytes) |
| `0x04` | IPv6 — 16 octets |

`DST.PORT` is 2 bytes, network byte order (big-endian).

### OPTIONS (TLV)

Zero or more type-length-value entries concatenated:

```
+------+--------+-------+
| TYPE | LENGTH | VALUE |
+------+--------+-------+
| u16  | u16    | bytes |
+------+--------+-------+
```

If `OPTLEN == 0` there are no option entries. Unknown option types MUST be
silently ignored by the receiver.

Reserved option types (version 1):

| Type | Name | Description |
|------|------|-------------|
| `0x0001` | Padding | Value is ignored; used for traffic shaping |

## 5. Reply

```
+------+-----+------+----------+----------+--------+---------+
| VER  | REP | ATYP | BND.ADDR | BND.PORT | OPTLEN | OPTIONS |
+------+-----+------+----------+----------+--------+---------+
| 0x06 | u8  | u8   | variable | u16 BE   | u16 BE | TLV[]   |
+------+-----+------+----------+----------+--------+---------+
```

No RSV byte. Address and options encoding is the same as in the request.

### Reply Codes

| Value | Meaning |
|-------|---------|
| `0x00` | Succeeded |
| `0x01` | General failure |
| `0x02` | Connection not allowed by ruleset |
| `0x03` | Network unreachable |
| `0x04` | Host unreachable |
| `0x05` | Connection refused |
| `0x07` | Command not supported |
| `0x08` | Address type not supported |

After a successful `CONNECT` reply (`REP == 0x00`), the connection enters
**relay mode**: raw bytes are forwarded bidirectionally between client and
destination without any further framing.

## 6. UDP Datagram Header

After a successful `UDP ASSOCIATE`, datagrams are carried inside the tunnel
using length-prefixed framing (`u16 BE` length prefix per datagram). Each
datagram starts with:

```
+-----+------+------+----------+----------+---------+
| RSV | FRAG | ATYP | DST.ADDR | DST.PORT | PAYLOAD |
+-----+------+------+----------+----------+---------+
| u16 | u8   | u8   | variable | u16 BE   | bytes   |
+-----+------+------+----------+----------+---------+
```

`RSV` is `0x0000`. Fragmentation (`FRAG != 0`) SHOULD be silently dropped
by implementations that do not support it.

## 7. State Machine

```
Client                           Server
  |                                |
  |--- Client Greeting ---------->|
  |<-- Server Choice -------------|
  |                                |
  |  [if METHOD == 0x02]           |
  |--- Auth sub-negotiation ----->|
  |<-- Auth result ---------------|
  |                                |
  |--- Request ------------------>|
  |<-- Reply ---------------------|
  |                                |
  |  [if CONNECT succeeded]        |
  |<===== bidirectional relay ====>|
  |                                |
  |  [if UDP ASSOCIATE succeeded]  |
  |<= length-prefixed datagrams =>|
```

## 8. Wire Examples (hex)

### Greeting — no auth

```
Client → 06 01 00
Server ← 06 00
```

### CONNECT to example.com:80, no options

```
Client → 06 01 03 0b 65 78 61 6d 70 6c 65 2e 63 6f 6d 00 50 00 00
         VER CMD ATYP LEN ------- "example.com" -------  PORT  OPTLEN

Server ← 06 00 01 c0 a8 01 01 1f 90 00 00
         VER REP ATYP -- 192.168.1.1 -- PORT  OPTLEN
```

### Error reply — host unreachable

```
Server ← 06 04 01 00 00 00 00 00 00 00 00
         VER REP ATYP -- 0.0.0.0 --  PORT  OPTLEN
```
