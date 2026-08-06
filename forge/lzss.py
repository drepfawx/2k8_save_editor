"""lzss.py -- LZSS block decoder for this engine's compressed forge/save sections.

Bit-packed format: each control bit selects a literal byte (0) or a match (1). A match is either
"short" (1 more control bit, 2 bytes: offset-1, 2-bit length) or "long" (2 bytes: 5-bit offset-low
+ 8-bit offset-high + 3-bit length, with length 0 meaning an extended/escape length that continues
reading extra length bytes, and offset 0 in that case marking end-of-block).
"""


def lzss_block(src, ip):
    """Decode one LZSS block starting at byte offset `ip` in `src`. Returns (decoded_bytes,
    bytes_consumed)."""
    out = bytearray()
    bb = 0
    bc = 0
    start = ip

    def need(n):
        nonlocal bb, bc, ip
        while bc < n:
            bb |= src[ip] << bc
            ip += 1
            bc += 8

    while True:
        need(1)
        bit = bb & 1
        bb >>= 1
        bc -= 1
        if bit == 0:
            out.append(src[ip])
            ip += 1
            continue
        need(1)
        tb = bb & 1
        bb >>= 1
        bc -= 1
        if tb == 0:
            need(2)
            length = (bb & 3) + 2
            bb >>= 2
            bc -= 2
            o = src[ip]
            ip += 1
            m = len(out) - o - 1
            for _ in range(length):
                out.append(out[m])
                m += 1
        else:
            b0 = src[ip]
            b1 = src[ip + 1]
            ip += 2
            o = (b1 << 5) | (b0 & 0x1f)
            l3 = b0 >> 5
            m = len(out) - o
            if l3 == 0:
                length = 9
                while src[ip] == 0:
                    length += 0xff
                    ip += 1
                length += src[ip]
                ip += 1
            else:
                if o == 0:
                    break
                length = l3 + 2
            for _ in range(length):
                out.append(out[m])
                m += 1
    return bytes(out), ip - start
