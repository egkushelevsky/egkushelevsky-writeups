#!/usr/bin/env python3

import base64
import struct
import sys

WAV = "youcanstealmystuff.wav"
PART1 = "csaw{but_y0u_"
PART4 = "bIxtsWGHgeV9"
VIGENERE_KEY = "almostthere"


def riff_info(path):
    data = open(path, "rb").read()
    assert data[:4] == b"RIFF" and data[8:12] == b"WAVE"
    off, info = 12, {}
    while off + 8 <= len(data):
        cid, size = data[off:off + 4], struct.unpack("<I", data[off + 4:off + 8])[0]
        body = data[off + 8:off + 8 + size]
        if cid == b"LIST" and body[:4] == b"INFO":
            p = 4
            while p + 8 <= len(body):
                sid, ssz = body[p:p + 4], struct.unpack("<I", body[p + 4:p + 8])[0]
                info[sid.decode()] = body[p + 8:p + 8 + ssz].rstrip(b"\0").decode()
                p += 8 + ssz + (ssz & 1)
        off += 8 + size + (size & 1)
    return info


def vigenere_decrypt(text, key):
    out, j = [], 0
    for char in text:
        if char.isalpha():
            # shift letters
            base = ord("A") if char.isupper() else ord("a")
            shift = ord(key[j % len(key)]) - ord("a")
            out.append(chr((ord(char) - base - shift) % 26 + base))
            j += 1
        else:
            # don’t shift numbers or symbols
            out.append(char)
    return "".join(out)


def write_hidden_voice(out):
    import wave
    import numpy as np
    from pedalboard import Pedalboard, PitchShift
    with wave.open(WAV) as w:
        rate = w.getframerate()
        x = np.frombuffer(w.readframes(w.getnframes()), "<i2").reshape(-1, 2)

    # clip from time 22.4 to 26.4 for some wiggle room
    right = x[int(22.4 * rate):int(26.4 * rate), 1].astype(np.float32) / 32768

    # shift down by 57 semitones
    y = Pedalboard([PitchShift(semitones=-57)])(right[None].copy(), rate)[0]
    y = (y / np.abs(y).max() * 0.8 * 32767).astype("<i2")
    with wave.open(out, "wb") as o:
        o.setnchannels(1); o.setsampwidth(2); o.setframerate(rate)
        o.writeframes(y.tobytes())
    print(f"wrote {out}")


def main():
    if len(sys.argv) == 2:
        write_hidden_voice(sys.argv[1])
        return
    info = riff_info(WAV)
    print("Encoded flag portion:", info.get("ICRD"))
    parts = []
    for ciphertext in (info["ICRD"], PART4):
        shifted = vigenere_decrypt(ciphertext, VIGENERE_KEY)
        plain = base64.b64decode(shifted).decode()
        print(f"{ciphertext} -> {shifted} -> {plain}")
        parts.append(plain)
    print("\n" + PART1 + "".join(parts))


if __name__ == "__main__":
    main()
