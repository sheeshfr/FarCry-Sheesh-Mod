import array
import json
import math
import os
import shutil
import struct
import sys
import zipfile
import zlib

REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VOICE_GAIN = 1.25
VOICE_KNEE = 0.90
VOICE_HEADROOM = 0.095


def xor_bytes(a: bytes, b: bytes) -> bytes:
    la, lb = len(a), len(b)
    m = max(la, lb)
    if m == 0:
        return b""
    a_pad = a + b"\x00" * (m - la)
    b_pad = b + b"\x00" * (m - lb)
    return (int.from_bytes(a_pad, "little") ^ int.from_bytes(b_pad, "little")).to_bytes(m, "little")


def should_boost_voice(arc_lower: str) -> bool:
    if not arc_lower.endswith(".wav"):
        return False
    return (
        arc_lower.startswith("languages/missiontalk/")
        or arc_lower.startswith("languages/voicepacks/krieger/")
        or arc_lower.startswith("languages/voicepacks/mission_generic/")
        or arc_lower.startswith("languages/voicepacks/val/affirmative_")
        or arc_lower.startswith("languages/voicepacks/val/receive_")
    )


def build_pcm16_lut() -> list:
    lut = [0] * 65536
    for i in range(65536):
        s = i if i < 32768 else i - 65536
        x = (s / 32768.0) * VOICE_GAIN
        ax = abs(x)
        if ax <= VOICE_KNEE:
            y = x
        else:
            sign = 1.0 if x >= 0.0 else -1.0
            excess = ax - VOICE_KNEE
            y = sign * (VOICE_KNEE + VOICE_HEADROOM * math.tanh(excess / VOICE_HEADROOM))
        out_s = int(round(y * 32768.0))
        if out_s > 32767:
            out_s = 32767
        elif out_s < -32767:
            out_s = -32767
        lut[i] = out_s
    return lut


def boost_wav_bytes(wav_bytes: bytes, lut: list) -> tuple[bytes, bool]:
    if len(wav_bytes) < 12 or wav_bytes[:4] != b"RIFF" or wav_bytes[8:12] != b"WAVE":
        return wav_bytes, False

    pos = 12
    fmt_code = None
    bits = None
    chunks = []
    boosted_any = False

    while pos + 8 <= len(wav_bytes):
        cid = wav_bytes[pos : pos + 4]
        csz = struct.unpack_from("<I", wav_bytes, pos + 4)[0]
        data_start = pos + 8
        data_end = min(len(wav_bytes), data_start + csz)
        payload = wav_bytes[data_start:data_end]

        if cid == b"fmt " and len(payload) >= 16:
            fmt_code, _ch, _sr, _br, _ba, bits = struct.unpack_from("<HHIIHH", payload, 0)
        elif cid == b"data" and fmt_code == 1 and bits == 16 and len(payload) >= 2:
            even_len = len(payload) & ~1
            arr = array.array("h")
            arr.frombytes(payload[:even_len])
            out_arr = array.array("h", (lut[v & 0xFFFF] for v in arr))
            payload = out_arr.tobytes() + payload[even_len:]
            boosted_any = True

        chunks.append((cid, payload))
        pos = data_start + csz + (csz & 1)

    if not boosted_any:
        return wav_bytes, False

    body = bytearray(b"WAVE")
    for cid, payload in chunks:
        body.extend(cid)
        body.extend(struct.pack("<I", len(payload)))
        body.extend(payload)
        if len(payload) & 1:
            body.append(0)

    out = bytearray(b"RIFF")
    out.extend(struct.pack("<I", len(body)))
    out.extend(body)
    return bytes(out), True


def generate_boosted_voices_pak(game_dir: str) -> int:
    eng_pak = os.path.join(game_dir, "FCData", "Localized", "english.pak")
    if not os.path.isfile(eng_pak):
        return 0

    out_pak = os.path.join(game_dir, "FCData", "zz_sheesh_voices.pak")
    tmp_pak = out_pak + ".tmp"
    lut = build_pcm16_lut()
    boosted_count = 0

    with zipfile.ZipFile(eng_pak, "r") as zin, zipfile.ZipFile(tmp_pak, "w", compression=zipfile.ZIP_STORED) as zout:
        for info in zin.infolist():
            if info.is_dir():
                continue
            low = info.filename.replace("\\", "/").lower()
            if not should_boost_voice(low):
                continue
            data, ok = boost_wav_bytes(zin.read(info.filename), lut)
            if ok:
                zi = zipfile.ZipInfo(filename=info.filename.replace("\\", "/"), date_time=info.date_time)
                zi.compress_type = zipfile.ZIP_STORED
                zi.external_attr = info.external_attr
                zout.writestr(zi, data)
                boosted_count += 1

    if boosted_count > 0:
        os.replace(tmp_pak, out_pak)
    elif os.path.exists(tmp_pak):
        os.remove(tmp_pak)
    return boosted_count


def main():
    if len(sys.argv) < 2:
        game_dir = input("Enter path to your Far Cry installation folder: ").strip().strip('"')
    else:
        game_dir = sys.argv[1].strip().strip('"')

    obj_pak = os.path.join(game_dir, "FCData", "Objects.pak")
    if not os.path.exists(obj_pak):
        print(f"ERROR: Could not find FCData\\Objects.pak in {game_dir}")
        sys.exit(1)

    with open(obj_pak, "rb") as f:
        bv_ref = f.read(15 * 1024 * 1024)

    with open(os.path.join(REPO_DIR, "deltas", "manifest.json"), "r", encoding="utf-8") as f:
        manifest = json.load(f)

    pak_cache = {}

    def get_pak(pak_rel):
        if pak_rel not in pak_cache:
            pak_cache[pak_rel] = zipfile.ZipFile(os.path.join(game_dir, pak_rel), "r")
        return pak_cache[pak_rel]

    entries = manifest["entries"]
    print(f"Applying Far Cry — Sheesh! Mod ({manifest['version']}) — {len(entries)} records...")
    for e in entries:
        op = e["op"]
        dst = os.path.join(game_dir, e["target"])
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if op == "COPY_ASSET":
            src = os.path.join(REPO_DIR, e["asset_file"].replace("/", os.sep))
            shutil.copy2(src, dst)
        elif op == "EXTRACT_FROM_PAK":
            data = get_pak(e["source_pak"]).read(e["pak_entry"])
            with open(dst, "wb") as fo:
                fo.write(data)
        elif op == "DELTA_REF_OBJECTS_PAK":
            comp = open(os.path.join(REPO_DIR, e["delta_file"].replace("/", os.sep)), "rb").read()
            raw_xor = zlib.decompress(comp)
            out = xor_bytes(bv_ref[: e["size"]], raw_xor)[: e["size"]]
            with open(dst, "wb") as fo:
                fo.write(out)
        elif op == "DELTA_AGAINST_PAK_ENTRY":
            v_bytes = get_pak(e["source_pak"]).read(e["pak_entry"])
            comp = open(os.path.join(REPO_DIR, e["delta_file"].replace("/", os.sep)), "rb").read()
            raw_xor = zlib.decompress(comp)
            out = xor_bytes(v_bytes, raw_xor)[: e["size"]]
            with open(dst, "wb") as fo:
                fo.write(out)

    for zf in pak_cache.values():
        zf.close()

    voices = generate_boosted_voices_pak(game_dir)
    if voices > 0:
        print(f"Generated FCData\\zz_sheesh_voices.pak ({voices} story dialogue clips boosted +25%).")
    print("SUCCESS! Far Cry — Sheesh! Mod has been applied.")


if __name__ == "__main__":
    main()
