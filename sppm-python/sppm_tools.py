"""Read, preview, and convert Switchnote Studio SPPM files."""
from __future__ import annotations

import array
import hashlib
import hmac
import os
import shutil
import struct
import subprocess
import tempfile
import wave
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional, Union

import numpy as np
from PIL import Image

WIDTH, HEIGHT = 640, 360
PIXELS = WIDTH * HEIGHT
HEADER_SIZE = 36
MAX_FILE_SIZE = 512 * 1024 * 1024
MAX_AUDIO_SAMPLES = 32 * 1024 * 1024
PUBLIC_FOOTER_SIZE = 4 + 3 * 48 + 64
Input = Union[str, os.PathLike, bytes, bytearray, memoryview]


class SppmError(ValueError):
    """Malformed, unsupported, or damaged SPPM input."""


@dataclass
class AudioTrack:
    index: int
    channels: int
    reference_fps: int
    sample_rate: int
    name: str
    frame_triggers: list[int]
    pcm: array.array
    reference_speed: int = 0


@dataclass
class SppmNote:
    metadata: dict
    palette: list[tuple[int, int, int, int]]
    # Each frame stores four validated RLE byte strings, A through D.
    frames: list[tuple[memoryview, ...]]
    audio_tracks: list[AudioTrack]
    signature: dict


def _read_input(source: Input) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    else:
        data = Path(source).read_bytes()
    if len(data) < HEADER_SIZE or len(data) > MAX_FILE_SIZE + PUBLIC_FOOTER_SIZE + 36:
        raise SppmError("file size outside supported limits")
    return data


class _Reader:
    def __init__(self, data: bytes | memoryview, end: Optional[int] = None):
        self.data = memoryview(data)
        self.end = len(self.data) if end is None else end
        self.at = 0

    def take(self, size: int) -> memoryview:
        if size < 0 or size > self.end - self.at:
            raise SppmError("truncated payload")
        start = self.at
        self.at += size
        return self.data[start:self.at]

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]

    def string(self, maximum: int) -> str:
        size = self.u16()
        if size > maximum:
            raise SppmError("metadata string exceeds limit")
        raw = bytes(self.take(size))
        if b"\0" in raw:
            raise SppmError("metadata contains NUL")
        try:
            return raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise SppmError("metadata is not valid UTF-8") from exc

    def id(self, optional: bool = False) -> str:
        value = bytes(self.take(16)).decode("ascii", "strict")
        if optional and value == "0" * 16:
            return ""
        if len(value) != 16 or any(c not in "0123456789abcdefABCDEF" for c in value) or value == "0" * 16:
            raise SppmError("invalid lineage ID")
        return value.upper()


def _validate_rle(encoded: memoryview) -> None:
    src = 0
    output = 0
    while src < len(encoded):
        command = encoded[src]
        src += 1
        count = (command & 0x7F) + 1
        if output + count > PIXELS:
            raise SppmError("RLE layer expands beyond canvas size")
        if command & 0x80:
            if src >= len(encoded):
                raise SppmError("truncated RLE repeat packet")
            src += 1
        else:
            if src + count > len(encoded):
                raise SppmError("truncated RLE literal packet")
            src += count
        output += count
    if output != PIXELS:
        raise SppmError("RLE layer has incorrect decoded size")


def _decode_layer(encoded: memoryview) -> bytes:
    out = bytearray(PIXELS)
    src = 0
    dst = 0
    while src < len(encoded):
        command = encoded[src]
        src += 1
        count = (command & 0x7F) + 1
        if command & 0x80:
            value = encoded[src]
            src += 1
            out[dst:dst + count] = bytes((value,)) * count
        else:
            out[dst:dst + count] = encoded[src:src + count]
            src += count
        dst += count
    return bytes(out)


def _identity_fsid(key: bytes, tag: bytes) -> str:
    if not any(key) or not any(tag):
        return ""
    digest = hashlib.sha256(b"FlipnoteNX-public-fsid-v2\0" + key + tag).digest()
    return digest[:8].hex().upper()


def _verify_public_signature(body: bytes, footer: memoryview) -> tuple[dict, list[tuple[bytes, bytes]]]:
    fr = _Reader(footer)
    if bytes(fr.take(4)) != b"SPP3":
        raise SppmError("invalid public-signature marker")
    identities = [(bytes(fr.take(32)), bytes(fr.take(16))) for _ in range(3)]
    signature = bytes(fr.take(64))
    if fr.at != fr.end or not any(identities[2][0]) or not any(identities[2][1]):
        raise SppmError("invalid public identity footer")
    digest = hashlib.sha256(
        b"FlipnoteNX-SPPM-public-signature-v3\0" + body + b"".join(k + tag for k, tag in identities)
    ).digest()
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(identities[2][0]).verify(signature, digest)
        status = "verified"
    except ImportError:
        status = "present-unverified"
    except Exception as exc:
        raise SppmError("public signature verification failed") from exc
    return {"status": status, "algorithm": "Ed25519"}, identities


def read_sppm(source: Input, *, legacy_hmac_key: Optional[bytes] = None) -> SppmNote:
    """Parse and structurally validate an SPPM note. V3 signature verification uses optional `cryptography`."""
    data = _read_input(source)
    if data[:4] != b"SPPM":
        raise SppmError("bad file magic")
    body_end = len(data)
    signature = {"status": "unsigned"}
    identities = None
    public_at = len(data) - PUBLIC_FOOTER_SIZE
    if public_at >= HEADER_SIZE and data[public_at:public_at + 4] == b"SPP3":
        body_end = public_at
        signature, identities = _verify_public_signature(data[:body_end], memoryview(data)[public_at:])
    elif len(data) >= HEADER_SIZE + 36 and data[-36:-32] == b"SPPS":
        body_end = len(data) - 36
        signature = {"status": "present-unverified", "algorithm": "HMAC-SHA-256"}
        if legacy_hmac_key is not None:
            valid = hmac.compare_digest(hmac.new(legacy_hmac_key, data[:body_end], hashlib.sha256).digest(), data[-32:])
            if not valid:
                raise SppmError("legacy HMAC verification failed")
            signature["status"] = "verified"

    body = memoryview(data)[:body_end]
    r = _Reader(body)
    r.take(4)
    version, header_size = r.u16(), r.u16()
    total_size, expected_crc = r.u64(), r.u32()
    width, height, layer_count, palette_count, fps, flags = r.u16(), r.u16(), r.u8(), r.u16(), r.u8(), r.u8()
    frame_count, audio_count, reserved = r.u32(), r.u8(), r.u16()
    if (version not in (1, 2, 3) or header_size != HEADER_SIZE or total_size != len(body) or
        width != WIDTH or height != HEIGHT or layer_count != 4 or palette_count != 256 or
        not 1 <= fps <= 30 or not 1 <= frame_count <= 9999 or audio_count > 4 or (reserved != 0 if version < 3 else reserved > 8) or
        (flags & ~(3 if version == 1 else 15))):
        raise SppmError("unsupported SPPM header")
    if zlib.crc32(body[HEADER_SIZE:]) & 0xFFFFFFFF != expected_crc:
        raise SppmError("payload CRC mismatch")

    palbytes = r.take(256 * 4)
    palette = []
    for i in range(256):
        rgba = tuple(palbytes[i * 4:i * 4 + 4])
        rr, gg, bb, aa = rgba
        if aa and (rr, gg, bb) == (26, 40, 72): rgba = (132, 66, 183, aa)
        elif aa and (rr, gg, bb) == (92, 224, 36): rgba = (239, 68, 133, aa)
        palette.append(rgba)
    meta = {
        "title": r.string(256), "description": r.string(4096), "authorName": r.string(128),
        "originalAuthorName": r.string(128), "lastEditorName": r.string(128),
        "authorFsid": r.id(), "originalAuthorFsid": r.id(), "lastEditorFsid": r.id(),
        "currentId": r.id(), "rootId": r.id(), "parentId": r.id(True),
        "createdUnixSeconds": r.u64(), "modifiedUnixSeconds": r.u64(), "coverFrame": r.u32(),
        "width": width, "height": height,
        "speed": reserved if version >= 3 else 0, "nominalFps": fps,
        "fps": (0.4985, 1.0, 2.0, 4.0, 5.9972, 11.986, 19.9459, 29.9275)[reserved - 1] if version >= 3 and reserved else fps,
        "locked": bool(flags & 1),
        "allowSpinoffs": bool(flags & 2), "bgmFollowsSpeed": version == 1 or bool(flags & 4),
        "loopPlayback": True if version == 1 else not bool(flags & 8),
        "frameCount": frame_count, "audioTrackCount": audio_count, "formatVersion": version,
        "signature": signature["status"],
    }
    if meta["coverFrame"] >= frame_count:
        raise SppmError("cover frame outside animation")
    if identities:
        meta["identities"] = [{"publicKeyHex": key.hex(), "deviceTagHex": tag.hex()} for key, tag in identities]
        for field, identity_index in (("authorFsid", 0), ("originalAuthorFsid", 1), ("lastEditorFsid", 2)):
            key, tag = identities[identity_index]
            derived = _identity_fsid(key, tag)
            if derived and meta[field] != derived:
                raise SppmError(f"{field} does not match signed public identity")

    frames = []
    for fi in range(frame_count):
        layers = []
        for li in range(4):
            codec, length, crc = r.u8(), r.u32(), r.u32()
            if codec != 1 or length < 1 or length > 460800:
                raise SppmError("unsupported or oversized layer")
            encoded = r.take(length)
            if zlib.crc32(encoded) & 0xFFFFFFFF != crc:
                raise SppmError(f"layer {li} CRC mismatch in frame {fi}")
            _validate_rle(encoded)
            layers.append(encoded)
        frames.append(tuple(layers))

    tracks = []
    total_samples = 0
    for ti in range(audio_count):
        index, channels = r.u8(), r.u8()
        reference_fps = r.u8() if version >= 2 else 0
        sample_rate, name, cue_count = r.u32(), r.string(64), r.u16()
        if index != ti or channels not in (1, 2) or not 8000 <= sample_rate <= 48000 or cue_count > frame_count or (ti == 0 and cue_count):
            raise SppmError("invalid audio metadata")
        cues = [r.u16() for _ in range(cue_count)]
        if any(c >= frame_count for c in cues) or any(a >= b for a, b in zip(cues, cues[1:])):
            raise SppmError("invalid sound-effect frame cues")
        sample_count, pcm_crc = r.u32(), r.u32()
        total_samples += sample_count
        if total_samples > MAX_AUDIO_SAMPLES or sample_count % channels:
            raise SppmError("audio sample count outside supported limits")
        raw_pcm = bytes(r.take(sample_count * 2))
        if zlib.crc32(raw_pcm) & 0xFFFFFFFF != pcm_crc:
            raise SppmError("audio PCM CRC mismatch")
        pcm = array.array("h")
        pcm.frombytes(raw_pcm)
        if struct.pack("=H", 1) != b"\x01\x00":
            pcm.byteswap()
        reference_speed = reference_fps if version >= 3 and reserved != 0 and ti == 0 else 0
        if version >= 3 and reserved != 0 and (reference_speed > 8 or (ti > 0 and reference_fps != 0)):
            raise SppmError("invalid audio speed metadata")
        legacy_reference_fps = (fps if ti == 0 else reference_fps) if version < 3 or reserved == 0 else 0
        tracks.append(AudioTrack(index, channels, legacy_reference_fps,
                                 sample_rate, name, cues, pcm, reference_speed))
    if r.at != body_end:
        raise SppmError("unexpected trailing bytes")
    return SppmNote(meta, palette, frames, tracks, signature)


def get_sppm_metadata(source: Input, **kwargs) -> dict:
    """Return the note's metadata dictionary (including signature status)."""
    return read_sppm(source, **kwargs).metadata


def render_frame(note: SppmNote, frame_index: int, *, background=(255, 255, 255, 255)) -> Image.Image:
    """Composite one animation frame to a 640x360 RGBA Pillow image."""
    if not 0 <= frame_index < len(note.frames):
        raise IndexError("frame index outside note")
    layers = [_decode_layer(layer) for layer in note.frames[frame_index]]
    rgba = bytearray(PIXELS * 4)
    br, bg, bb, ba = background
    for p in range(PIXELS):
        rr, gg, bl, alpha = br, bg, bb, ba
        # Stored A-D from front to back: compose from D up through A.
        for layer_index in (3, 2, 1, 0):
            ink = layers[layer_index][p]
            if ink == 0:
                continue
            sr, sg, sb, sa = note.palette[ink]
            if sa == 0:
                continue
            source_weight = sa * 255
            behind_weight = alpha * (255 - sa)
            total = source_weight + behind_weight
            out_a = (total + 127) // 255
            if out_a:
                rr = (sr * source_weight + rr * behind_weight + total // 2) // total
                gg = (sg * source_weight + gg * behind_weight + total // 2) // total
                bl = (sb * source_weight + bl * behind_weight + total // 2) // total
            alpha = out_a
        at = p * 4
        rgba[at:at + 4] = bytes((rr, gg, bl, alpha))
    return Image.frombytes("RGBA", (WIDTH, HEIGHT), bytes(rgba))


def get_sppm_thumbnail(source: Input, output: Optional[Union[str, os.PathLike]] = None,
                       *, size=(320, 180), background=(255, 255, 255, 255), **kwargs) -> Image.Image:
    """Render the designated cover frame as a solid-background thumbnail."""
    if len(size) != 2 or not all(isinstance(v, int) and 1 <= v <= 4096 for v in size):
        raise ValueError("thumbnail size values must be in 1..4096")
    note = read_sppm(source, **kwargs)
    image = render_frame(note, note.metadata["coverFrame"], background=background)
    if size != (WIDTH, HEIGHT):
        image = image.resize(size, Image.Resampling.NEAREST)
    if output is not None:
        image.save(output, format="PNG")
    return image


def _source_stereo(track: AudioTrack) -> np.ndarray:
    source = np.frombuffer(track.pcm, dtype=np.int16).astype(np.float32).reshape(-1, track.channels) / 32768.0
    if track.channels == 1:
        return np.repeat(source, 2, axis=1)
    return source


def _mix_wav(note: SppmNote, wav_path: str, sample_rate: int = 48000, chunk_seconds: int = 1) -> None:
    total_frames = round(len(note.frames) * sample_rate / note.metadata["fps"])
    fps = note.metadata["fps"]
    sources = [(track, _source_stereo(track)) for track in note.audio_tracks if len(track.pcm)]
    with wave.open(wav_path, "wb") as output:
        output.setnchannels(2)
        output.setsampwidth(2)
        output.setframerate(sample_rate)
        for base in range(0, total_frames, sample_rate * chunk_seconds):
            count = min(sample_rate * chunk_seconds, total_frames - base)
            mix = np.zeros((count, 2), dtype=np.float32)
            times = (base + np.arange(count, dtype=np.float64)) / sample_rate
            for track, source in sources:
                if track.index == 0:
                    reference_fps = ((0.4985, 1.0, 2.0, 4.0, 5.9972, 11.986, 19.9459, 29.9275)[track.reference_speed - 1]
                                     if track.reference_speed else (track.reference_fps or fps))
                    rate = track.sample_rate * (fps / reference_fps if note.metadata["bgmFollowsSpeed"] else 1.0)
                    positions = times * rate
                    valid = np.ones(count, dtype=bool) if note.metadata["loopPlayback"] else positions < len(source)
                    if note.metadata["loopPlayback"]:
                        positions = np.mod(positions, len(source))
                    indexes = np.minimum(positions.astype(np.int64), max(0, len(source) - 1))
                    next_indexes = np.minimum(indexes + 1, len(source) - 1)
                    fraction = (positions - indexes).astype(np.float32)[:, None]
                    sampled = source[indexes] * (1.0 - fraction) + source[next_indexes] * fraction
                    mix[valid] += sampled[valid]
                else:
                    source_len = len(source)
                    for cue in track.frame_triggers:
                        start = round(cue * sample_rate / fps)
                        duration = int(np.ceil(source_len * sample_rate / track.sample_rate))
                        out_start = max(base, start)
                        out_end = min(base + count, start + duration)
                        if out_end <= out_start:
                            continue
                        dst = np.arange(out_start, out_end, dtype=np.float64)
                        positions = (dst - start) * track.sample_rate / sample_rate
                        indexes = np.minimum(positions.astype(np.int64), source_len - 1)
                        next_indexes = np.minimum(indexes + 1, source_len - 1)
                        fraction = (positions - indexes).astype(np.float32)[:, None]
                        sampled = source[indexes] * (1.0 - fraction) + source[next_indexes] * fraction
                        mix[out_start - base:out_end - base] += sampled
            pcm = np.clip(mix, -1.0, 1.0)
            output.writeframesraw((pcm * 32767.0).astype("<i2").tobytes())


def sppm_to_mp4(source: Input, output: Union[str, os.PathLike], *, ffmpeg: str = "ffmpeg",
                include_audio: bool = True, video_crf: int = 18, preset: str = "medium",
                legacy_hmac_key: Optional[bytes] = None) -> Path:
    """Convert a note to H.264/AAC MP4. Requires Pillow, NumPy, and ffmpeg on PATH."""
    note = read_sppm(source, legacy_hmac_key=legacy_hmac_key)
    ffmpeg_path = shutil.which(ffmpeg) if not os.path.isfile(ffmpeg) else ffmpeg
    if not ffmpeg_path:
        raise FileNotFoundError("ffmpeg was not found; install ffmpeg or pass ffmpeg=... ")
    target = Path(output)
    if target.suffix.lower() != ".mp4":
        raise ValueError("output filename must end in .mp4")
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sppm-mp4-") as temp_dir:
        wav_path = os.path.join(temp_dir, "audio.wav")
        has_audio = include_audio and any(track.pcm for track in note.audio_tracks)
        if has_audio:
            _mix_wav(note, wav_path)
        command = [ffmpeg_path, "-hide_banner", "-loglevel", "error", "-y",
                   "-f", "rawvideo", "-pix_fmt", "rgba", "-s:v", f"{WIDTH}x{HEIGHT}",
                   "-r", str(note.metadata["fps"]), "-i", "-"]
        if has_audio:
            command += ["-i", wav_path]
        command += ["-map", "0:v:0"]
        if has_audio:
            command += ["-map", "1:a:0", "-c:a", "aac", "-b:a", "192k"]
        command += ["-c:v", "libx264", "-preset", preset, "-crf", str(video_crf),
                    "-pix_fmt", "yuv420p", "-r", str(note.metadata["fps"]),
                    "-movflags", "+faststart", str(target)]
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        assert process.stdin is not None
        try:
            for index in range(len(note.frames)):
                process.stdin.write(render_frame(note, index).tobytes())
            process.stdin.close()
            stderr = process.stderr.read() if process.stderr else b""
            if process.stderr:
                process.stderr.close()
            status = process.wait()
        except BaseException:
            process.kill()
            process.wait()
            raise
        if status:
            target.unlink(missing_ok=True)
            raise RuntimeError(f"ffmpeg conversion failed ({status}): {stderr.decode('utf-8', 'replace').strip()}")
    return target


__all__ = ["AudioTrack", "SppmError", "SppmNote", "get_sppm_metadata", "get_sppm_thumbnail",
           "read_sppm", "render_frame", "sppm_to_mp4"]
