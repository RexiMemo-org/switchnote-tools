import os
import shutil
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from sppm_tools import get_sppm_metadata, get_sppm_thumbnail, read_sppm, sppm_to_mp4


def fixture(version: int = 2, speed: int = 0) -> bytes:
    payload = bytearray()
    palette = bytearray(256 * 4)
    palette[4:8] = bytes((255, 0, 0, 255))
    payload.extend(palette)

    def text(value: str) -> None:
        encoded = value.encode("utf-8")
        payload.extend(struct.pack("<H", len(encoded)))
        payload.extend(encoded)

    for value in ("Python fixture", "", "Tester", "Tester", "Tester"):
        text(value)
    for value in ("1111111111111111", "1111111111111111", "1111111111111111",
                  "2222222222222222", "2222222222222222", "0000000000000000"):
        payload.extend(value.encode("ascii"))
    payload.extend(struct.pack("<QQI", 100, 100, 0))

    zero_runs = bytearray()
    for _ in range(1800):
        zero_runs.extend((255, 0))  # 128 transparent pixels per packet
    first_layer = bytes((0, 1)) + bytes(zero_runs[:3598]) + bytes((254, 0))
    for layer in range(4):
        encoded = first_layer if layer == 0 else bytes(zero_runs)
        payload.extend(struct.pack("<BII", 1, len(encoded), zlib.crc32(encoded) & 0xffffffff))
        payload.extend(encoded)

    pcm = struct.pack("<800h", *([1200, -1200] * 400))
    payload.extend(struct.pack("<BBB I", 0, 1, (6 if version >= 3 and speed else 12), 8000))
    text("BGM")
    payload.extend(struct.pack("<HII", 0, 800, zlib.crc32(pcm) & 0xffffffff))
    payload.extend(pcm)

    header = bytearray(b"SPPM")
    header.extend(struct.pack("<HHQ I HH B H B B I B H", version, 36, 36 + len(payload),
                              zlib.crc32(payload) & 0xffffffff, 640, 360, 4, 256,
                              12, 2, 1, 1, speed))
    assert len(header) == 36
    return bytes(header + payload)


class SppmToolTests(unittest.TestCase):
    def test_metadata_thumbnail_and_layer_composite(self):
        note = read_sppm(fixture())
        self.assertEqual(get_sppm_metadata(fixture())["title"], "Python fixture")
        self.assertEqual(note.metadata["frameCount"], 1)
        self.assertEqual(note.audio_tracks[0].name, "BGM")
        self.assertEqual(len(note.audio_tracks[0].pcm), 800)
        image = get_sppm_thumbnail(fixture(), size=(640, 360))
        self.assertEqual(image.getpixel((0, 0)), (255, 0, 0, 255))
        self.assertEqual(image.getpixel((1, 0)), (255, 255, 255, 255))

    @unittest.skipUnless(shutil.which("ffmpeg"), "ffmpeg not installed")
    def test_mp4_conversion(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture.mp4"
            result = sppm_to_mp4(fixture(), output)
            self.assertEqual(result, output)
            self.assertGreater(output.stat().st_size, 500)

    def test_rejects_corrupt_file(self):
        broken = bytearray(fixture())
        broken[80] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC"):
            read_sppm(broken)

    def test_reads_dsi_speed_indices_using_measured_rates(self):
        note = read_sppm(fixture(version=3, speed=1))
        self.assertEqual(note.metadata["speed"], 1)
        self.assertEqual(note.metadata["fps"], 0.4985)
        self.assertEqual(note.audio_tracks[0].reference_speed, 6)


if __name__ == "__main__":
    unittest.main()
