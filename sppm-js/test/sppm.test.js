import test from "node:test";
import assert from "node:assert/strict";
import { getSppmMetadata, getSppmThumbnail, readSppm, renderFrame } from "../index.js";

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const b of bytes) { crc ^= b; for (let i = 0; i < 8; i++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0); }
  return (crc ^ 0xffffffff) >>> 0;
}
function fixture() {
  const parts = [];
  const u8 = n => parts.push(Buffer.from([n & 255]));
  const u16 = n => { const b = Buffer.alloc(2); b.writeUInt16LE(n); parts.push(b); };
  const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n); parts.push(b); };
  const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); parts.push(b); };
  const str = s => { const b = Buffer.from(s); u16(b.length); parts.push(b); };
  parts.push(Buffer.from("SPPM")); u16(2); u16(36); u64(0); u32(0); u16(640); u16(360); u8(4); u16(256); u8(12); u8(2); u32(1); u8(0); u16(0);
  const palette = Buffer.alloc(1024); palette.set([255, 0, 0, 255], 4); parts.push(palette);
  ["JS fixture", "", "Tester", "Tester", "Tester"].forEach(str);
  ["1111111111111111", "1111111111111111", "1111111111111111", "2222222222222222", "2222222222222222", "0000000000000000"].forEach(id => parts.push(Buffer.from(id)));
  u64(100); u64(100); u32(0);
  const zeroRun = Buffer.alloc(3600); for (let i = 0; i < zeroRun.length; i += 2) { zeroRun[i] = 255; zeroRun[i + 1] = 0; }
  const firstLayer = Buffer.concat([Buffer.from([0, 1]), zeroRun.subarray(0, 3598), Buffer.from([254, 0])]); // one literal plus 230399 zeroes
  for (let layer = 0; layer < 4; layer++) {
    const encoded = layer === 0 ? firstLayer : zeroRun;
    u8(1); u32(encoded.length); u32(crc32(encoded)); parts.push(encoded);
  }
  let body = Buffer.concat(parts); body.writeBigUInt64LE(BigInt(body.length), 8); body.writeUInt32LE(crc32(body.subarray(36)), 16);
  return new Uint8Array(body);
}

test("reads metadata, validates RLE and renders a white-backed cover thumbnail", async () => {
  const bytes = fixture();
  const note = await readSppm(bytes);
  assert.equal((await getSppmMetadata(bytes)).title, "JS fixture");
  assert.equal(note.frames.length, 1);
  const rgba = renderFrame(note, 0);
  assert.deepEqual([...rgba.subarray(0, 4)], [255, 0, 0, 255]);
  const thumb = await getSppmThumbnail(bytes, { width: 2, height: 1 });
  assert.deepEqual([...thumb.data.subarray(0, 4)], [255, 0, 0, 255]);
  assert.deepEqual([...thumb.data.subarray(4, 8)], [255, 255, 255, 255]);
});

test("rejects damaged payload CRC", async () => {
  const bytes = fixture(); bytes[80] ^= 1;
  await assert.rejects(readSppm(bytes), /CRC/);
});
