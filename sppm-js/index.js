const WIDTH = 640, HEIGHT = 360, PIXELS = WIDTH * HEIGHT;
const HEADER_SIZE = 36, MAX_FILE_SIZE = 512 * 1024 * 1024;
const PUBLIC_FOOTER_SIZE = 4 + 3 * 48 + 64;

function fail(message) { throw new Error(`Invalid SPPM: ${message}`); }

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

async function inputBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  if (typeof Blob !== "undefined" && input instanceof Blob) return new Uint8Array(await input.arrayBuffer());
  if (typeof input === "string") {
    const { readFile } = await import("node:fs/promises");
    return new Uint8Array(await readFile(input));
  }
  fail("expected a path, Blob, ArrayBuffer, or Uint8Array");
}

class Reader {
  constructor(bytes, end = bytes.length) { this.bytes = bytes; this.view = new DataView(bytes.buffer, bytes.byteOffset, end); this.at = 0; this.end = end; }
  need(size) { if (!Number.isSafeInteger(size) || size < 0 || size > this.end - this.at) fail("truncated payload"); }
  u8() { this.need(1); return this.view.getUint8(this.at++); }
  u16() { this.need(2); const v = this.view.getUint16(this.at, true); this.at += 2; return v; }
  u32() { this.need(4); const v = this.view.getUint32(this.at, true); this.at += 4; return v; }
  u64() { this.need(8); const v = this.view.getBigUint64(this.at, true); this.at += 8; return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v.toString(); }
  take(size) { this.need(size); const result = this.bytes.subarray(this.at, this.at + size); this.at += size; return result; }
  string(max) {
    const size = this.u16(); if (size > max) fail("metadata string exceeds limit");
    const bytes = this.take(size);
    if (bytes.includes(0)) fail("metadata contains NUL");
    try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
    catch { fail("metadata is not valid UTF-8"); }
  }
  id(optional = false) {
    const bytes = this.take(16), value = String.fromCharCode(...bytes);
    if (optional && value === "0000000000000000") return "";
    if (!/^[0-9A-Fa-f]{16}$/.test(value) || value === "0000000000000000") fail("invalid lineage ID");
    return value.toUpperCase();
  }
}

function decodeLayer(encoded) {
  const out = new Uint8Array(PIXELS); let src = 0, dst = 0;
  while (src < encoded.length) {
    const command = encoded[src++], count = (command & 0x7f) + 1;
    if (dst + count > PIXELS) fail("RLE layer expands beyond canvas size");
    if (command & 0x80) {
      if (src >= encoded.length) fail("truncated RLE repeat packet");
      out.fill(encoded[src++], dst, dst + count);
    } else {
      if (src + count > encoded.length) fail("truncated RLE literal packet");
      out.set(encoded.subarray(src, src + count), dst); src += count;
    }
    dst += count;
  }
  if (dst !== PIXELS) fail("RLE layer has incorrect decoded size");
  return out;
}

function validateLayer(encoded) {
  let src = 0, dst = 0;
  while (src < encoded.length) {
    const command = encoded[src++], count = (command & 0x7f) + 1;
    if (dst + count > PIXELS) fail("RLE layer expands beyond canvas size");
    if (command & 0x80) {
      if (src >= encoded.length) fail("truncated RLE repeat packet");
      src++;
    } else {
      if (src + count > encoded.length) fail("truncated RLE literal packet");
      src += count;
    }
    dst += count;
  }
  if (dst !== PIXELS) fail("RLE layer has incorrect decoded size");
}
const decodedLayerCache = new WeakMap();
function decodedLayer(encoded) {
  let decoded = decodedLayerCache.get(encoded);
  if (!decoded) { decoded = decodeLayer(encoded); decodedLayerCache.set(encoded, decoded); }
  return decoded;
}

function migrateColor(r, g, b, a) {
  if (a && r === 26 && g === 40 && b === 72) return [132, 66, 183, a];
  if (a && r === 92 && g === 224 && b === 36) return [239, 68, 133, a];
  return [r, g, b, a];
}

async function getWebCrypto() {
  if (globalThis.crypto?.subtle) return globalThis.crypto;
  try { return (await import("node:crypto")).webcrypto; }
  catch { return null; }
}

async function verifyV3(body, footer) {
  const reader = new Reader(footer);
  if (String.fromCharCode(...reader.take(4)) !== "SPP3") fail("invalid public-signature marker");
  const identities = [];
  for (let i = 0; i < 3; i++) identities.push({ publicKey: reader.take(32), deviceTag: reader.take(16) });
  const signature = reader.take(64);
  if (reader.at !== reader.end || !identities[2].publicKey.some(Boolean) || !identities[2].deviceTag.some(Boolean)) fail("invalid public identity footer");
  const crypto = await getWebCrypto();
  if (!crypto) return { status: "present-unverified", identities };
  try {
    const domain = new TextEncoder().encode("FlipnoteNX-SPPM-public-signature-v3\0");
    const concat = new Uint8Array(domain.length + body.length + 3 * 48);
    let at = 0; concat.set(domain, at); at += domain.length; concat.set(body, at); at += body.length;
    for (const identity of identities) { concat.set(identity.publicKey, at); at += 32; concat.set(identity.deviceTag, at); at += 16; }
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", concat));
    const key = await crypto.subtle.importKey("raw", identities[2].publicKey, { name: "Ed25519" }, false, ["verify"]);
    const valid = await crypto.subtle.verify({ name: "Ed25519" }, key, signature, digest);
    if (!valid) fail("public signature verification failed");
    return { status: "verified", identities };
  } catch (error) {
    if (String(error?.message || error).includes("public signature verification failed")) throw error;
    return { status: "present-unverified", identities, verificationError: String(error?.message || error) };
  }
}

async function verifyLegacyHmac(body, signature, key) {
  if (!key) return "present-unverified";
  const crypto = await getWebCrypto(); if (!crypto) return "present-unverified";
  const rawKey = key instanceof Uint8Array ? key : new Uint8Array(key);
  const hmacKey = await crypto.subtle.importKey("raw", rawKey, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return await crypto.subtle.verify("HMAC", hmacKey, signature, body) ? "verified" : fail("legacy HMAC verification failed");
}

/** Parse a complete SPPM file. Public SPP3 signatures are verified where WebCrypto supports Ed25519. */
export async function readSppm(input, { legacyHmacKey = null } = {}) {
  const bytes = await inputBytes(input);
  if (bytes.length < HEADER_SIZE || bytes.length > MAX_FILE_SIZE + PUBLIC_FOOTER_SIZE + 36) fail("file size outside supported limits");
  if (String.fromCharCode(...bytes.subarray(0, 4)) !== "SPPM") fail("bad file magic");

  let bodyEnd = bytes.length, signature = { status: "unsigned" }, publicIdentities = null;
  const tail = bytes.length >= 4 ? String.fromCharCode(...bytes.subarray(-4)) : "";
  if (tail === "SPP3") fail("public signature footer is truncated or malformed");
  const publicAt = bytes.length - PUBLIC_FOOTER_SIZE;
  if (publicAt >= HEADER_SIZE && String.fromCharCode(...bytes.subarray(publicAt, publicAt + 4)) === "SPP3") {
    bodyEnd = publicAt;
    const checked = await verifyV3(bytes.subarray(0, bodyEnd), bytes.subarray(publicAt));
    signature = { status: checked.status, algorithm: "Ed25519", identities: checked.identities, verificationError: checked.verificationError };
    publicIdentities = checked.identities;
  } else if (bytes.length >= HEADER_SIZE + 36 && String.fromCharCode(...bytes.subarray(-36, -32)) === "SPPS") {
    bodyEnd = bytes.length - 36;
    signature = { status: await verifyLegacyHmac(bytes.subarray(0, bodyEnd), bytes.subarray(-32), legacyHmacKey), algorithm: "HMAC-SHA-256" };
  }

  const body = bytes.subarray(0, bodyEnd);
  const r = new Reader(body);
  r.take(4);
  const version = r.u16(), headerSize = r.u16(), totalBytes = r.u64(), expectedCrc = r.u32();
  const width = r.u16(), height = r.u16(), layerCount = r.u8(), paletteCount = r.u16(), fps = r.u8(), flags = r.u8(), frameCount = r.u32(), audioCount = r.u8(), reserved = r.u16();
  if ((version !== 1 && version !== 2 && version !== 3) || headerSize !== HEADER_SIZE || totalBytes !== body.length || width !== WIDTH || height !== HEIGHT || layerCount !== 4 || paletteCount !== 256 || fps < 1 || fps > 30 || frameCount < 1 || frameCount > 9999 || audioCount > 4 || reserved !== 0 || ((version === 1 ? flags & ~3 : flags & ~15) !== 0)) fail("unsupported SPPM header");
  if (crc32(body.subarray(HEADER_SIZE)) !== expectedCrc) fail("payload CRC mismatch");

  const paletteBytes = r.take(256 * 4), palette = new Array(256);
  for (let i = 0; i < 256; i++) palette[i] = migrateColor(...paletteBytes.subarray(i * 4, i * 4 + 4));
  const metadata = {
    title: r.string(256), description: r.string(4096), authorName: r.string(128), originalAuthorName: r.string(128), lastEditorName: r.string(128),
    authorFsid: r.id(), originalAuthorFsid: r.id(), lastEditorFsid: r.id(), currentId: r.id(), rootId: r.id(), parentId: r.id(true),
    createdUnixSeconds: r.u64(), modifiedUnixSeconds: r.u64(), coverFrame: r.u32(), width, height, fps,
    locked: !!(flags & 1), allowSpinoffs: !!(flags & 2), bgmFollowsSpeed: version === 1 || !!(flags & 4), loopPlayback: version === 1 ? true : !(flags & 8),
    frameCount, audioTrackCount: audioCount, formatVersion: version, signature: signature.status,
  };
  if (metadata.coverFrame >= frameCount) fail("cover frame outside animation");
  if (publicIdentities) {
    metadata.identities = publicIdentities.map(identity => ({ publicKeyHex: hex(identity.publicKey), deviceTagHex: hex(identity.deviceTag) }));
    const crypto = await getWebCrypto();
    if (crypto) for (const [field, index] of [["authorFsid", 0], ["originalAuthorFsid", 1], ["lastEditorFsid", 2]]) {
      const identity = publicIdentities[index];
      if (!identity.publicKey.some(Boolean) && !identity.deviceTag.some(Boolean)) continue;
      const domain = new TextEncoder().encode("FlipnoteNX-public-fsid-v2\0");
      const source = new Uint8Array(domain.length + 48); source.set(domain); source.set(identity.publicKey, domain.length); source.set(identity.deviceTag, domain.length + 32);
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", source));
      if (metadata[field] !== hex(digest.subarray(0, 8)).toUpperCase()) fail(`${field} does not match signed public identity`);
    }
  }

  const frames = [];
  for (let fi = 0; fi < frameCount; fi++) {
    const layers = [];
    for (let li = 0; li < 4; li++) {
      const codec = r.u8(), length = r.u32(), expected = r.u32();
      if (codec !== 1 || length < 1 || length > 460800) fail("unsupported or oversized layer");
      const encoded = r.take(length);
      if (crc32(encoded) !== expected) fail(`layer ${li} CRC mismatch in frame ${fi}`);
      validateLayer(encoded);
      layers.push(encoded);
    }
    frames.push({ layers });
  }
  const audioTracks = [];
  let audioSamples = 0;
  for (let ti = 0; ti < audioCount; ti++) {
    const index = r.u8(), channels = r.u8(), referenceFps = version >= 2 ? r.u8() : 0, sampleRate = r.u32(), name = r.string(64), triggerCount = r.u16();
    if (index !== ti || (channels !== 1 && channels !== 2) || sampleRate < 8000 || sampleRate > 48000 || triggerCount > frameCount || (ti === 0 && triggerCount !== 0)) fail("invalid audio metadata");
    const triggers = Array.from({ length: triggerCount }, () => r.u16());
    for (let i = 0; i < triggers.length; i++) if (triggers[i] >= frameCount || (i && triggers[i] <= triggers[i - 1])) fail("invalid sound-effect frame cues");
    const sampleCount = r.u32(), pcmCrc = r.u32(); audioSamples += sampleCount;
    if (sampleCount > 32 * 1024 * 1024 - (audioSamples - sampleCount) || sampleCount % channels !== 0) fail("audio sample count outside supported limits");
    const pcmBytes = r.take(sampleCount * 2);
    if (crc32(pcmBytes) !== pcmCrc) fail("audio PCM CRC mismatch");
    const pcm = new Int16Array(sampleCount);
    const sampleView = new DataView(pcmBytes.buffer, pcmBytes.byteOffset, pcmBytes.byteLength);
    for (let i = 0; i < sampleCount; i++) pcm[i] = sampleView.getInt16(i * 2, true);
    audioTracks.push({ index, name, channels, referenceFps: ti === 0 && version === 1 ? fps : referenceFps, sampleRate, frameTriggers: triggers, pcm });
  }
  if (r.at !== body.length) fail("unexpected trailing bytes");
  return { width, height, palette, metadata, frames, audioTracks, signature };
}

function hex(bytes) { return [...bytes].map(value => value.toString(16).padStart(2, "0")).join(""); }

/** Read only the public metadata fields from an SPPM file. */
export async function getSppmMetadata(input, options) {
  return (await readSppm(input, options)).metadata;
}

/** Composite a frame to RGBA bytes, with layer A at the front and D at the back. */
export function renderFrame(note, frameIndex, { background = [255, 255, 255, 255] } = {}) {
  if (!note?.frames?.length || frameIndex < 0 || frameIndex >= note.frames.length) throw new RangeError("frameIndex outside note");
  const out = new Uint8ClampedArray(PIXELS * 4), frame = note.frames[frameIndex], layers = frame.layers.map(decodedLayer), [br, bg, bb, ba] = background;
  for (let p = 0; p < PIXELS; p++) {
    let r = br, g = bg, b = bb, a = ba;
    for (let layer = 3; layer >= 0; layer--) {
      const colorIndex = layers[layer][p]; if (colorIndex === 0) continue;
      const [sr, sg, sb, sa] = note.palette[colorIndex]; if (!sa) continue;
      const sourceWeight = sa * 255, behindWeight = a * (255 - sa), total = sourceWeight + behindWeight;
      if (!total) { r = g = b = a = 0; continue; }
      r = Math.floor((sr * sourceWeight + r * behindWeight + total / 2) / total);
      g = Math.floor((sg * sourceWeight + g * behindWeight + total / 2) / total);
      b = Math.floor((sb * sourceWeight + b * behindWeight + total / 2) / total);
      a = Math.floor((total + 127) / 255);
    }
    const at = p * 4; out[at] = r; out[at + 1] = g; out[at + 2] = b; out[at + 3] = a;
  }
  return out;
}

/** Get an RGBA thumbnail for the note's designated cover frame. */
export async function getSppmThumbnail(input, { width = 320, height = 180, background = [255, 255, 255, 255], ...readOptions } = {}) {
  if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1 || width > 4096 || height > 4096) throw new RangeError("thumbnail dimensions must be 1..4096");
  const note = await readSppm(input, readOptions), source = renderFrame(note, note.metadata.coverFrame, { background });
  const data = new Uint8ClampedArray(width * height * 4);
  for (let y = 0; y < height; y++) for (let x = 0; x < width; x++) {
    const sx = Math.min(WIDTH - 1, Math.floor(x * WIDTH / width)), sy = Math.min(HEIGHT - 1, Math.floor(y * HEIGHT / height));
    data.set(source.subarray((sy * WIDTH + sx) * 4, (sy * WIDTH + sx) * 4 + 4), (y * width + x) * 4);
  }
  return { width, height, data };
}

/** Draw the cover thumbnail into a browser canvas (keeps nearest-pixel sampling). */
export async function drawSppmThumbnail(canvas, input, options = {}) {
  const thumbnail = await getSppmThumbnail(input, { width: canvas.width || 320, height: canvas.height || 180, ...options });
  const context = canvas.getContext("2d");
  context.putImageData(new ImageData(thumbnail.data, thumbnail.width, thumbnail.height), 0, 0);
  return thumbnail;
}

/** Canvas animation playback, including SPPM BGM and frame-cued sound effects. */
export class SppmPlayer {
  constructor(canvas, note, { audio = true, context = null } = {}) {
    if (!canvas?.getContext || !note?.frames?.length) throw new TypeError("SppmPlayer requires a canvas and a parsed note");
    this.canvas = canvas; this.note = note; this.audioEnabled = audio; this.audioContext = context;
    this.frame = 0; this.playing = false; this.loop = note.metadata.loopPlayback; this.raf = 0; this.startedAt = 0; this.cycle = 0; this.sources = [];
    canvas.width = note.width; canvas.height = note.height;
    this.context2d = canvas.getContext("2d", { alpha: false });
    this.render();
  }
  render() {
    const rgba = renderFrame(this.note, this.frame);
    this.context2d.putImageData(new ImageData(rgba, this.note.width, this.note.height), 0, 0);
    this.onframechange?.(this.frame);
  }
  async play({ fromStart = true } = {}) {
    if (fromStart) this.frame = 0;
    if (this.playing && !fromStart) return;
    this.#stopAudio(); this.render();
    this.playing = true; this.cycle = 0; this.startedAt = performance.now();
    if (this.audioEnabled) await this.#scheduleAudio();
    const tick = now => {
      if (!this.playing) return;
      const cycleMs = this.note.frames.length * 1000 / this.note.metadata.fps;
      const elapsed = now - this.startedAt;
      if (elapsed >= cycleMs) {
        if (this.loop) {
          this.cycle++; this.startedAt += cycleMs; this.#stopAudio();
          if (this.audioEnabled) this.#scheduleAudio().catch(error => this.onerror?.(error));
        } else {
          this.frame = this.note.frames.length - 1; this.render(); this.playing = false; this.#stopAudio(); this.onended?.(); return;
        }
      }
      const nextFrame = Math.min(this.note.frames.length - 1, Math.floor((now - this.startedAt) * this.note.metadata.fps / 1000));
      if (nextFrame !== this.frame) { this.frame = nextFrame; this.render(); }
      this.raf = requestAnimationFrame(tick);
    };
    this.raf = requestAnimationFrame(tick);
  }
  pause() {
    if (!this.playing) return;
    this.playing = false; cancelAnimationFrame(this.raf);
    this.frame = Math.min(this.note.frames.length - 1, Math.floor((performance.now() - this.startedAt) * this.note.metadata.fps / 1000));
    this.#stopAudio(); this.render(); this.onpause?.(this.frame);
  }
  stop() { this.playing = false; cancelAnimationFrame(this.raf); this.frame = 0; this.#stopAudio(); this.render(); }
  seek(frame) {
    if (!Number.isInteger(frame) || frame < 0 || frame >= this.note.frames.length) throw new RangeError("frame outside note");
    this.frame = frame; this.render();
    if (this.playing) { this.startedAt = performance.now() - frame * 1000 / this.note.metadata.fps; this.#stopAudio(); if (this.audioEnabled) this.#scheduleAudio().catch(error => this.onerror?.(error)); }
  }
  destroy() { this.stop(); if (this.audioContext && !this.externalAudioContext) this.audioContext.close?.(); }
  async #scheduleAudio() {
    const AudioContextCtor = globalThis.AudioContext || globalThis.webkitAudioContext;
    if (!this.audioContext) { if (!AudioContextCtor) return; this.audioContext = new AudioContextCtor(); }
    await this.audioContext.resume?.();
    const start = this.audioContext.currentTime + 0.04;
    const fps = this.note.metadata.fps;
    for (const track of this.note.audioTracks) {
      if (!track.pcm.length) continue;
      const buffer = this.audioContext.createBuffer(track.channels, track.pcm.length / track.channels, track.sampleRate);
      for (let ch = 0; ch < track.channels; ch++) {
        const channel = buffer.getChannelData(ch);
        for (let i = 0; i < channel.length; i++) channel[i] = track.pcm[i * track.channels + ch] / 32768;
      }
      if (track.index === 0) {
        const source = this.audioContext.createBufferSource(); source.buffer = buffer;
        if (this.note.metadata.bgmFollowsSpeed) source.playbackRate.value = fps / (track.referenceFps || fps);
        source.loop = !!this.loop; source.connect(this.audioContext.destination); source.start(start); this.sources.push(source);
      } else for (const cue of track.frameTriggers) {
        const source = this.audioContext.createBufferSource(); source.buffer = buffer; source.connect(this.audioContext.destination);
        source.start(start + cue / fps); this.sources.push(source);
      }
    }
  }
  #stopAudio() { for (const source of this.sources) { try { source.stop(); } catch {} try { source.disconnect(); } catch {} } this.sources = []; }
}

export const SPPM = Object.freeze({ width: WIDTH, height: HEIGHT, layerCount: 4, paletteSize: 256 });
