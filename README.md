# Switchnote Tools

JavaScript and Python utilities for reading, validating, previewing, and exporting Switchnote `.sppm` files.

## Repository layout

```text
switchnote-tools/
├── LICENSE
├── README.md
├── sppm-js/
└── sppm-python/
```

## Features

- Read metadata, four layers per frame, the 256-entry palette, and audio tracks.
- Check format bounds, CRCs, layer RLE data, and sound-effect frame cues.
- Verify public Ed25519 SPP3 signatures when supported; legacy SPPS HMAC signatures can only be checked when the caller already has the key.
- Render frames and cover thumbnails.
- Play SPPM animation with BGM and frame-cued sound effects in a browser canvas (JavaScript).
- Convert animation to H.264/AAC MP4 with optional audio (Python and FFmpeg).

## JavaScript

Requires Node.js 20+ or a modern browser. The library has no third-party JavaScript dependencies. Browser callers should pass a `Blob`, `File`, `ArrayBuffer`, or typed array; Node.js callers may also pass a file path.

```js
import { readSppm, getSppmMetadata, getSppmThumbnail, SppmPlayer } from "./sppm-js/index.js";

const note = await readSppm("my-note.sppm");
const metadata = await getSppmMetadata("my-note.sppm");
const { width, height, data } = await getSppmThumbnail("my-note.sppm");
// data is RGBA pixel data; the thumbnail defaults to a white background.

const player = new SppmPlayer(document.querySelector("canvas"), note);
await player.play(); // starts from the first frame
```

Other exports include `renderFrame` and `drawSppmThumbnail`. `SppmPlayer` uses the Web Audio API for stored audio when available.

## Python

Requires Python 3.10+, Pillow, and NumPy. Install `cryptography` separately to verify Ed25519 signatures. MP4 conversion additionally requires FFmpeg on `PATH`.

```sh
cd sppm-python
python -m pip install -r requirements.txt
```

```python
from sppm_tools import get_sppm_metadata, get_sppm_thumbnail, sppm_to_mp4

metadata = get_sppm_metadata("my-note.sppm")
cover = get_sppm_thumbnail("my-note.sppm", "cover.png")
sppm_to_mp4("my-note.sppm", "animation.mp4")
```

The Python module also exposes `read_sppm` and `render_frame`. MP4 conversion includes BGM and frame-cued sound effects by default; pass `include_audio=False` for a silent video.

## Signatures and locked notes

These packages are readers, renderers, and converters; they contain no SPPM writer, signing-key generator, signature-creation API, lock-removal API, key recovery, or key/identity brute-force function. SPP3 verification uses the Ed25519 public key embedded in the file. If crypto support is unavailable, a signature may be reported as present but unverified. Legacy HMAC verification requires a key supplied by the caller; the tools cannot derive or recover it.

The format is not encrypted. A note's `locked` field is a metadata/UI flag, not access control: the readers can display and export the contents of a locked file. The public identity footer contains public keys, FSIDs, and device tags—not private signing keys. These identifiers may still make files linkable to the same creator. Respect creators' rights and permissions when exporting or sharing notes.

Because SPPM is a parseable file format, the source code necessarily documents its structure. Someone could use that knowledge to write a separate encoder, but this repository itself does not encode or sign notes.

## Tests

```sh
cd sppm-js
npm test

cd ../sppm-python
python -m unittest -v test_sppm_tools.py
```

## License

MIT; see [LICENSE](LICENSE).
