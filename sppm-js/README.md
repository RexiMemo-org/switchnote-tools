# SPPM JavaScript tools

Dependency-free ES module for Node.js 20+ and modern browsers.

```js
import { readSppm, getSppmMetadata, getSppmThumbnail, SppmPlayer } from "./index.js";

const note = await readSppm("my-note.sppm");
console.log(await getSppmMetadata("my-note.sppm"));
const { width, height, data } = await getSppmThumbnail("my-note.sppm");
const player = new SppmPlayer(document.querySelector("canvas"), note);
await player.play(); // starts at the first frame; includes BGM and frame-cued effects
```

`readSppm` validates the container and CRCs. Current Ed25519 `SPP3` signatures
are verified through WebCrypto when supported. Legacy `SPPS` HMAC files are
reported as unverified unless `legacyHmacKey` is provided. This module reads and
renders notes; it does not create or sign SPPM files. The thumbnail is RGBA with
a solid white background by default and uses the note's cover frame.
