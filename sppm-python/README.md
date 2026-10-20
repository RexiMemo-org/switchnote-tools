# SPPM Python tools

Python 3.10+ module. Install Pillow and NumPy with `python -m pip install -r requirements.txt`.
Install `cryptography` separately if Ed25519 signature verification is needed.
MP4 conversion also needs `ffmpeg` installed and available on `PATH`.

```python
from sppm_tools import get_sppm_metadata, get_sppm_thumbnail, sppm_to_mp4

metadata = get_sppm_metadata("my-note.sppm")
thumbnail = get_sppm_thumbnail("my-note.sppm", "cover.png")
sppm_to_mp4("my-note.sppm", "animation.mp4")
```

Thumbnails use the note's selected cover frame and default to a solid white background.
Video exports composite layers D→C→B→A at the note's stored frame rate, with AAC audio
mixed from BGM and frame-cued sound effects. Structural bounds, payload CRCs, per-layer
RLE, audio CRCs, and frame cues are checked. Current SPP3 Ed25519 signatures are verified
when the optional `cryptography` dependency is installed; legacy SPPS HMAC signatures are
verified only if the caller passes `legacy_hmac_key`. This package does not write or sign
SPPM files. The format's `locked` metadata flag is not encryption; this reader can still
render and convert a locked note.
