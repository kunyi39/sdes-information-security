"""Assemble genuine GUI screenshots into a readable demonstration GIF.

The frame display durations are presentation time, not measured cracking time.
Pillow is needed only for rebuilding this GIF, not for S-DES or experiments.
"""

import json
from pathlib import Path

from PIL import Image


if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    directory = root / "artifacts" / "gui_frames"
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    frames = []
    for entry in manifest:
        with Image.open(directory / entry["file"]) as screenshot:
            frames.append(screenshot.convert("RGB"))
    assert len(frames) == 5 and len({frame.size for frame in frames}) == 1
    destination = root / "artifacts" / "stage4-bruteforce.gif"
    frames[0].save(destination, save_all=True, append_images=frames[1:],
                   duration=[3000, 5000, 4000, 3000, 6000], loop=0, disposal=2)
    with Image.open(destination) as animation:
        assert animation.n_frames == 5
        for index in range(animation.n_frames):
            animation.seek(index)
            animation.load()
    print(f"Verified 5-frame GUI demonstration: {destination}")
