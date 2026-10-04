#!/usr/bin/env python3
"""Build a portable Digital Alibi USB bundle on the current target platform.

PyInstaller is not a cross compiler. Run this script in a project-local virtual
environment on each target OS to make the matching bundle.
"""
from __future__ import print_function

import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENTRY = ROOT / "alibi_core.py"


def require_virtualenv() -> None:
    if sys.prefix == getattr(sys, "base_prefix", sys.prefix):
        raise SystemExit("Refusing to build outside a virtual environment. Create .venv and invoke .venv/bin/python build_forensic_usb.py.")


def platform_tag() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower().replace("amd64", "x86_64")
    supported = {"windows", "linux", "darwin"}
    if system not in supported:
        raise SystemExit("Unsupported build host: %s. Build on Windows, Linux, or macOS." % platform.system())
    return "%s-%s" % (system, machine)


def main() -> int:
    require_virtualenv()
    if not ENTRY.is_file():
        raise SystemExit("Missing entry point: %s" % ENTRY)
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        raise SystemExit("PyInstaller is not installed in this virtual environment. Run: python -m pip install -r requirements-build.txt")

    tag = platform_tag()
    name = "DigitalAlibi-%s" % tag
    build_root = ROOT / "build" / tag
    dist_root = ROOT / "dist"
    release_dir = dist_root / name
    if release_dir.exists():
        shutil.rmtree(str(release_dir))
    build_root.mkdir(parents=True, exist_ok=True)
    dist_root.mkdir(parents=True, exist_ok=True)

    # --onedir is intentional. PyInstaller --onefile extracts to a host temp
    # directory at execution time and would violate the acquisition model.
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--name",
        name,
        "--distpath",
        str(dist_root),
        "--workpath",
        str(build_root),
        "--specpath",
        str(build_root),
        "--collect-all",
        "cryptography",
        "--collect-all",
        "bleak",
        "--collect-all",
        "sounddevice",
        "--collect-all",
        "numpy",
        "--hidden-import",
        "bleak.backends.winrt",
        "--hidden-import",
        "bleak.backends.bluezdbus",
        "--hidden-import",
        "bleak.backends.corebluetooth",
        str(ENTRY),
    ]
    print("Building %s using %s" % (name, sys.executable))
    completed = subprocess.run(command, cwd=str(ROOT), check=False)
    if completed.returncode:
        return completed.returncode

    readme = release_dir / "USB_README.txt"
    readme.write_text(
        "Digital Alibi USB bundle\n\n"
        "Run the executable from the evidence USB root so all capture files are written there.\n"
        "Windows: %s.exe capture\n"
        "Linux/macOS: ./%s capture\n\n"
        "This is a self-contained PyInstaller onedir bundle, not a fully static binary.\n"
        "Do not use a PyInstaller onefile build for forensic acquisition because it extracts to temp.\n" % (name, name),
        encoding="utf-8",
    )
    print("Created portable bundle: %s" % release_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
