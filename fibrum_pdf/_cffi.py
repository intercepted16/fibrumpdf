"""ctypes bindings and library loading."""

from __future__ import annotations

import ctypes
import logging
import os
import sys
from functools import lru_cache
from importlib import metadata
from pathlib import Path

log = logging.getLogger(__name__)
_dll_directory_handles: list[object] = []


@lru_cache(maxsize=1)
def find_library() -> Path | None:
    env = os.environ.get("FIBRUMPDF_LIB")
    if env and (p := Path(env)).exists():
        log.debug("library from env: %s", p)
        return p.resolve()

    pkg = Path(__file__).resolve().parent
    proj, build = pkg.parent, pkg.parent / "build"
    lib_name = {"darwin": "libtomd.dylib", "win32": "libtomd.dll"}.get(
        sys.platform, "libtomd.so"
    )

    for d in [
        pkg / "lib",
        build / "lib" / "fibrum_pdf" / "lib",
        proj / "lib",
        proj / "lib" / "mupdf",
        build,
        build / "lib",
    ]:
        if d.exists():
            for f in d.rglob(lib_name):
                if f.is_file():
                    log.debug("found library: %s", f)
                    return f.resolve()

    if build.exists():
        for child in build.iterdir():
            if child.is_dir() and child.name.startswith("lib"):
                for f in (child / "fibrum_pdf" / "lib").rglob(lib_name):
                    if f.is_file():
                        return f.resolve()

    try:
        dist = metadata.distribution("fibrum-pdf")
    except metadata.PackageNotFoundError:
        dist = None

    if dist is not None:
        files = dist.files or []
        for file in files:
            if file.parts[-3:] == ("fibrum_pdf", "lib", lib_name):
                f = Path(dist.locate_file(file))
                if f.is_file():
                    log.debug("found installed package library: %s", f)
                    return f.resolve()

    log.warning("libtomd not found")
    return None


@lru_cache(maxsize=1)
def load_library(path: Path) -> ctypes.CDLL:
    log.debug("loading %s", path)
    dependency_dirs = [
        path.parent,
        path.parent.parent.parent / "lib" / "mupdf",
        Path(__file__).resolve().parent.parent / "lib" / "mupdf",
    ]
    if sys.platform == "win32":
        for d in dependency_dirs:
            if d.exists() and hasattr(os, "add_dll_directory"):
                _dll_directory_handles.append(os.add_dll_directory(str(d)))
            if d.exists():
                os.environ["PATH"] = f"{d}{os.pathsep}{os.environ.get('PATH', '')}"
    else:
        for d in dependency_dirs:
            if d.exists():
                for mupdf in sorted(d.glob("libmupdf.so.*"), reverse=True) or list(
                    d.glob("libmupdf.so")
                ):
                    try:
                        ctypes.CDLL(str(mupdf), mode=ctypes.RTLD_GLOBAL)
                        break
                    except Exception:
                        pass
    try:
        lib = ctypes.CDLL(str(path))
        lib.pdf_to_json.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.pdf_to_json.restype = ctypes.c_int
        return lib
    except OSError as e:
        log.error("load failed: %s", e)
        raise RuntimeError(f"failed to load libtomd: {e}") from e
