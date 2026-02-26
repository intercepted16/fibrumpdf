"""cffi bindings and library loading."""

from __future__ import annotations

import ctypes
import logging
import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

from cffi import FFI

log = logging.getLogger(__name__)
ENV_VAR = "FIBRUMPDF_LIB"


def _lib_names() -> str:
    if sys.platform == "darwin":
        return "libtomd.dylib"

    elif sys.platform == "win32":
        return "libtomd.dll"

    else:
        return "libtomd.so"


def _search_paths() -> list[Path]:
    pkg = Path(__file__).resolve().parent
    proj, build = pkg.parent, pkg.parent / "build"
    paths = [
        pkg / "lib",
        build / "lib" / "fibrum_pdf" / "lib",
        proj / "lib",
        proj / "lib" / "mupdf",
        build,
        build / "lib",
    ]
    if build.exists():
        for child in build.iterdir():
            if child.is_dir() and child.name.startswith("lib"):
                paths += [child / "fibrum_pdf" / "lib", child]
    return paths


@lru_cache(maxsize=1)
def find_library() -> Path | None:
    if env := os.environ.get(ENV_VAR):
        p = Path(env)
        if p.exists():
            log.debug("library from env: %s", p)
            return p.resolve()
    for d in _search_paths():
        if not d.exists():
            continue
        name = _lib_names()
        for f in d.rglob(name):
            if f.is_file():
                log.debug("found library: %s", f)
                return f.resolve()
    log.warning("libtomd not found")
    return None


@lru_cache(maxsize=1)
def get_ffi() -> FFI:
    ffi = FFI()
    ffi.cdef("""
        int pdf_to_json(const char *pdf_path, const char *output_dir);
        char *page_to_json_string(const char *pdf_path, int page_number);
        void free(void *ptr);
    """)
    return ffi


def load_library(path: Path) -> Any:
    log.debug("loading %s", path)
    if sys.platform != "win32":
        # look for mupdf in the same directory as libtomd, or in the project lib dir
        mupdf_search_paths = [
            path.parent,
            path.parent.parent.parent / "lib" / "mupdf",
            Path(__file__).resolve().parent.parent / "lib" / "mupdf",
        ]

        found_mupdf = False
        for d in mupdf_search_paths:
            if not d.exists():
                continue
            for mupdf in sorted(d.glob("libmupdf.so.*"), reverse=True) or list(
                d.glob("libmupdf.so")
            ):
                log.debug("preloading mupdf: %s", mupdf)
                try:
                    ctypes.CDLL(str(mupdf), mode=ctypes.RTLD_GLOBAL)
                    found_mupdf = True
                    break
                except Exception as e:
                    log.debug("failed to preload %s: %s", mupdf, e)
            if found_mupdf:
                break

    try:
        return get_ffi().dlopen(str(path))
    except OSError as e:
        log.error("load failed: %s", e)
        raise RuntimeError(f"failed to load libtomd: {e}") from e
