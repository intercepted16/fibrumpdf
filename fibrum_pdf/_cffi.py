"""ctypes bindings and native library discovery."""

from __future__ import annotations

import ctypes
import logging
import os
import sys
from functools import lru_cache
from pathlib import Path

log = logging.getLogger(__name__)
_dll_directory_handles: list[object] = []


def _library_name() -> str:
    return {
        "darwin": "libtomd.dylib",
        "win32": "libtomd.dll",
    }.get(sys.platform, "libtomd.so")


@lru_cache(maxsize=1)
def find_library() -> Path | None:
    """Find the bundled, locally built, or explicitly configured bridge."""
    if configured := os.environ.get("FIBRUMPDF_LIB"):
        path = Path(configured).expanduser()
        if path.is_file():
            return path.resolve()

    package = Path(__file__).resolve().parent
    project, name = package.parent, _library_name()
    candidates = [package / "lib" / name, project / "lib" / name]
    candidates.extend((project / "build").glob(f"lib*/fibrum_pdf/lib/{name}"))
    for path in candidates:
        if path.is_file():
            log.debug("found native library: %s", path)
            return path.resolve()
    return None


def _prepare_dependencies(path: Path) -> None:
    directories = (
        path.parent,
        Path(__file__).resolve().parent.parent / "lib" / "mupdf",
    )
    if sys.platform == "win32":
        for directory in directories:
            if directory.is_dir() and hasattr(os, "add_dll_directory"):
                _dll_directory_handles.append(os.add_dll_directory(str(directory)))
        return

    pattern = "libmupdf*.dylib*" if sys.platform == "darwin" else "libmupdf.so*"
    for directory in directories:
        for dependency in sorted(directory.glob(pattern), reverse=True):
            try:
                ctypes.CDLL(str(dependency), mode=ctypes.RTLD_GLOBAL)
                return
            except OSError:
                continue


def _configure_abi(library: ctypes.CDLL) -> None:
    library.pdf_to_json.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    library.pdf_to_json.restype = ctypes.c_int
    if hasattr(library, "pdf_to_json_with_error"):
        library.pdf_to_json_with_error.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        library.pdf_to_json_with_error.restype = ctypes.c_void_p
        library.free_string.argtypes = [ctypes.c_void_p]
        library.free_string.restype = None


@lru_cache(maxsize=1)
def load_library(path: Path) -> ctypes.CDLL:
    """Load and configure the native bridge at ``path``."""
    _prepare_dependencies(path)
    try:
        library = ctypes.CDLL(str(path))
    except OSError as error:
        raise RuntimeError(f"failed to load libtomd: {error}") from error
    _configure_abi(library)
    return library
