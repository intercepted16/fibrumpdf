from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import setup, Distribution
from setuptools.command.build_py import build_py as build_py_base
from setuptools.command.install import install as install_base

from setuptools.command.bdist_wheel import bdist_wheel as bdist_wheel_base

ROOT = Path(__file__).parent.resolve()
PACKAGENAME = "fibrum_pdf"
LIB_BASENAME = "tomd"
GO_DIR = ROOT / "go"
BUILD_DIR = ROOT / "build"
LIB_EXT_BY_PLATFORM = {"linux": ".so", "darwin": ".dylib", "win32": ".dll"}


def _download_go_deps() -> None:
    print("Downloading Go dependencies...")
    try:
        subprocess.check_call(["go", "mod", "download"], cwd=GO_DIR)
    except subprocess.CalledProcessError as e:
        print(f"Warning: Failed to download Go dependencies: {e}")


def _lib_name() -> str:
    lib_ext = LIB_EXT_BY_PLATFORM.get(sys.platform, ".so")
    return f"lib{LIB_BASENAME}{lib_ext}"


def _build_shared_library() -> Path:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    _download_go_deps()
    output_path = BUILD_DIR / _lib_name()
    print(f"Building Go shared library: {output_path.name}")
    subprocess.check_call(
        [
            "go",
            "build",
            "-buildmode=c-shared",
            "-o",
            str(output_path),
            "./cmd/tojson",
        ],
        cwd=GO_DIR,
        env=os.environ.copy(),
    )
    if not output_path.exists():
        raise FileNotFoundError(
            f"Go build succeeded but library not found at {output_path}"
        )
    return output_path


def _copy_library(output_path: Path, target_dir: Path, *, suffix: str = "") -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    message_suffix = f" {suffix}" if suffix else ""
    print(f"Copying {output_path} to {target_dir / output_path.name}{message_suffix}")
    shutil.copy2(output_path, target_dir / output_path.name)


class build_py(build_py_base):
    """Custom build that compiles the Go shared library."""

    def run(self) -> None:
        self._build_libtomd()
        super().run()

    def _build_libtomd(self) -> None:
        output_path = _build_shared_library()
        target_dir = Path(self.build_lib) / PACKAGENAME / "lib"
        _copy_library(output_path, target_dir)


class BinaryDistribution(Distribution):
    """Distribution which always forces a binary package with platform name."""

    def has_ext_modules(self):
        return True


class bdist_wheel(bdist_wheel_base):
    """Custom bdist_wheel to mark the wheel as platform-specific."""

    def finalize_options(self) -> None:
        super().finalize_options()

        self.root_is_pure = False

    def get_tag(self):

        python, abi, plat = super().get_tag()

        if abi == "none" and plat == "any":
            from wheel.bdist_wheel import get_platform

            plat = get_platform(self.bdist_dir)
            python = f"cp{sys.version_info.major}{sys.version_info.minor}"
            abi = f"cp{sys.version_info.major}{sys.version_info.minor}"
        return python, abi, plat


class install(install_base):
    """Custom install to use platlib instead of purelib and rebuild Go library."""

    def run(self) -> None:

        self._build_and_install_libtomd()
        super().run()

    def finalize_options(self) -> None:
        super().finalize_options()

        if self.install_lib is None:
            self.install_lib = self.install_platlib

    def _build_and_install_libtomd(self) -> None:
        """Build Go library and copy to both build location and source tree."""
        output_path = _build_shared_library()

        source_lib_dir = ROOT / PACKAGENAME / "lib"
        _copy_library(output_path, source_lib_dir, suffix="(source tree)")

        target_dir = Path(self.build_lib) / PACKAGENAME / "lib"
        _copy_library(output_path, target_dir, suffix="(build tree)")


if __name__ == "__main__":
    setup(
        name=PACKAGENAME,
        packages=[PACKAGENAME],
        package_data={PACKAGENAME: ["lib/*.so", "lib/*.dylib", "lib/*.dll"]},
        cmdclass={"build_py": build_py, "bdist_wheel": bdist_wheel, "install": install},
        distclass=BinaryDistribution,
    )
