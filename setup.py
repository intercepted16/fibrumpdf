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
TARGET_NAME = "tomd"
LIB_BASENAME = "tomd"
MUPDF_DIR = ROOT / "lib" / "mupdf"


def platform_lib_name() -> str:
    if sys.platform == "linux":
        return f"lib{LIB_BASENAME}.so"
    if sys.platform == "darwin":
        return f"lib{LIB_BASENAME}.dylib"
    if sys.platform == "win32":
        return f"lib{LIB_BASENAME}.dll"
    return f"lib{LIB_BASENAME}.so"


def platform_runtime_patterns() -> list[str]:
    if sys.platform == "linux":
        return ["libmupdf.so*"]
    if sys.platform == "darwin":
        return ["libmupdf*.dylib*"]
    if sys.platform == "win32":
        return ["*.dll"]
    return ["libmupdf*"]


def build_env() -> dict[str, str]:
    env = os.environ.copy()
    if MUPDF_DIR.exists():
        if sys.platform == "win32":
            env["PATH"] = f"{MUPDF_DIR}{os.pathsep}{env.get('PATH', '')}"
        elif sys.platform == "darwin":
            env["DYLD_LIBRARY_PATH"] = (
                f"{MUPDF_DIR}{os.pathsep}{env.get('DYLD_LIBRARY_PATH', '')}"
            )
        else:
            env["LD_LIBRARY_PATH"] = (
                f"{MUPDF_DIR}{os.pathsep}{env.get('LD_LIBRARY_PATH', '')}"
            )
    return env


def copy_mupdf_runtime_deps(target_dir: Path) -> None:
    if not MUPDF_DIR.exists():
        return
    copied = False
    for pattern in platform_runtime_patterns():
        for dep in MUPDF_DIR.glob(pattern):
            if dep.is_file():
                print(f"Copying MuPDF runtime dependency {dep} to {target_dir / dep.name}")
                shutil.copy2(dep, target_dir / dep.name)
                copied = True
    if sys.platform == "win32" and not copied:
        raise FileNotFoundError(
            f"Windows builds require libmupdf.dll in {MUPDF_DIR}. "
            "Download it from the mupdf-prebuilts release before building."
        )


class build_py(build_py_base):
    """Custom build that compiles the Go shared library."""

    def run(self) -> None:
        self._build_libtomd()
        super().run()

    def _build_libtomd(self) -> None:
        go_dir = ROOT / "go"
        build_dir = ROOT / "build"

        build_dir.mkdir(parents=True, exist_ok=True)

        print("Downloading Go dependencies...")
        try:
            subprocess.check_call(["go", "mod", "download"], cwd=go_dir)
        except subprocess.CalledProcessError as e:
            print(f"Warning: Failed to download Go dependencies: {e}")

        lib_name = platform_lib_name()
        output_path = build_dir / lib_name

        print(f"Building Go shared library: {lib_name}")
        build_cmd = [
            "go",
            "build",
            "-buildmode=c-shared",
            "-o",
            str(output_path),
            "./cmd/tojson",
        ]

        env = build_env()

        try:
            subprocess.check_call(build_cmd, cwd=go_dir, env=env)
        except subprocess.CalledProcessError as e:
            print(f"Error building Go library: {e}")
            raise

        if not output_path.exists():
            raise FileNotFoundError(
                f"Go build succeeded but library not found at {output_path}"
            )

        target_dir = Path(self.build_lib) / PACKAGENAME / "lib"
        target_dir.mkdir(parents=True, exist_ok=True)

        print(f"Copying {output_path} to {target_dir / lib_name}")
        shutil.copy2(output_path, target_dir / lib_name)
        copy_mupdf_runtime_deps(target_dir)


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
        go_dir = ROOT / "go"
        build_dir = ROOT / "build"

        build_dir.mkdir(parents=True, exist_ok=True)

        print("Downloading Go dependencies...")
        try:
            subprocess.check_call(["go", "mod", "download"], cwd=go_dir)
        except subprocess.CalledProcessError as e:
            print(f"Warning: Failed to download Go dependencies: {e}")

        lib_name = platform_lib_name()
        output_path = build_dir / lib_name

        print(f"Building Go shared library: {lib_name}")
        build_cmd = [
            "go",
            "build",
            "-buildmode=c-shared",
            "-o",
            str(output_path),
            "./cmd/tojson",
        ]

        env = build_env()

        try:
            subprocess.check_call(build_cmd, cwd=go_dir, env=env)
        except subprocess.CalledProcessError as e:
            print(f"Error building Go library: {e}")
            raise

        if not output_path.exists():
            raise FileNotFoundError(
                f"Go build succeeded but library not found at {output_path}"
            )

        source_lib_dir = ROOT / PACKAGENAME / "lib"
        source_lib_dir.mkdir(parents=True, exist_ok=True)
        print(f"Copying {output_path} to {source_lib_dir / lib_name} (source tree)")
        shutil.copy2(output_path, source_lib_dir / lib_name)
        copy_mupdf_runtime_deps(source_lib_dir)

        target_dir = Path(self.build_lib) / PACKAGENAME / "lib"
        target_dir.mkdir(parents=True, exist_ok=True)
        print(f"Copying {output_path} to {target_dir / lib_name} (build tree)")
        shutil.copy2(output_path, target_dir / lib_name)
        copy_mupdf_runtime_deps(target_dir)


if __name__ == "__main__":
    setup(
        name=PACKAGENAME,
        packages=[PACKAGENAME],
        package_data={
            PACKAGENAME: ["lib/*.so", "lib/*.so.*", "lib/*.dylib", "lib/*.dll"]
        },
        cmdclass={"build_py": build_py, "bdist_wheel": bdist_wheel, "install": install},
        distclass=BinaryDistribution,
    )
