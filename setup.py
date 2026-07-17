"""Build the platform-native FibrumPDF wheel."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import Distribution, setup
from setuptools.command.bdist_wheel import bdist_wheel as bdist_wheel_base
from setuptools.command.build_py import build_py as build_py_base

ROOT = Path(__file__).parent.resolve()
PACKAGE = "fibrum_pdf"
MUPDF_DIR = ROOT / "lib" / "mupdf"


def library_name() -> str:
    """Return the native bridge filename for the build platform."""
    return {
        "darwin": "libtomd.dylib",
        "win32": "libtomd.dll",
    }.get(sys.platform, "libtomd.so")


def build_environment() -> dict[str, str]:
    """Expose locally supplied MuPDF libraries to Go and the linker."""
    environment = os.environ.copy()
    variable = {
        "win32": "PATH",
        "darwin": "DYLD_LIBRARY_PATH",
    }.get(sys.platform, "LD_LIBRARY_PATH")
    environment[variable] = f"{MUPDF_DIR}{os.pathsep}{environment.get(variable, '')}"
    return environment


def runtime_patterns() -> tuple[str, ...]:
    """Return MuPDF runtime dependency patterns for the build platform."""
    if sys.platform == "linux":
        return ("libmupdf.so.*",)
    if sys.platform == "darwin":
        return ("libmupdf*.dylib*",)
    if sys.platform == "win32":
        return ("*.dll",)
    return ("libmupdf*",)


def copy_runtime_dependencies(target: Path) -> None:
    """Copy the MuPDF runtime beside the bridge for wheel repair tools."""
    copied = False
    for pattern in runtime_patterns():
        for dependency in MUPDF_DIR.glob(pattern):
            if dependency.is_file():
                shutil.copy2(dependency, target / dependency.name)
                copied = True
    if sys.platform == "win32" and not copied:
        raise FileNotFoundError(f"Windows builds require MuPDF DLLs in {MUPDF_DIR}")


def build_native(target: Path) -> None:
    """Compile the Go bridge once and copy its runtime dependencies."""
    target = target.resolve()
    target.mkdir(parents=True, exist_ok=True)
    output = target / library_name()
    subprocess.run(
        ["go", "build", "-buildmode=c-shared", "-o", output, "./cmd/tojson"],
        cwd=ROOT / "go",
        env=build_environment(),
        check=True,
    )
    output.with_suffix(".h").unlink(missing_ok=True)
    copy_runtime_dependencies(target)


class BuildPy(build_py_base):
    """Build Python sources and the native bridge into the wheel tree."""

    def run(self) -> None:
        """Run the standard Python build, then add native artifacts."""
        super().run()
        build_native(Path(self.build_lib) / PACKAGE / "lib")


class BinaryDistribution(Distribution):
    """Mark the distribution as platform-specific."""

    def has_ext_modules(self) -> bool:
        """Force a platform wheel despite using a ctypes bridge."""
        return True


class PlatformWheel(bdist_wheel_base):
    """Tag the ctypes-based wheel for any supported Python 3 runtime."""

    def finalize_options(self) -> None:
        """Install package data into the platform library directory."""
        super().finalize_options()
        self.root_is_pure = False

    def get_tag(self) -> tuple[str, str, str]:
        """Return a Python-ABI-independent, platform-specific wheel tag."""
        return "py3", "none", super().get_tag()[2]


setup(
    name=PACKAGE,
    packages=[PACKAGE],
    include_package_data=False,
    cmdclass={"build_py": BuildPy, "bdist_wheel": PlatformWheel},
    distclass=BinaryDistribution,
)
