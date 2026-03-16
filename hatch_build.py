from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

logger = logging.getLogger(__name__)

LIB_NAME = "libtomd"


def get_ext(platform: str) -> str:
    matches: dict[str, str] = {"darwin": "dylib", "win32": "dll", "linux": "so"}
    return matches.get(platform, "so")


class CustomBuildHook(BuildHookInterface):  # type: ignore
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        if self.target_name not in ["wheel", "sdist"]:
            return

        self._build_libtomd()
        self._update_force_include()

        build_data["pure_python"] = False
        build_data["infer_tag"] = True

    def _build_libtomd(self) -> None:
        root = Path(self.root)
        go_dir = root / "go"
        build_dir = root / "build"

        build_dir.mkdir(parents=True, exist_ok=True)

        try:
            subprocess.check_call(["go", "mod", "download"], cwd=go_dir)
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to download Go dependencies: {e}")

        lib_ext = get_ext(sys.platform)

        lib_name = f"{LIB_NAME}.{lib_ext}"
        output_path = build_dir / lib_name

        logger.info(f"Building Go shared library: {lib_name}")
        build_cmd = [
            "go",
            "build",
            "-buildmode=c-shared",
            "-o",
            str(output_path),
            "./cmd/tojson",
        ]

        env = os.environ.copy()

        try:
            subprocess.check_call(build_cmd, cwd=go_dir, env=env)
        except subprocess.CalledProcessError as e:
            logger.error(f"Go build failed: {e}")
            raise

        if not output_path.exists():
            raise FileNotFoundError(
                f"Go build succeeded but library not found at {output_path}"
            )

        logger.info(f"Go library built successfully at {output_path}")

    def _update_force_include(self) -> None:
        root = Path(self.root)
        build_dir = root / "build"

        ext = get_ext(sys.platform)

        lib_name = f"{LIB_NAME}.{ext}"

        lib_path = build_dir / lib_name

        if lib_path.exists():
            if "force-include" in self.config:
                self.config["force-include"].clear()

            self.config.setdefault("force-include", {})[str(lib_path)] = (
                f"fibrum_pdf/lib/{lib_name}"
            )
