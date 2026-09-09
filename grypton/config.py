"""Explicit model routing; there is no implicit provider or model fallback."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from importlib.resources import files
from pathlib import Path


class GryptonError(Exception):
    """An actionable error suitable for the CLI after credential redaction."""


def resource(name: str) -> str:
    return files("grypton").joinpath("resources", name).read_text(encoding="utf-8")


@dataclass(frozen=True)
class Model:
    runner: str
    provider: str
    model: str
    effort: str
    name: str

    @property
    def qualified(self) -> str:
        return f"{self.provider}/{self.model}" if self.runner == "opencode" else self.model

    def public(self) -> dict:
        return {**asdict(self), "qualified": self.qualified}


MODELS = {role: Model(**value) for role, value in json.loads(resource("models.json")).items()}


@dataclass(frozen=True)
class Settings:
    root: Path
    timeout: float = 600

    @classmethod
    def load(cls, root: str | Path | None = None, timeout: float = 600) -> Settings:
        package_root = Path(__file__).resolve().parent.parent
        default_root = package_root if (package_root / "FORK_MANIFEST.json").is_file() else Path.cwd()
        chosen = root or os.environ.get("GRYPTON_ROOT") or default_root
        path = Path(chosen).expanduser().absolute()
        if "targets" in path.parts or path == Path("/root/krypton") or Path("/root/krypton") in path.parents:
            raise GryptonError("Choose a Grypton workspace outside the original project and targets directories.")
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise GryptonError("The workspace path must not contain symlinks.")
        if not 1 <= timeout <= 3600:
            raise GryptonError("The provider timeout must be between 1 and 3600 seconds.")
        path = path.resolve()
        if "targets" in path.parts or path == Path("/root/krypton") or Path("/root/krypton") in path.parents:
            raise GryptonError("Choose a workspace outside the original project and targets directories.")
        return cls(path, timeout)

    @property
    def state(self) -> Path:
        return self.root / ".state"
