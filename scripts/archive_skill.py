"""Zip the installable Agent Skill directory for distribution.

The skill is not part of the wheel or of the frozen binaries, so it ships as its own
archive: unzip it into any Agent Skills-compatible client's skill directory.
"""
import pathlib
import shutil
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILL_NAME = "ddt-dos-reverse-engineering"
VERSION = "0.1.0"
EXPECTED = frozenset({
    f"{SKILL_NAME}/SKILL.md",
    f"{SKILL_NAME}/references/commands.md",
    f"{SKILL_NAME}/references/evidence.md",
})


def build(destination: pathlib.Path) -> pathlib.Path:
    """Write the skill archive into destination and return the archive path."""
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / f"DDT-{VERSION}-skill.zip"
    archive.unlink(missing_ok=True)
    archive = pathlib.Path(shutil.make_archive(
        str(archive.with_suffix("")), "zip", root_dir=ROOT / "skills", base_dir=SKILL_NAME))
    with zipfile.ZipFile(archive) as opened:
        members = frozenset(name for name in opened.namelist() if not name.endswith("/"))
    if members != EXPECTED:
        archive.unlink()
        raise SystemExit(f"unexpected skill archive contents: {sorted(members)}")
    return archive


if __name__ == "__main__":
    print(build(ROOT / "release"))
