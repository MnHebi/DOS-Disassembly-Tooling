"""Zip the platform-native PyInstaller onedir distribution."""
import pathlib
import platform
import shutil

root = pathlib.Path(__file__).resolve().parent.parent
system = platform.system().lower()
if system not in ("linux", "windows"):
    raise SystemExit(f"unsupported release host: {system}")
release = root / "release"
release.mkdir(exist_ok=True)
name = f"DDT-0.1.0-{system}-x86_64"
result = shutil.make_archive(str(release / name), "zip", root_dir=root / "dist", base_dir="ddt")
print(result)
