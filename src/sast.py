import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from .config import resolve

CPP_SUFFIXES = {".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"}
NULL_CWES = {"476"}


def cppcheck_exe(cfg):
    configured = resolve(cfg["sast"]["cppcheck_path"])
    if configured.exists():
        return str(configured)
    found = shutil.which("cppcheck")
    if not found:
        raise FileNotFoundError("Cppcheck not found: set sast.cppcheck_path in config.yaml or add cppcheck to PATH")
    return found


def scan(cfg, code, file_path=""):
    suffix = ".cpp" if Path(file_path or "").suffix.lower() in CPP_SUFFIXES else ".c"
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / f"func{suffix}"
        source.write_text(code, encoding="utf-8")
        proc = subprocess.run(
            [cppcheck_exe(cfg), *cfg["sast"]["args"], "--xml", "--quiet", str(source)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=cfg["sast"]["timeout"],
        )
    try:
        root = ET.fromstring(proc.stderr)
    except ET.ParseError:
        return []
    alerts = []
    for error in root.iter("error"):
        location = error.find("location")
        alerts.append(
            {
                "id": error.get("id"),
                "severity": error.get("severity"),
                "cwe": error.get("cwe"),
                "line": int(location.get("line")) if location is not None else None,
                "msg": error.get("msg"),
            }
        )
    return alerts


def is_null_alert(alert):
    return alert["cwe"] in NULL_CWES or "nullpointer" in (alert["id"] or "").lower()
