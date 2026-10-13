from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load_config(path="config.yaml"):
    with open(resolve(path), encoding="utf-8") as f:
        return yaml.safe_load(f)


def resolve(path):
    path = Path(path)
    return path if path.is_absolute() else ROOT / path
