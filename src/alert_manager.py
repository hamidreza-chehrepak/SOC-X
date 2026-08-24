import json
from pathlib import Path

from src.event import SecurityEvent


def save_alerts(alerts: list[SecurityEvent], file_path: str) -> None:
    path = Path(file_path)

    data = [alert.model_dump(mode="json") for alert in alerts]

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)