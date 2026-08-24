from pathlib import Path


def read_log_file(file_path: str) -> list[str]:
    path = Path(file_path)

    with path.open("r", encoding="utf-8") as file:
        return file.readlines()


def parse_log_line(line: str) -> dict:
    parts = [part.strip() for part in line.split("|")]

    return {
        "timestamp": parts[0],
        "event_type": parts[1],
        "source_ip": parts[2],
        "details": parts[3],
    }


def parse_log_file(file_path: str) -> list[dict]:
    lines = read_log_file(file_path)

    return [parse_log_line(line) for line in lines]