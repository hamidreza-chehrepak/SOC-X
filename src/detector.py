from src.event import SecurityEvent, Severity


def detect_brute_force(failed_attempts: int, source_ip: str) -> SecurityEvent | None:
    if failed_attempts >= 5:
        return SecurityEvent(
            source_ip=source_ip,
            event_type="Brute Force",
            severity=Severity.HIGH,
            description=f"{failed_attempts} failed login attempts detected",
        )

    return None


def analyze_events(events: list[dict]) -> list[SecurityEvent]:
    failed_attempts_by_ip: dict[str, int] = {}

    for event in events:
        if event["event_type"] == "AUTH_FAILED":
            source_ip = event["source_ip"]

            failed_attempts_by_ip[source_ip] = (
                failed_attempts_by_ip.get(source_ip, 0) + 1
            )

    alerts: list[SecurityEvent] = []

    for source_ip, failed_attempts in failed_attempts_by_ip.items():
        alert = detect_brute_force(failed_attempts, source_ip)

        if alert:
            alerts.append(alert)

    return alerts