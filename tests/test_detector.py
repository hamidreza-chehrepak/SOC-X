from src.detector import detect_brute_force, analyze_events


def test_brute_force_detected():
    alert = detect_brute_force(7, "192.168.1.50")

    assert alert is not None
    assert alert.source_ip == "192.168.1.50"
    assert alert.event_type == "Brute Force"
    assert alert.severity.value == "High"


def test_brute_force_not_detected():
    alert = detect_brute_force(3, "192.168.1.50")

    assert alert is None


def test_multiple_attack_sources():
    events = []

    for _ in range(5):
        events.append(
            {
                "timestamp": "2026-08-24 14:00:01",
                "event_type": "AUTH_FAILED",
                "source_ip": "10.0.0.25",
                "details": "username=root",
            }
        )

    for _ in range(5):
        events.append(
            {
                "timestamp": "2026-08-24 14:00:02",
                "event_type": "AUTH_FAILED",
                "source_ip": "172.16.0.10",
                "details": "username=admin",
            }
        )

    alerts = analyze_events(events)

    assert len(alerts) == 2