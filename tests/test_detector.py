from src.detector import detect_brute_force


def test_brute_force_detected():
    alert = detect_brute_force(7, "192.168.1.50")

    assert alert is not None
    assert alert.source_ip == "192.168.1.50"
    assert alert.event_type == "Brute Force"
    assert alert.severity.value == "High"


def test_brute_force_not_detected():
    alert = detect_brute_force(3, "192.168.1.50")

    assert alert is None