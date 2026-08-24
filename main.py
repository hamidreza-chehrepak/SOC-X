from src.alert_manager import save_alerts
from src.detector import analyze_events
from src.log_parser import parse_log_file


def main():
    log_file = "data/sample_auth.log"
    alert_file = "reports/alerts.json"

    events = parse_log_file(log_file)
    alerts = analyze_events(events)

    print("SOC-X")
    print("Security Operations Center Platform")
    print()
    print(f"Log file: {log_file}")
    print(f"Events analyzed: {len(events)}")
    print()

    if alerts:
        save_alerts(alerts, alert_file)

        print(f"SECURITY ALERTS: {len(alerts)}")
        print(f"Alerts saved to: {alert_file}")
        print()

        for alert in alerts:
            print(f"Source IP: {alert.source_ip}")
            print(f"Event Type: {alert.event_type}")
            print(f"Severity: {alert.severity.value}")
            print(f"Description: {alert.description}")
            print()
    else:
        print("No security threats detected.")


if __name__ == "__main__":
    main()