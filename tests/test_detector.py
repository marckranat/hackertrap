from hackertrap.detector import PortScanTracker


def test_port_scan_triggers_at_threshold():
    tracker = PortScanTracker(threshold=3, window_seconds=60)
    base = 1000.0
    assert tracker.record("10.0.0.1", 22, now=base) is False
    assert tracker.record("10.0.0.1", 23, now=base + 1) is False
    assert tracker.record("10.0.0.1", 80, now=base + 2) is True
    # Same IP should not re-alert immediately
    assert tracker.record("10.0.0.1", 443, now=base + 3) is False


def test_port_scan_respects_window():
    tracker = PortScanTracker(threshold=3, window_seconds=10)
    base = 2000.0
    tracker.record("10.0.0.2", 22, now=base)
    tracker.record("10.0.0.2", 23, now=base + 1)
    # Old hits expired — need three fresh ports to trigger
    assert tracker.record("10.0.0.2", 80, now=base + 15) is False
    assert tracker.record("10.0.0.2", 443, now=base + 16) is False
    assert tracker.record("10.0.0.2", 8080, now=base + 17) is True
