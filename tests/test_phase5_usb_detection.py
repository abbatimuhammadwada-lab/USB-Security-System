"""
Phase 5 tests: device fingerprinting, classification, the simulation
monitor, and backend selection.

Run with: pytest tests/test_phase5_usb_detection.py -v
"""

import time

import pytest

from app.core.enums import DeviceClass, DeviceEventType
from app.core.exceptions import DeviceFingerprintError, USBDetectionError
from app.usb.device_info import USBDeviceInfo
from app.usb.fingerprint import compute_fingerprint
from app.usb.classifier import classify_device
from app.usb.simulation_monitor import SimulationUSBMonitor, DEVICE_PROFILES
from app.usb.factory import create_usb_monitor


# --- fingerprinting -------------------------------------------------
def test_fingerprint_strong_with_full_identity():
    info = USBDeviceInfo(
        event_type=DeviceEventType.CONNECTED.value,
        vendor_id="0951", product_id="1666", serial_number="ABC123",
    )
    fp = compute_fingerprint(info)
    assert fp.strength == "STRONG"
    assert len(fp.fingerprint_hash) == 64  # sha256 hex digest


def test_fingerprint_stable_across_calls():
    info = USBDeviceInfo(
        event_type=DeviceEventType.CONNECTED.value,
        vendor_id="0951", product_id="1666", serial_number="ABC123",
    )
    fp1 = compute_fingerprint(info)
    fp2 = compute_fingerprint(info)
    assert fp1.fingerprint_hash == fp2.fingerprint_hash


def test_fingerprint_case_insensitive():
    info_upper = USBDeviceInfo(event_type="CONNECTED", vendor_id="0951", product_id="1666", serial_number="ABC123")
    info_lower = USBDeviceInfo(event_type="CONNECTED", vendor_id="0951", product_id="1666", serial_number="abc123")
    assert compute_fingerprint(info_upper).fingerprint_hash == compute_fingerprint(info_lower).fingerprint_hash


def test_fingerprint_different_serials_differ():
    info1 = USBDeviceInfo(event_type="CONNECTED", vendor_id="0951", product_id="1666", serial_number="AAA")
    info2 = USBDeviceInfo(event_type="CONNECTED", vendor_id="0951", product_id="1666", serial_number="BBB")
    assert compute_fingerprint(info1).fingerprint_hash != compute_fingerprint(info2).fingerprint_hash


def test_fingerprint_weak_without_serial():
    info = USBDeviceInfo(event_type="CONNECTED", vendor_id="1234", product_id="5678")
    fp = compute_fingerprint(info)
    assert fp.strength == "WEAK"


def test_fingerprint_falls_back_to_name_when_no_ids():
    info = USBDeviceInfo(event_type="CONNECTED", name="Some Device", manufacturer="Acme")
    fp = compute_fingerprint(info)
    assert fp.strength == "WEAK"
    assert fp.fingerprint_hash


def test_fingerprint_raises_with_zero_information():
    info = USBDeviceInfo(event_type="CONNECTED")
    with pytest.raises(DeviceFingerprintError):
        compute_fingerprint(info)


def test_fingerprint_pnp_id_used_when_no_serial():
    info = USBDeviceInfo(
        event_type="CONNECTED", vendor_id="0951", product_id="1666",
        pnp_device_id=r"USBSTOR\DISK&VEN_X\INSTANCE1",
    )
    fp = compute_fingerprint(info)
    assert fp.strength == "STRONG"


# --- classification -------------------------------------------------
def test_classify_mass_storage():
    info = USBDeviceInfo(event_type="CONNECTED", name="Kingston DataTraveler", raw_device_class="USB Mass Storage")
    assert classify_device(info) == DeviceClass.MASS_STORAGE


def test_classify_mouse_not_confused_by_generic_hid_class():
    """Regression test: a mouse whose OS-reported class string is a
    generic 'Keyboard'/HID string must still classify as Mouse because
    its name is the more reliable signal. Caught during Phase 5
    development via the demo script - name must be checked before the
    raw OS class string, not merged with it."""
    info = USBDeviceInfo(event_type="CONNECTED", name="Logitech USB Optical Mouse", raw_device_class="Keyboard")
    assert classify_device(info) == DeviceClass.MOUSE


def test_classify_keyboard():
    info = USBDeviceInfo(event_type="CONNECTED", name="Dell USB Keyboard")
    assert classify_device(info) == DeviceClass.KEYBOARD


def test_classify_unknown_with_no_metadata():
    info = USBDeviceInfo(event_type="CONNECTED")
    assert classify_device(info) == DeviceClass.UNKNOWN


def test_classify_other_peripheral_when_unrecognized_string_present():
    info = USBDeviceInfo(event_type="CONNECTED", name="Some Obscure Widget 9000")
    assert classify_device(info) == DeviceClass.OTHER_PERIPHERAL


def test_classify_smartphone():
    info = USBDeviceInfo(event_type="CONNECTED", name="Samsung Galaxy (MTP)")
    assert classify_device(info) == DeviceClass.SMARTPHONE


# --- simulation monitor -------------------------------------------------
@pytest.fixture()
def collected_events():
    events = []
    return events


def test_simulation_monitor_emits_connect_event(collected_events):
    monitor = SimulationUSBMonitor(on_event=collected_events.append)
    monitor.start()
    monitor.inject_connect("kingston_datatraveler")
    time.sleep(0.2)
    monitor.stop()

    assert len(collected_events) == 1
    assert collected_events[0].is_simulated is True
    assert collected_events[0].event_type == DeviceEventType.CONNECTED.value
    assert collected_events[0].name == "Kingston DataTraveler 3.0"


def test_simulation_monitor_emits_remove_event(collected_events):
    monitor = SimulationUSBMonitor(on_event=collected_events.append)
    monitor.start()
    monitor.inject_remove("kingston_datatraveler")
    time.sleep(0.2)
    monitor.stop()

    assert collected_events[0].event_type == DeviceEventType.REMOVED.value


def test_simulation_monitor_overrides_profile_fields(collected_events):
    monitor = SimulationUSBMonitor(on_event=collected_events.append)
    monitor.start()
    monitor.inject_connect("kingston_datatraveler", serial_number="OVERRIDDEN")
    time.sleep(0.2)
    monitor.stop()

    assert collected_events[0].serial_number == "OVERRIDDEN"
    assert collected_events[0].name == "Kingston DataTraveler 3.0"  # unchanged


def test_simulation_monitor_multiple_events_in_order(collected_events):
    monitor = SimulationUSBMonitor(on_event=collected_events.append)
    monitor.start()
    monitor.inject_connect("kingston_datatraveler")
    monitor.inject_connect("logitech_mouse")
    monitor.inject_remove("kingston_datatraveler")
    time.sleep(0.3)
    monitor.stop()

    assert len(collected_events) == 3
    assert collected_events[0].name == "Kingston DataTraveler 3.0"
    assert collected_events[1].name == "Logitech USB Optical Mouse"
    assert collected_events[2].event_type == DeviceEventType.REMOVED.value


def test_simulation_monitor_stop_is_clean_and_idempotent(collected_events):
    monitor = SimulationUSBMonitor(on_event=collected_events.append)
    monitor.start()
    monitor.stop()
    monitor.stop()  # must not raise
    assert monitor.is_running is False


def test_device_profiles_are_internally_consistent():
    """Every built-in demo profile must be fingerprintable and
    classifiable without raising, even the ones with sparse metadata."""
    for name, fields in DEVICE_PROFILES.items():
        info = USBDeviceInfo(event_type="CONNECTED", **fields)
        classify_device(info)  # must not raise
        if any(fields.values()):
            compute_fingerprint(info)  # must not raise for profiles with some identity
        else:
            with pytest.raises(DeviceFingerprintError):
                compute_fingerprint(info)


# --- factory / backend selection -------------------------------------------------
def test_factory_returns_simulation_monitor_when_simulation_mode_true():
    monitor = create_usb_monitor(on_event=lambda info: None, simulation_override=True)
    assert isinstance(monitor, SimulationUSBMonitor)


def test_factory_refuses_real_mode_on_non_windows(monkeypatch):
    from app.config import settings as settings_module
    if settings_module.settings.is_windows:
        pytest.skip("This test only applies on non-Windows platforms.")
    with pytest.raises(USBDetectionError):
        create_usb_monitor(on_event=lambda info: None, simulation_override=False)
