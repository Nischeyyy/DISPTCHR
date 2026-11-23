from pathlib import Path
import sys

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server import (
    MANAGER_PERMISSION_KEYS,
    enforce_manager_permission,
    normalize_manager_permissions,
    required_manager_permission,
    validate_shift_interval,
)


@pytest.mark.parametrize(
    ("path", "permission"),
    [
        ("/api/admin/dashboard", "dashboard.view"),
        ("/api/sos/active", "sos.manage"),
        ("/api/ops/live-locations", "locations.view"),
        ("/api/admin/guards", "guards.manage"),
        ("/api/admin/sites", "sites.manage"),
        ("/api/admin/scheduling/options", "scheduling.manage"),
        ("/api/admin/shifts", "scheduling.manage"),
        ("/api/admin/open-shifts", "scheduling.manage"),
        ("/api/admin/shift-swaps", "scheduling.manage"),
        ("/api/admin/timeclock", "timeclock.manage"),
        ("/api/admin/incidents", "incidents.manage"),
        ("/api/admin/payroll", "payroll.manage"),
        ("/api/admin/announcements", "announcements.manage"),
        ("/api/admin/community/posts/123", "announcements.manage"),
        ("/api/admin/compliance", "compliance.view"),
    ],
)
def test_manager_route_permission_map(path, permission):
    assert required_manager_permission(path) == permission


def test_missing_permissions_fail_closed():
    assert normalize_manager_permissions(None) == []
    with pytest.raises(HTTPException) as error:
        enforce_manager_permission({"role": "admin"}, "dashboard.view")
    assert error.value.status_code == 403


def test_unknown_permissions_are_removed():
    permissions = normalize_manager_permissions(["dashboard.view", "made.up", "dashboard.view"])
    assert permissions == ["dashboard.view"]
    assert set(permissions).issubset(MANAGER_PERMISSION_KEYS)


def test_employee_is_not_subject_to_manager_permission_helper():
    enforce_manager_permission({"role": "employee"}, "dashboard.view")


def test_shift_interval_rejects_invalid_or_reversed_values():
    with pytest.raises(HTTPException) as invalid:
        validate_shift_interval("not-a-date", "also-not-a-date")
    assert invalid.value.status_code == 422

    with pytest.raises(HTTPException) as reversed_interval:
        validate_shift_interval("2026-11-23T12:00:00Z", "2026-11-23T11:00:00Z")
    assert reversed_interval.value.status_code == 422

    validate_shift_interval("2026-11-23T11:00:00Z", "2026-11-23T12:00:00Z")
