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
)


@pytest.mark.parametrize(
    ("path", "permission"),
    [
        ("/api/admin/dashboard", "dashboard.view"),
        ("/api/sos/active", "sos.manage"),
        ("/api/ops/live-locations", "locations.view"),
        ("/api/admin/guards", "guards.manage"),
        ("/api/admin/sites", "sites.manage"),
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
