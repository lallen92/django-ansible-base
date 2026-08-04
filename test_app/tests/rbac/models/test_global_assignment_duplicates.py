"""Regression tests for AAP-83436: duplicate global role assignments."""

import pytest
from django.db import IntegrityError

from ansible_base.rbac.models import RoleTeamAssignment, RoleUserAssignment


@pytest.mark.django_db
class TestGlobalUserAssignmentConstraint:
    def test_idempotent(self, rando, global_inv_rd):
        assignment1 = global_inv_rd.give_global_permission(rando)
        assignment2 = global_inv_rd.give_global_permission(rando)
        assert assignment1.pk == assignment2.pk
        assert RoleUserAssignment.objects.filter(user=rando, role_definition=global_inv_rd, object_role__isnull=True).count() == 1

    def test_duplicate_prevented_by_constraint(self, rando, global_inv_rd):
        global_inv_rd.give_global_permission(rando)
        with pytest.raises(IntegrityError):
            RoleUserAssignment.objects.create(user=rando, role_definition=global_inv_rd, object_role=None)


@pytest.mark.django_db
class TestGlobalTeamAssignmentConstraint:
    def test_idempotent(self, team, global_inv_rd):
        assignment1 = global_inv_rd.give_global_permission(team)
        assignment2 = global_inv_rd.give_global_permission(team)
        assert assignment1.pk == assignment2.pk
        assert RoleTeamAssignment.objects.filter(team=team, role_definition=global_inv_rd, object_role__isnull=True).count() == 1

    def test_duplicate_prevented_by_constraint(self, team, global_inv_rd):
        global_inv_rd.give_global_permission(team)
        with pytest.raises(IntegrityError):
            RoleTeamAssignment.objects.create(team=team, role_definition=global_inv_rd, object_role=None)
