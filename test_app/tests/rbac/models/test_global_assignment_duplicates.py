"""Regression tests for AAP-83436: duplicate global role assignments."""

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError

from ansible_base.rbac.models import RoleDefinition, RoleTeamAssignment, RoleUserAssignment, DABContentType


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

    def test_different_users_same_role(self, global_inv_rd):
        user1 = get_user_model().objects.create(username='user1')
        user2 = get_user_model().objects.create(username='user2')
        assignment1 = global_inv_rd.give_global_permission(user1)
        assignment2 = global_inv_rd.give_global_permission(user2)
        assert assignment1.pk != assignment2.pk

    def test_same_user_different_roles(self, rando):
        rd1 = RoleDefinition.objects.create_from_permissions(permissions=['view_inventory'], name='global-view-inv', content_type=None)
        rd2 = RoleDefinition.objects.create_from_permissions(permissions=['change_inventory', 'view_inventory'], name='global-change-inv', content_type=None)
        assignment1 = rd1.give_global_permission(rando)
        assignment2 = rd2.give_global_permission(rando)
        assert assignment1.pk != assignment2.pk
        assert RoleUserAssignment.objects.filter(user=rando, object_role__isnull=True).count() == 2


    def test_constraint_does_not_affect_object_assignments(self, rando, inventory, global_inv_rd):
        rd = RoleDefinition.objects.create_from_permissions(
            permissions=['view_inventory'], name='object-view-inv', content_type=global_inv_rd.content_type or RoleUserAssignment.objects.model._meta.app_config.get_model('dabcontenttype').objects.first(),
        )
        # This test needs a role definition with a content_type to create object-level assignments
        ct = DABContentType.objects.get_for_model(inventory)
        rd = RoleDefinition.objects.create_from_permissions(permissions=['view_inventory'], name='obj-inv-rd', content_type=ct)
        rd.give_permission(rando, inventory)
        rd.give_global_permission(rando)
        assert RoleUserAssignment.objects.filter(user=rando, role_definition=rd).count() == 2


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
