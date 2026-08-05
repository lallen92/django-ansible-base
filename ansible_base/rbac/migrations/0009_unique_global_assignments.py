"""
Add partial unique constraints to prevent duplicate global role assignments.

Uses SeparateDatabaseAndState because Django's AddConstraint generates
CREATE INDEX (blocking writes). We use CREATE INDEX CONCURRENTLY on PostgreSQL
to avoid locking the table, which requires atomic = False and raw SQL.
Indexes are dropped before creation so the migration is safe to re-run
if it fails partway through (e.g. after only one index was created).
SQLite (CI-only) uses plain CREATE INDEX since it has no CONCURRENTLY support.
"""

import logging

from django.db import migrations, models, transaction

logger = logging.getLogger('ansible_base.rbac.migrations')

BATCH_SIZE = 1000


def deduplicate_global_assignments(apps, schema_editor):
    """Remove duplicate global role assignments, keeping the oldest (lowest pk) for each."""
    for model_name, actor_field in [('RoleUserAssignment', 'user'), ('RoleTeamAssignment', 'team')]:
        cls = apps.get_model('dab_rbac', model_name)
        duplicates = (
            cls.objects.filter(object_role__isnull=True)
            .values(actor_field, 'role_definition')
            .annotate(min_pk=models.Min('pk'), cnt=models.Count('pk'))
            .filter(cnt__gt=1)
            .iterator()
        )
        total_deleted = 0
        for dup in duplicates:
            qs = cls.objects.filter(
                object_role__isnull=True,
                role_definition=dup['role_definition'],
                **{actor_field: dup[actor_field]},
            ).exclude(pk=dup['min_pk'])
            while True:
                batch_pks = list(qs.values_list('pk', flat=True)[:BATCH_SIZE])
                if not batch_pks:
                    break
                with transaction.atomic():
                    deleted_count, _ = cls.objects.filter(pk__in=batch_pks).delete()
                total_deleted += deleted_count
        if total_deleted:
            logger.info('Deleted %d duplicate global %s entries', total_deleted, model_name)


def _drop_index_if_exists(schema_editor, index_name):
    """Drop an index if it exists, so CREATE INDEX can be re-run safely."""
    schema_editor.execute(
        "DROP INDEX IF EXISTS %s" % index_name
    )


def create_unique_indexes(apps, schema_editor):
    deduplicate_global_assignments(apps, schema_editor)

    if schema_editor.connection.vendor == 'postgresql':
        _drop_index_if_exists(schema_editor, '"unique_global_user_assignment"')
        _drop_index_if_exists(schema_editor, '"unique_global_team_assignment"')
        schema_editor.execute(
            'CREATE UNIQUE INDEX CONCURRENTLY "unique_global_user_assignment"'
            ' ON "dab_rbac_roleuserassignment" ("user_id", "role_definition_id")'
            ' WHERE "object_role_id" IS NULL'
        )
        schema_editor.execute(
            'CREATE UNIQUE INDEX CONCURRENTLY "unique_global_team_assignment"'
            ' ON "dab_rbac_roleteamassignment" ("team_id", "role_definition_id")'
            ' WHERE "object_role_id" IS NULL'
        )
    else:
        schema_editor.execute('DROP INDEX IF EXISTS "unique_global_user_assignment"')
        schema_editor.execute('DROP INDEX IF EXISTS "unique_global_team_assignment"')
        schema_editor.execute(
            'CREATE UNIQUE INDEX "unique_global_user_assignment"'
            ' ON "dab_rbac_roleuserassignment" ("user_id", "role_definition_id")'
            ' WHERE "object_role_id" IS NULL'
        )
        schema_editor.execute(
            'CREATE UNIQUE INDEX "unique_global_team_assignment"'
            ' ON "dab_rbac_roleteamassignment" ("team_id", "role_definition_id")'
            ' WHERE "object_role_id" IS NULL'
        )


def drop_unique_indexes(apps, schema_editor):
    if schema_editor.connection.vendor == 'postgresql':
        schema_editor.execute('DROP INDEX CONCURRENTLY IF EXISTS "unique_global_user_assignment"')
        schema_editor.execute('DROP INDEX CONCURRENTLY IF EXISTS "unique_global_team_assignment"')
    else:
        schema_editor.execute('DROP INDEX IF EXISTS "unique_global_user_assignment"')
        schema_editor.execute('DROP INDEX IF EXISTS "unique_global_team_assignment"')


class Migration(migrations.Migration):

    atomic = False

    dependencies = [
        ('dab_rbac', '0008_remote_permissions_cleanup'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(create_unique_indexes, drop_unique_indexes),
            ],
            state_operations=[
                migrations.AddConstraint(
                    model_name='roleuserassignment',
                    constraint=models.UniqueConstraint(
                        fields=['user', 'role_definition'],
                        condition=models.Q(object_role__isnull=True),
                        name='unique_global_user_assignment',
                    ),
                ),
                migrations.AddConstraint(
                    model_name='roleteamassignment',
                    constraint=models.UniqueConstraint(
                        fields=['team', 'role_definition'],
                        condition=models.Q(object_role__isnull=True),
                        name='unique_global_team_assignment',
                    ),
                ),
            ],
        ),
    ]
