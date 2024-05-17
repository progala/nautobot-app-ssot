# Generated by Django 3.2.23 on 2024-05-17 18:53

import django.core.serializers.json
from django.db import migrations, models
import django.db.models.deletion
import nautobot.core.models.fields
import nautobot.extras.models.mixins
import nautobot_ssot.integrations.infoblox.models
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("extras", "0102_set_null_objectchange_contenttype"),
        ("nautobot_ssot", "0008_auto_20240110_1019"),
    ]

    operations = [
        migrations.CreateModel(
            name="SSOTConfig",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
            ],
            options={
                "managed": False,
                "default_permissions": ("view",),
            },
        ),
        migrations.CreateModel(
            name="SSOTInfobloxConfig",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True
                    ),
                ),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                (
                    "_custom_field_data",
                    models.JSONField(blank=True, default=dict, encoder=django.core.serializers.json.DjangoJSONEncoder),
                ),
                ("name", models.CharField(max_length=255, unique=True)),
                ("description", models.CharField(blank=True, max_length=255)),
                ("infoblox_wapi_version", models.CharField(default="v2.12", max_length=255)),
                ("enable_sync_to_infoblox", models.BooleanField(default=False)),
                ("import_ip_addresses", models.BooleanField(default=False)),
                ("import_subnets", models.BooleanField(default=False)),
                ("import_vlan_views", models.BooleanField(default=False)),
                ("import_vlans", models.BooleanField(default=False)),
                (
                    "infoblox_sync_filters",
                    models.JSONField(
                        default=nautobot_ssot.integrations.infoblox.models._get_default_sync_filters,
                        encoder=django.core.serializers.json.DjangoJSONEncoder,
                    ),
                ),
                (
                    "infoblox_dns_view_mapping",
                    models.JSONField(default=dict, encoder=django.core.serializers.json.DjangoJSONEncoder),
                ),
                (
                    "cf_fields_ignore",
                    models.JSONField(default=dict, encoder=django.core.serializers.json.DjangoJSONEncoder),
                ),
                ("import_ipv4", models.BooleanField(default=True)),
                ("import_ipv6", models.BooleanField(default=False)),
                ("create_host_record", models.BooleanField(default=True)),
                ("create_a_record", models.BooleanField(default=False)),
                ("create_ptr_record", models.BooleanField(default=False)),
                ("job_enabled", models.BooleanField(default=False)),
                ("default_status", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="extras.status")),
                (
                    "infoblox_instance",
                    models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="extras.externalintegration"),
                ),
                ("tags", nautobot.core.models.fields.TagsField(through="extras.TaggedItem", to="extras.Tag")),
            ],
            options={
                "verbose_name": "SSOT Infoblox Config",
                "verbose_name_plural": "SSOT Infoblox Configs",
            },
            bases=(
                models.Model,
                nautobot.extras.models.mixins.DynamicGroupMixin,
                nautobot.extras.models.mixins.NotesMixin,
            ),
        ),
    ]
