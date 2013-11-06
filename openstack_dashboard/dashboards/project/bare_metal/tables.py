# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Nebula, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import logging

from django.core import urlresolvers
from django import shortcuts
from django import template
from django.template.defaultfilters import timesince  # noqa
from django.template.defaultfilters import title  # noqa
from django.utils.http import urlencode  # noqa
from django.utils.translation import string_concat  # noqa
from django.utils.translation import ugettext_lazy as _  # noqa

from horizon import conf
from horizon import exceptions
from horizon import messages
from horizon import tables
from horizon.templatetags import sizeformat
from horizon.utils import filters

from openstack_dashboard import api
from openstack_dashboard.dashboards.project.access_and_security.floating_ips \
    import workflows
from openstack_dashboard.dashboards.project.bare_metal import tabs


LOG = logging.getLogger(__name__)

ACTIVE_STATES = ("ACTIVE",)
SNAPSHOT_READY_STATES = ("ACTIVE", "SHUTOFF")

POWER_STATES = {
    0: "NO STATE",
    1: "RUNNING",
    2: "BLOCKED",
    3: "PAUSED",
    4: "SHUTDOWN",
    5: "SHUTOFF",
    6: "CRASHED",
    7: "SUSPENDED",
    8: "FAILED",
    9: "BUILDING",
}

PAUSE = 0
UNPAUSE = 1
SUSPEND = 0
RESUME = 1


def is_deleting(instance):
    task_state = getattr(instance, "OS-EXT-STS:task_state", None)
    if not task_state:
        return False
    return task_state.lower() == "deleting"


class TerminateInstance(tables.BatchAction):
    name = "terminate"
    action_present = _("Terminate")
    action_past = _("Scheduled termination of")
    data_type_singular = _("Server")
    data_type_plural = _("Servers")
    classes = ('btn-danger', 'btn-terminate')

    def allowed(self, request, instance=None):
        return True

    def action(self, request, obj_id):
        api.ironic.server_delete(request, obj_id)


class RebootInstance(tables.BatchAction):
    name = "reboot"
    action_present = _("Hard Reboot")
    action_past = _("Hard Rebooted")
    data_type_singular = _("Server")
    data_type_plural = _("Servers")
    classes = ('btn-danger', 'btn-reboot')

    def allowed(self, request, instance=None):
        return True

    def action(self, request, obj_id):
        api.ironic.server_reboot(request, obj_id, soft_reboot=False)


class SoftRebootInstance(RebootInstance):
    name = "soft_reboot"
    action_present = _("Soft Reboot")
    action_past = _("Soft Rebooted")

    def action(self, request, obj_id):
        api.ironic.server_reboot(request, obj_id, soft_reboot=True)


class ProvisionLink(tables.LinkAction):
    name = "provision"
    verbose_name = _("Provision")
    url = "horizon:project:bare_metal:launch"
    classes = ("btn-launch", "ajax-modal")

    def allowed(self, request, datum):
        return True  # The action should always be displayed

class DiscoverLink(tables.LinkAction):
    name = "discover"
    verbose_name = _("Discover")
    url = "horizon:project:bare_metal:discover"
    classes = ("btn-launch", "ajax-modal")

    def allowed(self, request, datum):
        return True  # The action should always be displayed

class ProvisionServer(tables.LinkAction):
    name = "provision"
    verbose_name = _("Provision Server")
    url = "horizon:project:bare_metal:provision"
    classes = ("ajax-modal", "btn-edit")

    def get_link_url(self, project):
        return self._get_link_url(project, 'instance_info')

    def _get_link_url(self, project, step_slug):
        base_url = urlresolvers.reverse(self.url, args=[project.id])
        param = urlencode({"step": step_slug})
        return "?".join([base_url, param])

    def allowed(self, request, instance):
        return not is_deleting(instance)


class EditInstance(tables.LinkAction):
    name = "edit"
    verbose_name = _("Edit Instance")
    url = "horizon:project:bare_metal:update"
    classes = ("ajax-modal", "btn-edit")

    def get_link_url(self, project):
        return self._get_link_url(project, 'instance_info')

    def _get_link_url(self, project, step_slug):
        base_url = urlresolvers.reverse(self.url, args=[project.id])
        param = urlencode({"step": step_slug})
        return "?".join([base_url, param])

    def allowed(self, request, instance):
        return not is_deleting(instance)


class EditInstanceSecurityGroups(EditInstance):
    name = "edit_secgroups"
    verbose_name = _("Edit Security Groups")

    def get_link_url(self, project):
        return self._get_link_url(project, 'update_security_groups')

    def allowed(self, request, instance=None):
        return (instance.status in ACTIVE_STATES and
                not is_deleting(instance) and
                request.user.tenant_id == instance.tenant_id)


class CreateSnapshot(tables.LinkAction):
    name = "snapshot"
    verbose_name = _("Create Snapshot")
    url = "horizon:project:images_and_snapshots:snapshots:create"
    classes = ("ajax-modal", "btn-camera")

    def allowed(self, request, instance=None):
        return instance.status in SNAPSHOT_READY_STATES \
            and not is_deleting(instance)


class ConsoleLink(tables.LinkAction):
    name = "console"
    verbose_name = _("Console")
    url = "horizon:project:bare_metal:detail"
    classes = ("btn-console",)

    def allowed(self, request, instance=None):
        return instance.status in ACTIVE_STATES and not is_deleting(instance)

    def get_link_url(self, datum):
        base_url = super(ConsoleLink, self).get_link_url(datum)
        tab_query_string = tabs.ConsoleTab(
            tabs.InstanceDetailTabs).get_query_string()
        return "?".join([base_url, tab_query_string])


class LogLink(tables.LinkAction):
    name = "log"
    verbose_name = _("View Log")
    url = "horizon:project:bare_metal:detail"
    classes = ("btn-log",)

    def allowed(self, request, instance=None):
        return instance.status in ACTIVE_STATES and not is_deleting(instance)

    def get_link_url(self, datum):
        base_url = super(LogLink, self).get_link_url(datum)
        tab_query_string = tabs.LogTab(
            tabs.InstanceDetailTabs).get_query_string()
        return "?".join([base_url, tab_query_string])


class ResizeLink(tables.LinkAction):
    name = "resize"
    verbose_name = _("Resize Instance")
    url = "horizon:project:bare_metal:resize"
    classes = ("ajax-modal", "btn-resize")

    def get_link_url(self, project):
        return self._get_link_url(project, 'flavor_choice')

    def _get_link_url(self, project, step_slug):
        base_url = urlresolvers.reverse(self.url, args=[project.id])
        param = urlencode({"step": step_slug})
        return "?".join([base_url, param])

    def allowed(self, request, instance):
        return ((instance.status in ACTIVE_STATES
                 or instance.status == 'SHUTOFF')
                and not is_deleting(instance))


class RebuildInstance(tables.LinkAction):
    name = "rebuild"
    verbose_name = _("Rebuild Instance")
    classes = ("btn-rebuild", "ajax-modal")
    url = "horizon:project:bare_metal:rebuild"

    def allowed(self, request, instance):
        return ((instance.status in ACTIVE_STATES
                 or instance.status == 'SHUTOFF')
                and not is_deleting(instance))

    def get_link_url(self, datum):
        instance_id = self.table.get_object_id(datum)
        return urlresolvers.reverse(self.url, args=[instance_id])


class AssociateIP(tables.LinkAction):
    name = "associate"
    verbose_name = _("Associate Floating IP")
    url = "horizon:project:access_and_security:floating_ips:associate"
    classes = ("ajax-modal", "btn-associate")

    def allowed(self, request, instance):
        if api.network.floating_ip_simple_associate_supported(request):
            return False
        return not is_deleting(instance)

    def get_link_url(self, datum):
        base_url = urlresolvers.reverse(self.url)
        next = urlresolvers.reverse("horizon:project:bare_metal:index")
        params = {"instance_id": self.table.get_object_id(datum),
                  workflows.IPAssociationWorkflow.redirect_param_name: next}
        params = urlencode(params)
        return "?".join([base_url, params])


class SimpleAssociateIP(tables.Action):
    name = "associate-simple"
    verbose_name = _("Associate Floating IP")
    classes = ("btn-associate-simple",)

    def allowed(self, request, instance):
        if not api.network.floating_ip_simple_associate_supported(request):
            return False
        return not is_deleting(instance)

    def single(self, table, request, instance_id):
        try:
            # target_id is port_id for Neutron and instance_id for Nova Network
            # (Neutron API wrapper returns a 'portid_fixedip' string)
            target_id = api.network.floating_ip_target_get_by_instance(
                request, instance_id).split('_')[0]

            fip = api.network.tenant_floating_ip_allocate(request)
            api.network.floating_ip_associate(request, fip.id, target_id)
            messages.success(request,
                             _("Successfully associated floating IP: %s")
                             % fip.ip)
        except Exception:
            exceptions.handle(request,
                              _("Unable to associate floating IP."))
        return shortcuts.redirect("horizon:project:bare_metal:index")


class SimpleDisassociateIP(tables.Action):
    name = "disassociate"
    verbose_name = _("Disassociate Floating IP")
    classes = ("btn-danger", "btn-disassociate",)

    def allowed(self, request, instance):
        if not conf.HORIZON_CONFIG["simple_ip_management"]:
            return False
        return not is_deleting(instance)

    def single(self, table, request, instance_id):
        try:
            # target_id is port_id for Neutron and instance_id for Nova Network
            # (Neutron API wrapper returns a 'portid_fixedip' string)
            target_id = api.network.floating_ip_target_get_by_instance(
                request, instance_id).split('_')[0]

            fips = [fip for fip in api.network.tenant_floating_ip_list(request)
                    if fip.port_id == target_id]
            # Removing multiple floating IPs at once doesn't work, so this pops
            # off the first one.
            if fips:
                fip = fips.pop()
                api.network.floating_ip_disassociate(request,
                                                     fip.id, target_id)
                api.network.tenant_floating_ip_release(request, fip.id)
                messages.success(request,
                                 _("Successfully disassociated "
                                   "floating IP: %s") % fip.ip)
            else:
                messages.info(request, _("No floating IPs to disassociate."))
        except Exception:
            exceptions.handle(request,
                              _("Unable to disassociate floating IP."))
        return shortcuts.redirect("horizon:project:bare_metal:index")


def instance_fault_to_friendly_message(instance):
    fault = getattr(instance, 'fault', {})
    message = fault.get('message', _("Unknown"))
    default_message = _("Please try again later [Error: %s].") % message
    fault_map = {
        'NoValidHost': _("There is not enough capacity for this "
                         "flavor in the selected availability zone. "
                         "Try again later or select a different availability "
                         "zone.")
    }
    return fault_map.get(message, default_message)


def get_instance_error(instance):
    if instance.status.lower() != 'error':
        return None
    message = instance_fault_to_friendly_message(instance)
    preamble = _('Failed to launch instance "%s"'
                 ) % instance.name or instance.id
    message = string_concat(preamble, ': ', message)
    return message


class UpdateRow(tables.Row):
    ajax = True

    def get_data(self, request, instance_id):
        instance = api.ironic.server_get(request, instance_id)
        error = get_instance_error(instance)
        if error:
            messages.error(request, error)
        return instance


class StartInstance(tables.BatchAction):
    name = "start"
    action_present = _("Start")
    action_past = _("Started")
    data_type_singular = _("Instance")
    data_type_plural = _("Instances")

    def allowed(self, request, instance):
        #return instance.status in ("SHUTDOWN", "SHUTOFF", "CRASHED")
        return True

    def action(self, request, obj_id):
        api.ironic.server_start(request, obj_id)


class StopServer(tables.BatchAction):
    name = "stop"
    action_present = _("Shut Off")
    action_past = _("Shut Off")
    data_type_singular = _("Server")
    data_type_plural = _("Servers")
    classes = ('btn-danger',)

    def allowed(self, request, instance):
	return True

    def action(self, request, obj_id):
        api.ironic.server_stop(request, obj_id)


def get_ips(instance):
    template_name = 'project/bare_metal/_instance_ips.html'
    context = {"instance": instance}
    return template.loader.render_to_string(template_name, context)

def get_arch(instance):
    if hasattr(instance, 'properties'):
        return instance.properties['arch']
    return _("Not available")

def get_size(instance):
    if hasattr(instance, 'properties'):
        size_string = _("%(name)s | %(ram)s RAM | %(cpus)s VCPU "
                        "| %(disk)s Disk")
        vals = {'name': instance.properties['id'],
                'ram': sizeformat.mbformat(instance.properties['ram']),
                'cpus': instance.properties['cpus'],
                'disk': sizeformat.diskgbformat(instance.properties['disk'])}
        return size_string % vals
    return _("Not available")


def get_keyname(instance):
    if hasattr(instance, "key_name"):
        keyname = instance.key_name
        return keyname
    return _("Not available")


def get_power_state(instance):
    power_state = api.ironic.server_power_state(instance.id)
    return power_state['current']


STATUS_DISPLAY_CHOICES = (
    ("resize", "Resize/Migrate"),
    ("verify_resize", "Confirm or Revert Resize/Migrate"),
    ("revert_resize", "Revert Resize/Migrate"),
)


TASK_DISPLAY_CHOICES = (
    ("image_snapshot", "Snapshotting"),
    ("resize_prep", "Preparing Resize or Migrate"),
    ("resize_migrating", "Resizing or Migrating"),
    ("resize_migrated", "Resized or Migrated"),
    ("resize_finish", "Finishing Resize or Migrate"),
    ("resize_confirming", "Confirming Resize or Nigrate"),
    ("resize_reverting", "Reverting Resize or Migrate"),
    ("unpausing", "Resuming"),
)


class InstancesFilterAction(tables.FilterAction):

    def filter(self, table, instances, filter_string):
        """ Naive case-insensitive search. """
        q = filter_string.lower()
        return [instance for instance in instances
                if q in instance.name.lower()]


class InstancesTable(tables.DataTable):
    TASK_STATUS_CHOICES = (
        (None, True),
        ("none", True)
    )
    STATUS_CHOICES = (
        ("active", True),
        ("shutoff", True),
#        ("suspended", True),
#        ("paused", True),
        ("error", False),
    )
    name = tables.Column("name",
                         link=("horizon:project:bare_metal:detail"),
                         verbose_name=_("Server Name"))
    architecture = tables.Column(get_arch,
                               verbose_name=_("Architecture"))
#    ip = tables.Column(get_ips,
#                       verbose_name=_("IP Address"),
#                       attrs={'data-type': "ip"})
    storage = tables.Column(get_size,
                         verbose_name=_("Size"),
                         attrs={'data-type': 'size'})
    keypair = tables.Column(get_keyname, verbose_name=_("Keypair"))
#    status = tables.Column("status",
#                           filters=(title, filters.replace_underscores),
#                           verbose_name=_("Status"),
#                           status=True,
#                           status_choices=STATUS_CHOICES,
#                           display_choices=STATUS_DISPLAY_CHOICES)
#    task = tables.Column("OS-EXT-STS:task_state",
#                         verbose_name=_("Task"),
#                         filters=(title, filters.replace_underscores),
#                         status=True,
#                         status_choices=TASK_STATUS_CHOICES,
#                         display_choices=TASK_DISPLAY_CHOICES)
    state = tables.Column(get_power_state,
                          filters=(title, filters.replace_underscores),
                          verbose_name=_("Power State"))

    class Meta:
        name = "bare_metal"
        verbose_name = _("Bare Metal Servers")
        row_class = UpdateRow
        table_actions = (DiscoverLink, SoftRebootInstance, TerminateInstance,
                         InstancesFilterAction)
        row_actions = (ProvisionServer, SoftRebootInstance, RebootInstance, StopServer)
