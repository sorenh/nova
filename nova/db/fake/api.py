import uuid as uuidgen
import copy
import datetime
import re

from nova import block_device
from nova import context
from nova import db
from nova import exception
from nova import flags
from nova import log
from nova import utils
from nova.db.api import require_admin_context

LOG = log.getLogger('nova.tests')
FLAGS = flags.FLAGS

_baseline_db = {'networks': {},
                'provider_fw_rules': {},
                'services': {},
                'users': {},
                'projects': {},
                'key_pairs': {},
                'hosts': {},
                'instance_types': {},
                'compute_nodes': {},
                'floating_ips': {},
                's3_images': {},
                'instances': {},
                'quotas': {},
                'security_groups': {},
                'security_group_rules': {},
                'block_device_mapping': {},
                'zones': {},
                'bandwidth_usages': {},
                'virtual_interfaces': {},
                'fixed_ips': {},
                'volumes': {},
                'snapshots': {},
                'iscsi_targets': {},
                'auth_tokens': {},
                'volume_types': {},
                'certificates': {},
                'migrations': {},
                'console_pools': {},
                'consoles': {},
                'next_id': 0}

_db = None

class IntegrityError(Exception):
    pass

class FakeDbObj(object):
    safe_delete = True
    extra_items = []
    non_nullable_keys = []

    def __init__(self, values):
        self._values = values

    def __getitem__(self, key):
        return self._values[key]

    def __setitem__(self, key, value):
        self._values[key] = value

    def __contains__(self, key):
        return key in self._values or key in self.extra_items

    def keys(self):
        return self._values.keys() + self.extra_items

    def iteritems(self):
        for key in self._values:
            yield key, self[key]
        for key in self.extra_items:
            yield key, self[key]

    def get(self, key, *args):
        try:
            return self[key]
        except KeyError:
            if len(args) > 0:
                return args[0]

    @classmethod
    def create(cls, context, values):
        for key in cls.non_nullable_keys:
            if key not in values:
                raise exception.DBError('%s must be set' % (key,))
        values['created_at'] = values.get('created_at',
                                          utils.utcnow())
        values['updated_at'] = values.get('updated_at',
                                          None)
        values['deleted_at'] = values.get('deleted_at',
                                          None)
        values['deleted'] = values.get('deleted',
                                       False)
        if not 'id' in values:
            values['id'] = _get_id()
        obj = cls(values)
        obj = cls(values)
        _db[cls.key][obj['id']] = obj
        return obj

    @classmethod
    def delete(cls, context, id, purge=False):
        if cls.safe_delete and not purge:
            try:
                obj = cls.get_obj(context, id)
            except:
                return
            if obj:
                obj['deleted'] = True
                obj['deleted_at'] = utils.utcnow()
        else:
            del _db[cls.key][id]

    @classmethod
    def get_all(cls, context):
        if context.read_deleted:
            return _db[cls.key].values()
        else:
            return filter(lambda x:not x.get('deleted', False),
                          _db[cls.key].values())

    @classmethod
    def get_obj(cls, context, id):
        try:
            id = int(id)
        except:
            return None
        obj = _db[cls.key].get(id, None)
        if context.is_admin:
            return obj
        elif obj and not obj.get('deleted', False):
            return obj

    def update(self, values):
        values['updated_at'] = values.get('updated_at',
                                          utils.utcnow())
        for k,v in values.iteritems():
            if k == 'id':
                continue
            self[k] = v
        return self

class Console(FakeDbObj):
    key = 'consoles'

    @classmethod
    def get_by_pool_instance(cls, context, pool_id, instance_id):
        for x in cls.get_all(context):
            if (x['pool_id'] == pool_id and
                x['instance_id'] == instance_id):
                return x
        raise exception.ConsoleNotFoundInPoolForInstance(pool_id=pool_id,
                                                 instance_id=instance_id)


class ConsolePool(FakeDbObj):
    key = 'console_pools'

    def __getitem__(self, key):
        if key == 'consoles':
            consoles = []
            for console in Console.get_all(context.get_admin_context()):
                if console['pool_id'] == self['id']:
                    consoles.append(console)
            return consoles
        else:
            return super(ConsolePool, self).__getitem__(key)

    @classmethod
    def get_by_host_type(cls, context, compute_host, host, console_type):
        for x in cls.get_all(context):
            if (x['host'] == host and
                x['console_type'] == console_type and
                x['compute_host'] == compute_host):
                return x
        raise exception.ConsolePoolNotFoundForHostType(host=host,
                                                  console_type=console_type,
                                                  compute_host=compute_host)


class Quota(FakeDbObj):
    key = 'quotas'

    @classmethod
    def get_all_by_project(cls, context, project_id):
        result = {'project_id': project_id}
        for x in cls.get_all(context):
            if x['project_id'] == project_id:
                result[x['resource']] = x['hard_limit']
        return result


    @classmethod
    def get_by_project_and_resource(cls, context, project_id, resource):
        for x in cls.get_all(context):
            if x['project_id'] == project_id and x['resource'] == resource:
                return x
        raise exception.ProjectQuotaNotFound(project_id=project_id)

class Host(FakeDbObj):
    key = 'hosts'

class ProviderFwRule(FakeDbObj):
    key = 'provider_fw_rules'

    @classmethod
    def create(cls, context, values):
        values['cidr'] = values.get('cidr', None)
        return super(ProviderFwRule, cls).create(context, values)

    @classmethod
    def get_all_by_cidr(cls, context, cidr):
        rules = []
        all_rules = super(ProviderFwRule, cls).get_all(context)
        for rule in all_rules:
            if rule['cidr'] == cidr:
                rules += [rule]
        return rules

class Service(FakeDbObj):
    key = 'services'

    def __getitem__(self, key):
        if key == 'compute_node':
            compute_nodes = ComputeNode.get_all(context.get_admin_context())
            for compute_node in compute_nodes:
                if compute_node['service_id'] == self['id']:
                    return [compute_node]
            return None
        else:
            return super(Service, self).__getitem__(key)

    @classmethod
    def get_all_volume_sorted(cls, context):
        services = []
        for x in cls.get_all_by_topic(context, 'volume'):
            total_size = 0
            for y in Volume.get_all_by_host(context, x['host']):
                total_size += y['size']
            services.append((x, total_size))
        services.sort(key=lambda x:x[1])
        return services

    @classmethod
    def get_all_compute_sorted(cls, context):
        services = []
        for x in cls.get_all_by_topic(context, 'compute'):
            vcpus = 0
            for y in Instance.get_all_by_host(context, x['host']):
                vcpus += y['vcpus']
            services.append((x, vcpus))
        services.sort(key=lambda x:x[1])
        return services

    @classmethod
    def get_all_by_host(cls, context, host):
        objs = cls.get_all(context, False)
        return [obj for obj in objs if obj['host'] == host]

    @classmethod
    def get_all_by_topic(cls, context, topic):
        objs = cls.get_all(context, False)
        return [obj for obj in objs if obj['topic'] == topic]

    @classmethod
    def get_all(cls, context, disabled=False):
        objs = super(Service, cls).get_all(context)
        return [obj for obj in objs if disabled or not obj.get('disabled', False)]

    @classmethod
    def get_all_compute_by_host(cls, context, host):
        services = []
        for x in cls.get_all(context, True):
            if x.get('host', None) == host and x.get('topic', None) == 'compute':
                services += [x]
        if not services:
            raise exception.ComputeHostNotFound(host=host)
        return services

    @classmethod
    def get_by_host_and_topic(cls, context, host, topic):
        for x in cls.get_all(context, True):
            if x['host'] == host and x['topic'] == topic:
                return x

    @classmethod
    def get_by_args(cls, context, host, binary):
        for x in cls.get_all(context, True):
            if x['host'] == host and x['binary'] == binary:
                return x
        raise exception.HostBinaryNotFound(host=host, binary=binary)

class VolumeType(FakeDbObj):
    key = 'volume_types'

    @classmethod
    def get_by_name(cls, context, name):
        for x in cls.get_all(context):
            if x.get('name', None) == name:
                return x

class Network(FakeDbObj):
    key = 'networks'

    simple_fields = ['label', 'injected', 'cidr', 'cidr_v6', 'multi_host',
                     'gateway_v6', 'netmask_v6', 'netmask', 'bridge',
                     'bridge_interface', 'gateway', 'broadcast', 'dns1',
                     'dns2', 'vlan', 'vpn_public_address', 'vpn_public_port',
                     'vpn_private_address', 'dhcp_start', 'project_id',
                     'priority', 'host', 'uuid']

    defaults = {'injected': False,
                'multi_host': False}

    def __getitem__(self, key):
        if key == 'uuid':
            if 'uuid' not in self._values:
                self._values['uuid'] = str(utils.gen_uuid())
            return self._values['uuid']
        elif key in self.simple_fields:
            return self._values.get(key, self.defaults.get(key, None))
        elif key == 'virtual_interfaces':
            virtual_interfaces = []
            for x in VirtualInterface.get_all(context.get_admin_context()):
                if x['network_id'] == self['id']:
                    virtual_interfaces.append(x)
            return virtual_interfaces
        elif key == 'fixed_ips':
            fixed_ips = []
            for x in FixedIp.get_all(context.get_admin_context()):
                if x['network_id'] == self['id']:
                    fixed_ips.append(x)
            return fixed_ips
        else:
            return super(Network, self).__getitem__(key)

    @classmethod
    def get_by_project(cls, context, project_id, associate):
        networks = []
        for x in cls.get_all(context):
            if x.get('project_id', None) == project_id:
                networks.append(x)
        if not networks:
            if not associate:
                return []
            else:
                return [network_associate(context, project_id)]
        return networks

    @classmethod
    def associate(cls, context, project_id, force=False):
        network = None
        if not force:
            for x in cls.get_all(context):
                if x.get('project_id', None) == project_id:
                    network = x
                    break

        if force or not network:
            network = None
            for x in cls.get_all(context):
                if x.get('project_id', None) is None:
                    network = x

            if not network:
                raise db.NoMoreNetworks()

            network['project_id'] = project_id
        return network


    @classmethod
    def get_by_host(cls, context, host):
        networks = []
        for x in cls.get_all(context):
            if x['host'] == host:
                networks.append(x)
        return networks

    @classmethod
    def get_all(cls, context):
        objs = super(Network, cls).get_all(context)
        if not objs:
            raise exception.NoNetworksFound()
        return objs

class User(FakeDbObj):
    key = 'users'
    safe_delete = False

    @classmethod
    def create(cls, context, values):
        values['key_pairs'] = []
        values['roles'] = []
        values['project_roles'] = []
        return super(User, cls).create(context, values)

    @classmethod
    def get_obj(cls, context, id):
        obj = _db[cls.key].get(id, None)
        if not obj:
            raise exception.UserNotFound()
        else:
            return obj

    @classmethod
    def get_by_access_key(cls, context, access_key):
        for x in cls.get_all(context):
            if x.get('access_key') == access_key:
                return x

    def destroy_key_pairs(self, context):
        for kp in self['key_pairs']:
            KeyPair.delete(context, kp['id'])
        self['key_pairs'] = []

    def add_role(self, context, role):
        self['roles'] += [role]

    def remove_role(self, context, role):
        self['roles'].remove(role)

    def add_project_role(self, context, project_id, project_role):
        self['project_roles'] += [(project_id, project_role)]

    def remove_project_role(self, context, project_id, project_role):
        self['project_roles'].remove((project_id, project_role))

    def get_roles_for_project(self, context, project_id):
        roles = []
        for pid, role in self['project_roles']:
            if pid == project_id:
                roles += [role]
        return roles

    def get_roles(self, context):
        return self['roles']

class Project(FakeDbObj):
    key = 'projects'
    safe_delete = False

    @classmethod
    def get_obj(cls, context, id):
        obj = _db[cls.key].get(id, None)
        if not obj:
            raise exception.ProjectNotFound()
        else:
            return obj

    @classmethod
    def get_by_user(cls, context, user_id):
        projects = []
        user = User.get_obj(context, user_id)
        for x in cls.get_all(context):
            if user in x['members']:
                projects.append(x)
        return projects

    def add_member(self, context, user_id):
        user = User.get_obj(context, user_id)
        self['members'] += [user]

    def remove_member(self, context, user_id):
        user = User.get_obj(context, user_id)
        self['members'].remove(user)

    def get_networks(self, context):
        return self.get('networks', [])

    @classmethod
    def create(cls, context, values):
        obj = super(Project, cls).create(context, values)
        obj['members'] = []
        return obj

    def update(self, values):
        members = self['members']
        super(Project, self).update(values)
        self['members'] = members

class S3Image(FakeDbObj):
    key = 's3_images'

    @classmethod
    def get_by_uuid(cls, context, uuid):
        for x in cls.get_all(context):
            if x['uuid'] == uuid:
                return x
        raise exception.ImageNotFound(image_id=uuid)

    @classmethod
    def get_obj(cls, context, id):
        obj = _db[cls.key].get(id, None)
        if not obj:
            raise exception.ImageNotFound(image_id=id)
        return obj


class SecurityGroupRule(FakeDbObj):
    key = 'security_group_rules'

    def __getitem__(self, key):
        if key == 'protocol':
            return self._values.get(key, None)
        if key == 'group_id':
            return self._values.get(key, None)
        else:
            return super(SecurityGroupRule, self).__getitem__(key)

    @classmethod
    def get_by_security_group(cls, context, security_group_id):
        rules = []
        for x in cls.get_all(context):
            if x['parent_group_id'] == security_group_id:
                rules.append(x)
        return rules

    @classmethod
    def get_obj(cls, context, id):
        obj = super(SecurityGroupRule, cls).get_obj(context, str(id))
        if not obj:
            raise exception.SecurityGroupNotFoundForRule(rule_id=id)
        return obj

class SecurityGroup(FakeDbObj):
    key = 'security_groups'

    def __getitem__(self, key):
        if key == 'rules':
            return SecurityGroupRule.get_by_security_group(context.get_admin_context(),
                                                           self['id'])
        elif key == 'instances':
            instances = []
            for x in Instance.get_all(context.get_admin_context()):
                if self in x['security_groups']:
                    instances.append(x)
            return instances
        elif key == 'description':
            return self._values.get(key, None)
        else:
            return super(SecurityGroup, self).__getitem__(key)

    @classmethod
    def get_by_name(cls, context, project_id, name):
        for x in cls.get_all(context):
            if x['project_id'] == project_id and x['name'] == name:
                return x


    @classmethod
    def get_obj(cls, context, id):
        obj = super(SecurityGroup, cls).get_obj(context, id)
        if not obj:
            raise exception.SecurityGroupNotFound(security_group_id=id)
        return obj

    @classmethod
    def get_by_instance(cls, context, instance_id):
        instance = Instance.get_obj(context, instance_id)
        return instance['security_groups']

    @classmethod
    def get_by_project(cls, context, project_id):
        groups = []
        for x in cls.get_all(context):
            if x.get('project_id', None) == project_id:
                groups.append(x)
        return groups


class BlockDeviceMapping(FakeDbObj):
    key = 'block_device_mapping'

    def __getitem__(self, key):
        if key == 'no_device':
            return self._values.get(key, False)
        elif key == 'virtual_name':
            return self._values.get(key, None)
        elif key == 'volume_id':
            return self._values.get(key, None)
        elif key == 'instances':
            return self._values.get(key, [])
        elif key == 'delete_on_termination':
            return self._values.get(key, False)
        else:
            return super(BlockDeviceMapping, self).__getitem__(key)

    @classmethod
    def get_by_instance_and_volume(cls, context, instance_id, volume_id):
        for x in cls.get_all(context):
            if x['instance_id'] == instance_id and x['volume_id'] == volume_id:
                return x

    @classmethod
    def get_by_instance_and_device_name(cls, context, instance_id, device_name):
        for x in cls.get_all(context):
            if x['instance_id'] == instance_id and x['device_name'] == device_name:
                return x

    @classmethod
    def get_all_by_instance(cls, context, instance_id):
        mappings = []
        for x in cls.get_all(context):
            if x['instance_id'] == instance_id:
                mappings.append(x)
        return mappings

class Zone(FakeDbObj):
    key = 'zones'

class FixedIp(FakeDbObj):
    key = 'fixed_ips'

    simple_fields = ['address', 'network_id', 'virtual_interface_id',
                     'instance_id', 'allocated', 'leased', 'reserved',
                     'host']

    defaults = {'allocated': False,
                'leased': False,
                'reserved': False}

    def __getitem__(self, key):
        if key == 'network':
            if self['network_id'] is not None:
                return Network.get_obj(context.get_admin_context(),
                                       self['network_id'])
            else:
                return None
        elif key == 'floating_ips':
            return FloatingIp.get_by_fixed_ip(context.get_admin_context(),
                                              self['id'])
        elif key == 'virtual_interface':
            if self['virtual_interface_id'] is not None:
                return VirtualInterface.get_obj(context.get_admin_context(),
                                                self['virtual_interface_id'])
            else:
                return None
        elif key == 'instance':
            if self['instance_id'] is not None:
                return Instance.get_obj(context.get_admin_context(),
                                        self['instance_id'])
            else:
                return None
        elif key in self.simple_fields:
            return self._values.get(key, self.defaults.get(key, None))
        else:
            return super(FixedIp, self).__getitem__(key)

    @classmethod
    def get_by_address(cls, context, address):
        for x in cls.get_all(context):
            if x['address'] == address:
                return x

    @classmethod
    def get_by_instance(cls, context, instance):
        fixed_ips =  []
        for x in cls.get_all(context):
            if x.get('instance_id', None) == instance:
                fixed_ips.append(x)
        return fixed_ips

    @classmethod
    def associate_pool(cls, context, network_id, instance_id, host):
        fixed_ip = None
        for x in cls.get_all(context):
            if ((x['network_id'] in [None, network_id]) and
                not x.get('reserved', False) and
                x.get('instance', None) is None and
                x.get('host', None) is None):
                fixed_ip = x
                break

        if not fixed_ip:
            raise exception.NoMoreFixedIps()

        if not fixed_ip['network_id']:
            fixed_ip['network_id'] = network_get(context, network_id)

        if instance_id:
            fixed_ip['instance_id'] = instance_id

        if host:
            fixed_ip['host'] = host

        return fixed_ip['address']

class Volume(FakeDbObj):
    key = 'volumes'
    extra_items = ['name', 'instance', 'attach_time', 'mountpoint', 'status', 'size', 'availability_zone', 'project_id', 'host', 'attach_status', 'display_name', 'display_description', 'volume_metadata']

    def __getitem__(self, key):
        if key == 'name':
            return self.name
        elif key == 'instance':
            instance_id = self.get('instance_id', None)
            if not instance_id:
                return
            return Instance.get_obj(context.get_admin_context(), instance_id)
        elif key == 'mountpoint':
            return self._values.get(key, None)
        elif key == 'host':
            return self._values.get(key, None)
        elif key == 'project_id':
            return self._values.get(key, None)
        elif key == 'availability_zone':
            return self._values.get(key, None)
        elif key == 'display_description':
            return self._values.get(key, None)
        elif key == 'display_name':
            return self._values.get(key, None)
        elif key == 'attach_status':
            return self._values.get(key, None)
        elif key == 'status':
            return self._values.get(key, None)
        elif key == 'instance_id':
            return self._values.get(key, None)
        elif key == 'size':
            return self._values.get(key, None)
        elif key == 'volume_type_id':
            return self._values.get(key, None)
        elif key == 'attach_time':
            return self._values.get(key, None)
        elif key == 'volume_metadata':
            data = self._values.get('metadata', [])
            if not data:
                data = []
            return [{'key': key, 'value': data[key]} for key in data]
        else:
            return super(Volume, self).__getitem__(key)

    @property
    def name(self):
        return FLAGS.volume_name_template % int(self['id'])

    @classmethod
    def create(cls, context, values):
        values['created_at'] = utils.utcnow()
        values['updated_at'] = None
        values['deleted'] = False
        if not 'id' in values:
            values['id'] = _get_id()
            values['id'] = _get_id()
        values['id'] = int(values['id'])
        obj = cls(values)
        obj = cls(values)
        _db[cls.key][int(obj['id'])] = obj
        return obj

    @classmethod
    def get_data_for_project(cls, context, project_id):
        count = 0
        total_size = 0
        for x in cls.get_all(context):
            count += 1
            total_size += x['size']
        return count, total_size

    @classmethod
    def get_all_by_instance(cls, context, instance_id):
        volumes = []
        for x in cls.get_all(context):
            if x['instance_id'] == instance_id:
                volumes.append(x)
        return volumes

    @classmethod
    def get_all_by_host(cls, context, host_id):
        volumes = []
        for x in cls.get_all(context):
            if x.get('host', None) == host_id:
                volumes.append(x)
        return volumes

    @classmethod
    def get_obj(cls, context, id):
        obj = super(Volume, cls).get_obj(context, int(id))
        if obj and obj.get('deleted', False) and not context.read_deleted:
            obj = None
        if not obj:
            raise exception.VolumeNotFound(volume_id=id)
        return obj

    @classmethod
    def get_by_instance(cls, context, instance_id):
        volumes = []
        for x in cls.get_all(context):
            if x['instance_id'] == instance_id:
                volumes.append(x)
        return volumes

    def set_attached(self, context, instance_id, mountpoint):
        self['instance_id'] = instance_id
        self['mountpoint'] = mountpoint
        self['status'] = 'in-use'
        self['attach_status'] = 'attached'

    def unset_attached(self, context):
        self['instance_id'] = None
        self['mountpoint'] = None
        self['status'] = 'available'
        self['attach_status'] = 'detached'


class Snapshot(FakeDbObj):
    key = 'snapshots'

    extra_items = ['status', 'progress', 'project_id', 'volume_size', 'display_description', 'display_name']
    def __getitem__(self, key):
        if key == 'name':
            return self.name
        elif key == 'attach_time':
            return self._values.get(key, None)
        elif key == 'volume_name':
            return self._values.get(key, None)
        elif key == 'display_name':
            return self._values.get(key, None)
        elif key == 'display_description':
            return self._values.get(key, None)
        elif key == 'progress':
            return self._values.get(key, None)
        elif key == 'size':
            return self._values.get(key, None)
        elif key == 'volume_size':
            return self._values.get(key, None)
        elif key == 'project_id':
            return self._values.get(key, None)
        elif key == 'status':
            return self._values.get(key, None)
        else:
            return super(Snapshot, self).__getitem__(key)

    @property
    def name(self):
        return FLAGS.snapshot_name_template % int(self['id'])

class IscsiTarget(FakeDbObj):
    key = 'iscsi_targets'

    @classmethod
    def count_by_host(cls, context, host):
        count = 0
        for x in cls.get_all(context):
            if x['host'] == host:
                count += 1
        return count

    @classmethod
    def allocate_volume(cls, context, volume_id, host):
        for x in cls.get_all(context):
            if x['host'] == host and not x.get('volume_id', None):
                x['volume_id'] = volume_id
                return x['target_num']

        raise db.NoMoreTargets()

    @classmethod
    def get_by_volume(cls, context, volume_id):
        for x in cls.get_all(context):
            if x.get('volume_id', None) == volume_id:
                return x

class AuthToken(FakeDbObj):
    key = 'auth_tokens'

    @classmethod
    def get_by_token_hash(cls, context, token_hash):
        for x in cls.get_all(context):
            if x['token_hash'] == token_hash:
                return x

class Migration(FakeDbObj):
    key = 'migrations'

    def __getitem__(self, key):
        if key == 'source_compute':
            return self._values.get(key, None)
        elif key == 'dest_compute':
            return self._values.get(key, None)
        else:
            return super(Migration, self).__getitem__(key)


    @classmethod
    def get_all_unconfirmed(cls, context, confirm_window):
        confirm_window = (utils.utcnow() -
                          datetime.timedelta(seconds=confirm_window))

        migrations = []
        for x in cls.get_all(context):
            if (x['updated_at'] <= confirm_window and
                x['status'] == 'FINISHED'):
                migrations.append(x)
        return migrations


    @classmethod
    def get_by_instance_and_status(cls, context, instance_uuid, status):
        for x in cls.get_all(context):
            if x['instance_uuid'] == instance_uuid and x['status'] == status:
                return x

class Certificate(FakeDbObj):
    key = 'certificates'

class KeyPair(FakeDbObj):
    key = 'key_pairs'

    @classmethod
    def get_all_by_user(cls, context, user_id):
        key_pairs = []
        for x in cls.get_all(context):
            if x['user_id'] == user_id:
                key_pairs.append(x)
        return key_pairs

    @classmethod
    def get_by_user_and_name(cls, context, user_id, name):
        for x in cls.get_all(context):
            if x['user_id'] == user_id and x['name'] == name:
                return x
        raise exception.NotFound()

    @classmethod
    def destroy_all_by_user(cls, context, user_id):
        for x in cls.get_all_by_user(context, user_id):
            cls.delete(context, x['id'])

class VirtualInterface(FakeDbObj):
    key = 'virtual_interfaces'
    non_nullable_keys = ['instance_id']

    def __getitem__(self, key):
        if key == 'network':
            return Network.get_obj(context.get_admin_context(),
                                   self['network_id'])
        else:
            return super(VirtualInterface, self).__getitem__(key)

    @classmethod
    def get_by_instance(cls, context, instance):
        vifs = []
        for x in cls.get_all(context):
            if x.get('instance_id', None) == instance:
                vifs.append(x)
        return vifs

    @classmethod
    def get_by_instance_and_network(cls, context, instance_id, network_id):
        for x in cls.get_all(context):
            if (x['instance_id'] == instance_id and
                x['network_id'] == network_id):
                return x

class BandwidthUsage(FakeDbObj):
    key = 'bandwidth_usages'

    @classmethod
    def get_by_instance(cls, context, instance_id, start_period):
        usages = []
        for x in cls.get_all(context):
            if x['instance_id'] == instance_id:
                usages.append(x)
        return usages

class Instance(FakeDbObj):
    key = 'instances'

    extra_items = ['fixed_ips', 'name', 'instance_type', 'uuid', 'volumes', 'kernel_id', 'project_id', 'ramdisk_id', 'launch_index', 'power_state', 'key_name', 'display_name', 'display_description', 'vm_state', 'host', 'reservation_id', 'progress', 'launched_at', 'root_device_name', 'locked']

    def __getitem__(self, key):
        if key == 'name':
            return self.name
        elif key == 'volumes':
            return Volume.get_by_instance(context.get_admin_context(),
                                          self['id'])
        elif key == 'fixed_ips':
            return FixedIp.get_by_instance(context.get_admin_context(),
                                           self['id'])
        elif key == 'project':
            project_id = self._values.get('project_id', None)
            if project_id:
                return None
            else:
                return Project.get_obj(context.get_admin_context(),
                                       project_id)
        elif key == 'ramdisk_id':
            return self._values.get(key, None)
        elif key == 'kernel_id':
            return self._values.get(key, None)
        elif key == 'task_state':
            return self._values.get(key, None)
        elif key == 'progress':
            return self._values.get(key, None)
        elif key == 'power_state':
            return self._values.get(key, None)
        elif key == 'key_name':
            return self._values.get(key, None)
        elif key == 'project_id':
            return self._values.get(key, None)
        elif key == 'display_name':
            return self._values.get(key, None)
        elif key == 'display_description':
            return self._values.get(key, None)
        elif key == 'reservation_id':
            return self._values.get(key, None)
        elif key == 'launch_index':
            return self._values.get(key, None)
        elif key == 'vm_state':
            return self._values.get(key, None)
        elif key == 'locked':
            return self._values.get(key, None)
        elif key == 'root_device_name':
            return self._values.get(key, None)
        elif key == 'host':
            return self._values.get(key, None)
        elif key == 'metadata':
            data = self._values.get(key, [])
            return [{'key': key, 'value': data[key]} for key in data]
        elif key == 'launched_at':
            return self._values.get(key, None)
        elif key == 'instance_type_id':
            return self._values.get(key, 0)
        elif key == 'security_groups':
            return self._values.get('security_groups', [])
        elif key == 'uuid':
            uuid = self._values.get('uuid', None)
            if uuid is None:
                self['uuid'] = str(uuidgen.uuid4())
                return self['uuid']
            return uuid
        elif key == 'instance_type':
            return InstanceType.get_obj(context.get_admin_context(),
                                        self['instance_type_id'])
        else:
            return super(Instance, self).__getitem__(key)

    @property
    def name(self):
        try:
            base_name = FLAGS.instance_name_template % int(self['id'])
        except TypeError:
            # Support templates like "uuid-%(uuid)s", etc.
            info = {}
            for key in self.keys():
                # prevent recursion if someone specifies %(name)s
                # %(name)s will not be valid.
                if key == 'name':
                    continue
                info[key] = self[key]
            try:
                base_name = FLAGS.instance_name_template % info
            except KeyError:
                base_name = self['uuid']
        if getattr(self, '_rescue', False):
            base_name += "-rescue"
        return base_name


    @classmethod
    def get_project_vpn(cls, context, project_id):
        for x in cls.get_all(context):
            if (x['project_id'] <= project_id and
                x['image_ref'] == FLAGS.vpn_image_id):
                return x

    @classmethod
    def get_all_hung_in_rebooting(cls, context, reboot_window):
        reboot_window = (datetime.datetime.utcnow() -
                         datetime.timedelta(seconds=reboot_window))

        instances = []
        for x in cls.get_all(context):
            if (x['updated_at'] <= reboot_window and
                x['task_state'] == 'rebooting'):
                instances.append(x)

        return instances

    @classmethod
    def get_all_by_filters(cls, context, filters):
        filters = filters.copy()

        def listify(val):
            if not (isinstance(val, list) or isinstance(val, set)):
                return [val]
            return val
            
        objs = cls.get_all(context)
        if 'deleted' in filters:
            val = listify(filters.pop('deleted'))
            objs = filter(lambda x: x.get('deleted', False) in val, objs)

        if 'reservation_id' in filters:
            val = listify(filters.pop('reservation_id'))
            objs = filter(lambda x: x['reservation_id'] in val, objs)

        if 'instance_type_id' in filters:
            val = listify(filters.pop('instance_type_id'))
            objs = filter(lambda x: x['instance_type_id'] in val, objs)

        if 'image_ref' in filters:
            val = listify(filters.pop('image_ref'))
            objs = filter(lambda x: x['image_ref'] in val, objs)

        if 'power_state' in filters:
            val = listify(filters.pop('power_state'))
            objs = filter(lambda x: x['power_state'] in val, objs)

        if 'uuid' in filters:
            val = listify(filters.pop('uuid'))
            objs = filter(lambda x: x['uuid'] in val, objs)

        if 'name' in filters:
            regex = re.compile(filters.pop('name'))
            objs = filter(lambda x: regex.match(str(x['name'])), objs)

        if 'ip' in filters:
            regex = re.compile(filters.pop('ip'))
            # I have no clue what this does, and I'm been unable to work it
            # out by looking at the code :(

        if 'ip6' in filters:
            regex = re.compile(filters.pop('ip6'))
            # I have no clue what this does, and I'm been unable to work it
            # out by looking at the code :(

        if 'display_name' in filters:
            regex = re.compile(filters.pop('display_name'))
            objs = filter(lambda x: regex.match(str(x['display_name'])), objs)

        if 'local_zone_only' in filters:
            val = filters.pop('local_zone_only')
            # I have no clue what this does, and I'm been unable to work it
            # out by looking at the code :(

        if 'metadata' in filters:
            val = listify(filters.pop('metadata'))
            for term in val:
                for k, v in term.iteritems():
                    # First filter out any objects that don't even have the key..
                    objs = filter(lambda x: k in [y['key'] for y in x['metadata']], objs)

                    # Then filter based on its value
                    objs = filter(lambda x: v == [y['value'] for y in x['metadata'] if y['key'] == k][0], objs)

        if filters:
            raise Exception(repr(filters))

        return objs

    @classmethod
    def get_all_by_host(cls, context, host_id):
        instances = []
        for x in cls.get_all(context):
            if x.get('host', None) == host_id:
                instances.append(x)
        return instances

    @classmethod
    def get_all_for_project(cls, context, project_id):
        instances = []
        for x in cls.get_all(context):
            if x['project'] == project_id:
                instances.append(x)
        return instances

    @classmethod
    def get_data_for_project(cls, context, project_id):
        instance_count = 0
        total_vcpus = 0
        total_memory = 0
        for instance in cls.get_all_for_project(context, project_id):
            instance_count += 1
            total_vcpus += instance['vcpus']
            total_memory += instance['memory_mb']
        return instance_count, total_vcpus, total_memory

    def add_security_group(self, context, security_group):
        self['security_groups'] += [security_group]

    @classmethod
    def get_by_uuid(cls, context, uuid):
        for x in cls.get_all(context):
            if x['uuid'] == uuid:
                return x
        raise exception.InstanceNotFound(instance_id=id)

    @classmethod
    def get_obj(cls, context, id):
        obj = super(Instance, cls).get_obj(context, str(id))
        if not obj:
            raise exception.InstanceNotFound(instance_id=id)
        return obj


class InstanceType(FakeDbObj):
    key = 'instance_types'

    def __getitem__(self, key):
        if key == 'rxtx_cap':
            return self._values.get('rxtx_cap', None)
        elif key == 'flavorid':
            v = self._values.get(key, None)
            if v is not None:
                return str(v)
            else:
                return None
        else:
            return super(InstanceType, self).__getitem__(key)

    @classmethod
    def get_by_flavor_id(cls, context, id):
        for x in cls.get_all(context):
            if str(x['flavorid']) == str(id):
                return x
        raise exception.FlavorNotFound(flavor_id=id)

    @classmethod
    def get_by_name(cls, context, name):
        for x in cls.get_all(context):
            if x['name'] == name:
                return x
        raise exception.InstanceTypeNotFoundByName(instance_type_name=name)

class FloatingIp(FakeDbObj):
    key = 'floating_ips'

    def __getitem__(self, key):
        if key in ['fixed_ip_id']:
            return self._values.get(key, None)
        elif key == 'host':
            return self._values.get(key, None)
        elif key == 'fixed_ips':
            fixed_ip_id = self['fixed_ip_id']
            if fixed_ip_id:
                return FixedIp.get_obj(context.get_admin_context(),
                                       fixed_ip_id)
        elif key == 'fixed_ip':
            fixed_ip_id = self['fixed_ip_id']
            if fixed_ip_id:
                return FixedIp.get_obj(context.get_admin_context(),
                                       fixed_ip_id)
        else:
            return super(FloatingIp, self).__getitem__(key)

    @classmethod
    def get_by_fixed_ip(cls, context, fixed_ip_id):
        fixed_ips = []
        for x in cls.get_all(context):
            if x['fixed_ip_id'] == fixed_ip_id:
                fixed_ips.append(x)
        return fixed_ips

    @classmethod
    def allocate_address(cls, context, project_id):
        for x in cls.get_all(context):
            if x.get('project_id', None) is None:
                x['project_id'] = project_id
                return x['address']
        raise exception.NoMoreFloatingIps()


    def deallocate(self, context):
        self['project_id'] = None
        self['host'] = None
        self['auto_assigned'] = False

    def disassociate(self, context):
        self['fixed_ip_id'] = None
        self['host'] = None

    def associate_fixed_ip(self, context, fixed_ip, host):
        self['fixed_ip_id'] = fixed_ip['id']
        self['host'] = host

    @classmethod
    def count_by_project(cls, context, project_id):
        count = 0
        for x in cls.get_all(context):
            if x.get('project_id', None) == project_id:
                count += 1
        return count

    @classmethod
    def get_by_address(cls, context, address):
        for x in cls.get_all(context):
            if x['address'] == address:
                return x

    @classmethod
    def get_all_by_host(cls, context, host):
        floating_ips = []
        for x in cls.get_all(context):
            if x['host'] == host:
                floating_ips.append(x)
        return floating_ips

class ComputeNode(FakeDbObj):
    key = 'compute_nodes'

def _get_id():
    global _db
    _db['next_id'] += 1
    return _db['next_id']

def db_sync(version=None):
    LOG.info('Pretending to sync')
    return None

### Network ###

def network_create_safe(context, values):
    return Network.create(context, values)

def network_associate(context, project_id, force=False):
    return Network.associate(context, project_id, force)

def network_get_all(context=None):
    return Network.get_all(context)

def network_update(context, id, values):
    return Network.get_obj(context, id).update(values)

def network_set_host(context, network_id, host):
    Network.get_obj(context, network_id)['host'] = host

def network_get(context, network_id):
    return Network.get_obj(context, network_id)

def network_get_all_by_host(context, host):
    return Network.get_by_host(context, host)


### Fixed Ip ###

def fixed_ip_create(context, values):
    return FixedIp.create(context, values)['address']

def fixed_ip_get(context, id):
    return FixedIp.get_obj(context, id)

def fixed_ip_get_by_address(context, address):
    return FixedIp.get_by_address(context, address)

def fixed_ip_get_by_instance(context, instance_id):
    return FixedIp.get_by_instance(context, instance_id)

def fixed_ip_associate_pool(context, network_id, instance_id=None, host=None):
    return FixedIp.associate_pool(context, network_id, instance_id, host)

def fixed_ip_bulk_create(context, ips):
    for ip in ips:
        FixedIp.create(context, ip)

def fixed_ip_update(context, address, values):
    return FixedIp.get_by_address(context, address).update(values)

### Provider FW Rule ###

def provider_fw_rule_get_all(context):
    return ProviderFwRule.get_all(context)

def provider_fw_rule_get_all_by_cidr(context, cidr):
    return ProviderFwRule.get_all_by_cidr(context, cidr)

def provider_fw_rule_create(context, values):
    return ProviderFwRule.create(context, values)

def provider_fw_rule_destroy(context, rule_id):
    return ProviderFwRule.delete(context, rule_id)

### Service ###

def service_get_all_volume_sorted(context):
    return Service.get_all_volume_sorted(context)

def service_get_all_compute_sorted(context):
    return Service.get_all_compute_sorted(context)

def service_get_all_by_topic(context, topic):
    return Service.get_all_by_topic(context, topic)

def service_get_all_by_host(context, host):
    return Service.get_all_by_host(context, host)

def service_get_all_compute_by_host(context, host):
    return Service.get_all_compute_by_host(context, host)

def service_get_all(context, disabled):
    return Service.get_all(context, disabled)

def service_get(context, id):
    return Service.get_obj(context, id)

def service_destroy(context, id):
    return Service.delete(context, id)

def service_update(context, id, values):
    return Service.get_obj(context, id).update(values)

def service_get_by_args(context, host, binary):
    return Service.get_by_args(context, host, binary)

def service_get_by_host_and_topic(context, host, topic):
    return Service.get_by_host_and_topic(context, host, topic)

def service_create(context, values):
    return Service.create(context, values)

### Host ###

def host_get(context, id):
    return Host.get(context, id)

### Instance ###

def instance_get_id_to_uuid_mapping(context, ids):
    mapping = {}
    for id in ids:
        inst = Instance.get_obj(context, id)
        mapping[inst['id']] = inst['uuid']
    return mapping

def instance_metadata_delete(context, instance_id, key):
    instance = instance_get(context, instance_id)
    del instance['metadata'][key]

def instance_metadata_update(context, instance_id, metadata, delete):
    instance = instance_get(context, instance_id)
    if delete:
        instance['metadata'] = {}

    instance['metadata'].update(metadata)
    return metadata

def instance_get_all_by_filters(context, filters):
    return Instance.get_all_by_filters(context, filters)

def instance_destroy(context, id):
    return Instance.delete(context, id)

def instance_create(context, values):
    return Instance.create(context, values)

def instance_add_security_group(context, instance_id, security_group_id):
    if utils.is_uuid_like(instance_id):
        inst = Instance.get_by_uuid(context, instance_id)
    else:
        inst = Instance.get_obj(context, instance_id)
    security_group = SecurityGroup.get_obj(context, security_group_id)
    inst.add_security_group(context, security_group)

def instance_update(context, instance_id, values):
    if utils.is_uuid_like(instance_id):
        inst = Instance.get_by_uuid(context, instance_id)
    else:
        inst = Instance.get_obj(context, instance_id)
    return inst.update(values)

def instance_get(context, id):
    return Instance.get_obj(context, id)


def instance_data_get_for_project(context, project_id):
    return Instance.get_data_for_project(context, project_id)

def instance_get_floating_address(context, instance_id):
    if utils.is_uuid_like(instance_id):
        inst = Instance.get_by_uuid(context, instance_id)
    else:
        inst = Instance.get_obj(context, instance_id)

    fixed_ip_refs = fixed_ip_get_by_instance(context, inst['id'])
    if not fixed_ip_refs:
        return None
    if not fixed_ip_refs[0]['floating_ips']:
        return None
    return fixed_ip_refs[0]['floating_ips'][0]['address']


def instance_get_by_uuid(context, uuid):
    return Instance.get_by_uuid(context, uuid)

def instance_get_all(context):
    return Instance.get_all(context)

def instance_get_all_by_host(context, host_id):
    return Instance.get_all_by_host(context, host_id)

def instance_get_all_hung_in_rebooting(context, reboot_window, session=None):
    return Instance.get_all_hung_in_rebooting(context, reboot_window)

def instance_get_project_vpn(context, project_id):
    return Instance.get_project_vpn(context, project_id)


### Volume ###

def volume_get_iscsi_target_num(context, volume_id):
    obj =  IscsiTarget.get_by_volume(context, volume_id)
    if not obj:
        raise exception.ISCSITargetNotFoundForVolume(volume_id=volume_id)
    return obj['target_num']

def volume_allocate_iscsi_target(context, volume_id, host):
    return IscsiTarget.allocate_volume(context, volume_id, host)

def volume_create(context, values):
    return Volume.create(context, values)

def volume_destroy(context, id):
    return Volume.delete(context, id)

def volume_get(context, id):
    return Volume.get_obj(context, id)

def volume_get_all(context):
    return Volume.get_all(context)

def volume_update(context, id, values):
    return Volume.get_obj(context, id).update(values)

def volume_data_get_for_project(context, project_id):
    return Volume.get_data_for_project(context, project_id)

def volume_attached(context, volume_id, instance_id, mountpoint):
    return Volume.get_obj(context, volume_id).set_attached(context,
                                                           instance_id,
                                                           mountpoint)


def volume_detached(context, volume_id):
    return Volume.get_obj(context, volume_id).unset_attached(context)


def volume_get_all_by_host(context, host_id):
    return Volume.get_all_by_host(context, host_id)

def volume_get_all_by_instance(context, instance_id):
    return Volume.get_all_by_instance(context, instance_id)

def volume_get_instance(context, volume_id):
    return Volume.get_obj(context, volume_id)['instance']


### User ###

def user_get_by_access_key(context, access_key):
    return User.get_by_access_key(context, access_key)

def user_create(context, values):
    return User.create(context, values)

def user_update(context, id, values):
    return User.get_obj(context, id).update(values)

def user_get(context, id):
    return User.get_obj(context, id)

def user_get_all(context):
    return User.get_all(context)

def user_delete(context, id):
    return User.delete(context, id)

def user_add_role(context, user_id, role):
    return User.get_obj(context, user_id).add_role(context, role)

def user_remove_role(context, user_id, role):
    return User.get_obj(context, user_id).remove_role(context, role)

def user_add_project_role(context, user_id, project_id, project_role):
    return User.get_obj(context, user_id).add_project_role(context, project_id, project_role)

def user_remove_project_role(context, user_id, project_id, project_role):
    return User.get_obj(context, user_id).remove_project_role(context, project_id, project_role)

def user_get_roles_for_project(context, user_id, project_id):
    return User.get_obj(context, user_id).get_roles_for_project(context, project_id)

def user_get_roles(context, user_id):
    return User.get_obj(context, user_id).get_roles(context)

### Project ###

def project_create(context, values):
    return Project.create(context, values)

def project_add_member(context, project_id, user_id):
    proj = Project.get_obj(context, project_id)
    proj.add_member(context, user_id)

def project_remove_member(context, project_id, user_id):
    proj = Project.get_obj(context, project_id)
    proj.remove_member(context, user_id)

def project_get(context, id):
    return Project.get_obj(context, id)

def project_get_by_user(context, user_id):
    return Project.get_by_user(context, user_id)

def project_get_all(context):
    return Project.get_all(context)

def project_get_networks(context, project_id, associate=True):
    return Network.get_by_project(context, project_id, associate)

def project_update(context, id, values):
    return Project.get_obj(context, id).update(values)

def project_delete(context, id):
    return Project.delete(context, id)

### Key pair ###

def key_pair_get(context, user_id, name):
    return KeyPair.get_by_user_and_name(context, user_id, name)

def key_pair_create(context, values):
    return KeyPair.create(context, values)

def key_pair_destroy(context, user_id, name):
    key_pair = key_pair_get(context, user_id, name)
    return KeyPair.delete(context, key_pair['id'])

def key_pair_destroy_all_by_user(context, user_id):
    return KeyPair.destroy_all_by_user(context, user_id)

def key_pair_get_all_by_user(context, user_id):
    return KeyPair.get_all_by_user(context, user_id)

### Instance type ###

def instance_type_get_by_flavor_id(context, flavor_id):
    return InstanceType.get_by_flavor_id(context, flavor_id)

def instance_type_get_by_name(context, name):
    return InstanceType.get_by_name(context, name)

def instance_type_create(context, values):
    if 'flavorid' in values:
        try:
            InstanceType.get_by_flavor_id(context, values['flavorid'])
            raise exception.DBError('Duplicate flavorid given')
        except exception.FlavorNotFound:
            pass

    if 'name' in values:
        try:
            InstanceType.get_by_name(context, values['name'])
            raise exception.DBError('Duplicate name given')
        except exception.InstanceTypeNotFoundByName:
            pass

    return InstanceType.create(context, values)

def instance_type_purge(ctxt, id):
    read_deleted_ctxt = context.get_admin_context(read_deleted=True)
    inst_type = InstanceType.get_by_name(read_deleted_ctxt, str(id))
    return InstanceType.delete(context, inst_type['id'], purge=True)

def instance_type_destroy(context, id):
    inst_type = InstanceType.get_by_name(context, str(id))
    return InstanceType.delete(context, inst_type['id'])

def instance_type_get(context, id):
    obj =  InstanceType.get_obj(context, str(id))
    if not obj:
        raise exception.InstanceTypeNotFound(instance_type_id=id)
    return obj

def instance_type_get_all(context, inactive=False, filters=None):
    objs = InstanceType.get_all(context)

    if filters and 'min_local_gb' in filters:
        val = filters.pop('min_local_gb')
        objs = filter(lambda x: x.get('local_gb', 0) >= val, objs)

    if filters and 'min_memory_mb' in filters:
        val = filters.pop('min_memory_mb')
        objs = filter(lambda x: x.get('memory_mb', 0) >= val, objs)

    if filters:
        raise Exception(str(filters))
    return objs


### Compute node ###

def compute_node_create(context, values):
    return ComputeNode.create(context, values)

### Floating IP ###

def floating_ip_get_all(context):
    return FloatingIp.get_all(context)

def floating_ip_create(context, values):
    return FloatingIp.create(context, values)['address']

def floating_ip_update(context, address, values):
    return FloatingIp.get_by_address(context, address).update(values)

def floating_ip_destroy(context, address):
    floating_ip = FloatingIp.get_by_address(context, address)
    FloatingIp.delete(context, floating_ip['id'])

def floating_ip_count_by_project(context, project_id):
    return FloatingIp.count_by_project(context, project_id)

def floating_ip_allocate_address(context, project_id):
    return FloatingIp.allocate_address(context, project_id)

def floating_ip_get_all_by_host(context, host):
    return FloatingIp.get_all_by_host(context, host)

def floating_ip_fixed_ip_associate(context, floating_address,
                                   fixed_address, host):
    floating_ip = FloatingIp.get_by_address(context, floating_address)
    fixed_ip = FixedIp.get_by_address(context, fixed_address)
    floating_ip.associate_fixed_ip(context, fixed_ip, host)

def floating_ip_disassociate(context, floating_address):
    FloatingIp.get_by_address(context, floating_address).disassociate(context)

def floating_ip_deallocate(context, floating_address):
    FloatingIp.get_by_address(context, floating_address).deallocate(context)

def floating_ip_get_by_address(context, address):
    return FloatingIp.get_by_address(context, address)

### S3 Image ###

def s3_image_create(context, uuid):
    return S3Image.create(context, {'uuid': uuid})

def s3_image_get(context, id):
    return S3Image.get_obj(context, id)

def s3_image_get_by_uuid(context, uuid):
    return S3Image.get_by_uuid(context, uuid)

### Quota ###

def quota_create(context, project_id, resource, limit):
    return Quota.create(context, {'project_id': project_id,
                                  'resource': resource,
                                  'hard_limit': limit})

def quota_get_all_by_project(context, project_id):
    return Quota.get_all_by_project(context, project_id)

@require_admin_context
def quota_update(context, project_id, resource, limit):
    Quota.get_by_project_and_resource(context, project_id, resource)['hard_limit'] = limit

### Security Group ###

def security_group_get_by_instance(context, instance_id):
    return SecurityGroup.get_by_instance(context, instance_id)

def security_group_exists(context, project_id, group_name):
    security_group = SecurityGroup.get_by_name(context, project_id, group_name)
    return security_group is not None

def security_group_rule_destroy(context, id):
    return SecurityGroupRule.delete(context, id)

def security_group_rule_get(context, id):
    return SecurityGroupRule.get_obj(context, id)

def security_group_rule_create(context, values):
    return SecurityGroupRule.create(context, values)


def security_group_destroy(context, id):
    group = SecurityGroup.get_obj(context, id)
    for rule in group['rules']:
        security_group_rule_destroy(context, rule['id'])
    for instance in Instance.get_all(context):
        if group in instance['security_groups']:
            instance['security_groups'].remove(group)
    SecurityGroup.delete(context, id)

def security_group_get(context, id):
    return SecurityGroup.get_obj(context, id)

def security_group_create(context, values):
    return SecurityGroup.create(context, values)

def security_group_get_all(context):
    return SecurityGroup.get_all(context)

def security_group_get_by_name(context, project_id, group_name):
    result = SecurityGroup.get_by_name(context, project_id, group_name)
    if not result:
        raise exception.SecurityGroupNotFoundForProject(project_id=project_id,
                                                 security_group_id=group_name)
    return result

def security_group_get_by_project(context, project_id):
    return SecurityGroup.get_by_project(context, project_id)

### Queue ###

# XXX(soren): What the #%&@#! is this doing in the db layer?
def queue_get_for(_context, topic, physical_node_id):
    return "%s.%s" % (topic, physical_node_id)

### Block device mapping ###

def block_device_mapping_create(context, values):
    return BlockDeviceMapping.create(context, values)

def block_device_mapping_destroy(context, id):
    return BlockDeviceMapping.delete(context, id)

def block_device_mapping_update(context, id, values):
    return BlockDeviceMapping.get_obj(context, id).update(values)

def block_device_mapping_update_or_create(context, values):
    instance_id = values['instance_id']
    device_name = values['device_name']
    bdm = BlockDeviceMapping.get_by_instance_and_device_name(context,
                                                             instance_id,
                                                             device_name)
    if bdm:
        obj =  bdm.update(values)
    else:
        obj =  BlockDeviceMapping.create(context, values)

    virtual_name = values['virtual_name']
    if (virtual_name is not None and
        block_device.is_swap_or_ephemeral(virtual_name)):
        to_delete = []
        for x in BlockDeviceMapping.get_all(context):
            if (x['instance_id'] == instance_id and
                x['virtual_name'] == virtual_name and
                x['device_name'] != values['device_name']):
                to_delete.append(x['id'])
        for id in to_delete:
            BlockDeviceMapping.delete(context, id)

def block_device_mapping_get_all_by_instance(context, instance_id):
    return BlockDeviceMapping.get_all_by_instance(context, instance_id)

def block_device_mapping_destroy_by_instance_and_volume(context, instance_id,
                                                        volume_id):
    bdm = BlockDeviceMapping.get_by_instance_and_volume(context, instance_id,
                                                        volume_id)
    BlockDeviceMapping.delete(context, bdm['id'])

### Zone ###

def zone_get_all(context):
    return Zone.get_all(context)

### Bandwidth usage ###

def bw_usage_get_by_instance(context, instance_id, start_period):
    return BandwidthUsage.get_by_instance(context, instance_id, start_period)

### Virtual interface ###

def virtual_interface_create(context, values):
    return VirtualInterface.create(context, values)


def virtual_interface_get_by_instance_and_network(context,
                                                  instance_id, network_id):
    return VirtualInterface.get_by_instance_and_network(context,
                                                        instance_id,
                                                        network_id)

def virtual_interface_get_by_instance(context, instance_id):
    return VirtualInterface.get_by_instance(context, instance_id)


### Snapshot ###

def snapshot_create(context, values):
    return Snapshot.create(context, values)

def snapshot_get_all(context):
    return Snapshot.get_all(context)

def snapshot_get(context, id):
    return Snapshot.get_obj(context, id)

def snapshot_update(context, id, values):
    return Snapshot.get_obj(context, id).update(values)

def snapshot_destroy(context, id):
    return Snapshot.delete(context, id)

def iscsi_target_count_by_host(context, host):
    return IscsiTarget.count_by_host(context, host)

### Iscsi target ###

def iscsi_target_create_safe(context, values):
    return IscsiTarget.create(context, values)

### Auth token ###

def auth_token_get(context, token_hash):
    return AuthToken.get_by_token_hash(context, token_hash)

def auth_token_create(context, values):
    return AuthToken.create(context, values)

def auth_token_destroy(context, token_hash):
    token = AuthToken.get_by_token_hash(context, token_hash)
    AuthToken.delete(context, token['id'])

def auth_token_update(context, token_hash, values):
    return AuthToken.get_by_token_hash(context, token_hash).update(values)

### Volume type ###

def volume_type_get_by_name(context, name):
    return VolumeType.get_by_name(context, name)

def volume_type_get(context, id):
    return VolumeType.get_obj(context, id)

def volume_type_create(context, values):
    return VolumeType.create(context, values)

def volume_type_purge(context, name):
    volume_type = volume_type_get_by_name(context, name)
    return VolumeType.delete(context, volume_type['id'], purge=True)

### Certificates ###

def certificate_create(context, values):
    return Certificate.create(context, values)

### Console pool ###

def console_pool_get_by_host_type(context, compute_host, host, console_type):
    return ConsolePool.get_by_host_type(context, compute_host, host,
                                        console_type)

def console_pool_create(context, values):
    return ConsolePool.create(context, values)

### Console ###

def console_get_by_pool_instance(context, pool_id, instance_id):
    return Console.get_by_pool_instance(context, pool_id, instance_id)

def console_create(context, values):
    return Console.create(context, values)

def console_delete(context, id):
    return Console.delete(context, id)

def console_get(context, console_id, instance_id=None):
    console = Console.get_obj(context, console_id)
    if instance_id:
        if console and console['instance_id'] == instance_id:
            return console
        else:
            raise exception.ConsoleNotFoundForInstance(console_id=console_id,
                                                       instance_id=instance_id)
    else:
        if console:
            return console
        else:
            raise exception.ConsoleNotFound(console_id=console_id)

### Migration ###

def migration_create(context, values):
    return Migration.create(context, values)

def migration_get(context, id):
    return Migration.get_obj(context, id)

def migration_update(context, id, values):
    return Migration.get_obj(context, id).update(values)

def migration_get_by_instance_and_status(context, instance_uuid, status):
    return Migration.get_by_instance_and_status(context, instance_uuid, status)

def migration_get_all_unconfirmed(context, confirm_window, session=None):
    return Migration.get_all_unconfirmed(context, confirm_window)

def _add_instance_types():
    # From nova/db/sqlalchemy/migrate_repo/versions/008_add_instance_types.py
    types = { 'm1.tiny': dict(memory_mb=512, vcpus=1, local_gb=0, flavorid=1),
      'm1.small': dict(memory_mb=2048, vcpus=1, local_gb=20, flavorid=2),
      'm1.medium': dict(memory_mb=4096, vcpus=2, local_gb=40, flavorid=3),
      'm1.large': dict(memory_mb=8192, vcpus=4, local_gb=80, flavorid=4),
      'm1.xlarge': dict(memory_mb=16384, vcpus=8, local_gb=160, flavorid=5)}

    for name, values in types.iteritems():
        values['name'] = name
        InstanceType.create(None, values)

_baseline_recorded = False

def baseline_recorded():
    return _baseline_recorded

def record_baseline():
    global _baseline_db
    global _baseline_recorded
    _baseline_db = copy.deepcopy(_db)
    _baseline_recorded = True

def reset():
    global _db
    _db = copy.deepcopy(_baseline_db)

reset()
_add_instance_types()
