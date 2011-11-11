# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
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

"""Unit tests for the DB API"""

import datetime

from nova import context
from nova import db
from nova import exception
from nova import flags
from nova import test
from nova import tests

FLAGS = flags.FLAGS


def _setup_networking(instance_id, ip='1.2.3.4', flo_addr='1.2.1.2'):
    ctxt = context.get_admin_context()
    network_ref = db.project_get_networks(ctxt,
                                           'fake',
                                           associate=True)[0]
    vif = {'address': '56:12:12:12:12:12',
           'network_id': network_ref['id'],
           'instance_id': instance_id}
    vif_ref = db.virtual_interface_create(ctxt, vif)

    fixed_ip = {'address': ip,
                'network_id': network_ref['id'],
                'virtual_interface_id': vif_ref['id'],
                'allocated': True,
                'instance_id': instance_id}
    db.fixed_ip_create(ctxt, fixed_ip)
    fix_ref = db.fixed_ip_get_by_address(ctxt, ip)
    db.floating_ip_create(ctxt, {'address': flo_addr,
                                 'fixed_ip_id': fix_ref['id']})


class __DbApiTestCase(test.TestCase):
    def setUp(self):
        super(__DbApiTestCase, self).setUp()
        self.user_id = 'fake'
        self.project_id = 'fake'
        self.context = context.RequestContext(self.user_id, self.project_id)

    def test_instance_get_project_vpn(self):
        values = {'instance_type_id': FLAGS.default_instance_type,
                  'image_ref': FLAGS.vpn_image_id,
                  'project_id': self.project_id,
                 }
        instance = db.instance_create(self.context, values)
        result = db.instance_get_project_vpn(self.context.elevated(),
                                             self.project_id)
        self.assertEqual(instance['id'], result['id'])

    def test_instance_get_project_vpn_joins(self):
        values = {'instance_type_id': FLAGS.default_instance_type,
                  'image_ref': FLAGS.vpn_image_id,
                  'project_id': self.project_id,
                 }
        instance = db.instance_create(self.context, values)
        _setup_networking(instance['id'])
        result = db.instance_get_project_vpn(self.context.elevated(),
                                             self.project_id)
        self.assertEqual(instance['id'], result['id'])
        self.assertEqual(result['fixed_ips'][0]['floating_ips'][0]['address'],
                         '1.2.1.2')

    def test_instance_get_all_by_filters(self):
        args = {'reservation_id': 'a', 'image_ref': 1, 'host': 'host1'}
        inst1 = db.instance_create(self.context, args)
        inst2 = db.instance_create(self.context, args)
        result = db.instance_get_all_by_filters(self.context, {})
        self.assertTrue(2, len(result))

    def _test_instance_get_all_by_filters_deleted(self):
        args1 = {'reservation_id': 'a', 'image_ref': 1, 'host': 'host1'}
        inst1 = db.instance_create(self.context, args1)
        args2 = {'reservation_id': 'b', 'image_ref': 1, 'host': 'host1'}
        inst2 = db.instance_create(self.context, args2)
        db.instance_destroy(self.context, inst1['id'])
        result = db.instance_get_all_by_filters(self.context.elevated(), {})
        self.assertEqual(2, len(result))
        self.assertIn(inst1.id, [result[0]['id'], result[1]['id']])
        self.assertIn(inst2.id, [result[0]['id'], result[1]['id']])
        if inst1.id == result[0].id:
            self.assertTrue(result[0]['deleted'])
        else:
            self.assertTrue(result[1]['deleted'])

    def test_migration_get_all_unconfirmed(self):
        ctxt = context.get_admin_context()

        # Ensure no migrations are returned.
        results = db.migration_get_all_unconfirmed(ctxt, 10)
        self.assertEqual(0, len(results))

        # Ensure one migration older than 10 seconds is returned.
        updated_at = datetime.datetime(2000, 01, 01, 12, 00, 00)
        values = {"status": "FINISHED", "updated_at": updated_at}
        migration = db.migration_create(ctxt, values)
        results = db.migration_get_all_unconfirmed(ctxt, 10)
        self.assertEqual(1, len(results))
        db.migration_update(ctxt, migration['id'], {"status": "CONFIRMED"})

        # Ensure the new migration is not returned.
        updated_at = datetime.datetime.utcnow()
        values = {"status": "FINISHED", "updated_at": updated_at}
        migration = db.migration_create(ctxt, values)
        results = db.migration_get_all_unconfirmed(ctxt, 10)
        self.assertEqual(0, len(results))
        db.migration_update(ctxt, migration['id'], {"status": "CONFIRMED"})

    def test_instance_get_all_hung_in_rebooting(self):
        ctxt = context.get_admin_context()

        # Ensure no instances are returned.
        results = db.instance_get_all_hung_in_rebooting(ctxt, 10)
        self.assertEqual(0, len(results))

        # Ensure one rebooting instance with updated_at older than 10 seconds
        # is returned.
        updated_at = datetime.datetime(2000, 01, 01, 12, 00, 00)
        values = {"task_state": "rebooting", "updated_at": updated_at}
        instance = db.instance_create(ctxt, values)
        results = db.instance_get_all_hung_in_rebooting(ctxt, 10)
        self.assertEqual(1, len(results))
        db.instance_update(ctxt, instance['id'], {"task_state": None})

        # Ensure the newly rebooted instance is not returned.
        updated_at = datetime.datetime.utcnow()
        values = {"task_state": "rebooting", "updated_at": updated_at}
        instance = db.instance_create(ctxt, values)
        results = db.instance_get_all_hung_in_rebooting(ctxt, 10)
        self.assertEqual(0, len(results))
        db.instance_update(ctxt, instance['id'], {"task_state": None})

    def test_network_create_safe(self):
        ctxt = context.get_admin_context()
        values = {'host': 'localhost', 'project_id': 'project1'}
        network = db.network_create_safe(ctxt, values)
        self.assertNotEqual(None, network.uuid)
        self.assertEqual(36, len(network.uuid))
        db_network = db.network_get(ctxt, network.id)
        self.assertEqual(network.uuid, db_network.uuid)

    def test_instance_update_with_instance_id(self):
        """ test instance_update() works when an instance id is passed """
        ctxt = context.get_admin_context()

        # Create an instance with some metadata
        metadata = {'host': 'foo'}
        values = {'metadata': metadata}
        instance = db.instance_create(ctxt, values)

        # Update the metadata
        metadata = {'host': 'bar'}
        values = {'metadata': metadata}
        db.instance_update(ctxt, instance.id, values)

        # Retrieve the metadata to ensure it was successfully updated
        instance_meta = db.instance_metadata_get(ctxt, instance.id)
        self.assertEqual('bar', instance_meta['host'])

    def test_instance_update_with_instance_uuid(self):
        """ test instance_update() works when an instance UUID is passed """
        ctxt = context.get_admin_context()

        # Create an instance with some metadata
        metadata = {'host': 'foo'}
        values = {'metadata': metadata}
        instance = db.instance_create(ctxt, values)

        # Update the metadata
        metadata = {'host': 'bar'}
        values = {'metadata': metadata}
        db.instance_update(ctxt, instance.uuid, values)

        # Retrieve the metadata to ensure it was successfully updated
        instance_meta = db.instance_metadata_get(ctxt, instance.id)
        self.assertEqual('bar', instance_meta['host'])

class _DbApiTestCase(test.TestCase):
    def setUp(self):
        self.saved_db_imp = db.api.IMPL
        self.saved_migration_imp = db.migration.IMPL

        db.api.IMPL = self.get_db_driver()
        db.migration.IMPL = self.get_migration_driver()

        tests.setup()
        super(_DbApiTestCase, self).setUp()

    def tearDown(self):
        super(_DbApiTestCase, self).tearDown()
        db.api.IMPL = self.saved_db_imp 
        db.migration.IMPL = self.saved_db_imp 

    def test_network_create_safe_defaults(self):
        ctxt = context.get_admin_context()
        network = db.network_create_safe(ctxt, {})

        # TODO(soren): Document somewhere that this is required.
        #              All the *_create methods return severely
        #              amputated objects (nothing is joinedloaded)
        network = db.network_get(ctxt, network['id'])

        for key in ['label', 'cidr', 'cidr_v6', 'gateway_v6', 'netmask_v6',
                    'netmask', 'bridge', 'bridge_interface', 'gateway',
                    'broadcast', 'dns1', 'dns2', 'vlan', 'vpn_public_address',
                    'vpn_public_port', 'vpn_private_address', 'dhcp_start',
                    'project_id', 'priority', 'host']:
            self.assertIsNone(network[key], '%s was not None by default')

        for key in ['injected', 'multi_host']:
            self.assertFalse(network[key], '%s was not False by default')

        for key in ['virtual_interfaces', 'fixed_ips']:
            self.assertTrue(len(network[key]) == 0, '%s was not of length 0 by default')

    def test_network_associate(self):
        ctxt = context.get_admin_context()

        network_ids = []
        network_ids.append(db.network_create_safe(ctxt, {})['id'])
        network_ids.append(db.network_create_safe(ctxt, {})['id'])

        network = db.network_associate(ctxt, 'fake')
        network_ids.remove(network['id'])

        self.assertEquals(db.network_associate(ctxt, 'fake')['id'],
                          network['id'],
                          'network_associate(..., force=False) didn\'t give '
                          'the same network when called for a project for the '
                          'second time.')

        # Calling network_associate with force=True should associate
        # the other network with his project_id
        network = db.network_associate(ctxt, 'fake', force=True)
        self.assertEquals(network['id'], network_ids[0])

        # ...and finally, if there are no more networks, we should get an error
        self.assertRaises(db.NoMoreNetworks,
                          db.network_associate, ctxt, 'fake', force=True)


    def test_network_get_all(self):
        ctxt = context.get_admin_context()

        self.assertRaises(exception.NoNetworksFound, db.network_get_all, ctxt)

        network_ids = []
        network_ids.append(db.network_create_safe(ctxt, {})['id'])
        self.assertEquals(len(db.network_get_all(ctxt)), 1)
        network_ids.append(db.network_create_safe(ctxt, {})['id'])
        self.assertEquals(len(db.network_get_all(ctxt)), 2)

        self.assertEquals(set([n['id'] for n in db.network_get_all(ctxt)]),
                          set(network_ids))

    def test_network_vif_backref(self):
        ctxt = context.get_admin_context()
        network = db.network_create_safe(ctxt, {})
        inst = db.instance_create(ctxt, {})

        vif = db.virtual_interface_create(ctxt, {'network_id': network['id'],
                                                 'instance_id': inst['id']})

        # Reload the network objects
        network = db.network_get(ctxt, network['id'])
        self.assertTrue(len(network['virtual_interfaces']) == 1)
        self.assertEquals(network['virtual_interfaces'][0]['id'], vif['id'])

    def test_network_fixed_ip_backref(self):
        ctxt = context.get_admin_context()
        network = db.network_create_safe(ctxt, {})

        fixed_ip = db.fixed_ip_create(ctxt, {'address': '10.10.10.10',
                                             'network_id': network['id']})

        self.assertTrue(len(network['fixed_ips']) == 1)
        self.assertEquals(network['fixed_ips'][0]['address'],
                          fixed_ip)


    def test_virtual_interface_create_requires_instance(self):
        ctxt = context.get_admin_context()
        inst = db.instance_create(ctxt, {})

        # Fails without instance_id set
        self.assertRaises(exception.DBError,
                          db.virtual_interface_create, ctxt, {})

        # Succeeds if it's added
        db.virtual_interface_create(ctxt, {'instance_id': inst['id']})

    def test_network_update(self):
        ctxt = context.get_admin_context()
        network = db.network_create_safe(ctxt, {'label': 'oldlabel'})
        db.network_update(ctxt, network['id'], {'label': 'newlabel'})

        network = db.network_get(ctxt, network['id'])
        self.assertEquals(network['label'], 'newlabel')

    def test_network_set_host(self):
        ctxt = context.get_admin_context()
        network = db.network_create_safe(ctxt, {})

        db.network_set_host(ctxt, network['id'], 'somehost')

        network = db.network_get(ctxt, network['id'])
        self.assertEquals(network['host'], 'somehost')

    def test_network_get_all_by_host(self):
        ctxt = context.get_admin_context()

        expected = {}
        for host in ['hosta', 'hostb']:
            expected[host] = []
            for x in range(2):
                network = db.network_create_safe(ctxt, {})
                expected[host].append(network['id'])
                db.network_set_host(ctxt, network['id'], host)
                # NOTE(soren): This is only needed as long as bug 898167 exists
                db.fixed_ip_create(ctxt, {'network_id': network['id']})

        for host in ['hosta', 'hostb']:
            actual = db.network_get_all_by_host(ctxt, host)
            self.assertEquals(set([x['id'] for x in actual]),
                              set(expected[host]))


class FakeDbDriverTestCase(_DbApiTestCase):
    def get_db_driver(self):
        import nova.db.fake.api
        return nova.db.fake.api

    def get_migration_driver(self):
        import nova.db.fake.api
        return nova.db.fake.api

class SQLAlchemyDbDriverTestCase(_DbApiTestCase):
    def get_db_driver(self):
        import nova.db.sqlalchemy.api
        return nova.db.sqlalchemy.api

    def get_migration_driver(self):
        import nova.db.sqlalchemy.migration
        return nova.db.sqlalchemy.migration
