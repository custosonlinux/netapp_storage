"""
Tests für snapshot_engine Hilfsfunktionen

Testet isolierte Logik ohne PegaProx-Laufzeitabhängigkeiten.
"""

import json
import types
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

# Flask-Stub
_flask_stub = types.ModuleType('flask')
_flask_stub.send_file = lambda *a, **kw: None
_flask_stub.redirect = lambda *a, **kw: None
_flask_stub.request = MagicMock()
sys.modules.setdefault('flask', _flask_stub)

# requests-Stub
_req_stub = types.ModuleType('requests')
_req_stub.Session = MagicMock
_req_stub.RequestException = Exception
class _ConnError(Exception): pass
_req_stub.ConnectionError = _ConnError
_req_stub.auth = types.ModuleType('requests.auth')
class _HTTPBasicAuth:
    def __init__(self, u, p): pass
_req_stub.auth.HTTPBasicAuth = _HTTPBasicAuth
sys.modules.setdefault('requests', _req_stub)
sys.modules.setdefault('requests.auth', _req_stub.auth)

# Minimale Stubs für PegaProx-Module damit import nicht knallt
for mod in ['pegaprox', 'pegaprox.globals', 'pegaprox.core', 'pegaprox.core.db',
            'pegaprox.constants', 'pegaprox.utils', 'pegaprox.utils.ssh_pool']:
    if mod not in sys.modules:
        sys.modules[mod] = types.ModuleType(mod)

sys.modules['pegaprox.globals'].cluster_managers = {}
sys.modules['pegaprox.core.db'].get_db = MagicMock()
sys.modules['pegaprox.constants'].PEGAPROX_VERSION = 'test'
sys.modules['pegaprox.utils.ssh_pool'].controlmaster_args = lambda host, user, **kw: []

from plugins.netapp_storage.core.snapshot_engine import (
    _extract_disk_files,
    _config_to_conf_string,
    _resolve_node_host,
)
from plugins.netapp_storage.core._helpers import get_ssh_creds


class TestExtractDiskFiles(unittest.TestCase):

    def test_qemu_scsi_disk(self):
        cfg = {'scsi0': 'nfs-store:images/100/vm-100-disk-0.qcow2,size=20G', 'name': 'my-vm'}
        disks = _extract_disk_files(cfg, 'nfs-store', 'qemu')
        self.assertEqual(len(disks), 1)
        self.assertEqual(disks[0]['key'], 'scsi0')
        self.assertEqual(disks[0]['file'], 'images/100/vm-100-disk-0.qcow2')

    def test_qemu_multiple_disks(self):
        cfg = {
            'scsi0': 'nfs-store:images/100/disk-0.qcow2,size=20G',
            'scsi1': 'nfs-store:images/100/disk-1.qcow2,size=40G',
            'ide2': 'none,media=cdrom',  # kein Disk
        }
        disks = _extract_disk_files(cfg, 'nfs-store', 'qemu')
        self.assertEqual(len(disks), 2)
        keys = {d['key'] for d in disks}
        self.assertIn('scsi0', keys)
        self.assertIn('scsi1', keys)

    def test_qemu_ignores_other_storage(self):
        cfg = {
            'scsi0': 'local-lvm:vm-100-disk-0,size=20G',
            'scsi1': 'nfs-store:images/100/disk-1.qcow2,size=10G',
        }
        disks = _extract_disk_files(cfg, 'nfs-store', 'qemu')
        self.assertEqual(len(disks), 1)
        self.assertEqual(disks[0]['key'], 'scsi1')

    def test_lxc_rootfs(self):
        cfg = {'rootfs': 'nfs-store:subvol-101-disk-0,size=8G', 'hostname': 'web01'}
        disks = _extract_disk_files(cfg, 'nfs-store', 'lxc')
        self.assertEqual(len(disks), 1)
        self.assertEqual(disks[0]['key'], 'rootfs')

    def test_lxc_mount_point(self):
        cfg = {
            'rootfs': 'nfs-store:subvol-101-disk-0,size=8G',
            'mp0': 'nfs-store:subvol-101-disk-1,mp=/data,size=50G',
        }
        disks = _extract_disk_files(cfg, 'nfs-store', 'lxc')
        self.assertEqual(len(disks), 2)

    def test_empty_config(self):
        disks = _extract_disk_files({}, 'nfs-store', 'qemu')
        self.assertEqual(disks, [])

    def test_virtio_disk(self):
        cfg = {'virtio0': 'nfs-store:images/200/vm-200-disk-0.qcow2,size=10G'}
        disks = _extract_disk_files(cfg, 'nfs-store', 'qemu')
        self.assertEqual(len(disks), 1)
        self.assertEqual(disks[0]['key'], 'virtio0')

    def test_efidisk(self):
        cfg = {'efidisk0': 'nfs-store:images/100/vm-100-efidisk0.qcow2,size=528K'}
        disks = _extract_disk_files(cfg, 'nfs-store', 'qemu')
        self.assertEqual(len(disks), 1)


class TestConfigToConfString(unittest.TestCase):

    def test_basic_output(self):
        cfg = {'name': 'my-vm', 'memory': 2048, 'scsi0': 'nfs:images/disk.qcow2'}
        result = _config_to_conf_string(cfg)
        self.assertIn('name: my-vm', result)
        self.assertIn('memory: 2048', result)
        self.assertIn('scsi0: nfs:images/disk.qcow2', result)
        self.assertTrue(result.endswith('\n'))

    def test_skips_nested(self):
        cfg = {'name': 'vm', 'nested': {'foo': 'bar'}, 'list': [1, 2]}
        result = _config_to_conf_string(cfg)
        self.assertNotIn('nested', result)
        self.assertNotIn('list', result)

    def test_sorted_output(self):
        cfg = {'z_key': 'last', 'a_key': 'first'}
        result = _config_to_conf_string(cfg)
        lines = [l for l in result.strip().split('\n') if l]
        self.assertEqual(lines[0], 'a_key: first')
        self.assertEqual(lines[1], 'z_key: last')


class TestGetSshCreds(unittest.TestCase):

    def _make_mgr(self, pass_='secret', ssh_key='', ssh_user=None):
        mgr = MagicMock()
        mgr.config.pass_ = pass_
        mgr.config.ssh_key = ssh_key
        if ssh_user is not None:
            mgr.config.ssh_user = ssh_user
        else:
            del mgr.config.ssh_user
        return mgr

    def test_password_auth(self):
        mgr = self._make_mgr(pass_='mypass', ssh_key='')
        user, password, key = get_ssh_creds(mgr)
        self.assertEqual(user, 'root')
        self.assertEqual(password, 'mypass')
        self.assertEqual(key, '')

    def test_key_auth_clears_password(self):
        mgr = self._make_mgr(pass_='mypass', ssh_key='-----BEGIN OPENSSH PRIVATE KEY-----\n...')
        user, password, key = get_ssh_creds(mgr)
        self.assertEqual(password, '')
        self.assertTrue(key.startswith('-----BEGIN'))

    def test_custom_ssh_user(self):
        mgr = self._make_mgr(ssh_user='pveadmin')
        user, _, _ = get_ssh_creds(mgr)
        self.assertEqual(user, 'pveadmin')

    def test_default_user_root(self):
        mgr = self._make_mgr()
        user, _, _ = get_ssh_creds(mgr)
        self.assertEqual(user, 'root')


class TestResolveNodeHost(unittest.TestCase):

    def test_returns_ip_when_available(self):
        mgr = MagicMock()
        mgr.get_node_status.return_value = {'pve01': {'ip': '10.0.1.5', 'host': 'pve01.local'}}
        result = _resolve_node_host(mgr, 'pve01')
        self.assertEqual(result, '10.0.1.5')

    def test_falls_back_to_node_name(self):
        mgr = MagicMock()
        mgr.get_node_status.return_value = {}
        result = _resolve_node_host(mgr, 'pve01')
        self.assertEqual(result, 'pve01')

    def test_handles_exception(self):
        mgr = MagicMock()
        mgr.get_node_status.side_effect = Exception('timeout')
        result = _resolve_node_host(mgr, 'pve01')
        self.assertEqual(result, 'pve01')

    def test_none_mgr(self):
        result = _resolve_node_host(None, 'pve01')
        self.assertEqual(result, 'pve01')


if __name__ == '__main__':
    unittest.main()
