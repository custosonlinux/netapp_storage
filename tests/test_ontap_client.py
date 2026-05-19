"""
Tests für OntapClient

Kein echter ONTAP nötig – alle HTTP-Calls werden via unittest.mock abgefangen.
"""

import json
import types
import sys
import os
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

# Flask-Stub damit __init__.py importierbar ist ohne laufende Flask-App
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
class _HTTPBasicAuth:
    def __init__(self, u, p): pass
_req_stub.ConnectionError = _ConnError
_req_stub.auth = types.ModuleType('requests.auth')
_req_stub.auth.HTTPBasicAuth = _HTTPBasicAuth
sys.modules.setdefault('requests', _req_stub)
sys.modules.setdefault('requests.auth', _req_stub.auth)

# urllib3-Stub (wird bei ssl_verify=False importiert)
_urllib3 = types.ModuleType('urllib3')
_urllib3.exceptions = types.ModuleType('urllib3.exceptions')
class _InsecureRequestWarning(UserWarning): pass
_urllib3.exceptions.InsecureRequestWarning = _InsecureRequestWarning
_urllib3.disable_warnings = lambda *a, **kw: None
sys.modules.setdefault('urllib3', _urllib3)
sys.modules.setdefault('urllib3.exceptions', _urllib3.exceptions)

# PegaProx-Stubs
for _m in ['pegaprox', 'pegaprox.core', 'pegaprox.core.db',
           'pegaprox.utils', 'pegaprox.utils.auth', 'pegaprox.constants']:
    sys.modules.setdefault(_m, types.ModuleType(_m))
sys.modules['pegaprox.core.db'].get_db = MagicMock()
sys.modules['pegaprox.constants'].PEGAPROX_VERSION = 'test'

from plugins.netapp_storage.core.ontap_client import OntapClient, OntapError


def _mock_response(status_code, body):
    r = MagicMock()
    r.status_code = status_code
    r.ok = status_code < 400
    r.json.return_value = body
    r.text = json.dumps(body)
    r.content = json.dumps(body).encode()
    return r


class TestOntapClientConnection(unittest.TestCase):

    def setUp(self):
        with patch('requests.Session') as mock_sess_cls:
            self.mock_session = MagicMock()
            mock_sess_cls.return_value = self.mock_session
            self.client = OntapClient('ontap.example.com', 'admin', 'secret', ssl_verify=False)

    def test_test_connection_success(self):
        self.mock_session.get.return_value = _mock_response(200, {
            'name': 'prod-cluster', 'version': {'full': 'ONTAP 9.14.1'}
        })
        name, ver = self.client.test_connection()
        self.assertEqual(name, 'prod-cluster')
        self.assertIn('9.14', ver)

    def test_test_connection_auth_failure(self):
        self.mock_session.get.return_value = _mock_response(401, {'message': 'Unauthorized'})
        with self.assertRaises(OntapError) as ctx:
            self.client.test_connection()
        self.assertIn('401', str(ctx.exception))

    def test_test_connection_network_error(self):
        import requests as req
        self.mock_session.get.side_effect = req.ConnectionError('refused')
        with self.assertRaises(OntapError) as ctx:
            self.client.test_connection()
        self.assertIn('network error', str(ctx.exception))


class TestSnapshotOperations(unittest.TestCase):

    def setUp(self):
        with patch('requests.Session'):
            self.client = OntapClient('ontap.example.com', 'admin', 'secret')
        self.client._session = MagicMock()

    def test_list_snapshots(self):
        self.client._session.get.return_value = _mock_response(200, {
            'records': [
                {'uuid': 'aaa', 'name': 'pegaprox-20240101', 'create_time': '2024-01-01T10:00:00Z'},
                {'uuid': 'bbb', 'name': 'pegaprox-20240102', 'create_time': '2024-01-02T10:00:00Z'},
            ]
        })
        result = self.client.list_snapshots('vol-uuid-123')
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['name'], 'pegaprox-20240101')

    def test_create_snapshot_returns_job_uuid(self):
        self.client._session.post.return_value = _mock_response(202, {
            'job': {'uuid': 'job-uuid-xyz'}
        })
        job_uuid = self.client.create_snapshot('vol-uuid-123', 'pegaprox-test', comment='test')
        self.assertEqual(job_uuid, 'job-uuid-xyz')
        call_args = self.client._session.post.call_args
        # kwargs enthält json=...; expliziter key-Zugriff statt or-Fallback (leeres dict ist falsy)
        sent_body = call_args.kwargs.get('json', call_args[1].get('json', {}))
        self.assertEqual(sent_body.get('name'), 'pegaprox-test')

    def test_delete_snapshot(self):
        self.client._session.delete.return_value = _mock_response(202, {
            'job': {'uuid': 'del-job-uuid'}
        })
        job_uuid = self.client.delete_snapshot('vol-uuid-123', 'snap-uuid-abc')
        self.assertEqual(job_uuid, 'del-job-uuid')


class TestJobPolling(unittest.TestCase):

    def setUp(self):
        with patch('requests.Session'):
            self.client = OntapClient('ontap.example.com', 'admin', 'secret')
        self.client._session = MagicMock()

    def test_poll_job_success_immediate(self):
        self.client._session.get.return_value = _mock_response(200, {
            'state': 'success', 'uuid': 'job-1'
        })
        result = self.client.poll_job('job-1', interval_s=0, timeout_s=10)
        self.assertEqual(result['state'], 'success')

    def test_poll_job_failure_raises(self):
        self.client._session.get.return_value = _mock_response(200, {
            'state': 'failure', 'message': 'disk full'
        })
        with self.assertRaises(OntapError) as ctx:
            self.client.poll_job('job-1', interval_s=0, timeout_s=10)
        self.assertIn('disk full', str(ctx.exception))

    def test_poll_job_timeout(self):
        self.client._session.get.return_value = _mock_response(200, {'state': 'running'})
        with self.assertRaises(OntapError) as ctx:
            self.client.poll_job('job-1', interval_s=0, timeout_s=0)
        self.assertIn('Timeout', str(ctx.exception))

    def test_poll_job_retries_until_done(self):
        responses = [
            _mock_response(200, {'state': 'running'}),
            _mock_response(200, {'state': 'running'}),
            _mock_response(200, {'state': 'success'}),
        ]
        self.client._session.get.side_effect = responses
        with patch('time.sleep'):
            result = self.client.poll_job('job-1', interval_s=0, timeout_s=60)
        self.assertEqual(result['state'], 'success')
        self.assertEqual(self.client._session.get.call_count, 3)


class TestRestoreFile(unittest.TestCase):

    def setUp(self):
        with patch('requests.Session'):
            self.client = OntapClient('ontap.example.com', 'admin', 'secret')
        self.client._session = MagicMock()

    def test_restore_file_sends_correct_body(self):
        self.client._session.post.return_value = _mock_response(200, {'message': 'success'})
        self.client.restore_file(
            svm_name='svm-prod',
            volume_name='vol_vmstore',
            snap_name='pegaprox-20240101',
            file_path='images/100/vm-100-disk-0.qcow2',
            restore_path='images/100/vm-100-disk-0.qcow2',
        )
        body = self.client._session.post.call_args.kwargs.get('json') or {}
        self.assertEqual(body['vserver'], 'svm-prod')
        self.assertEqual(body['volume'], 'vol_vmstore')
        self.assertEqual(body['snapshot'], 'pegaprox-20240101')
        self.assertTrue(body['path'].startswith('/'))
        self.assertTrue(body['restore-path'].startswith('/'))

    def test_restore_file_strips_leading_slash(self):
        self.client._session.post.return_value = _mock_response(200, {})
        self.client.restore_file('svm', 'vol', 'snap', '//double/slash', 'dst')
        body = self.client._session.post.call_args.kwargs.get('json') or {}
        self.assertEqual(body['path'], '/double/slash')


class TestFlexClone(unittest.TestCase):

    def setUp(self):
        with patch('requests.Session'):
            self.client = OntapClient('ontap.example.com', 'admin', 'secret')
        self.client._session = MagicMock()

    def test_create_flexclone(self):
        self.client._session.post.return_value = _mock_response(202, {
            'uuid': 'clone-vol-uuid',
            'job': {'uuid': 'clone-job-uuid'}
        })
        vol_uuid, job_uuid = self.client.create_flexclone(
            'parent-vol-uuid', 'my-snap', 'my-clone', 'svm-prod', '/my-clone'
        )
        self.assertEqual(vol_uuid, 'clone-vol-uuid')
        self.assertEqual(job_uuid, 'clone-job-uuid')
        body = self.client._session.post.call_args.kwargs.get('json') or {}
        self.assertTrue(body['clone']['is_flexclone'])
        self.assertEqual(body['clone']['parent_volume']['uuid'], 'parent-vol-uuid')
        self.assertEqual(body['clone']['parent_snapshot']['name'], 'my-snap')
        self.assertEqual(body['nas']['path'], '/my-clone')


if __name__ == '__main__':
    unittest.main()
