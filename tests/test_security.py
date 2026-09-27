import asyncio
import hashlib
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from iterm2_harness.common import APIError, boolean, integer, strict_json
from iterm2_harness.security import (DEFAULT_CONFIG, LEGACY_SCOPES, SCOPES, TokenStore,
                                     authorize, grant_request, load_config, token_hash)
from iterm2_harness.filesystem import Files, MAX_FILE
from iterm2_harness.protocol import check_origin, read_body, read_head


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.addCleanup(self.temp.cleanup)

    def test_safe_defaults(self):
        self.assertEqual(DEFAULT_CONFIG['host'], '127.0.0.1')
        self.assertFalse(DEFAULT_CONFIG['file_access']['enabled'])

    def test_boolean_string_is_not_false(self):
        with self.assertRaises(APIError):
            boolean('false', 'enter')
        self.assertFalse(boolean(False, 'enter'))

    def test_invalid_integer_types(self):
        for value in (True, 1.5, '-1', '1_0', '+1', None):
            with self.subTest(value=value), self.assertRaises(APIError):
                integer(value, 'value', 0, 100)

    def test_strict_json(self):
        for raw in (b'[]', b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e9999}', '{}'.encode('utf-16'), b'\xff'):
            with self.subTest(raw=raw), self.assertRaises(APIError):
                strict_json(raw)

    def test_remote_bind_requires_explicit_opt_in(self):
        (self.root/'config.json').write_text(json.dumps({'host':'0.0.0.0'}))
        with self.assertRaises(APIError) as ctx:
            load_config(self.root, {'ITERM2_HARNESS_HOME':str(self.root/'state')})
        self.assertEqual(ctx.exception.code, 'remote_not_enabled')

    def test_invalid_config_does_not_fall_back(self):
        (self.root/'config.json').write_text('{bad')
        with self.assertRaises(APIError):
            load_config(self.root, {'ITERM2_HARNESS_HOME':str(self.root/'state')})

    def test_legacy_migration_cannot_accept_hash_as_bearer(self):
        path = self.root/'tokens.json'
        path.write_text(json.dumps({'old-secret':{'device_name':'old'}}))
        store = TokenStore(path)
        self.assertIsNotNone(store.lookup('old-secret'))
        self.assertIsNone(store.lookup(token_hash('old-secret')))
        self.assertNotIn('old-secret', path.read_text())
        self.assertEqual(set(store.lookup('old-secret')['scopes']), set(LEGACY_SCOPES))
        self.assertNotIn('session.create', store.lookup('old-secret')['scopes'])
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_hashed_v2_record_is_not_usable_as_bearer(self):
        store = TokenStore(self.root/'tokens.json')
        issued = store.issue('agent', ['terminal.read'], ['a'], 60)
        self.assertIsNone(store.lookup(token_hash(issued['token'])))
        self.assertNotIn(issued['token'], (self.root/'tokens.json').read_text())

    def test_token_expiry_and_revocation(self):
        store = TokenStore(self.root/'tokens.json')
        issued = store.issue('agent', ['terminal.read'], ['a'], 60)
        self.assertIsNone(store.lookup(issued['token'], issued['expires_at']))
        self.assertTrue(store.revoke(issued['token_id']))
        self.assertIsNone(store.lookup(issued['token']))

    def test_scope_and_session_are_independent_checks(self):
        info = {'scopes':['terminal.read'], 'session_ids':['a']}
        authorize(info, 'terminal.read', 'a')
        with self.assertRaises(APIError): authorize(info, 'terminal.write', 'a')
        with self.assertRaises(APIError): authorize(info, 'terminal.read', 'b')

    def test_grant_validation(self):
        for body in ({'scopes':['root']}, {'scopes':'terminal.read'}, {'session_ids':[]},
                     {'session_ids':['active']}, {'device_name':'name\nAllow everything'}):
            with self.subTest(body=body), self.assertRaises(APIError): grant_request(body)

    def test_browser_origin_and_rebinding_host_denied(self):
        for headers in ({'origin':'http://evil.test','host':'localhost'}, {'host':'evil.test'},
                        {'host':'localhost@evil.test'}):
            with self.subTest(headers=headers), self.assertRaises(APIError):
                check_origin(headers, DEFAULT_CONFIG)
        check_origin({'host':'127.0.0.1:6770'}, DEFAULT_CONFIG)


class FilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.allowed = self.root/'project'
        self.allowed.mkdir()
        self.files = Files({'enabled':True, 'allowed_paths':[str(self.allowed)]})

    def test_prefix_sibling_denied(self):
        with self.assertRaises(APIError): self.files.path(str(self.root/'project-secret'/'x'))

    def test_empty_allowlist_denies(self):
        with self.assertRaises(APIError): Files({'enabled':True,'allowed_paths':[]}).path(str(self.allowed/'x'))

    def test_relative_path_denied(self):
        with self.assertRaises(APIError): self.files.path('project/x')

    def test_symlink_parent_cannot_escape(self):
        outside = self.root/'outside'
        outside.mkdir()
        (outside/'secret').write_text('do not read')
        (self.allowed/'escape').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(APIError): self.files.read({'path':str(self.allowed/'escape'/'secret')})
        with self.assertRaises(APIError): self.files.write({'path':str(self.allowed/'escape'/'secret')}, {'content':'bad'})
        self.assertEqual((outside/'secret').read_text(), 'do not read')

    def test_symlink_leaf_denied(self):
        target = self.root/'secret'
        target.write_text('secret')
        (self.allowed/'link').symlink_to(target)
        with self.assertRaises(APIError): self.files.read({'path':str(self.allowed/'link')})
        with self.assertRaises(APIError): self.files.delete({'path':str(self.allowed/'link')})

    def test_fifo_is_rejected_without_blocking(self):
        fifo = self.allowed/'fifo'
        os.mkfifo(fifo)
        start = time.monotonic()
        with self.assertRaises(APIError): self.files.read({'path':str(fifo)})
        self.assertLess(time.monotonic()-start, 1)

    def test_invalid_write_preserves_existing_file(self):
        target = self.allowed/'x'
        target.write_text('original')
        with self.assertRaises(APIError): self.files.write({'path':str(target)}, {'content':{'oops':1}})
        self.assertEqual(target.read_text(), 'original')

    def test_atomic_write_and_bounded_tail(self):
        target = self.allowed/'new'/'x'
        self.files.write({'path':str(target)}, {'content':'a\nb\nc\n', 'mkdir':True})
        self.assertEqual(self.files.read({'path':str(target),'tail':'2'})['content'], 'b\nc\n')
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)

    def test_read_bound_and_regex_rejection(self):
        target = self.allowed/'large'
        with target.open('wb') as stream: stream.truncate(MAX_FILE+1)
        with self.assertRaises(APIError): self.files.read({'path':str(target)})
        target.write_text('a'*30+'!')
        with self.assertRaises(APIError): self.files.read({'path':str(target), 'grep_regex':'true', 'grep':'(a+)+$'})

    def test_hardlinked_overwrite_denied(self):
        target = self.allowed/'x'
        target.write_text('original')
        os.link(target, self.root/'other')
        with self.assertRaises(APIError): self.files.write({'path':str(target)}, {'content':'bad'})
        self.assertEqual(target.read_text(), 'original')

    def test_protected_paths_are_hidden(self):
        protected = self.allowed/'state'
        protected.mkdir()
        (protected/'tokens.json').write_text('secret')
        self.files.protected = [str(protected)]
        with self.assertRaises(APIError): self.files.read({'path':str(protected/'tokens.json')})
        self.assertEqual(self.files.list({'path':str(self.allowed), 'recursive':'true'})['entries'], [])

    def test_mkdir_does_not_create_ancestors_above_root(self):
        root = self.root/'missing-parent'/'grant'
        files = Files({'enabled':True,'allowed_paths':[str(root)]})
        with self.assertRaises(APIError): files.write({'path':str(root/'x')},{'content':'x','mkdir':True})
        self.assertFalse((self.root/'missing-parent').exists())


class HTTPParserTests(unittest.IsolatedAsyncioTestCase):
    async def head(self, raw):
        reader = asyncio.StreamReader(limit=8194)
        reader.feed_data(raw)
        reader.feed_eof()
        return await read_head(reader)

    async def test_valid_request(self):
        result = await self.head(b'GET /api/v2/sessions HTTP/1.1\r\nHost: localhost\r\n\r\n')
        self.assertEqual(result[:2], ('GET','/api/v2/sessions'))

    async def test_bad_framing_cases(self):
        cases = [
            b'GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n',
            b'GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: -1\r\n\r\n',
            b'GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1_0\r\n\r\n',
            b'GET / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n',
            b'GET / HTTP/1.1\r\nHost: localhost',
            b'GET / HTTP/1.1\r\n Host: localhost\r\n\r\n',
            b'GET / HTTP/1.1\r\nHost : localhost\r\n\r\n',
            b'GET http://localhost/ HTTP/1.1\r\nHost: localhost\r\n\r\n',
            b'GET /?x=1&x=2 HTTP/1.1\r\nHost: localhost\r\n\r\n',
            b'GET /?token=secret HTTP/1.1\r\nHost: localhost\r\n\r\n',
            b'GET /%xx HTTP/1.1\r\nHost: localhost\r\n\r\n',
            b'GET / HTTP/1.1\r\n\r\n',
        ]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(APIError): await self.head(raw)

    async def test_request_line_and_body_budgets(self):
        with self.assertRaises(APIError) as ctx:
            await self.head(b'GET /'+b'x'*9000+b' HTTP/1.1\r\nHost: localhost\r\n\r\n')
        self.assertEqual(ctx.exception.status, 414)
        with self.assertRaises(APIError) as ctx:
            await self.head(b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 33554433\r\n\r\n')
        self.assertEqual(ctx.exception.status, 413)

    async def test_incomplete_json_body(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b'{')
        reader.feed_eof()
        with self.assertRaises(APIError) as ctx:
            await read_body(reader, {'content-type':'application/json'}, 2)
        self.assertEqual(ctx.exception.status, 400)
