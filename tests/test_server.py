import asyncio
import json
import secrets
import tempfile
import unittest
from pathlib import Path

from iterm2_harness.common import APIError
from iterm2_harness.iterm import Adapter
from iterm2_harness.security import DEFAULT_CONFIG, SCOPES
from iterm2_harness.server import Server
from iterm2_harness.state import EventLog, Observations
from fakes import App, sdk_for

ROOT = Path(__file__).resolve().parents[1]


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.app = App()
        self.events = EventLog(epoch='testepoch')
        self.observations = Observations(self.events)
        self.adapter = Adapter(None, self.events, self.observations, sdk_for(self.app))
        await self.adapter.start()
        self.consents = []
        async def consent(message, timeout):
            self.consents.append(message)
            return True
        config = dict(DEFAULT_CONFIG, home=self.root/'home', protect_focused_session=True)
        self.service = Server(config, self.adapter, self.events, self.observations, consent, ROOT)
        self.issued = self.service.tokens.issue('test', sorted(SCOPES), None, 3600)
        self.token = self.issued['token']
        self.listener = await asyncio.start_server(self.service.handle_client, '127.0.0.1', 0, limit=8194)
        self.port = self.listener.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.listener.close()
        await self.listener.wait_closed()
        self.service.stop.set()
        await self.service.close_clients()
        await self.adapter.close()
        self.temp.cleanup()

    async def connection(self, method, suffix, body=None, token='DEFAULT', key=None, version=2, extra=None):
        token = self.token if token == 'DEFAULT' else token
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        raw = json.dumps(body).encode() if body is not None else b''
        headers = {'Host':'127.0.0.1', 'Content-Length':str(len(raw)), 'Content-Type':'application/json'}
        if token: headers['Authorization'] = 'Bearer '+token
        if method != 'GET' and version == 2:
            headers['Idempotency-Key'] = key or secrets.token_hex(8)
            headers['X-Harness-Epoch'] = self.events.epoch
        headers.update(extra or {})
        request = ('%s /api/v%d%s HTTP/1.1\r\n' % (method, version, suffix)
                   + ''.join('%s: %s\r\n' % pair for pair in headers.items()) + '\r\n').encode()+raw
        writer.write(request)
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 2)
        status = int(head.split(b' ')[1])
        return status, head, reader, writer

    async def request(self, method, suffix, body=None, **kw):
        status, head, reader, writer = await self.connection(method,suffix,body,**kw)
        result = await asyncio.wait_for(reader.read(), 3)
        writer.close()
        await writer.wait_closed()
        return status, json.loads(result)

    async def input_body(self, value='hello'):
        status, lease = await self.request('POST','/sessions/a/lease',{})
        self.assertEqual(status,200)
        metadata = await self.adapter.metadata('a')
        return {'text':value,'enter':True,'lease_id':lease['lease_id'],'expected_context':metadata['context_id']}

    async def test_auth_before_body_and_no_unauthorized_device_call(self):
        status, data = await self.request('POST','/sessions/a/send-text', {'text':'bad'},token=None)
        self.assertEqual(status,401)
        self.assertEqual(self.adapter.session('a').writes,[])

    async def test_scoped_inventory_and_snapshot(self):
        token = self.service.tokens.issue('reader',['terminal.read'],['a'],3600)['token']
        for suffix in ('/sessions','/snapshot'):
            status, data = await self.request('GET',suffix,token=token)
            self.assertEqual(status,200)
            self.assertEqual([x['session_id'] for x in data['sessions']],['a'])
        status,_ = await self.request('GET','/sessions/b/screen',token=token)
        self.assertEqual(status,403)

    async def test_read_only_token_cannot_send(self):
        token = self.service.tokens.issue('reader',['terminal.read'],['a'],3600)['token']
        status,_=await self.request('POST','/sessions/a/send-text',{'text':'bad'},token=token)
        self.assertEqual(status,403)
        self.assertFalse(self.adapter.session('a').writes)

    async def test_explicit_id_not_active_proxy(self):
        status,_=await self.request('GET','/sessions/active/screen')
        self.assertEqual(status,400)

    async def test_v1_cannot_bypass_new_mutation_rules(self):
        for suffix in ('/windows','/sessions/a/lease','/sessions/a/activate'):
            status,_=await self.request('POST',suffix,{},version=1)
            self.assertEqual(status,404)

    async def test_split_text_enter_and_broadcast_suppression(self):
        body=await self.input_body()
        status,data=await self.request('POST','/sessions/a/send-text',body)
        self.assertEqual(status,200)
        self.assertEqual(self.adapter.session('a').writes,[('hello',True),('\r',True)])
        self.assertFalse(data['execution_verified'])
        self.assertNotIn('sent',data)

    async def test_same_key_does_not_type_twice(self):
        body=await self.input_body()
        status,first=await self.request('POST','/sessions/a/send-text',body,key='unique')
        status,second=await self.request('POST','/sessions/a/send-text',body,key='unique')
        self.assertEqual(status,200)
        self.assertTrue(second['receipt']['replayed'])
        self.assertEqual(len(self.adapter.session('a').writes),2)
        self.assertEqual(first['receipt']['action_id'],second['receipt']['action_id'])

    async def test_idempotency_payload_conflict(self):
        body=await self.input_body()
        await self.request('POST','/sessions/a/send-text',body,key='unique')
        status,_=await self.request('POST','/sessions/a/send-text',dict(body,text='different'),key='unique')
        self.assertEqual(status,409)
        self.assertEqual(len(self.adapter.session('a').writes),2)

    async def test_unknown_rpc_outcome_is_not_retried(self):
        body=await self.input_body()
        def fail(): raise asyncio.TimeoutError()
        session=self.adapter.session('a')
        session.after_write=fail
        status,data=await self.request('POST','/sessions/a/send-text',body,key='uncertain')
        self.assertEqual(status,503)
        self.assertEqual(data['receipt']['state'],'unknown')
        await self.request('POST','/sessions/a/send-text',body,key='uncertain')
        self.assertEqual(len(session.writes),1)

    async def test_revocation_between_text_and_enter(self):
        body=await self.input_body()
        session=self.adapter.session('a')
        session.after_write=lambda:self.service.tokens.revoke(self.issued['token_id'])
        status,data=await self.request('POST','/sessions/a/send-text',body)
        self.assertEqual(status,409)
        self.assertEqual(data['error'],'partial_input')
        self.assertEqual(session.writes,[('hello',True)])

    async def test_context_change_after_local_approval_blocks_input(self):
        body=await self.input_body()
        self.app.current_window=self.app.windows[0]
        async def consent(message,timeout):
            self.adapter.session('a').variables['hostname']='different-host'
            return True
        self.service.consent=consent
        status,data=await self.request('POST','/sessions/a/send-text',body)
        self.assertEqual(status,409)
        self.assertEqual(data['error'],'context_changed')
        self.assertEqual(self.adapter.session('a').writes,[])

    async def test_focus_change_between_writes_withholds_enter(self):
        body=await self.input_body()
        session=self.adapter.session('a')
        session.after_write=lambda:setattr(self.app,'current_window',self.app.windows[0])
        status,data=await self.request('POST','/sessions/a/send-text',body)
        self.assertEqual(status,409)
        self.assertEqual(data['error'],'partial_input')
        self.assertEqual(session.writes,[('hello',True)])

    async def test_local_denial_blocks_create(self):
        async def deny(message,timeout): return False
        self.service.consent=deny
        status,data=await self.request('POST','/windows/w/tabs',{})
        self.assertEqual(status,403)
        self.assertEqual(self.app.windows[0].created_tabs,0)

    async def test_creation_requires_global_target_grant(self):
        token=self.service.tokens.issue('scoped',['session.create'],['a'],3600)['token']
        status,_=await self.request('POST','/sessions/a/split',{},token=token)
        self.assertEqual(status,403)
        self.assertNotIn('new-split',self.adapter.all_sessions())

    async def test_explicit_profile_requires_allowlist(self):
        status,_=await self.request('POST','/windows',{'profile':'dangerous'})
        self.assertEqual(status,403)

    async def test_stale_epoch_denied_before_input(self):
        body=await self.input_body()
        status,_=await self.request('POST','/sessions/a/send-text',body,extra={'X-Harness-Epoch':'old'})
        self.assertEqual(status,409)
        self.assertEqual(self.adapter.session('a').writes,[])

    async def test_second_actor_cannot_use_v1_to_bypass_lease(self):
        await self.input_body()
        other=self.service.tokens.issue('other',['terminal.write'],['a'],3600)['token']
        status,_=await self.request('POST','/sessions/a/send-text',{'text':'bad'},token=other,version=1)
        self.assertEqual(status,409)
        self.assertEqual(self.adapter.session('a').writes,[])

    async def test_nonboolean_enter_rejected(self):
        body=await self.input_body()
        status,_=await self.request('POST','/sessions/a/send-text',dict(body,enter='false'))
        self.assertEqual(status,400)
        self.assertEqual(self.adapter.session('a').writes,[])

    async def test_screen_offset_does_not_expand_rpc_work(self):
        status,data=await self.request('GET','/sessions/a/screen?limit=10&offset=5000')
        self.assertEqual(status,200)
        self.assertEqual(self.adapter.session('a').reads[-1][1],10)
        self.assertEqual(data['first_line'],300+10024-5000-10)

    async def test_unsupported_capabilities_are_not_advertised_as_native(self):
        status,data=await self.request('GET','/capabilities')
        self.assertEqual(status,200)
        for key in ('native_ai_chat','native_workgroups','native_session_status','browser_automation','structured_execution'):
            self.assertFalse(data['features'][key]['implemented'])

    async def test_event_replay_authorization(self):
        token=self.service.tokens.issue('reader',['terminal.read'],['a'],3600)['token']
        cursor=self.events.cursor
        self.events.publish('command.started','b',command='SECRET')
        self.events.publish('command.started','a',command='visible')
        status,head,reader,writer=await self.connection('GET','/events',token=token,extra={'Last-Event-ID':cursor})
        self.assertEqual(status,200)
        frame=await asyncio.wait_for(reader.readuntil(b'\n\n'),1)
        self.assertIn(b'visible',frame)
        self.assertNotIn(b'SECRET',frame)
        writer.close()
        await writer.wait_closed()

    async def test_invalid_event_filter_returns_403_before_stream(self):
        token=self.service.tokens.issue('reader',['terminal.read'],['a'],3600)['token']
        status,_=await self.request('GET','/events?session_id=b',token=token)
        self.assertEqual(status,403)

    async def test_event_reconnect_with_old_epoch_requires_resync(self):
        status,data=await self.request('GET','/events',extra={'Last-Event-ID':'old:0'})
        self.assertEqual(status,409)
        self.assertEqual(data['error'],'resync_required')

    async def test_revoked_stream_is_closed(self):
        token=self.service.tokens.issue('reader',['terminal.read'],['a'],3600)
        status,head,reader,writer=await self.connection('GET','/events',token=token['token'])
        self.assertEqual(status,200)
        self.service.tokens.revoke(token['token_id'])
        self.events.publish('screen.invalidated','a')
        self.assertEqual(await asyncio.wait_for(reader.read(),1),b'')
        writer.close()
        await writer.wait_closed()

    async def test_variable_namespace_does_not_expose_arbitrary_rpc(self):
        status,_=await self.request('PUT','/sessions/a/variables/user.other',{'value':'x'})
        self.assertEqual(status,403)
        status,_=await self.request('PUT','/sessions/a/variables/user.harness.role',{'value':'tester'})
        self.assertEqual(status,200)

    async def test_watchdog_detects_backend_loss(self):
        self.app.fail_probe=True
        with self.assertRaises(APIError): await self.adapter.supervise(asyncio.Event())

    async def test_auth_management_is_not_a_remote_approval_endpoint(self):
        status,_=await self.request('POST','/actions/some-id/approve',{})
        self.assertEqual(status,404)

    async def test_receipts_visible_only_to_actor(self):
        body=await self.input_body()
        _,result=await self.request('POST','/sessions/a/send-text',body)
        other=self.service.tokens.issue('other',['terminal.read'],None,3600)['token']
        status,_=await self.request('GET','/actions/'+result['receipt']['action_id'],token=other)
        self.assertEqual(status,404)

    async def test_openapi_is_unwrapped_and_matches_routes(self):
        from iterm2_harness.routes import openapi
        status, data = await self.request('GET', '/openapi.json')
        self.assertEqual(status, 200)
        self.assertEqual(data, openapi())
        self.assertNotIn('epoch', data)

    async def test_close_requires_local_consent_even_with_scope(self):
        body = await self.input_body()
        async def deny(message, timeout):
            return False
        self.service.consent = deny
        status, _ = await self.request('DELETE', '/sessions/a', body)
        self.assertEqual(status, 403)
        self.assertIsNone(self.adapter.session('a').close_force)

    async def test_close_after_exact_local_consent_avoids_native_modal(self):
        body = await self.input_body()
        status, result = await self.request('DELETE', '/sessions/a', body)
        self.assertEqual(status, 200)
        self.assertTrue(self.adapter.session('a').close_force)
        self.assertTrue(self.consents)
        self.assertFalse(result['process_exit_verified'])

    async def test_repeated_rate_limit_denials_do_not_reset_the_window(self):
        for _ in range(5):
            status, _ = await self.request('POST', '/auth/request', {'scopes':['terminal.read']}, token=None)
            self.assertEqual(status, 201)
        for _ in range(3):
            status, _ = await self.request('POST', '/auth/request', {'scopes':['terminal.read']}, token=None)
            self.assertEqual(status, 429)
