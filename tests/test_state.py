import asyncio
import unittest
from iterm2_harness.common import APIError
from iterm2_harness.state import Actions, EventLog, Observations


class StateTests(unittest.TestCase):
    def test_event_epoch_and_overflow_require_resync(self):
        log = EventLog(capacity=2, epoch='new')
        for _ in range(3): log.publish('event')
        for cursor in ('old:0','new:0','new:4'):
            with self.assertRaises(APIError) as ctx: log.position(cursor)
            self.assertEqual(ctx.exception.code,'resync_required')
        self.assertEqual(log.position('new:1'), 1)

    def test_events_filter_session_secrets(self):
        log = EventLog(epoch='e')
        log.publish('command.started','a',command='public')
        log.publish('command.started','b',command='secret')
        items, position = log.read(0,{'session_ids':['a']})
        self.assertEqual(len(items),1)
        self.assertEqual(items[0]['data']['command'],'public')
        self.assertEqual(position,2)

    def test_orphan_completion_not_invented_success(self):
        obs = Observations(EventLog())
        obs.prompt_event('a','command.finished',0,'p')
        item=obs.history('a')['commands'][0]
        self.assertIsNone(item['command'])
        self.assertFalse(item['start_observed'])
        self.assertEqual(item['outcome'],'unmatched_completion')
        self.assertEqual(obs.status('a')['shell_state'],'unknown')

    def test_matching_native_ids_correlate(self):
        obs=Observations(EventLog())
        obs.prompt_event('a','command.started','pytest','p')
        obs.prompt_event('a','command.finished',1,'p')
        item=obs.history('a')['commands'][0]
        self.assertEqual(item['outcome'],'completed')
        self.assertEqual(item['exit_status'],1)
        self.assertEqual(item['command'],'pytest')

    def test_missing_native_ids_do_not_correlate(self):
        obs=Observations(EventLog())
        obs.prompt_event('a','command.started','dangerous')
        obs.prompt_event('a','command.finished',0)
        self.assertEqual(len(obs.history('a')['commands']),2)
        self.assertIsNone(obs.history('a')['commands'][0]['exit_status'])

    def test_wrong_native_id_cannot_finish_active_command(self):
        obs=Observations(EventLog())
        obs.prompt_event('a','command.started','long-job','p2')
        obs.prompt_event('a','command.finished',0,'p1')
        first=obs.history('a')['commands'][0]
        self.assertEqual(first['outcome'],'running')
        self.assertIsNone(first['exit_status'])

    def test_prompt_without_end_does_not_invent_exit_code(self):
        obs=Observations(EventLog())
        obs.prompt_event('a','command.started','job','p')
        obs.prompt_event('a','prompt.ready',None,'next')
        self.assertEqual(obs.history('a')['commands'][0]['outcome'],'unknown_missing_end')
        self.assertIsNone(obs.history('a')['commands'][0]['exit_status'])

    def test_duplicate_completion_is_deduplicated(self):
        obs=Observations(EventLog())
        obs.prompt_event('a','command.started','job','p')
        obs.prompt_event('a','command.finished',0,'p')
        obs.prompt_event('a','command.finished',0,'p')
        self.assertEqual(len(obs.history('a')['commands']),1)

    def test_monitor_gap_invalidates_running_state(self):
        obs=Observations(EventLog())
        obs.prompt_event('a','command.started','job','p')
        obs.monitor_failed('a','dropped')
        self.assertEqual(obs.status('a')['shell_state'],'unknown')
        self.assertEqual(obs.history('a')['commands'][0]['outcome'],'unknown_monitor_gap')

    def test_history_bound_and_no_claim_of_completeness(self):
        obs=Observations(EventLog(),history_limit=2)
        for i in range(3): obs.prompt_event('a','command.started',str(i),str(i))
        history=obs.history('a')
        self.assertEqual(len(history['commands']),2)
        self.assertEqual(history['evicted'],1)
        self.assertFalse(history['history_complete'])

    def test_report_ttl_and_sequence(self):
        obs=Observations(EventLog())
        body={'state':'idle','provider':'codex','sequence':1,'ttl_seconds':5}
        obs.report_agent('a',body,'actor',now=0)
        with self.assertRaises(APIError): obs.report_agent('a',body,'actor',now=1)
        with self.assertRaises(APIError): obs.report_agent('a',dict(body,sequence=2),'other',now=1)
        self.assertEqual(obs.agent_status('a',now=4)['state'],'idle')
        self.assertEqual(obs.agent_status('a',now=5)['state'],'unknown')
        self.assertTrue(obs.agent_status('a',now=5)['stale'])


class ActionTests(unittest.TestCase):
    def test_receipt_replay_and_payload_conflict(self):
        actions=Actions('epoch')
        first,fresh=actions.begin('actor','key',{'text':'a'},'epoch')
        self.assertTrue(fresh)
        actions.finish(first,200,{'ok':True})
        second,fresh=actions.begin('actor','key',{'text':'a'},'epoch')
        self.assertFalse(fresh)
        self.assertIs(first,second)
        with self.assertRaises(APIError): actions.begin('actor','key',{'text':'b'},'epoch')

    def test_epoch_prevents_replay_after_restart(self):
        with self.assertRaises(APIError): Actions('new').begin('actor','key',{},'old')

    def test_receipt_capacity_does_not_evict(self):
        actions=Actions('epoch',capacity=1)
        first,_=actions.begin('actor','key',{},'epoch')
        with self.assertRaises(APIError): actions.begin('actor','other',{},'epoch')
        self.assertIs(actions.begin('actor','key',{},'epoch')[0],first)

    def test_lease_conflict_expiry_and_owner(self):
        actions=Actions('epoch')
        lease=actions.acquire('a','actor',ttl=10,now=0)
        with self.assertRaises(APIError): actions.acquire('a','other',now=1)
        with self.assertRaises(APIError): actions.check_lease('a','actor',lease['lease_id'],now=10)
        with self.assertRaises(APIError): actions.check_lease('a','other',required=False,now=1)
        new=actions.acquire('a','other',now=11)
        self.assertNotEqual(new['lease_id'],lease['lease_id'])
