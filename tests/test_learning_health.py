"""Learning diagnostics and spend controls in the framework runtime, without model calls."""
import asyncio
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from usr.plugins.dspy_rlm.helpers import autopilot, config, learning_health, paths
from usr.plugins.dspy_rlm.helpers.engines import EngineBudget, GepaEngine
from usr.plugins.dspy_rlm.helpers.engines import prompt_gepa
from usr.plugins.dspy_rlm.tests.test_gepa_engine import _actionable_finding, _fake_dspy


class LearningHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / 'learning.sqlite'
        self.scope = patch.object(paths, 'STORE_FILE', self.db)
        self.scope.start()
        self.addCleanup(self.scope.stop)

    def create_db(self):
        with sqlite3.connect(self.db) as db:
            db.executescript('''CREATE TABLE jobs(job_key TEXT, context_id TEXT, status TEXT, result_json TEXT, updated_at REAL);
            CREATE TABLE evidence_events(context_id TEXT,event_type TEXT,created_at REAL);
            CREATE TABLE runtime_context_state(context_id TEXT,state_json TEXT);''')

    def test_missing_store_does_not_create_files(self):
        self.assertEqual(learning_health.read_learning_health('chat')['state'], 'empty')
        self.assertEqual(learning_health.read_progress_inputs('chat', {}), (0, {}))
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_corrupt_store_unavailable_and_untouched(self):
        self.db.write_bytes(b'not a database')
        self.assertEqual(learning_health.read_learning_health('chat')['state'], 'unavailable')
        self.assertEqual(autopilot.optimization_progress('chat', {}, readonly=True).state, 'unavailable')
        self.assertEqual(self.db.read_bytes(), b'not a database')

    def test_window_scope_outcomes_and_private_reason_redaction(self):
        self.create_db()
        with sqlite3.connect(self.db) as db:
            for n in range(25):
                db.execute('INSERT INTO jobs VALUES (?,?,?,?,?)', (str(n), 'chat', 'succeeded', json.dumps({'status':'skipped','reason':'optimization already running','private':'secret'}), n))
            db.execute('INSERT INTO jobs VALUES (?,?,?,?,?)', ('26','other','failed','{}',26))
            db.execute('INSERT INTO jobs VALUES (?,?,?,?,?)', ('27','chat','succeeded',json.dumps({'status':'candidate','candidate_id':'candidate','reason':'private prompt'}),27))
        before = self.db.read_bytes()
        health = learning_health.read_learning_health('chat')
        self.assertEqual(health['recorded_jobs'], 20)
        self.assertEqual(health['outcomes'], {'candidate':1, 'skipped':19})
        self.assertEqual(health['last_reason'], 'details_unavailable')
        self.assertNotIn('secret', json.dumps(health))
        self.assertNotIn('private prompt', json.dumps(health))
        self.assertEqual(before, self.db.read_bytes())

    def test_semantic_job_states_do_not_invent_success(self):
        for status, result, expected in [
            ('succeeded', {'status':'skipped'}, 'skipped'),
            ('succeeded', {'status':'failed'}, 'failed'),
            ('succeeded', {'status':'candidate_rejected'}, 'rejected'),
            ('succeeded', {'status':'candidate'}, 'completed_without_candidate'),
            ('failed', {'status':'candidate','candidate_id':'x'}, 'failed'),
            ('succeeded', {}, 'completed_without_candidate'),
        ]:
            with self.subTest(result=result):
                self.assertEqual(learning_health.job_outcome(status,json.dumps(result))[0],expected)

    def test_readonly_progress_filters_expired_and_other_chat_events(self):
        self.create_db()
        now = datetime(2030,1,1,tzinfo=timezone.utc)
        with sqlite3.connect(self.db) as db:
            db.executemany('INSERT INTO evidence_events VALUES (?,?,?)', [
                ('chat','loop',now.timestamp()), ('chat','loop',now.timestamp()-1000),
                ('other','loop',now.timestamp()), ('chat','tool',now.timestamp())])
            db.execute('INSERT INTO runtime_context_state VALUES (?,?)',('chat','{}'))
        before = self.db.read_bytes()
        cfg = {'trace_capture':{'event_ttl_seconds':60},'optimization':{'auto_optimize_interval_messages':2}}
        with patch.object(autopilot.trace,'summarize_context',side_effect=AssertionError('must not open writer')):
            progress = autopilot.optimization_progress('chat',cfg,now=now,readonly=True)
        self.assertEqual(progress.completed_loops,1)
        self.assertEqual(before,self.db.read_bytes())

    def test_failed_dispatch_preserves_interval_success_consumes_it(self):
        progress = autopilot.OptimizationProgress('ready',12,12,12,0,0)
        for dispatched in (False,True):
            with self.subTest(dispatched=dispatched), patch.object(autopilot,'optimization_progress',return_value=progress), patch.object(autopilot,'schedule_optimization_job',return_value={'dispatched':dispatched}), patch.object(autopilot.state,'_store_for_root') as store:
                autopilot._maybe_schedule_context('chat',{})
                self.assertEqual(store.called,dispatched)
                if dispatched:
                    self.assertEqual(store.return_value.set_context_state.call_args.args[1]['autopilot_last_trigger_loop_count'],12)

    def test_status_respects_framework_toggle_without_mutating_saved_config(self):
        import helpers
        from usr.plugins.dspy_rlm.api import autopilot_status
        saved = config.normalize_config({'enabled': True})
        context = SimpleNamespace(id='chat', agent0=object(), get_data=lambda key: None)
        for enabled in (False, True):
            plugins = SimpleNamespace(get_enabled_plugins=lambda agent: ['dspy_rlm'] if enabled else [])
            with patch.object(helpers, 'plugins', plugins, create=True), patch.object(autopilot_status.AgentContext, 'get', return_value=context), patch.object(autopilot_status.config_module, 'load_config', return_value=saved), patch.object(autopilot_status, 'project_autopilot_status', side_effect=lambda **kwargs: kwargs['config']):
                handler = object.__new__(autopilot_status.AutopilotStatus)
                result = asyncio.run(handler.process({'context_id':'chat'}, None))
            self.assertEqual(result['enabled'], enabled)
            self.assertTrue(saved['enabled'])

    def test_next_action_prioritizes_disabled_and_evidence(self):
        args = dict(enabled=False,mode='autopilot',generation=[],promotion=[])
        self.assertEqual(learning_health.next_action({},**args),'enable_plugin')
        args.update(enabled=True,mode='review')
        self.assertEqual(learning_health.next_action({'last_reason':'no_actionable_rlm_findings'},**args),'collect_evidence')

    def test_budget_is_normalized_and_limits_growth(self):
        self.assertEqual(config.normalize_config({})['optimization']['max_metric_calls'],24)
        self.assertEqual(config.normalize_config({'optimization':{'max_metric_calls':9999}})['optimization']['max_metric_calls'],1000)
        for invalid in (True,0,1001,'24'):
            with self.assertRaises(ValueError): EngineBudget(max_metric_calls=invalid)
        records = {}
        result = GepaEngine(dspy_api=_fake_dspy(records)).compile(context_id='chat',objective_bucket='support',findings=tuple(_actionable_finding(finding_id=f'f-{i}') for i in range(32)),model_config_ref='test',budget=EngineBudget(max_metric_calls=7))
        self.assertTrue(result.succeeded)
        self.assertEqual(records['gepa_kwargs']['max_metric_calls'],7)

    def prompt_compile(self, *, cost=None, unchanged=False):
        records={}
        class Compiled:
            signature=SimpleNamespace(instructions='source' if unchanged else 'Improved instructions')
            cost_usd=cost
            def __call__(self,**kwargs): return SimpleNamespace(response='expected response')
        class Compiler:
            def __init__(self,**kwargs): records.update(kwargs)
            def compile(self,**kwargs):
                example=kwargs['trainset'][0]
                score=records['metric'](example,SimpleNamespace(response='expected response'),None,'predict',None)
                self_test.assertEqual(score.score,1.0)
                return Compiled()
        self_test=self
        fake=_fake_dspy({})
        fake.GEPA=Compiler
        fake.Signature=lambda text,**kwargs: SimpleNamespace(**kwargs)
        with patch.dict(sys.modules,{'dspy':fake}),patch.object(prompt_gepa,'build_dspy_lm',return_value=object()):
            result=prompt_gepa.PromptGepaEngine().compile(context_id='chat',snapshot={'snapshot_id':'snapshot','base_digest':'sha256:'+'a'*64,'components':[{'component_id':'segment:0','source_digest':'sha256:'+'b'*64,'body':'source'}]},objective_rows=[{'objective_content_approved':True,'user_intent':'intent','latest_response':'expected response'}]*3,model_config_ref='test',target_mode='selected_components',activation_mode='manual',selected_components=['segment:0'],budget=EngineBudget(max_metric_calls=5))
        return result,records

    def test_prompt_engine_accepts_real_five_argument_metric_and_budget(self):
        (artifact,result),records=self.prompt_compile()
        self.assertEqual(result['status'],'succeeded')
        self.assertIsNotNone(artifact)
        self.assertEqual(records['max_metric_calls'],5)

    def test_prompt_engine_checks_reported_cost_even_without_changed_instructions(self):
        (artifact,result),_=self.prompt_compile(cost=1,unchanged=True)
        self.assertIsNone(artifact)
        self.assertEqual(result['error'],'compile_cost_budget_exceeded')


if __name__ == '__main__':
    unittest.main()
