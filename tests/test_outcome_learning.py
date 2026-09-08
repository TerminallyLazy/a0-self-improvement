"""Outcome learning acceptance without providers, credentials, or runtime mutation."""
import asyncio
from contextlib import nullcontext
import importlib
import json
import sqlite3
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from usr.plugins.dspy_rlm.helpers import autopilot, config, dspy_runtime, evidence, learning_insights, objective, paths, trace
from usr.plugins.dspy_rlm.helpers.outcomes import outcome_counts
from usr.plugins.dspy_rlm.helpers.rlm import EvidenceIndex, RlmQuery


class OutcomeLearningTests(unittest.TestCase):
    def event(self, success=None, *, message='one', tool='code_execution_tool', event_type='tool', stamp=None, occurrence='one'):
        return evidence.sanitize_event({'context_id':'chat','event_type':event_type,'tool':tool,
            'success':success,'outcome_source':'structured_tool_result' if type(success) is bool else 'unknown',
            'objective':f'message_ref:{message}','loop_iteration':0,'timestamp':stamp or time.time(),
            'occurrence_ref':occurrence})

    def test_unknown_survives_projection_without_fabricating_failure(self):
        for value in (None, 'false', 0, 1, {}, []):
            with self.subTest(value=value):
                row=self.event(value)
                self.assertIsNone(row['success'])
                self.assertEqual(row['error_class'],'unknown')
                self.assertIsNone(EvidenceIndex([row]).events_for()[0]['success'])

    def test_rates_exclude_unknown_denominator(self):
        events=[self.event(True),self.event(False),self.event(None)]
        counts=outcome_counts(events)
        self.assertEqual((counts['success_count'],counts['failure_count'],counts['unknown_count']),(1,1,1))
        self.assertEqual(counts['success_rate'],0.5)
        self.assertEqual(counts['known_outcome_count'],2)
        sample=evidence.objective_sample('chat',events)
        self.assertEqual(sample['unknown_count'],1)
        self.assertEqual(sample['success_rate'],0.5)

    def test_all_queries_keep_unknowns_out_of_failures(self):
        index=EvidenceIndex([self.event(True),self.event(False),self.event(None)])
        for kind in ('aggregate_metrics','objective_bucket','error_cluster','tool_reliability'):
            with self.subTest(kind=kind):
                query=RlmQuery(kind,{'objective_bucket':'shell'} if kind=='objective_bucket' else {})
                finding=index.query(query,max_evidence_chars=10000)
                self.assertEqual(finding.metrics['failure_count'],1)

    def test_unknown_only_findings_cannot_drive_candidate_generation_or_model_calls(self):
        index=EvidenceIndex([self.event(None)])
        for kind in ('aggregate_metrics','objective_bucket','error_cluster','tool_reliability'):
            query=RlmQuery(kind,{'objective_bucket':'shell'} if kind=='objective_bucket' else {})
            finding=index.query(query,max_evidence_chars=10000)
            self.assertTrue(finding.review_only)
        with patch.object(dspy_runtime,'resolve_dspy_model') as model:
            self.assertEqual(dspy_runtime.analyze_with_dspy_rlm(index,'shell',{'rlm':{'enabled':True}}),())
            model.assert_not_called()

    def test_identical_calls_in_same_second_have_distinct_occurrences(self):
        first=self.event(False,stamp=1000,occurrence='log-one')
        second=self.event(False,stamp=1000,occurrence='log-two')
        self.assertNotEqual(first['event_ref'],second['event_ref'])
        self.assertNotIn('log-one',json.dumps(first))
        self.assertEqual(first['event_ref'],self.event(False,stamp=1000,occurrence='log-one')['event_ref'])

    def test_loop_retention_is_per_message_not_reused_counter(self):
        rows=[self.event(True,message=str(i),stamp=1000+i) for i in range(3)]
        kept=evidence.retain_events(rows,policy=evidence.EvidencePolicy(max_events_per_loop=1),now=1003)
        self.assertEqual(len(kept),3)

    def test_scoped_objectives_do_not_mix_reused_loop_zero(self):
        now=time.time()
        rows=[self.event(False,message='old',stamp=now-3), self.event(None,message='old',event_type='loop',stamp=now-2),
              self.event(True,message='new',tool='search',stamp=now-1), self.event(None,message='new',event_type='loop',stamp=now)]
        with patch.object(objective.trace,'read_context_events',return_value=rows):
            samples=objective.collect_recent_objectives('chat',{})
        self.assertEqual(samples[0]['loop_iteration'],0)
        self.assertEqual((samples[0]['success_events'],samples[0]['failure_events']),(1,0))
        self.assertEqual((samples[1]['success_events'],samples[1]['failure_events']),(0,1))
        self.assertEqual(samples[0]['tool_contract'],['search'])
        self.assertEqual(samples[1]['tool_contract'],['code_execution_tool'])

    def test_same_timestamp_scoped_tools_are_found_after_loop_sort_position(self):
        row=self.event(False)
        loop=self.event(None,event_type='loop')
        with patch.object(objective.trace,'read_context_events',return_value=[loop,row]):
            sample=objective.collect_recent_objectives('chat',{})[0]
        self.assertEqual(sample['failure_events'],1)

    def test_unscoped_legacy_fallback_stays_within_its_chronological_loop(self):
        rows=[self.event(False,message='old'),self.event(None,message='old',event_type='loop'),
              self.event(True,message='new',tool='search'),self.event(None,message='new',event_type='loop')]
        for row in rows:
            if row['event_type']=='tool': row.pop('objective_ref',None)
        with patch.object(objective.trace,'read_context_events',return_value=rows):
            samples=objective.collect_recent_objectives('chat',{})
        self.assertEqual(samples[0]['failure_events'],0)
        self.assertEqual(samples[1]['failure_events'],1)

    def test_failure_target_wins_over_latest_success(self):
        rows=[{'objective_bucket':'reasoning','success_events':5,'objective_signature':'latest'},
              {'objective_bucket':'shell','failure_events':2,'objective_signature':'failure'}]
        target=learning_insights.select_learning_target(rows)
        self.assertEqual(target,{'bucket':'shell','signature':'failure','reason':'observed_failures'})

    def test_opportunities_are_content_free_and_older_labels_are_unverified(self):
        old=self.event(True);old.pop('outcome_source')
        malicious={'event_type':'tool','redacted':True,'outcome_source':{'secret':'private'}}
        insights=learning_insights.summarize_opportunities([self.event(False),self.event(False),self.event(None),old,malicious])
        self.assertEqual(insights['opportunities'][0]['state'],'recurring_failures')
        self.assertEqual(insights['totals']['failure_count'],2)
        self.assertEqual(insights['totals']['unknown_count'],1)
        self.assertEqual(insights['unverified_older_events'],2)
        self.assertNotIn('private',json.dumps(insights))
        self.assertNotIn('code_execution_tool',json.dumps(insights))

    def test_live_hook_preserves_explicit_failures_and_missing_signals(self):
        module=importlib.import_module('usr.plugins.dspy_rlm.extensions.python.tool_execute_after._40_dspy_rlm_trace')
        cfg=config.normalize_config({'enabled':True,'automation':{'mode':'review'}})
        for value in (False,True,None,'false'):
            for persistent in ({},None):
                with self.subTest(value=value,persistent=persistent):
                    response=module.Response(message='private output',break_loop=False,additional={'success':value})
                    agent=SimpleNamespace(context=SimpleNamespace(id='chat',get_data=lambda *a,**k:False),
                        loop_data=SimpleNamespace(iteration=0,params_persistent=persistent,current_tool=SimpleNamespace(name='code_execution_tool',log=SimpleNamespace(id='log-id')),user_message=SimpleNamespace(id='message-id')))
                    extension=object.__new__(module.DspyRlmToolTrace);extension.agent=agent
                    with patch.object(module.config_module,'load_config',return_value=cfg),patch.object(module,'open_runtime_repository',return_value=nullcontext(object())),patch.object(module,'record_runtime_observation'),patch.object(autopilot.trace,'append_event',side_effect=lambda event,**kw:evidence.sanitize_event(event)) as capture:
                        asyncio.run(extension.execute(response=response))
                    captured=capture.call_args.args[0]
                    self.assertIs(captured['success'],value if type(value) is bool else None)
                    self.assertNotIn('private output',json.dumps(captured))
                    self.assertEqual(captured['objective'],'message_ref:message-id')

    def test_readonly_insights_are_context_scoped_and_bounded(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(paths,'STORE_FILE',Path(folder)/'store.sqlite'):
            self.assertEqual(learning_insights.read_learning_insights('chat',{})['state'],'empty')
            self.assertFalse(paths.STORE_FILE.exists())
            with sqlite3.connect(paths.STORE_FILE) as db:
                db.execute('CREATE TABLE evidence_events(event_id TEXT,context_id TEXT,event_type TEXT,event_json TEXT,created_at REAL)')
                now=time.time()
                db.executemany('INSERT INTO evidence_events VALUES (?,?,?,?,?)',[
                    (str(i),'chat','tool',json.dumps(self.event(False)),now) for i in range(2005)])
                db.execute('INSERT INTO evidence_events VALUES (?,?,?,?,?)',('other','other','tool',json.dumps(self.event(True)),now))
            before=paths.STORE_FILE.read_bytes()
            result=learning_insights.read_learning_insights('chat',{})
            self.assertEqual(result['totals']['failure_count'],2000)
            self.assertEqual(result['totals']['success_count'],0)
            self.assertEqual(before,paths.STORE_FILE.read_bytes())


if __name__=='__main__': unittest.main()
