"""Bounded pull delivery and source revalidation after slow editor reads.

Synthetic reports below test transport accounting, not detector correctness.
The integration cases reuse the explicit subprocess scanner double.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from test_lsp_pull import PullFixture, lsp


class FiniteSink:
    """Model the real stdio queue without keeping serialized duplicate arrays."""
    def __init__(self):
        self.capacity = 2 * lsp.MAX_MESSAGE
        self.used = 0
        self.messages = []

    def available(self):
        return self.capacity - self.used

    def send(self, message):
        size = len(lsp.frame(message))
        if self.used + size > self.capacity:
            raise AssertionError('Adapter overran the real stdio output limit')
        self.used += size
        self.messages.append(message)

    def consume(self):
        self.used = 0


class PullDeliveryTests(PullFixture):
    def setUp(self):
        super().setUp()
        self.server.timeout = 5

    def block_output(self):
        self.server.output_available = lambda: lsp.DIAGNOSTIC_CONTROL_RESERVE

    def unblock_output(self):
        self.server.output_available = lambda: 2 * lsp.MAX_MESSAGE

    def stage(self, count=2, diagnostics=None):
        """Stage a labeled synthetic report without invoking a detector."""
        self.start()
        self.open()
        for request_id in range(10, 10 + count):
            self.pull(request_id)
        self.server.pending.clear()
        self.server.finish_pulls(self.uri, diagnostics if diagnostics is not None else [lsp.note('ubs.test-only', 'test payload')])

    def test_large_fanout_shares_payload_and_drains_with_backpressure(self):
        diagnostics = [lsp.note('ubs.test-only', 'x' * 8192) for _ in range(400)]
        self.stage(count=8, diagnostics=diagnostics)
        payload_bytes = len(json.dumps(diagnostics, ensure_ascii=True, sort_keys=True))
        self.assertEqual(self.server.pull_reply_bytes, payload_bytes)
        groups = [request['reply_group'] for request in self.server.pulls.values()]
        self.assertTrue(all(group is groups[0] for group in groups))
        self.assertEqual(groups[0]['refs'], 8)
        sink = FiniteSink()
        self.server.send = sink.send
        self.server.output_available = sink.available
        self.server.drain_pulls()
        self.assertGreater(len(sink.messages), 0)
        self.assertLess(len(sink.messages), 8)
        first_count = len(sink.messages)
        self.server.drain_pulls()
        self.assertEqual(len(sink.messages), first_count, 'blocked replies must not overflow or spin-serialize')
        self.assertGreaterEqual(sink.available(), lsp.DIAGNOSTIC_CONTROL_RESERVE)
        while self.server.pulls:
            sink.consume()
            self.server.drain_pulls()
        self.assertEqual(len(sink.messages), 8)
        self.assertEqual({message['id'] for message in sink.messages}, set(range(10, 18)))
        self.assertTrue(all(message['result']['items'] == diagnostics for message in sink.messages))
        self.assertEqual(self.server.pull_reply_bytes, 0)
        self.assertEqual(self.calls(), [])

    def test_cancelled_readers_release_shared_array_only_after_last_reference(self):
        self.stage(count=3)
        retained = self.server.pull_reply_bytes
        self.assertGreater(retained, 0)
        for request_id in (10, 11):
            self.send('$/cancelRequest', {'id': request_id})
            self.assertEqual(self.response(request_id)['error']['code'], -32800)
            self.assertEqual(self.server.pull_reply_bytes, retained)
        self.send('$/cancelRequest', {'id': 12})
        self.assertEqual(self.server.pull_reply_bytes, 0)
        self.assertEqual(self.server.pulls, {})

    def test_control_messages_remain_deliverable_when_results_are_blocked(self):
        diagnostics = [lsp.note('ubs.test-only', 'x' * 8192) for _ in range(400)]
        self.stage(count=8, diagnostics=diagnostics)
        sink = FiniteSink()
        self.server.send = sink.send
        self.server.output_available = sink.available
        self.server.drain_pulls()
        waiting = list(self.server.pulls)
        self.assertTrue(waiting)
        for request_id in waiting:
            self.send('$/cancelRequest', {'id': request_id})
        self.assertEqual(sum(message.get('error', {}).get('code') == -32800 for message in sink.messages), len(waiting))
        self.assertLessEqual(sink.used, sink.capacity)
        self.assertEqual(self.server.pull_reply_bytes, 0)

    def test_aggregate_reply_limit_returns_errors_not_truncated_success(self):
        with patch.object(lsp, 'MAX_DIAGNOSTIC_REPLY_BYTES', 1):
            self.stage(count=2, diagnostics=[])
        self.assertEqual(self.server.pull_reply_bytes, 0)
        self.assertEqual(self.server.pulls, {})
        for request_id in (10, 11):
            reply = self.response(request_id)
            self.assertNotIn('result', reply)
            self.assertEqual(reply['error']['code'], -32802)
            self.assertFalse(reply['error']['data']['retriggerRequest'])

    def test_deferred_replies_still_count_toward_admission_limit(self):
        self.stage(count=2)
        with patch.object(lsp, 'MAX_DIAGNOSTIC_REQUESTS', 2):
            self.pull(12)
        self.assertEqual(len(self.server.pulls), 2)
        self.assertIn('Too many', self.response(12)['error']['message'])

    def test_queued_reply_deadline_and_shutdown_release_all_accounting(self):
        self.block_output()
        self.stage(count=2)
        retained = self.server.pull_reply_bytes
        self.server.pulls[10]['deadline'] = 0
        self.server.tick()
        self.assertIn('timed out', self.response(10)['error']['message'])
        self.assertEqual(self.server.pull_reply_bytes, retained)
        self.send('shutdown', id=99)
        self.assertEqual(self.response(11)['error']['code'], -32802)
        self.assertEqual(self.server.pull_reply_bytes, 0)
        self.assertEqual(self.server.pulls, {})

    def test_edit_cancels_ready_results_before_delivery(self):
        self.block_output()
        self.stage(count=2, diagnostics=[])
        self.send('textDocument/didChange', {'textDocument': {'uri': self.uri, 'version': 2},
                                           'contentChanges': [{'text': 'unsaved new version\n'}]})
        self.unblock_output()
        self.server.drain_pulls()
        for request_id in (10, 11):
            self.assertEqual(self.response(request_id)['error']['code'], -32802)
            self.assertEqual(sum(message.get('id') == request_id for message in self.messages), 1)
        self.assertEqual(self.server.pull_reply_bytes, 0)

    def test_fresh_pull_does_not_cancel_a_completed_reply_waiting_for_delivery(self):
        self.start()
        self.open()
        self.block_output()
        self.pull(10)
        self.until(lambda: 'reply' in self.server.pulls[10])
        self.pull(11)
        self.assertIsNone(self.response(10))
        self.until(lambda: 'reply' in self.server.pulls[11])
        self.assertEqual(len(self.calls()), 2, 'a new pull must get fresh analysis, not the undelivered old reply')
        self.unblock_output()
        self.server.drain_pulls()
        self.assertEqual(self.response(10)['result'], self.response(11)['result'])
        self.assertEqual(self.server.pull_reply_bytes, 0)

    def test_disk_change_while_editor_is_stalled_rejects_deferred_clean_result(self):
        self.start()
        self.open()
        self.block_output()
        self.pull(10)
        self.until(lambda: 'reply' in self.server.pulls[10])
        self.source.write_text('BUG\n')
        self.unblock_output()
        self.server.drain_pulls()
        self.assertEqual(self.response(10)['error']['code'], -32802)
        self.assertIn('before delivery', self.response(10)['error']['message'])
        self.assertNotIn('result', self.response(10))
        self.assertEqual(self.server.pull_reply_bytes, 0)

    def test_group_guard_checks_all_sources_before_delivering_first_member(self):
        self.start()
        self.open()
        other = self.root / 'b.py'
        other.write_text('clean\n')
        self.open(uri=other.as_uri(), text='clean\n')
        self.send('workspace/executeCommand', {'command': 'ubs.scanOpenDocuments'}, id=9)
        self.block_output()
        self.pull(10)
        self.pull(11, uri=other.as_uri())
        self.until(lambda: all('reply' in self.server.pulls[request_id] for request_id in (10, 11)))
        self.assertEqual(len(self.calls()), 1)
        other.write_text('BUG\n')
        self.unblock_output()
        self.server.drain_pulls()
        for request_id in (10, 11):
            self.assertEqual(self.response(request_id)['error']['code'], -32802)
            self.assertNotIn('result', self.response(request_id))
        self.assertEqual(self.server.pull_reply_bytes, 0)

    def test_buffer_context_change_invalidates_stalled_reply(self):
        self.server.close()
        self.server = lsp.Server(self.root, self.scanner, self.messages.append, timeout=5,
                                 buffer_mode=True, incremental_workspace=True)
        self.addCleanup(self.server.close)
        dependency = self.root / 'dependency.py'
        dependency.write_text('old dependency\n')
        self.start()
        self.open(text='new unsaved contents\n')
        self.block_output()
        self.pull(10)
        self.until(lambda: 'reply' in self.server.pulls[10])
        dependency.write_text('changed dependency\n')
        self.unblock_output()
        self.server.drain_pulls()
        self.assertEqual(self.response(10)['error']['code'], -32802)
        self.assertEqual(self.source.read_text(), 'clean\n')
        self.assertEqual(self.server.pull_reply_bytes, 0)

    def test_unchanged_responses_do_not_retain_duplicate_diagnostic_arrays(self):
        self.start()
        self.source.write_text('BUG\n')
        self.open()
        self.pull(10)
        first = self.result(10)
        self.block_output()
        self.pull(11, previous=first['resultId'])
        self.until(lambda: 'reply' in self.server.pulls[11])
        self.assertEqual(self.server.pulls[11]['reply']['kind'], 'unchanged')
        self.assertIsNone(self.server.pulls[11]['reply_group'])
        self.assertEqual(self.server.pull_reply_bytes, 0)
        self.unblock_output()
        self.server.drain_pulls()
        self.assertEqual(self.response(11)['result']['kind'], 'unchanged')

    def test_duplicate_request_id_on_another_method_is_answered_once(self):
        self.start()
        self.open()
        self.pull(10)
        self.send('workspace/executeCommand', {'command': 'ubs.scanOpenDocuments'}, id=10)
        self.assertEqual(self.response(10)['error']['code'], -32600)
        self.idle()
        self.assertEqual(sum(message.get('id') == 10 for message in self.messages), 1)

    def test_wire_bound_covers_maximally_escaped_request_id(self):
        self.start()
        self.open()
        request_id = '🦀' * 256
        self.pull(request_id)
        self.server.pending.clear()
        self.server.finish_pulls(self.uri, [lsp.note('ubs.test-only', '🦀' * 100)])
        request = self.server.pulls[request_id]
        actual = len(lsp.frame({'jsonrpc': '2.0', 'id': request_id, 'result': request['reply']}))
        self.assertLessEqual(actual, request['wire_bound'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
