"""Gemini backend: message conversion and response parsing (no network)."""
import json

from agent import investigator
from backend import config
from test_investigator import GOOD_REPORT


class FakeResponse:
    def __init__(self, data, status_code=200):
        self.data, self.status_code, self.text = data, status_code, json.dumps(data)

    def json(self):
        return self.data


def use_gemini(monkeypatch, replies, sent):
    monkeypatch.setattr(config, "LLM_PROVIDER", "gemini")
    monkeypatch.setattr(config, "GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(config, "GEMINI_RETRY_DELAY_SECONDS", 0)

    def fake_post(url, json=None, headers=None, timeout=None):
        sent.append({"url": url, "json": dict(json), "headers": headers})
        return next(replies)
    monkeypatch.setattr(investigator.requests, "post", fake_post)


def test_tool_calls_get_ids_and_results_are_linked():
    msgs = [
        {"role": "system", "content": "s"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "abc", "function": {"name": "get_alert_details", "arguments": {"alert_id": 1}}}]},
        {"role": "tool", "tool_name": "get_alert_details", "content": "{}"},
        {"role": "assistant", "content": "", "tool_calls": []},  # empty turn is dropped
    ]
    out = investigator._to_openai_messages(msgs)
    assert out[1]["tool_calls"][0] == {"id": "abc", "type": "function", "function": {
        "name": "get_alert_details", "arguments": '{"alert_id": 1}'}}
    assert out[2] == {"role": "tool", "tool_call_id": "abc", "content": "{}"}
    assert len(out) == 3


def test_full_investigation_through_gemini(db, stored_alert, monkeypatch):
    aid = stored_alert.alert_id
    call = lambda name, cid: {"id": cid, "type": "function", "function": {  # noqa: E731
        "name": name, "arguments": json.dumps({"alert_id": aid})}}
    replies = iter([
        FakeResponse({"choices": [{"message": {"content": None, "tool_calls": [
            call("get_alert_details", "c1"), call("count_distinct_ports", "c2"),
            call("summarize_time_window", "c3")]}}], "usage": {"completion_tokens": 20}}),
        FakeResponse({"choices": [{"message": {"content": "```json\n" + json.dumps(GOOD_REPORT) + "\n```"}}],
                      "usage": {"completion_tokens": 80}}),
    ])
    sent = []
    use_gemini(monkeypatch, replies, sent)
    inv = investigator.investigate(aid, db_path=db)
    assert inv.status == "ok", inv.error
    assert inv.model == config.GEMINI_MODEL
    assert [tc.name for tc in inv.tool_calls] == ["get_alert_details", "count_distinct_ports",
                                                  "summarize_time_window"]
    assert inv.tokens_generated == 100
    assert sent[0]["url"].endswith("/chat/completions")
    assert sent[0]["headers"]["Authorization"] == "Bearer test-key"
    assert [m["tool_call_id"] for m in sent[1]["json"]["messages"] if m["role"] == "tool"] == ["c1", "c2", "c3"]
    assert sent[1]["json"]["response_format"]["type"] == "json_schema"


def test_busy_model_is_retried_then_next_model_answers(db, stored_alert, monkeypatch):
    busy = FakeResponse({"error": {"code": 503, "status": "UNAVAILABLE"}}, status_code=503)
    ok = FakeResponse({"choices": [{"message": {"content": json.dumps(GOOD_REPORT)}}]})
    # tool round: busy, busy, then the 2nd model answers (no tool calls);
    # report round: 1st model answers directly.
    replies = iter([busy, busy, FakeResponse({"choices": [{"message": {"content": ""}}]}), ok])
    sent = []
    use_gemini(monkeypatch, replies, sent)
    inv = investigator.investigate(stored_alert.alert_id, db_path=db)
    assert inv.status == "ok", inv.error
    assert [r["json"]["model"] for r in sent] == [config.GEMINI_MODELS[0], config.GEMINI_MODELS[0],
                                                 config.GEMINI_MODELS[1], config.GEMINI_MODELS[0]]
    assert any("was busy" in w for w in inv.warnings)


def test_gemini_error_gives_fallback_report(db, stored_alert, monkeypatch):
    sent = []
    use_gemini(monkeypatch, iter(lambda: FakeResponse({"error": "quota"}, status_code=429), None), sent)
    inv = investigator.investigate(stored_alert.alert_id, db_path=db)
    assert inv.status == "fallback"
    assert "429" in inv.error
    assert len(sent) == config.GEMINI_RETRIES * len(config.GEMINI_MODELS)


def test_bad_key_is_not_retried(db, stored_alert, monkeypatch):
    sent = []
    use_gemini(monkeypatch, iter(lambda: FakeResponse({"error": "bad key"}, status_code=403), None), sent)
    inv = investigator.investigate(stored_alert.alert_id, db_path=db)
    assert inv.status == "fallback" and "403" in inv.error
    assert len(sent) == 1


def test_missing_key_gives_fallback_report(db, stored_alert, monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "gemini")
    monkeypatch.setattr(config, "GEMINI_API_KEY", "")
    inv = investigator.investigate(stored_alert.alert_id, db_path=db)
    assert inv.status == "fallback"
    assert "GEMINI_API_KEY" in inv.error
