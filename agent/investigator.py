"""AI alert investigator: a model (local Ollama or Gemini) + read-only tools + guardrails.

Flow for one investigation:
  1. The model is asked to investigate one alert and may call the tools in
     tools.py (max MAX_TOOL_ROUNDS rounds). The app runs each call itself.
  2. If the model never asks for get_alert_details, the app fetches it anyway
     and records that the *app* made that call.
  3. The model writes the final report as JSON matching REPORT_SCHEMA.
  4. The report is validated. Numbers it quotes are checked against the
     tool outputs and over-confident wording is flagged.
  5. If the model is unreachable or the report is unusable, a deterministic
     fallback report built from the same tool outputs is returned.
"""
import json
import re
import time
from datetime import datetime
from typing import Any, Callable

import requests

from backend import config
from agent import tools
from backend.models import Investigation, ToolCall

SYSTEM_PROMPT = """You are a cautious network-alert investigator for a small team.
A rule-based detector has already raised the alert. Your job is to explain it.
Rules:
- Gather facts with the tools before answering. Call get_alert_details first,
  then count_distinct_ports and summarize_time_window.
- Use ONLY numbers and facts returned by the tools. Never invent values.
- Do not claim an attack is confirmed. Say what the evidence is consistent with.
- Give more than one possible explanation, including benign ones where plausible.
- Recommend only safe, read-only checks. Never suggest automatic blocking.

How to read the evidence:
- Many different service ports (below 1024) on one destination host within a
  minute is the typical pattern of port scanning / service discovery. Benign
  causes include an authorised vulnerability scan or inventory tool.
- Thousands of flows per minute from one source to one destination port is
  consistent with a flood (denial-of-service). Benign causes include load
  tests, backups or a misbehaving client retrying.
- Flows with only 1-2 packets and very short duration are probes or
  connection attempts rather than real data transfers.
- Compare the source with other_sources_median_flows_per_minute to show how
  unusual it is.
/no_think"""

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "observed_evidence": {"type": "array", "items": {"type": "string"}},
        "possible_explanations": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        "uncertainty": {"type": "string"},
        "recommended_checks": {"type": "array", "items": {"type": "string"}},
        "missing_information": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "observed_evidence", "possible_explanations", "confidence",
                 "uncertainty", "recommended_checks", "missing_information"],
}

FINAL_INSTRUCTION = (
    "Now write the investigation report as JSON with these fields: summary, "
    "observed_evidence (measured facts only, with numbers from the tools), "
    "possible_explanations (at least two), confidence (low/medium/high), "
    "uncertainty, recommended_checks (safe read-only steps), missing_information."
)

OVERCONFIDENT = re.compile(
    r"\b(confirmed|definitely|certainly|undoubtedly|proven|without (a )?doubt)\b", re.I)
# "not confirmed", "cannot be proven" etc. are the cautious wording we want.
NEGATED = re.compile(
    r"\b(not|never|cannot|can't|no|without)\b(\W+\w+){0,2}?\W+"
    r"(confirmed|definitely|certainly|proven)\b|\bunconfirmed\b", re.I)
UNSAFE_ACTION = re.compile(r"\b(automatically block|auto-block|shut ?down the network)\b", re.I)
THINK_BLOCK = re.compile(r"^.*?</think>\s*", re.S)


class ModelUnavailable(RuntimeError):
    pass


RETRYABLE_STATUS = {429, 500, 502, 503, 504}


# --- Ollama ---------------------------------------------------------------

def ollama_status(base_url: str = config.OLLAMA_URL) -> dict[str, Any]:
    """Return {'running': bool, 'models': [...]} without raising."""
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=3)
        resp.raise_for_status()
        return {"running": True, "models": [m["name"] for m in resp.json().get("models", [])]}
    except requests.RequestException:
        return {"running": False, "models": []}


def model_status() -> dict[str, Any]:
    """Status of the configured AI provider, for the dashboard header."""
    if config.LLM_PROVIDER == "gemini":
        # Not pinged on every page load: that would spend quota. A bad key
        # shows up as a clear error (and a fallback report) on Investigate.
        return {"provider": "gemini", "running": bool(config.GEMINI_API_KEY),
                "models": config.GEMINI_MODELS}
    return {"provider": "ollama", **ollama_status()}


def chat(messages: list[dict], model: str, tools_schema=None, response_format=None,
         max_tokens: int = config.MAX_TOKENS_REPORT,
         base_url: str | None = None) -> dict[str, Any]:
    """Send one chat request to the configured provider.

    Messages and the returned dict use Ollama's format; the Gemini backend
    converts to and from it, so the agent loop is the same for both."""
    if config.LLM_PROVIDER == "gemini":
        return gemini_chat(messages, model, tools_schema, response_format, base_url=base_url)
    return ollama_chat(messages, model, tools_schema, response_format, max_tokens,
                       base_url=base_url or config.OLLAMA_URL)


def ollama_chat(messages: list[dict], model: str, tools_schema=None, response_format=None,
                max_tokens: int = config.MAX_TOKENS_REPORT,
                base_url: str = config.OLLAMA_URL) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": model, "messages": messages, "stream": False,
        "think": False, "options": {**config.MODEL_OPTIONS, "num_predict": max_tokens},
    }
    if tools_schema:
        payload["tools"] = tools_schema
    if response_format:
        payload["format"] = response_format
    try:
        resp = requests.post(f"{base_url}/api/chat", json=payload,
                             timeout=config.OLLAMA_TIMEOUT_SECONDS)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise ModelUnavailable(f"Could not reach the local model: {exc}") from exc
    return resp.json()


# --- Gemini (OpenAI-compatible endpoint) -------------------------------------

def _to_openai_messages(messages: list[dict]) -> list[dict]:
    """Ollama-style messages -> OpenAI-style (tool calls need ids)."""
    out: list[dict] = []
    pending: list[tuple[str, str]] = []  # (tool name, call id) awaiting a result
    for m in messages:
        role = m["role"]
        if role == "assistant":
            calls = []
            for call in m.get("tool_calls") or []:
                fn = call.get("function", {})
                call_id = call.get("id") or f"call_{len(out)}_{len(calls)}"
                args = fn.get("arguments") or {}
                calls.append({"id": call_id, "type": "function", "function": {
                    "name": fn.get("name", ""),
                    "arguments": args if isinstance(args, str) else json.dumps(args)}})
                pending.append((fn.get("name", ""), call_id))
            if calls:
                out.append({"role": "assistant", "content": m.get("content") or None, "tool_calls": calls})
            elif m.get("content"):
                out.append({"role": "assistant", "content": m["content"]})
        elif role == "tool":
            name = m.get("tool_name", "")
            idx = next((i for i, (n, _) in enumerate(pending) if n == name), 0 if pending else None)
            call_id = pending.pop(idx)[1] if idx is not None else "call_unknown"
            out.append({"role": "tool", "tool_call_id": call_id, "content": m["content"]})
        else:
            out.append({"role": role, "content": m["content"]})
    return out


def gemini_chat(messages: list[dict], model: str, tools_schema=None, response_format=None,
                base_url: str | None = None) -> dict[str, Any]:
    if not config.GEMINI_API_KEY:
        raise ModelUnavailable("GEMINI_API_KEY is not set.")
    payload: dict[str, Any] = {
        "model": model, "messages": _to_openai_messages(messages), "temperature": 0,
        "max_tokens": config.GEMINI_MAX_TOKENS,
    }
    if config.GEMINI_REASONING_EFFORT:
        payload["reasoning_effort"] = config.GEMINI_REASONING_EFFORT
    if tools_schema:
        payload["tools"] = tools_schema
    if response_format:
        payload["response_format"] = {"type": "json_schema",
                                      "json_schema": {"name": "report", "schema": response_format}}
    url = f"{(base_url or config.GEMINI_URL).rstrip('/')}/chat/completions"
    headers = {"Authorization": f"Bearer {config.GEMINI_API_KEY}"}
    started = time.perf_counter()

    def post() -> requests.Response:
        resp = requests.post(url, json=payload, headers=headers, timeout=config.GEMINI_TIMEOUT_SECONDS)
        if resp.status_code == 400 and response_format and payload["response_format"]["type"] != "json_object":
            # Older endpoint versions reject json_schema; plain JSON mode still
            # works and the report is validated afterwards anyway.
            payload["response_format"] = {"type": "json_object"}
            resp = requests.post(url, json=payload, headers=headers, timeout=config.GEMINI_TIMEOUT_SECONDS)
        return resp

    # Busy (503), rate-limited (429) or flaky (5xx) models are retried with a
    # short backoff, then the other Gemini models are tried in order.
    candidates = list(dict.fromkeys([model, *config.GEMINI_MODELS]))
    last_error = "no attempt made"
    resp = None
    for candidate in candidates:
        payload["model"] = candidate
        for attempt in range(config.GEMINI_RETRIES):
            if attempt:
                time.sleep(config.GEMINI_RETRY_DELAY_SECONDS * attempt)
            try:
                resp = post()
            except requests.RequestException as exc:
                last_error = f"Could not reach the Gemini API: {type(exc).__name__}"
                continue
            if resp.status_code == 200:
                break
            last_error = f"Gemini API error {resp.status_code} ({candidate}): {resp.text[:300]}"
            if resp.status_code not in RETRYABLE_STATUS:
                raise ModelUnavailable(last_error)
        if resp is not None and resp.status_code == 200:
            break
    else:
        raise ModelUnavailable(last_error)
    data = resp.json()
    try:
        msg = data["choices"][0]["message"]
    except (KeyError, IndexError) as exc:
        raise ModelUnavailable("Gemini API returned no answer.") from exc

    calls = []
    for call in msg.get("tool_calls") or []:
        fn = call.get("function", {})
        args = fn.get("arguments") or "{}"
        try:
            args = json.loads(args) if isinstance(args, str) else args
        except json.JSONDecodeError:
            args = {}
        calls.append({"id": call.get("id"), "function": {"name": fn.get("name", ""), "arguments": args}})
    content = msg.get("content") or ""
    if isinstance(content, list):  # some responses split text into parts
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    # A fenced ```json block still parses after the fences are removed.
    content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip())
    return {
        "model": payload["model"],
        "message": {"role": "assistant", "content": content, "tool_calls": calls},
        "eval_count": (data.get("usage") or {}).get("completion_tokens", 0),
        "eval_duration": int((time.perf_counter() - started) * 1e9),
    }


# --- Validation -------------------------------------------------------------

def _numbers_in(value: Any) -> set[str]:
    text = json.dumps(value)
    return {n.replace(",", "") for n in re.findall(r"\d[\d,]*\.?\d*", text)}


def validate_report(report: Any, tool_outputs: list[dict]) -> tuple[list[str], list[str]]:
    """Return (errors, warnings). Errors make the report unusable."""
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(report, dict):
        return ["Report is not a JSON object."], warnings
    for key in REPORT_SCHEMA["required"]:
        if key not in report:
            errors.append(f"Missing field '{key}'.")
    for key in ("observed_evidence", "possible_explanations", "recommended_checks"):
        if key in report and (not isinstance(report[key], list) or not report[key]):
            errors.append(f"Field '{key}' must be a non-empty list.")
    if report.get("confidence") not in ("low", "medium", "high"):
        errors.append("Field 'confidence' must be low, medium or high.")
    if errors:
        return errors, warnings

    text = json.dumps(report)
    if OVERCONFIDENT.search(NEGATED.sub("", text)):
        errors.append("Report uses over-confident wording (e.g. 'confirmed').")
    if UNSAFE_ACTION.search(text):
        errors.append("Report recommends an unsafe automatic action.")
    if len(report["possible_explanations"]) < 2:
        warnings.append("Only one possible explanation was given.")

    # Grounding check: numbers quoted as evidence should come from the tools.
    known = set()
    for out in tool_outputs:
        known |= _numbers_in(out)
    numeric = [float(n) for n in known if re.fullmatch(r"\d+\.?\d*", n)]
    known |= {str(int(v)) for v in numeric}
    # shares like 0.321 are often quoted as percentages (32.1%)
    known |= {f"{v * 100:g}" for v in numeric if v <= 1} | {str(round(v * 100)) for v in numeric if v <= 1}
    quoted = _numbers_in(report["observed_evidence"])
    unknown = sorted(n for n in quoted
                     if n not in known and n.rstrip("0").rstrip(".") not in known and len(n) > 1)
    if unknown:
        warnings.append("Numbers not found in tool outputs: " + ", ".join(unknown[:10]))
    return errors, warnings


# --- Fallback ---------------------------------------------------------------

def fallback_report(details: dict, ports: dict | None, window: dict | None, reason: str) -> dict:
    """Deterministic explanation built only from tool outputs."""
    evidence = [
        f"Rule '{details['rule_name']}' fired for source {details['source_ip']} "
        f"between {details['window_start']} and {details['window_end']}.",
        f"Peak {details['metric']} = {details['peak_value']} per {details['window_seconds']} s "
        f"(threshold {details['threshold']}, {details['times_over_threshold']}x).",
        f"{details['total_flows_in_alert']} flows in {details['windows_triggered']} window(s).",
    ]
    if ports:
        evidence.append(
            f"{ports['distinct_destination_ports']} distinct destination ports "
            f"({ports['distinct_service_ports_below_1024']} below 1024) on "
            f"{ports['distinct_destination_hosts']} destination host(s).")
    if window:
        evidence.append(
            f"{window['share_of_flows_with_at_most_2_forward_packets']:.0%} of flows sent at most "
            f"2 packets; other sources had a median of "
            f"{window['other_sources_median_flows_per_minute']} flows per minute.")
    if details["rule_name"] == "port_spread":
        explanations = ["A port scan or service discovery run against the destination host(s).",
                        "An inventory or vulnerability-scanning tool run by IT staff.",
                        "Misconfigured software trying many services."]
    else:
        explanations = ["A flood of connections, as in a denial-of-service attempt.",
                        "A load test, backup or update job generating heavy traffic.",
                        "A misbehaving or misconfigured application retrying connections."]
    return {
        "summary": f"Deterministic summary (AI unavailable): {details['source_ip']} exceeded the "
                   f"{details['rule_name']} threshold {details['times_over_threshold']}x.",
        "observed_evidence": evidence,
        "possible_explanations": explanations,
        "confidence": "low",
        "uncertainty": "This summary was generated without the AI model. The rule shows unusual "
                       "volume or spread, not intent.",
        "recommended_checks": ["Identify the device that owns the source IP.",
                               "Check whether scheduled scans, tests or jobs ran at that time.",
                               "Review logs on the destination host for the same period."],
        "missing_information": ["Device owner and role", "Whether the activity was authorised",
                                "Packet payloads / application logs"],
        "fallback_reason": reason,
    }


# --- Agent loop -------------------------------------------------------------

def _clean(content: str) -> str:
    return THINK_BLOCK.sub("", content or "").strip()


def investigate(alert_id: int, model: str | None = None,
                db_path=None, base_url: str | None = None,
                on_tool_call: Callable[[ToolCall], None] | None = None) -> Investigation:
    """Run one investigation. `on_tool_call` (optional) is called after each
    tool runs, so a UI can show the agent's progress live."""
    model = model or config.default_model()
    started = time.perf_counter()
    inv = Investigation(alert_id=alert_id, model=model, status="ok", report={},
                        started_at=datetime.now().isoformat(timespec="seconds"))
    outputs: dict[str, dict] = {}

    def run(name: str, args: dict, requested_by: str) -> dict:
        if name in outputs:  # small models sometimes repeat calls; don't re-run
            return {"note": f"{name} was already called; use the earlier result."}
        result = tools.run_tool(name, args, allowed_alert_id=alert_id, db_path=db_path)
        call = ToolCall(name=name, arguments=args, result=result, requested_by=requested_by)
        inv.tool_calls.append(call)
        if "error" not in result:
            outputs[name] = result
        if on_tool_call:
            on_tool_call(call)
        return result

    def count_tokens(resp: dict) -> None:
        inv.tokens_generated += resp.get("eval_count", 0)
        used = resp.get("model")
        note = f"{inv.model} was busy; {used} answered instead."
        if used and used != inv.model and note not in inv.warnings:
            inv.warnings.append(note)
        eval_ns.append(resp.get("eval_duration", 0))

    eval_ns: list[int] = []
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Investigate alert {alert_id}. /no_think"},
    ]
    try:
        for _ in range(config.MAX_TOOL_ROUNDS):
            if len(outputs) == len(tools.TOOLS):
                break  # every tool has been used; move on to the report
            resp = chat(messages, model, tools_schema=tools.ollama_tool_schemas(),
                        max_tokens=config.MAX_TOKENS_TOOL_ROUND, base_url=base_url)
            count_tokens(resp)
            msg = resp.get("message", {})
            calls = msg.get("tool_calls") or []
            messages.append({"role": "assistant", "content": _clean(msg.get("content", "")),
                             "tool_calls": calls})
            if not calls:
                break
            for call in calls:
                fn = call.get("function", {})
                args = fn.get("arguments") or {}
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                result = run(fn.get("name", ""), args, "model")
                messages.append({"role": "tool", "tool_name": fn.get("name", ""),
                                 "content": json.dumps(result)})

        if "get_alert_details" not in outputs:
            result = run("get_alert_details", {"alert_id": alert_id}, "app")
            inv.warnings.append("The model did not request get_alert_details; the app supplied it.")
            messages.append({"role": "user", "content": "Alert details from the app: " + json.dumps(result)})

        messages.append({"role": "user", "content": FINAL_INSTRUCTION})
        report, errors = None, []
        for attempt in range(2):  # one retry if the first report is rejected
            resp = chat(messages, model, response_format=REPORT_SCHEMA, base_url=base_url)
            count_tokens(resp)
            try:
                report = json.loads(_clean(resp.get("message", {}).get("content", "")))
            except json.JSONDecodeError:
                report = None
            errors, warnings = validate_report(report, list(outputs.values()))
            if not errors:
                inv.warnings.extend(warnings)
                break
            messages.append({"role": "user", "content": "Your report was rejected: "
                             + " ".join(errors) + " Write it again, following the rules."})
        if errors:
            raise ValueError("; ".join(errors))
        inv.report = report
    except (ModelUnavailable, ValueError) as exc:
        inv.status = "fallback"
        inv.error = str(exc)
        details = outputs.get("get_alert_details") or tools.get_alert_details(alert_id, db_path=db_path)
        ports = outputs.get("count_distinct_ports") or tools.count_distinct_ports(alert_id, db_path=db_path)
        window = outputs.get("summarize_time_window") or tools.summarize_time_window(alert_id, db_path=db_path)
        inv.report = fallback_report(details, ports, window, str(exc))

    inv.duration_seconds = round(time.perf_counter() - started, 1)
    total_eval_s = sum(eval_ns) / 1e9
    if total_eval_s > 0:
        inv.tokens_per_second = round(inv.tokens_generated / total_eval_s, 1)
    return inv
