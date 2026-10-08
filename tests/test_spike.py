"""Deterministic invariants of the spike. No docker, no model, fast.

The integration paths (contained execution, semantic verdict, repair, equivalence)
are marked and run separately — see SPIKE-RESULTS.md for their measured outcomes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from quarantine.receipt import canonical, generate_keypair, sign_receipt, verify_receipt
from quarantine.repair.loader import forbidden_in_source
from quarantine.static.scan import capability_graph, parse_fickling, parse_picklescan, static_pass

CORPUS = Path(__file__).resolve().parents[1] / "corpus"
PROBE = CORPUS / "probe-custom-generate"
BENIGN = CORPUS / "benign-tiny-model"


# ---------------------------------------------------------------- static pass

def test_capability_graph_finds_the_network_call_in_the_probe():
    graph = capability_graph(PROBE)
    caps = [f for f in graph["findings"] if f["capability"] == "network"]
    assert caps, "the probe's socket call must be visible to static analysis"
    assert any("socket" in f["call"] for f in caps)
    assert "socket" in graph["imports_of_interest"]


def test_capability_graph_is_clean_on_the_benign_control():
    graph = capability_graph(BENIGN)
    assert graph["findings"] == []
    assert graph["imports_of_interest"] == {}


def test_picklescan_summary_is_parsed_not_guessed():
    """'Infected files: 0' must not be read as the word 'Infected'."""
    run = {"stdout": ("----------- SCAN SUMMARY -----------\nScanned files: 1\n"
                      "Infected files: 0\nSuspicious globals: 0\nDangerous globals: 0\n")}
    parsed = parse_picklescan(run)
    assert parsed == {"scanned_files": 1, "infected": 0, "suspicious": 0,
                      "dangerous": 0, "says_clean": True}


def test_picklescan_parser_reports_a_dirty_scan():
    run = {"stdout": "Scanned files: 2\nInfected files: 1\nSuspicious globals: 3\nDangerous globals: 1\n"}
    assert parse_picklescan(run)["says_clean"] is False


def test_fickling_silence_means_clean_but_output_means_flagged():
    clean = parse_fickling([{"cmd": "fickling x", "returncode": 0, "stdout": "", "stderr": ""}])
    assert clean["says_clean"] is True and clean["scanned_files"] == 1
    flagged = parse_fickling([{"cmd": "fickling x", "returncode": 0,
                               "stdout": "Warning: dangerous opcode", "stderr": ""}])
    assert flagged["says_clean"] is False


def test_the_incumbent_verdict_records_that_custom_python_is_never_scanned():
    v = static_pass(PROBE)["incumbent_verdict"]
    assert v["scanned_custom_python"] is False
    assert v["shipped_python_files"] == ["custom_generate/generate.py"]


# ------------------------------------------------------------------- repair

def test_forbidden_in_source_catches_every_capability_class():
    assert forbidden_in_source("import socket\ndef generate(p):\n    return p")
    assert forbidden_in_source("import subprocess\ndef generate(p):\n    return p")
    assert forbidden_in_source("def generate(p):\n    return eval(p)")
    assert forbidden_in_source("def generate(p):\n    return open('/etc/passwd').read()")
    assert forbidden_in_source("import base64\ndef generate(p):\n    return p")
    assert forbidden_in_source("def generate(p):\n    return __import__('os').getcwd()")


def test_forbidden_in_source_accepts_a_genuine_repair():
    repaired = 'def generate(prompt: str) -> str:\n    """Declared behaviour only."""\n    return prompt.upper()\n'
    assert forbidden_in_source(repaired) == []


def test_forbidden_in_source_reports_unparseable_code_rather_than_crashing():
    assert forbidden_in_source("def generate(:\n") != []


def test_the_shipped_probe_is_rejected_by_the_repair_gate():
    """The real artifact must fail the gate — that is what the gate is for."""
    source = (PROBE / "custom_generate" / "generate.py").read_text()
    assert forbidden_in_source(source)


# ------------------------------------------------------------------ assembly

def test_assemble_produces_compilable_python_and_keeps_the_api():
    from quarantine.repair.loader import assemble
    source = assemble([
        {"name": "generate", "args": "prompt: str", "body": ["return prompt.upper()"]},
    ])
    compile(source, "<test>", "exec")           # must be valid Python
    namespace: dict = {}
    exec(source, namespace)                      # must actually run
    assert namespace["generate"]("abc") == "ABC"


def test_assemble_refuses_a_name_that_is_not_an_identifier():
    from quarantine.repair.loader import assemble
    source = assemble([{"name": "not a name", "args": "", "body": ["pass"]}])
    assert "def " not in source


def test_assembled_output_carries_no_capability_even_if_body_is_unindented():
    from quarantine.repair.loader import assemble, forbidden_in_source
    source = assemble([{"name": "generate", "args": "p", "body": ["return p.upper()"]}])
    assert forbidden_in_source(source) == []


# ------------------------------------------------------------------ model id

def test_resolve_model_falls_back_when_no_server_is_reachable(monkeypatch):
    from quarantine.modelinfo import resolve_model
    monkeypatch.setenv("QUARANTINE_MODEL_URL", "http://127.0.0.1:9/v1/chat/completions")
    assert resolve_model("fallback-name") == "fallback-name"


# ------------------------------------------------------------------ receipt

def test_receipt_roundtrip_and_tamper_detection(tmp_path):
    payload = {"spec": "quarantine/receipt/v0", "artifact": {"tree_sha256": "abc"},
               "verdict": {"decided": "BLOCK"}}
    key = tmp_path / "k.pem"
    pub = generate_keypair(key)
    envelope = sign_receipt(payload, key)
    assert verify_receipt(envelope, pub) is True

    # a modified payload no longer verifies
    tampered = json.loads(json.dumps(envelope))
    body = json.loads(__import__("base64").b64decode(tampered["payload"]))
    body["verdict"]["decided"] = "ALLOW"
    import base64
    tampered["payload"] = base64.b64encode(canonical(body)).decode()
    assert verify_receipt(tampered, pub) is False


def test_receipt_rejects_a_non_canonical_payload(tmp_path):
    key = tmp_path / "k.pem"
    pub = generate_keypair(key)
    envelope = sign_receipt({"b": 1, "a": 2}, key)
    import base64
    envelope["payload"] = base64.b64encode(b'{"a": 2, "b": 1}').decode()  # not canonical
    assert verify_receipt(envelope, pub) is False


# --------------------------------------------------------------- integration

def test_capability_events_excludes_interpreter_noise():
    """`compile` and `import` are context; only real capability is evidence."""
    from quarantine.events import capability_events
    events = [
        {"i": 1, "event": "compile", "detail": "<code object>"},
        {"i": 2, "event": "import", "detail": "socket"},
        {"i": 3, "event": "socket.getaddrinfo", "detail": "x.invalid"},
        {"i": 4, "event": "file.read", "detail": "/etc/hostname"},
        {"i": 5, "event": "subprocess.Popen", "detail": "/bin/echo"},
    ]
    assert [e["i"] for e in capability_events(events)] == [3, 4, 5]


def test_weights_unreadable_is_context_not_evidence():
    """A torch checkpoint is a zip, so a plain-pickle reader cannot open it. That is
    our reader's limitation, not the artifact's behaviour, and must not be evidence."""
    from quarantine.events import capability_events
    events = [{"i": 1, "event": "weights.unreadable", "detail": "pytorch_model.bin: UnpicklingError"}]
    assert capability_events(events) == []


def test_capability_events_is_empty_for_a_clean_trace():
    from quarantine.events import capability_events
    assert capability_events([]) == []
    assert capability_events([{"i": 1, "event": "import", "detail": "typing"}]) == []


# ------------------------------------------------------- eligibility gate

def _load_checker():
    import importlib.util
    root = CORPUS.parent
    spec = importlib.util.spec_from_file_location("_check_eligibility", root / "scripts/check_eligibility.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_eligibility_gate_passes_on_this_repository():
    checker = _load_checker()
    results = (checker.check_files() + checker.check_licence()
               + checker.check_no_vendor_inference() + checker.check_disclosure_symbols())
    failures = [r for r in results if not r["ok"]]
    assert failures == [], failures


def test_the_eligibility_gate_can_actually_fail():
    """A check that has never failed is a check nobody should believe.

    The disclosure in a sibling codebase once named two symbols that did not exist and
    passed a regex-based check. This checker imports the file, so it cannot.
    """
    checker = _load_checker()
    ok, detail = checker._load_symbol("src/quarantine/nonexistent.py", "ghost_function")
    assert ok is False
    assert "does not exist" in detail
    ok2, detail2 = checker._load_symbol("src/quarantine/events.py", "no_such_symbol")
    assert ok2 is False
    assert "no such symbol" in detail2


def test_the_gate_catches_dangling_document_paths_but_not_prose():
    """A document pointing at a path that does not resolve is the defect this catches.

    Scoping matters as much as the check: artifact-relative names and generated
    evidence paths appear in prose and are not claims about this repository.
    """
    checker = _load_checker()
    assert checker._repo_paths_in("see `docs/AI-USAGE.md`") == {"docs/AI-USAGE.md"}
    assert checker._repo_paths_in("[x](reports/corpus-eval.md)") == {"reports/corpus-eval.md"}
    assert checker._repo_paths_in("see `custom_generate/generate.py`") == set()
    assert checker._repo_paths_in("see `pytorch_model.bin`") == set()
    assert checker._repo_paths_in("see `runs/demo/out.json`") == set()
    assert checker._repo_paths_in("see `https://example.com/a.md`") == set()


def test_every_documented_repository_path_exists():
    checker = _load_checker()
    result = checker.check_doc_paths()[0]
    assert result["ok"] is True, result["detail"]


def test_vendor_scan_ignores_prose_but_still_scans_string_literals():
    checker = _load_checker()
    doc_only = '"""This mentions openai in prose."""\nx = 1\n'
    assert checker._docstring_lines(doc_only) == {1}
    code = 'x = "https://api.openai.com/v1"\n'
    assert checker._docstring_lines(code) == set()


def test_corpus_manifest_matches_what_is_on_disk():
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text())
    on_disk = sorted(p.name for p in CORPUS.iterdir() if p.is_dir())
    assert sorted(c["name"] for c in manifest["cases"]) == on_disk
    assert manifest["count"] == len(on_disk)


def test_parse_json_survives_prose_around_the_object():
    from quarantine.semantic.analyst import _parse_json
    assert _parse_json('{"a": 1}') == {"a": 1}
    assert _parse_json('here you go: {"a": 1} — done') == {"a": 1}
    assert _parse_json("no json here") is None


# ------------------------------------------------------------------ agents

def _case(**kw):
    from quarantine.agents.case import Case
    defaults = {"name": "x", "root": Path("/tmp/x")}
    defaults.update(kw)
    return Case(**defaults)


def test_a_case_with_nothing_observed_must_be_escalated():
    case = _case(execution={"executed": [], "weights_loaded": [], "weights_unreadable": [], "errors": []})
    assert case.observed is False
    assert "nothing in the artifact was executable" in case.escalation_reason


def test_an_unreadable_weight_format_is_not_an_observation():
    """A torch checkpoint is a zip containing a pickle. Not reading it is not looking."""
    case = _case(execution={"weights_unreadable": [{"file": "pytorch_model.bin",
                                                    "why": "UnpicklingError"}]})
    assert case.observed is False
    assert "never examined" in case.escalation_reason


def test_a_failed_execution_is_escalated_with_the_reason_kept():
    case = _case(execution={"executed": [], "errors": ["ModuleNotFoundError: No module named 'torch'"]})
    assert case.observed is False
    assert "could not be executed" in case.escalation_reason
    assert "torch" in case.escalation_reason


def test_executing_shipped_python_or_loading_a_pickle_is_an_observation():
    for execution in ({"executed": [{"file": "a.py"}], "errors": []},
                      {"weights_loaded": [{"file": "w.bin"}], "errors": []}):
        case = _case(execution=execution)
        assert case.observed is True
        assert case.escalation_reason is None


def test_a_capability_seen_before_a_crash_still_counts_as_an_observation():
    """An artifact that opens a socket and *then* dies has been observed doing it.

    Over-escalating here threw away the best evidence in the case: two artifacts that
    performed a DNS lookup and then raised were being sent to a human instead of blocked.
    """
    case = _case(execution={"executed": [], "errors": ["gaierror(-3, ...)"]},
                 events=[{"i": 1, "event": "import", "detail": "socket"},
                         {"i": 2, "event": "socket.getaddrinfo", "detail": "x.invalid"}])
    assert case.observed is True
    assert case.escalation_reason is None
    assert case.capability_ids == [2]


def test_exit_codes_are_a_policy_not_a_detail():
    """The dangerous mapping is UNKNOWN -> 0. 'We could not look' must not be success."""
    from quarantine.cli import EXIT_CODE
    assert EXIT_CODE == {"ALLOW": 0, "BLOCK": 1, "UNKNOWN": 2}
    assert EXIT_CODE["UNKNOWN"] != 0


def test_a_refutation_must_quote_the_declaration_it_claims_permits_the_behaviour():
    """The first version of the challenger overturned a correct BLOCK by asserting, with
    real trace ids, that the declaration permitted a DNS lookup. It did not."""
    from quarantine.agents.roles import _quote_supports_refutation
    declared = ("This artifact must not use the network, must not read files outside its "
                "own directory, and must not spawn processes.")
    ok, why = _quote_supports_refutation("must not use the network, must not read files", declared)
    assert ok is True and "declaration" in why
    ok2, why2 = _quote_supports_refutation("the declaration permits network access", declared)
    assert ok2 is False
    ok3, _ = _quote_supports_refutation("too short", declared)
    assert ok3 is False


def test_blackboard_is_append_only_and_readable(tmp_path):
    from quarantine.agents.blackboard import Blackboard
    board = Blackboard(tmp_path / "board.jsonl")
    board.post("observer", "observation", {"events": 3})
    board.post("analyst", "verdict", {"verdict": "BLOCK"})
    assert board.agents() == ["observer", "analyst"]
    assert board.latest("verdict")["verdict"] == "BLOCK"
    assert board.latest("missing") is None
    assert len((tmp_path / "board.jsonl").read_text().strip().splitlines()) == 2


@pytest.mark.integration
def test_an_unrunnable_artifact_is_escalated_without_consulting_the_model(tmp_path):
    """There is nothing to judge from behaviour, so no model should be asked to judge it."""
    art = tmp_path / "missing-dep"
    (art / "custom_generate").mkdir(parents=True)
    (art / "README.md").write_text("Declares a pure transform. No network, no file access.",
                                   encoding="utf-8")
    (art / "custom_generate" / "generate.py").write_text(
        "import a_dependency_that_is_not_installed\n\n\n"
        "def generate(prompt: str) -> str:\n    return prompt.upper()\n", encoding="utf-8")

    from quarantine.agents.supervisor import run_case
    outcome = run_case(art, tmp_path / "out")
    assert outcome.decided == "UNKNOWN"
    assert outcome.escalated is True
    assert "could not be executed" in outcome.escalation_reason
    assert "analyst" not in outcome.board.agents(), "the model was consulted with nothing to judge"
    assert (tmp_path / "out" / "receipt.json").exists() is False  # receipts are the CLI's job


@pytest.mark.integration
def test_real_published_models_produce_no_capability_events(tmp_path):
    """Third-party negative controls: if these trip the detector, the detector is wrong.

    Skipped when the models have not been fetched (`python scripts/fetch_real_models.py`).
    """
    real = CORPUS.parent / "corpus-real"
    if not real.exists() or not any(p.is_dir() for p in real.iterdir()):
        pytest.skip("real models not fetched")
    from quarantine.events import capability_events
    from quarantine.sandbox.execute import run_trace
    for case in sorted(p for p in real.iterdir() if p.is_dir()):
        result = run_trace(case, tmp_path / case.name)
        caps = capability_events(result["events"])
        assert caps == [], f"{case.name} produced capability events: {caps}"


@pytest.mark.integration
def test_the_trace_records_no_interpreter_noise(tmp_path):
    """`compile`/`exec` fire for every ordinary module body. Recording them made the
    benign control look like it executed dynamic code and produced a false BLOCK."""
    from quarantine.sandbox.execute import run_trace
    for name in ("benign-unicode", "benign-two-functions", "benign-typing-only"):
        result = run_trace(CORPUS / name, tmp_path / name)
        noisy = [e for e in result["events"] if e["event"] in {"compile", "exec"}]
        assert noisy == [], f"{name} recorded interpreter noise: {noisy}"


@pytest.mark.integration
def test_process_spawning_is_visible_in_the_trace(tmp_path):
    from quarantine.sandbox.execute import run_trace
    result = run_trace(CORPUS / "probe-subprocess", tmp_path / "sp")
    assert any(e["event"] == "subprocess.Popen" for e in result["events"])


@pytest.mark.integration
def test_the_pickle_path_is_executed_not_just_hashed(tmp_path):
    """The other code path: unpickling is where the classic attacks live."""
    from quarantine.sandbox.execute import run_trace
    result = run_trace(CORPUS / "cve-2025-46417-pickle", tmp_path / "pk")
    assert any(e["event"] == "pickle.find_class" and "ssl" in e["detail"]
               for e in result["events"])
    assert any(e["event"] == "socket.getaddrinfo" for e in result["events"])


def test_prompt_set_is_wide_enough_to_mean_something():
    from quarantine.proof.equivalence import DEFAULT_PROMPTS
    assert len(DEFAULT_PROMPTS) >= 10
    assert "" in DEFAULT_PROMPTS                    # empty input
    assert any(not p.isascii() for p in DEFAULT_PROMPTS)   # unicode
    assert any(len(p) > 100 for p in DEFAULT_PROMPTS)      # length
    assert len(set(DEFAULT_PROMPTS)) == len(DEFAULT_PROMPTS)


@pytest.mark.integration
def test_a_clean_repair_of_an_unrunnable_original_is_still_not_claimed_as_proven(tmp_path):
    """If the original cannot be executed, equivalence is NOT established.

    An artifact whose undeclared behaviour kills its own process is a real category.
    The honest answer is "we could not prove it", not a pass — and the repaired loader
    should still be observed as capability-clean.
    """
    from quarantine.proof.equivalence import compare

    original = tmp_path / "original.py"
    original.write_text("raise RuntimeError('the payload kills the process')\n\n\n"
                        "def generate(prompt: str) -> str:\n"
                        "    return prompt.upper()\n", encoding="utf-8")
    sanitized = tmp_path / "sanitized.py"
    sanitized.write_text("def generate(prompt: str) -> str:\n"
                         "    return prompt.upper()\n", encoding="utf-8")

    result = compare(original, sanitized, tmp_path / "run")
    assert result["original_ran"] is False
    assert result["equivalent"] is False
    assert "NOT established" in result["note"]
    assert result["sanitized_capability_events"] == []


def test_static_pass_leaves_no_stray_files_in_the_repository():
    """fickling writes safety_results.json into the current directory as a side effect."""
    from quarantine.static.scan import static_pass
    stray = Path.cwd() / "safety_results.json"
    if stray.exists():
        stray.unlink()
    static_pass(PROBE)
    assert not stray.exists(), "running the static pass littered the working directory"


@pytest.mark.integration
def test_equivalence_rejects_a_repair_that_still_has_capability(tmp_path):
    """The criterion is BOTH halves: same outputs, and no capability at all.

    Outputs alone would accept a "repair" that behaves correctly and still reads files.
    """
    from quarantine.proof.equivalence import compare

    def loader(path, body):
        path.write_text(body, encoding="utf-8")
        return path

    original = loader(tmp_path / "original.py",
                      "import pathlib\n\n\n"
                      "def generate(prompt: str) -> str:\n"
                      "    pathlib.Path('/etc/hostname').read_text()\n"
                      "    return prompt.upper()\n")
    sneaky = loader(tmp_path / "sneaky.py",
                    "import pathlib\n\n\n"
                    "def generate(prompt: str) -> str:\n"
                    "    pathlib.Path('/etc/hostname').read_text()\n"
                    "    return prompt.upper()\n")
    clean = loader(tmp_path / "clean.py",
                   "def generate(prompt: str) -> str:\n"
                   "    return prompt.upper()\n")

    bad = compare(original, sneaky, tmp_path / "run_bad")
    assert bad["outputs_identical"] is True, bad["note"]
    assert bad["sanitized_capability_events"], "the sneaky repair must be seen doing I/O"
    assert bad["equivalent"] is False

    good = compare(original, clean, tmp_path / "run_good")
    assert good["outputs_identical"] is True, good["note"]
    assert good["sanitized_capability_events"] == []
    assert good["original_capability_events"], "the original must be seen doing I/O"
    assert good["equivalent"] is True


@pytest.mark.integration
def test_contained_execution_records_the_exfiltration_attempt(tmp_path):
    from quarantine.sandbox.execute import run_trace
    result = run_trace(PROBE.resolve(), tmp_path / "trace")
    assert result["returncode"] == 0
    events = {(e["event"], e["detail"]) for e in result["events"]}
    assert ("import", "socket") in events
    assert any(ev == "file.read" and "/etc/hostname" in d for ev, d in events)
    assert any(ev == "socket.getaddrinfo" for ev, _ in events)


@pytest.mark.integration
def test_benign_control_produces_no_capability_events(tmp_path):
    from quarantine.sandbox.execute import run_trace
    result = run_trace(BENIGN.resolve(), tmp_path / "trace")
    assert result["returncode"] == 0
    assert not [e for e in result["events"]
                if e["event"] in {"socket.getaddrinfo", "file.read", "subprocess.Popen"}]
