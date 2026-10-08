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
                      "dangerous": 0, "says_clean": True,
                      "verdict_malicious": False, "flagged_anything": False}


def test_picklescan_verdict_is_kept_apart_from_a_suspicious_global():
    """A benign pickle that mentions json.dumps is 'suspicious', not infected.

    Conflating the two would let a comparison overstate detections *or* false positives,
    depending on which argument it was making. picklescan's own verdict is `infected`.
    """
    run = {"stdout": ("----------- SCAN SUMMARY -----------\nScanned files: 1\n"
                      "Infected files: 0\nSuspicious globals: 1\nDangerous globals: 0\n")}
    parsed = parse_picklescan(run)
    assert parsed["says_clean"] is False          # something was said
    assert parsed["verdict_malicious"] is False   # but it was not called malicious
    assert parsed["flagged_anything"] is True


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


# --------------------------------------------------------- weight-file reader

def test_only_tensor_machinery_is_stubbed_never_anything_that_can_do_io():
    """The allowlist is the security boundary: stub the serialization scaffolding, nothing else."""
    from quarantine.sandbox_runner import is_serialization_helper
    assert is_serialization_helper("torch._utils", "_rebuild_tensor_v2")
    assert is_serialization_helper("torch", "LongStorage")
    assert is_serialization_helper("torch.storage", "UntypedStorage")
    assert is_serialization_helper("numpy.core.multiarray", "_reconstruct")
    assert is_serialization_helper("collections", "OrderedDict")
    for module, name in (("ssl", "get_server_certificate"), ("socket", "getaddrinfo"),
                         ("os", "system"), ("subprocess", "Popen"), ("builtins", "eval"),
                         ("torch", "load"), ("numpy", "load")):
        assert not is_serialization_helper(module, name), f"{module}.{name} must never be stubbed"


def test_the_reader_opens_a_torch_zip_and_actually_runs_the_pickle_inside(tmp_path):
    """The whole point of the format fix: the pickle inside a checkpoint must execute."""
    import os as _os
    import pickle as _pickle
    import zipfile
    from quarantine.sandbox_runner import load_weights

    class Probe:
        def __reduce__(self):
            return (_os.getcwd, ())          # a real call with an observable result

    path = tmp_path / "model.bin"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("archive/data.pkl", _pickle.dumps({"a": Probe()}))
        zf.writestr("archive/data/0", b"\x00" * 8)

    notes: list[dict] = []
    obj, how = load_weights(str(path), notes)
    assert how == "zip:archive/data.pkl"
    assert isinstance(obj["a"], str) and obj["a"], "the embedded pickle did not run"
    assert notes == []


def test_serialization_scaffolding_is_not_evidence_of_capability():
    """Asking for a global is intent, not capability.

    Two rounds of controls were needed. First, reading torch checkpoints made every
    legitimate model ask for `collections.OrderedDict`, `torch._utils._rebuild_tensor_v2`
    and `torch.LongStorage`. Then a benign control group showed we were still counting
    *every* requested global — so an ordinary pickle mentioning `json.dumps` looked
    suspicious. Only unambiguous execution/IO globals count now.
    """
    from quarantine.events import capability_events
    events = [
        {"i": 1, "event": "pickle.find_class", "detail": "collections.OrderedDict"},
        {"i": 2, "event": "pickle.find_class", "detail": "torch._utils._rebuild_tensor_v2"},
        {"i": 3, "event": "pickle.find_class", "detail": "torch.LongStorage"},
        {"i": 4, "event": "pickle.find_class", "detail": "ssl.get_server_certificate"},
        {"i": 5, "event": "pickle.find_class", "detail": "builtins.eval"},
        {"i": 6, "event": "socket.getaddrinfo", "detail": "x.invalid"},
        # benign standard-library calls a legitimate pickle makes
        {"i": 7, "event": "pickle.find_class", "detail": "json.dumps"},
        {"i": 8, "event": "pickle.find_class", "detail": "math.sqrt"},
        {"i": 9, "event": "pickle.find_class", "detail": "posix.getcwd"},
        {"i": 10, "event": "pickle.find_class", "detail": "re.compile"},
        {"i": 11, "event": "pickle.find_class", "detail": "datetime.datetime"},
        # a recursive load counts only inside a loader module
        {"i": 12, "event": "pickle.find_class", "detail": "pickle.load"},
        {"i": 13, "event": "pickle.find_class", "detail": "json.load"},
    ]
    assert [e["i"] for e in capability_events(events)] == [4, 5, 6, 12]


def test_an_unresolvable_global_is_recorded_not_silently_stubbed():
    import io
    from quarantine.sandbox_runner import AuditUnpickler

    notes: list[dict] = []
    unpickler = AuditUnpickler(io.BytesIO(b""), notes)
    try:
        unpickler.find_class("a_module_that_does_not_exist", "f")
        raise AssertionError("expected the unresolved global to raise")
    except AssertionError:
        raise
    except Exception:
        pass
    assert notes and notes[0]["event"] == "unresolved"
    assert notes[0]["global"] == "a_module_that_does_not_exist.f"


def test_a_known_tensor_helper_is_stubbed_and_recorded():
    import io
    from quarantine.sandbox_runner import AuditUnpickler

    notes: list[dict] = []
    helper = AuditUnpickler(io.BytesIO(b""), notes).find_class("torch", "LongStorage")
    assert callable(helper)
    assert notes == [{"event": "stubbed", "global": "torch.LongStorage"}]


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


# ------------------------------------------------------- safetensors container

def _write_safetensors(path, index=None, header_bytes=None, pad=b"\x00" * 16):
    import json as _json
    import struct as _struct
    blob = header_bytes if header_bytes is not None else _json.dumps(
        index if index is not None else {"weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}
    ).encode()
    path.write_bytes(_struct.pack("<Q", len(blob)) + blob + pad)
    return path


def test_a_valid_safetensors_container_is_read_and_needs_no_pickle(tmp_path):
    """The format cannot execute code, so validating it is a conclusion, not a guess."""
    from quarantine.sandbox_runner import load_weights
    path = _write_safetensors(tmp_path / "model.safetensors")
    notes: list[dict] = []
    index, how = load_weights(str(path), notes)
    assert how == "safetensors"
    assert "weight" in index
    assert notes and notes[0]["event"] == "safetensors"


def test_every_real_safetensors_repo_is_now_examined_rather_than_escalated(tmp_path):
    """Before this, a safetensors-only repository was escalated: nothing to read."""
    from quarantine.agents.case import Case
    case = Case(name="m", root=tmp_path,
                execution={"weights_loaded": [{"file": "model.safetensors",
                                               "status": "loaded", "how": "safetensors"}]})
    assert case.observed is True
    assert case.escalation_reason is None
    assert case.capability_events == []


@pytest.mark.parametrize("broken", ["truncated", "not-json", "empty-object", "bad-index"])
def test_a_malformed_container_is_rejected_not_trusted(tmp_path, broken):
    from quarantine.sandbox_runner import load_weights
    path = tmp_path / "model.safetensors"
    if broken == "truncated":
        path.write_bytes(b"\x40\x00")                          # header claims 64, file has 2
    elif broken == "not-json":
        _write_safetensors(path, header_bytes=b"this is not json")
    elif broken == "empty-object":
        _write_safetensors(path, header_bytes=b"{}")
    else:
        _write_safetensors(path, header_bytes=b'{"weight": {"dtype": "F32"}}')  # no shape
    with pytest.raises(Exception):
        load_weights(str(path), [])


def test_a_pickle_renamed_safetensors_is_rejected_rather_than_trusted(tmp_path):
    """The dangerous direction: claiming a safe suffix must not buy a pass.

    A plain pickle renamed to `.safetensors` fails validation, which routes it to the
    escalation path — never to ALLOW.
    """
    import os as _os
    import pickle as _pickle
    from quarantine.sandbox_runner import load_weights

    class Probe:
        def __reduce__(self):
            return (_os.getcwd, ())

    path = tmp_path / "model.safetensors"
    path.write_bytes(_pickle.dumps({"x": Probe()}))
    with pytest.raises(Exception):
        load_weights(str(path), [])


# ------------------------------------------------------------- gguf container

def _write_gguf(path, magic=b"GGUF", version=3, tensors=4, kv=2, key=b"general.architecture"):
    import struct as _struct
    head = magic + _struct.pack("<IQQ", version, tensors, kv)
    path.write_bytes(head + _struct.pack("<Q", len(key)) + key + b"\x00" * 64)
    return path


def test_a_valid_gguf_container_is_read_and_needs_no_pickle(tmp_path):
    """GGUF is how the Nepali ecosystem mostly ships models; nothing in it can execute."""
    from quarantine.sandbox_runner import load_weights
    path = _write_gguf(tmp_path / "model.gguf")
    notes: list[dict] = []
    info, how = load_weights(str(path), notes)
    assert how == "gguf"
    assert info["tensor_count"] == 4 and info["version"] == 3
    assert notes and notes[0]["event"] == "gguf"


def test_a_gguf_only_repository_is_examined_rather_than_escalated(tmp_path):
    from quarantine.agents.case import Case
    case = Case(name="nepali", root=tmp_path,
                execution={"weights_loaded": [{"file": "model.gguf", "status": "loaded",
                                               "how": "gguf"}]})
    assert case.observed is True
    assert case.escalation_reason is None
    assert case.capability_events == []


@pytest.mark.parametrize("broken", ["bad-magic", "short", "bad-version", "zero-tensors", "bad-key"])
def test_a_malformed_gguf_is_rejected_not_trusted(tmp_path, broken):
    from quarantine.sandbox_runner import load_weights
    path = tmp_path / "model.gguf"
    if broken == "bad-magic":
        _write_gguf(path, magic=b"PK\x03\x04")
    elif broken == "short":
        path.write_bytes(b"GGUF")
    elif broken == "bad-version":
        _write_gguf(path, version=99)
    elif broken == "zero-tensors":
        _write_gguf(path, tensors=0)
    else:
        _write_gguf(path, key=b"\xff\xfe not utf8")
    with pytest.raises(Exception):
        load_weights(str(path), [])


def test_a_pickle_renamed_gguf_is_rejected_rather_than_trusted(tmp_path):
    """Claiming the safe suffix must not buy a pass down the escalation path."""
    import os as _os
    import pickle as _pickle
    from quarantine.sandbox_runner import load_weights

    class Probe:
        def __reduce__(self):
            return (_os.getcwd, ())

    path = tmp_path / "model.gguf"
    path.write_bytes(_pickle.dumps({"x": Probe()}))
    with pytest.raises(Exception):
        load_weights(str(path), [])


# -------------------------------------- partial observation and block grounding

def test_custom_code_that_cannot_run_is_escalated_even_when_weights_loaded():
    """The real published case: rotary-indictrans2.

    Its `modeling_*.py` imports torch, so the code path never ran — while its pickle weights
    loaded fine, which made the case look "observed". Not escalating let the analyst treat
    the ModuleNotFoundError as evidence and BLOCK a benign model.
    """
    case = _case(static={"custom_code_files": ["modeling_rotary_indictrans.py"]},
                 execution={"weights_loaded": [{"file": "pytorch_model.bin"}],
                            "errors": ["modeling_rotary_indictrans.py: ModuleNotFoundError: torch"]})
    assert case.observed is True          # the weights did load
    assert case.code_path_unrun is True   # the code path did not
    assert case.escalation_reason is not None
    assert "code path was never observed" in case.escalation_reason


def test_shipped_code_that_acted_before_dying_is_still_judged():
    """`probe-obfuscated` performs its DNS call and *then* dies. That is evidence, not noise."""
    case = _case(static={"custom_code_files": ["custom_generate/generate.py"]},
                 execution={"errors": ["gaierror(-3, ...)"]},
                 events=[{"i": 1, "event": "socket.getaddrinfo", "detail": "x.invalid"}])
    assert case.code_path_unrun is False
    assert case.escalation_reason is None
    assert case.capability_ids == [1]


def test_a_block_must_cite_a_capability_event_not_an_error():
    """An error means we could not look; it is not an observed capability."""
    from quarantine.semantic.analyst import verdict_is_grounded
    valid, caps = {1, 2, 3}, {3}
    assert verdict_is_grounded("BLOCK", [3], valid, caps) is True     # cites the capability
    assert verdict_is_grounded("BLOCK", [1], valid, caps) is False    # cites an error only
    assert verdict_is_grounded("BLOCK", [1, 3], valid, caps) is True  # cites both
    assert verdict_is_grounded("BLOCK", [], valid, caps) is False     # cites nothing
    assert verdict_is_grounded("BLOCK", [99], valid, caps) is False   # cites a phantom id
    assert verdict_is_grounded("ALLOW", [], valid, set()) is True     # no capability observed
    assert verdict_is_grounded("ALLOW", [], valid, caps) is False     # capability observed
    assert verdict_is_grounded("UNKNOWN", [], valid, caps) is True    # abstention is always admissible


# ------------------------------------------------- the measured noise floor

def test_noise_key_ignores_the_random_part_of_a_temporary_path():
    from quarantine.events import noise_key
    assert noise_key("os.mkdir", "/tmp/torchinductor_uid_1000") == noise_key("os.mkdir", "/tmp/fleig390")
    assert noise_key("ctypes.dlopen", "/usr/lib/libtorch.so") != noise_key("ctypes.dlopen", "/usr/lib/libevil.so")


def test_a_measured_noise_floor_is_subtracted_from_the_trace(tmp_path, monkeypatch):
    """What the image does by importing its own libraries is not the artifact's behaviour."""
    import json as _json
    from quarantine import events as ev

    floor = tmp_path / "floor.jsonl"
    floor.write_text(
        _json.dumps({"event": "ctypes.dlopen", "detail": "/usr/lib/libtorch.so"}) + "\n"
        + _json.dumps({"event": "os.mkdir", "detail": "/tmp/torchinductor_uid_1000"}) + "\n",
        encoding="utf-8")

    monkeypatch.setattr(ev, "baseline_path", lambda image=None: floor)
    ev._BASELINE_CACHE.clear()
    trace = [
        {"i": 1, "event": "ctypes.dlopen", "detail": "/usr/lib/libtorch.so"},   # in the floor
        {"i": 2, "event": "os.mkdir", "detail": "/tmp/torchinductor_uid_1000"},  # in the floor
        {"i": 3, "event": "socket.getaddrinfo", "detail": "exfil.invalid"},      # never in the floor
        {"i": 4, "event": "ctypes.dlopen", "detail": "/tmp/evil.so"},            # a different library
    ]
    assert [e["i"] for e in ev.capability_events(trace)] == [3, 4]
    ev._BASELINE_CACHE.clear()


def test_an_unmeasured_image_subtracts_nothing(tmp_path, monkeypatch):
    """A missing noise floor must fail safe: nothing is excused."""
    from quarantine import events as ev
    monkeypatch.setattr(ev, "baseline_path", lambda image=None: tmp_path / "does-not-exist.jsonl")
    ev._BASELINE_CACHE.clear()
    trace = [{"i": 1, "event": "ctypes.dlopen", "detail": "/usr/lib/libtorch.so"}]
    assert [e["i"] for e in ev.capability_events(trace)] == [1]
    ev._BASELINE_CACHE.clear()


# ------------------------------------------- independent receipt verification

def _root() -> Path:
    return CORPUS.parent


def _run_standalone(receipt, pub):
    """Run the standalone verifier as a subprocess — it must not need our package.

    The environment is deliberately stripped: no PYTHONPATH, so an accidental import of
    `quarantine` would fail rather than silently succeed.
    """
    import os
    import subprocess
    import sys
    return subprocess.run(
        [sys.executable, str(_root() / "tools" / "verify_receipt_standalone.py"),
         str(receipt), "--pub", str(pub)],
        capture_output=True, text=True, timeout=120, cwd=str(_root()),
        env={"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "")})


def test_a_receipt_verifies_without_importing_our_code_or_our_dependencies():
    """Ed25519 checked by openssl: a different implementation than the one that signed it."""
    receipt = _root() / "runs" / "probe" / "receipt.json"
    pub = _root() / "runs" / "probe" / "keys" / "quarantine.pub.pem"
    if not (receipt.exists() and pub.exists()):
        pytest.skip("committed probe receipt not present")
    if not __import__("shutil").which("openssl"):
        pytest.skip("openssl not available")
    done = _run_standalone(receipt, pub)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "VERIFIED" in done.stdout
    assert "Signature Verified Successfully" in done.stdout


def test_the_standalone_verifier_rejects_a_payload_with_the_verdict_flipped(tmp_path):
    """The forgery that matters: BLOCK edited to ALLOW, signature left in place."""
    import base64 as _b64
    import json as _json
    receipt = _root() / "runs" / "probe" / "receipt.json"
    pub = _root() / "runs" / "probe" / "keys" / "quarantine.pub.pem"
    if not (receipt.exists() and pub.exists()):
        pytest.skip("committed probe receipt not present")
    if not __import__("shutil").which("openssl"):
        pytest.skip("openssl not available")
    envelope = _json.loads(receipt.read_text(encoding="utf-8"))
    payload = _json.loads(_b64.b64decode(envelope["payload"]))
    assert payload["verdict"]["decided"] == "BLOCK"
    payload["verdict"]["decided"] = "ALLOW"
    forged = tmp_path / "forged.json"
    forged.write_text(_json.dumps({
        "payloadType": envelope["payloadType"],
        "payload": _b64.b64encode(_json.dumps(
            payload, sort_keys=True, separators=(",", ":")).encode()).decode(),
        "signatures": envelope["signatures"],
    }), encoding="utf-8")
    done = _run_standalone(forged, pub)
    assert done.returncode == 1
    assert "NOT VERIFIED" in done.stdout


def test_the_standalone_verifier_rejects_an_unrelated_key(tmp_path):
    receipt = _root() / "runs" / "probe" / "receipt.json"
    pub = _root() / "runs" / "probe" / "keys" / "quarantine.pub.pem"
    if not (receipt.exists() and pub.exists()):
        pytest.skip("committed probe receipt not present")
    if not __import__("shutil").which("openssl"):
        pytest.skip("openssl not available")
    other = tmp_path / "other.pem"
    key = tmp_path / "other.key"
    __import__("subprocess").run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)], capture_output=True)
    __import__("subprocess").run(
        ["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(other)], capture_output=True)
    done = _run_standalone(receipt, other)
    assert done.returncode == 1
    assert "does not match the public key" in done.stdout


# ---------------------------------------- the model-calling success paths

def test_the_analyst_success_path_with_a_stubbed_model(monkeypatch):
    """Hermetic: no model server needed, and it covers the path a shipped bug escaped through.

    A refactor deleted the module's MODEL constant and left `out["model"] = resolve_model(MODEL)`
    behind it. The delete-the-AI experiment returned early and never reached that line, the suite
    exercised no *successful* analysis, and the first real artifact crashed with NameError. A
    stubbed client closes that hole and runs in CI.
    """
    from quarantine.semantic import analyst

    monkeypatch.setattr(analyst, "resolve_model", lambda name: "stub-model")
    monkeypatch.setattr(analyst.llm, "chat", lambda messages, schema=None, **kw: (
        '{"verdict":"BLOCK","declared_matches_behaviour":false,'
        '"mechanism":"read outside its directory","evidence_ids":[2],"confidence":0.9}', None))

    events = [{"i": 1, "event": "import", "detail": "socket"},
              {"i": 2, "event": "file.read", "detail": "/etc/hostname"}]
    out = analyst.analyse_artifact("declared: a pure text transform", "code", events,
                                   {"capability_graph": {}}, {})
    assert out["reachable"] is True
    assert out["verdict"]["verdict"] == "BLOCK"
    assert out["grounded"] is True
    assert out["cited_ids"] == [2]
    assert out["model"] == "stub-model"           # the line that crashed


def test_the_analyst_retries_when_a_block_cites_no_capability_event(monkeypatch):
    """An ungrounded first answer is rejected and re-asked, never accepted."""
    from quarantine.semantic import analyst

    calls: list[int] = []

    def fake_chat(messages, schema=None, **kw):
        calls.append(1)
        if len(calls) == 1:      # cites a context event, so the block is inadmissible
            return ('{"verdict":"BLOCK","declared_matches_behaviour":false,"mechanism":"m",'
                    '"evidence_ids":[1],"confidence":0.5}', None)
        return ('{"verdict":"BLOCK","declared_matches_behaviour":false,"mechanism":"m",'
                '"evidence_ids":[2],"confidence":0.9}', None)

    monkeypatch.setattr(analyst, "resolve_model", lambda name: "stub-model")
    monkeypatch.setattr(analyst.llm, "chat", fake_chat)
    events = [{"i": 1, "event": "artifact.error", "detail": "boom"},
              {"i": 2, "event": "socket.getaddrinfo", "detail": "x.invalid"}]
    out = analyst.analyse_artifact("declared: no network", "code", events,
                                   {"capability_graph": {}}, {})
    assert len(calls) == 2, "the ungrounded block should have been re-asked"
    assert out["grounded"] is True
    assert out["cited_ids"] == [2]


def test_the_analyst_reports_an_unreachable_model_without_raising(monkeypatch):
    """An outage must surface as a reason, not as a traceback."""
    from quarantine.semantic import analyst

    def dead(messages, schema=None, **kw):
        raise analyst.llm.ModelUnreachable("URLError: connection refused")

    monkeypatch.setattr(analyst.llm, "chat", dead)
    out = analyst.analyse_artifact("d", "c", [{"i": 1, "event": "import", "detail": "x"}],
                                   {"capability_graph": {}}, {})
    assert out["reachable"] is False
    assert "connection refused" in out["error"]


def test_the_repairer_success_path_with_a_stubbed_model(monkeypatch):
    """The harness assembles the file; the model only writes bodies."""
    from quarantine.repair import loader

    monkeypatch.setattr(loader, "resolve_model", lambda name: "stub-model")
    # The contract is specific: `body` is one string per line and `args` is required,
    # because the harness writes the def line and the model only writes the body.
    monkeypatch.setattr(loader.llm, "chat", lambda messages, schema=None, **kw: (
        '{"functions":[{"name":"generate","args":"prompt",'
        '"body":["return prompt.strip()"]}],"removed":["_sync"]}', None))
    out = loader.synthesize_loader("declared: a pure text transform",
                                   "def generate(prompt):\n    _sync()\n    return prompt\n",
                                   {"verdict": "BLOCK", "mechanism": "network on load"})
    assert out["ok"] is True
    assert "def generate(prompt)" in out["code"], "the harness must write the def line and args"
    assert "return prompt.strip()" in out["code"]
    assert out["forbidden"] == []


@pytest.mark.integration
def test_the_whole_loop_on_a_known_probe(tmp_path):
    """One artifact through the whole agent team, against the real local model.

    Marked integration because it needs llama.cpp on 127.0.0.1:8081 and Docker; it skips
    rather than fails when either is absent, so CI stays green without them.
    """
    from quarantine.agents.supervisor import run_case

    probe = CORPUS / "probe-custom-generate"
    if not probe.exists():
        pytest.skip("corpus not present")
    try:
        llm_probe = __import__("quarantine.llm", fromlist=["chat"]).chat(
            [{"role": "user", "content": "reply with the single word: ok"}], max_tokens=5)
        del llm_probe
    except Exception:                                  # noqa: BLE001
        pytest.skip("local model server not reachable")

    outcome = run_case(probe, tmp_path / "e2e")
    assert outcome.decided == "BLOCK"
    assert outcome.escalated is False
    assert outcome.analysis and outcome.analysis["grounded"] is True
    assert outcome.repair and outcome.repair["ok"] is True
    assert outcome.equivalence and outcome.equivalence["equivalent"] is True
    assert len(outcome.transcript) >= 4, "the transcript should carry the whole team's notes"


# ---------------------------------------- the stated ground must be available

def test_the_reason_vocabulary_is_grammar_enforced():
    """The ground is a closed vocabulary, not free text.

    Free text is how a 7B model came to answer UNKNOWN with the mechanism "unresolved globals"
    on an artifact whose unresolved-globals count was zero.
    """
    from quarantine.semantic.analyst import REASONS, REASON_VERDICT, verdict_schema

    schema = verdict_schema([1, 2, 3])
    assert schema["properties"]["reason"]["enum"] == list(REASONS)
    assert "reason" in schema["required"]
    assert set(REASON_VERDICT) == set(REASONS)


@pytest.mark.parametrize("reason,verdict,cap,unres,observed,admissible", [
    ("nothing_observed", "ALLOW", 0, 0, True, True),
    ("capability_observed", "BLOCK", 2, 0, True, True),
    ("nothing_run", "UNKNOWN", 0, 0, False, True),
    ("counters_incomplete", "UNKNOWN", 0, 1, True, True),
    ("evidence_ambiguous", "UNKNOWN", 0, 0, True, True),
    # the failure that motivated the rule: claiming partial counters when there are none
    ("counters_incomplete", "UNKNOWN", 0, 0, True, False),
    # claiming the artifact never ran when the harness watched it run
    ("nothing_run", "UNKNOWN", 0, 0, True, False),
    # asserting nothing happened when something did
    ("nothing_observed", "ALLOW", 1, 0, True, False),
    # a capability ground with no capability observed
    ("capability_observed", "BLOCK", 0, 0, True, False),
    # THE RULE CHECKS COUNTERS, NOT LABELS. A correct verdict with an imprecise or even a
    # contradictory label is accepted: `bert-tiny` was rejected here and lost its ALLOW.
    ("nothing_observed", "ALLOW", 0, 0, True, True),
    ("evidence_ambiguous", "ALLOW", 0, 0, True, True),
    ("nothing_observed", "UNKNOWN", 0, 0, True, True),
])
def test_reason_admissibility(reason, verdict, cap, unres, observed, admissible):
    from quarantine.semantic.analyst import reason_is_admissible

    ok, why = reason_is_admissible(reason, verdict, cap, unres, observed)
    assert ok is admissible, why


def test_a_ground_the_counters_contradict_is_recorded_but_does_not_veto(monkeypatch):
    """The measured policy: a false ground is annotated, not decisive.

    Enforcing it was tried and measured over two models and eleven artifacts. It never improved
    a decision - the 7B still abstained after three retries - and it cost two: a correct ALLOW
    rejected over a label, and `benign-unicode` escalated after its retries failed, taking the
    corpus from 0 escalations to 1. So the ground is carried into the receipt and the decision
    rests on the evidence ids.
    """
    from quarantine.semantic import analyst

    calls: list[str] = []

    def fake_chat(messages, schema=None, **kw):
        calls.append(messages[-1]["content"][-400:])
        if len(calls) == 1:
            # The 7B's answer: UNKNOWN blaming unresolved globals that the harness counted as 0.
            return ('{"verdict":"UNKNOWN","declared_matches_behaviour":false,'
                    '"mechanism":"unresolved globals","evidence_ids":[],"confidence":0.4,'
                    '"reason":"counters_incomplete"}', None)
        return ('{"verdict":"ALLOW","declared_matches_behaviour":true,'
                '"mechanism":"nothing capability-like happened","evidence_ids":[],'
                '"confidence":0.9,"reason":"nothing_observed"}', None)

    monkeypatch.setattr(analyst, "resolve_model", lambda name: "stub-model")
    monkeypatch.setattr(analyst.llm, "chat", fake_chat)
    events = [{"i": 1, "event": "import", "detail": "json"}]
    out = analyst.analyse_artifact(
        "declared: a pure text transform", "code", events, {"capability_graph": {}},
        execution={"executed": [{"file": "custom_generate/generate.py"}]},
    )
    assert len(calls) == 1, "an unavailable ground no longer spends a retry: that was measured"
    assert out["verdict"]["verdict"] == "UNKNOWN"
    assert out["grounded"] is True, "UNKNOWN is admissible, and the ground does not veto it"
    assert out["reason"] == "counters_incomplete"
    assert out["reason_ok"] is False, "but the contradiction is recorded for the receipt"
    assert "0 unresolved globals" in out["reason_why"]
    assert "nothing_observed" in out["admissible_reasons"]
    # and the label is not compared against the verdict: a loose label must not cost a decision
    from quarantine.semantic.analyst import reason_is_admissible
    assert reason_is_admissible("evidence_ambiguous", "ALLOW", 0, 0, True)[0] is True


def test_an_honest_abstention_is_still_allowed(monkeypatch):
    """evidence_ambiguous must survive, or the rule would eliminate abstention entirely."""
    from quarantine.semantic import analyst

    monkeypatch.setattr(analyst, "resolve_model", lambda name: "stub-model")
    monkeypatch.setattr(analyst.llm, "chat", lambda messages, schema=None, **kw: (
        '{"verdict":"UNKNOWN","declared_matches_behaviour":false,'
        '"mechanism":"the evidence fits neither case","evidence_ids":[],"confidence":0.3,'
        '"reason":"evidence_ambiguous"}', None))
    out = analyst.analyse_artifact(
        "declared: unclear", "code", [{"i": 1, "event": "import", "detail": "json"}],
        {"capability_graph": {}}, execution={"executed": [{"file": "x.py"}]},
    )
    assert out["verdict"]["verdict"] == "UNKNOWN"
    assert out["reason_ok"] is True
