# The business case

**Product:** Quarantine — the offline clean room for untrusted model artifacts
**Companion:** [`README.md`](../README.md) (what it does) · [`SPIKE-RESULTS.md`](../SPIKE-RESULTS.md) (what was measured) · [`EVENT-REQUIREMENTS.md`](EVENT-REQUIREMENTS.md) (the organisers' terms, mapped)

**How to read the numbers.** Every figure is marked **[verified]** (source linked), **[derived]** (arithmetic on a
verified figure, assumptions stated), or **[proposed]** (our decision, to be tested with design partners).
Nothing here is a forecast. The technical claims are weaker-labelled than usual for a business document
because **they are checkable in this repository** — each one links to the report that produced it.

---

## 1. The business in one sentence

Every organisation that pulls an open-weight model is executing a stranger's code. We sell the open tool that
runs it where it cannot hurt you, proves what it did, and repairs what it can — and because it runs entirely
on the customer's own hardware, it is the only one that can be sold into the air-gapped, IP-sensitive and
regulated environments where a cloud scanner is not allowed to look.

## 2. What this repository already proves

A business case built on unverifiable claims is worth nothing, so this section is deliberately first and every
line is a file in this repository.

| Claim | Evidence | Status |
|---|---|---|
| It detects what static scanners miss | 9/9 undeclared artifacts blocked, 0 false positives, 0 escalations, against 2/9 for each incumbent | [`reports/corpus-eval.md`](../reports/corpus-eval.md) |
| It does not cry wolf on real models | 20 real published models: 20 allowed, 0 blocked, 0 escalated — where fickling false-positives 18 of 20 | [`reports/corpus-real-eval.md`](../reports/corpus-real-eval.md) |
| The AI is load-bearing, not decorative | with the model endpoint closed, **0 of 13 artifacts can be allowed or blocked**; all 13 escalate | [`reports/delete-the-ai.md`](../reports/delete-the-ai.md) |
| A block is not a dead end | 9/9 blocked; 7 repairs attempted; 7/7 capability-clean; 6/7 verified equivalent on 12 prompts | [`reports/repair-eval.md`](../reports/repair-eval.md) |
| The box holds, as far as we attacked it | 10 breakout primitives, 0 escaped | [`reports/sandbox-escape.md`](../reports/sandbox-escape.md) |
| A verdict can be checked without trusting us | Ed25519 receipt, verified with `openssl` by a verifier that imports nothing from this project | [`tools/verify_receipt_standalone.py`](../tools/verify_receipt_standalone.py) |

**And the number that argues against us, in the same list:** on picklescan's own published corpus of 91
malicious samples, their denylist flags 88 (97%) and our contained observation sees 43 (47%). On that corpus
they win, and we publish it ([`reports/third-party-eval.md`](../reports/third-party-eval.md)). The honest
product claim is therefore **not a replacement for a pickle scanner — it is the half that opens the `.py` files
and repairs what it blocks.** A buyer who needs only pickle-opcode matching should keep the tool they have.

## 3. What is being bought

Not "AI security" in general. A specific, newly created workflow: **artifact admission control** — the decision
to let a third-party model artifact into a training or serving environment, and the evidence that justifies it
to someone who was not in the room. Today that decision is made by a human reading a README, or by a static
scanner that provably misses.

Three structural shifts created the market:

1. **Code arrived inside the artifact.** `safetensors` closed the pickle hole; it did not close
   `trust_remote_code`, `custom_generate`, custom tokenizers and processors. The risk moved from *data* to
   *code*, and the tooling did not move with it.
2. **Provenance became mandatory and insufficient.** Model signing answers *who published it*. Buyers now need
   *what it does*, because they have to defend the decision — and a signature says nothing about behaviour.
3. **The highest-value buyers cannot use the cloud.** A fine-tune is a company's IP; a customer's model is
   regulated data; registry audits happen air-gapped. Cloud-assisted scanning is structurally excluded from
   that segment.

**Why now, with sources:**

| Fact | Source |
|---|---|
| picklescan reported "no issues" on a pickle that read `/etc/passwd` and exfiltrated it over DNS | [CVE-2025-46417 / GHSA-93mv-x874-956g](https://osv.dev/vulnerability/GHSA-93mv-x874-956g) |
| Transformers wrote attacker-controlled `custom_generate/generate.py` to disk before the consent check | [CERT VU#456290](https://kb.cert.org/vuls/id/456290) |
| ~3 million public models on Hugging Face | [HF blog](https://huggingface.co/blog/ivanfioravanti/three-million-models-and-counting) |
| The incumbent AI-security vendor's published price band is $0–$100,000/year (acquired by Palo Alto Networks) | [CostBench, Jul 2026](https://costbench.com/software/ai-security/protect-ai/) |

## 4. Customers and buyers

| Segment | Who feels the pain | Who signs | Trigger | Priority |
|---|---|---|---|---|
| **AI-heavy product companies** | ML platform / AppSec engineers pulling weights weekly | Head of Security or ML Platform | a near-miss, or a customer questionnaire asking "how do you vet models?" | **1 — beachhead** |
| **Regulated enterprise** (bank, insurer, hospital) | third-party / model risk teams | CISO, Model Risk Committee | model-risk policy extended to third-party weights | 2 |
| **Air-gapped / defence-adjacent** | secure-enclave operators | programme security lead | a supply-chain incident report | 3 — highest ACV, longest cycle |
| **Registries and platforms** | platform trust & safety | Head of Platform | a published malicious-model incident | 4 — partner, not customer |
| **Open-source maintainers** | maintainers vendoring models | *nobody — free forever* | — | funnel, not revenue |

**The wedge:** segment 1 pays fastest and produces the case studies that unlock 2 and 3. Segment 5 is the
distribution engine — the corpus and a one-line CI action are how the tool reaches engineers without a sales
team.

## 5. Packaging and unit economics

| Tier | What it is | Price | Serves |
|---|---|---|---|
| **Community** | Apache-2.0 CLI, the artifact corpus, the receipt format, the local evaluation harness. Fully functional and offline, unlimited local scans. | free | adoption; the corpus as public infrastructure |
| **Team** | CI gate: fails the pipeline on `BLOCK`, stores signed receipts, policy as code, PR annotations. Self-hosted. | $299–$999 / repo / month **[proposed]** | AI-heavy product companies |
| **Enterprise** | Air-gapped install path, registry integration, SSO and audit export, SLA, attestation feed, support. | $25k–$90k / year **[proposed]** | regulated and air-gapped |
| **Attestation** | We countersign a receipt for an artifact you publish. | per artifact **[proposed]** | registries, model publishers |

**Why open core is the right shape here rather than an ideology:** the corpus and the CLI *are* the trust
artifact — a closed behavioural scanner cannot be used as evidence. The paid layer is the operational envelope
(CI integration, policy, attestation, support, air-gap) that enterprises buy as a matter of course.

Local-first execution is the structural advantage: **we do not pay for inference, and neither does the
customer.**

| Line | Value | Note |
|---|---|---|
| Blended ARPU | $18,000/yr **[proposed]** | below the incumbent's $100k top, above the ~$10k enterprise floor |
| COGS per account | $1,500–$4,000/yr **[derived]** | support, attestation hosting and release engineering; **no inference cost** |
| Gross margin | 78–92% **[derived]** | software-like, because the compute is the customer's |
| CAC | $2,000–$6,000 self-serve · $10,000–$20,000 enterprise **[derived]** | open-source inbound vs a security review |
| **LTV/CAC** | **~8× self-serve · 2–4× enterprise [derived]** | viable, not a land-grab: enterprise must be sold, not marketed |
| Payback | 4–10 months **[derived]** | |

**A scenario, not a projection.** Paid accounts only, ARPU rising with enterprise mix, 85% gross margin:

| | Y1 (to Oct 2027) | Y2 | Y3 |
|---|---|---|---|
| Paid accounts | 8–12 | 25–40 | 60–90 |
| Exit ARR | **$150k–$215k** | **$525k–$840k** | **$1.4M–$2.2M** |

The single number that decides whether any of this is true is the conversion rate from free CLI users to paid
CI accounts, and it is measurable from month four. **No part of this has been market-tested.**

## 6. Go-to-market, and why Nepal first

**Phase 0 — credibility (months 0–6).** Ship the corpus and the head-to-head numbers, including the ones we
lose. A CI action anyone can add in one line. Target: 1,000 installs, 10 external contributors. Cost: near zero.
Asset created: the reference corpus.

**Phase 1 — the CI gate (months 4–14).** Convert pipelines into paid Team accounts; design partners recruited
from Phase 0 users. Target: 8–12 paid accounts, the Y1 ARR above.

**Phase 2 — the air gap (months 12–30).** Enterprise and regulated: air-gapped install path, support SLA, SOC 2
readiness. Partner with registries rather than competing with them.

**The regional beachhead is the cheapest route to a reference customer, not sentiment.** The product's
constraint is also its fit here: no paid API key, no vendor account, no reliable bandwidth required. For a
Kathmandu consultancy with intermittent connectivity and a client whose data cannot leave the country, that is
the difference between deployable and not deployable — and the same property sells later into India's
offshore-services market and into any regulated buyer.

**The hook is a finding, not a pitch.** Pointing the tool at 268 Nepali and Indic repositories found **46
shipping `.py` files and 15 declaring `auto_map`** — models that force `trust_remote_code=True` and are
invisible to both incumbent scanners ([`docs/NEPAL.md`](NEPAL.md)). A Nepali model author can be shown, in one
command, whether their own artifact is checkable. **We would not open with government or the central bank:**
those cycles are long, the compliance drivers are not local, and a small team should spend its first year on
buyers who can say yes in a week.

## 7. Competition, and what the moat actually is

| Competitor | Their strength | Why this wins the segment |
|---|---|---|
| **Protect AI / ModelScan** (Palo Alto) | brand, distribution, $0–$100k band, OSS scanner | static/signature paradigm; cloud-assisted posture excluded from air-gapped buyers |
| **picklescan / fickling** | free, familiar, already in the pipeline | demonstrably bypassable ([CVE-2025-46417](https://osv.dev/vulnerability/GHSA-93mv-x874-956g)); no verdict, no repair, no receipt — and they do not open `.py` files at all |
| **Hugging Face hub scanning** | platform-side default for everyone | upload-time, platform-scoped, static: says nothing about *your* copy in *your* environment |
| **Software-supply-chain platforms** | strong for packages and containers | not aimed at `trust_remote_code` semantics; cloud-first |
| **Doing nothing** | free | the incumbent until an incident; the job is to make the cost of the incident legible |

**Moat, ranked honestly:** (1) the **published behavioural corpus with labels, receipts and the measurements we
lose** — competitors cannot copy it without doing the work; (2) the **offline position**, structurally
unavailable to cloud vendors; (3) the **repair path**, which nothing else ships; (4) switching cost once
receipts are wired into CI and audit trails. **Not a moat:** the sandbox — that is engineering, not
defensibility.

## 8. Intellectual property — what is actually ownable

The grand prize is described as a patent filing, so this gets a straight answer rather than optimism. **Most of
this product is deliberately not ownable.**

The code is Apache-2.0 and stays that way. Anyone can read `is_serialization_helper` and reimplement the
container checks in an afternoon; fencing it off would cost the thing that matters for a security tool —
adoption, and therefore the corpus and the receipts that flow back.

Prior art is dense where a filing looks most tempting: static pickle scanning is picklescan, fickling and
ModelScan; containment is a well-trodden pattern; output-equivalence testing is as old as compilers.

| Asset | Defensible? | Why |
|---|---|---|
| **The labelled corpus and evaluation harness** | yes, as a data/benchmark asset | 13 labelled artifacts with benign counterparts plus 20 English and 5 Nepali/Indic third-party controls, reproducible from scripts. Competitors can copy the code in a day; the corpus takes far longer |
| **The receipt format** | yes, by adoption | value comes from an auditor, a customer and a regulator accepting the same signed artifact. Standards win by being adopted — the SLSA/in-toto playbook |
| **The deterministic admissibility rule** | **the one place a filing is defensible** | an `ALLOW` admitted only when the harness independently counted zero capability events from a contained run, with the verdict bound to a re-derivable trace inside a signed receipt. A specific mechanism, not a category |
| **The brand** | yes, slowly | "Quarantine" as a class name for artifact containment, if the tool is adopted |

**Freedom to operate.** picklescan and fickling are invoked as *measurement* tools in `scripts/` and declared in
`requirements-dev.txt`, never imported on the analysis path — enforced by
[`scripts/check_eligibility.py`](../scripts/check_eligibility.py). No code is copied from them.

**This is a judgement about defensibility, not legal advice.** No patent search has been run and no attorney
consulted; the cited prior art was read as tools, not as claims.

## 9. Risks, including the ones we cause

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| 1 | **Sandbox escape while doing the job** — we execute untrusted code for a living | high | no network, read-only root, dropped capabilities, resource limits, throwaway containers; the isolation design and the 10-primitive escape attempt are published; insurance before enterprise sales |
| 2 | **Detection is limited to what the payload does** | high | stated plainly in [`LIMITATIONS.md`](../LIMITATIONS.md): a payload that never acts is not observed. This is why the pickle scanners remain the other half |
| 3 | **"The platform vendors bundle it"** | high | stay open and behavioural; serve the air-gapped segment they cannot; make the corpus the ecosystem default |
| 4 | **Open-core monetization fails** | high | paid tier and design partners from month four; grants and prizes are runway, never the model |
| 5 | **Local model quality causes false positives** | medium | `UNKNOWN` as a first-class verdict; the measured noise floor; the false-positive rate on 20 real models is published |
| 6 | **Legal exposure from handling malware** | medium | publish recipes and benign replicas rather than live samples; never execute on the host; clear acceptable-use terms |
| 7 | **Adoption is invisible** | low | receipts land in CI and audit trails by design |

## 10. Impact

The problem being made smaller: **malicious model artifacts entering production because the only cheap check is
a scanner that misses.** The outputs are an open tool, a labelled public corpus, and durable signed receipts.
The outcome is fewer compromised deployments and a buyer who can defend the decision. Even where a scan is lost
to a competitor, a published corpus of what scanners miss raises the floor for everyone using open weights.

## 11. What could not be verified

This section exists because the rest of the document would be worth less without it.

- **No customer has been asked for money.** Not one design partner, letter of intent or pilot. The Nepal
  beachhead is reasoning about reachability and cost, not evidence of demand.
- **The pricing is [proposed], not tested.** Protect AI's published band and the ~$10k enterprise floor are the
  anchors; no comparable open-core security tool's actual contract values were obtainable.
- **The market sizing is a sanity check, not a study.** The "organisations running third-party open weights in
  production" figure is a [derived] assumption, and it is the single most important unknown here.
- **Grant availability changes.** Every programme named in the funding plan must be checked for a live window
  before applying.
- **No external party has verified a receipt.** The keys are self-signed and published; what has been verified
  is that the signature checks out under `openssl` and that tampering is detected. That is not the same as a
  third party attesting to a verdict.
- **The product's own limits are documented, not solved.** [`LIMITATIONS.md`](../LIMITATIONS.md) lists 19 of
  them, and 32 defects were found by running the tool — most of them ours.
