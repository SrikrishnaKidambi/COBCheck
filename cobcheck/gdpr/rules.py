"""
cobcheck/gdpr/rules.py
───────────────────────
GDPR rule definitions R1–R9, grounded in the article text at
https://gdpr-info.eu/ (Art. 4, 5, 6, 9, 10, 32, 44), cross-checked against
Torre, Alferez, Soltana, Sabetzadeh, Briand, "Modeling Data Protection and
Privacy: Application and Experience with GDPR", SoSyM 20(6), 2021 — whose
GDPR conceptual model independently uses the same principle boundaries
(Integrity_And_Confidentiality, Lawfulness, Storage_Limitation, Data_Transfer
packages) this rule set is organised around.

Rule → Article → Fires When → Neutralised By
─────────────────────────────────────────────────────────────────────────────
R1   Art. 5(1)(f)  any PII -> log/display, unmasked            sanitiser on path
R1B  Art. 32       any PII -> log/display, unmasked            sanitiser on path
R2   Art. 6(1)     any PII -> any sink, no basis indicator      guard on path
R3   Art. 44       any PII -> external/cross-border sink        (structural)
R4   Art. 5(1)(f)  any PII -> file/DB at-rest, unencrypted      sanitiser on path
R4B  Art. 32       any PII -> file/DB at-rest, unencrypted      sanitiser on path
R5   Art. 9        special-category PII -> any sink,            explicit-consent
                    no explicit-consent indicator                 guard on path
R6   Art. 10       criminal-offence PII -> any sink              (structural — flag
                                                                   for review)
R7   Art. 5(1)(e)  any PII -> file/DB at-rest, no               retention marker
                    retention/expiry marker on path                on path
R8   Art. 6(4)     any PII crosses a program boundary            (structural — flag
                    to a materially different-purpose sink         for review)
R9   Art. 5(1)(c)  PII passed across a CALL boundary and         callee referencing
                    never referenced by the callee                 the field

R1/R1B and R4/R4B are DELIBERATELY reported as separate findings, not a
single pooled citation. Art. 5(1)(f) is the principle ("integrity and
confidentiality"); Art. 32 is the concrete security-of-processing
obligation that implements it — legally distinct provisions, and pooling
them into one citation string hides which specific article a reviewer
should check evidence against (this repo's own evaluation standard:
"reported per article rather than pooled, since pooling hides the claim").
Un-pooling was chosen over inventing new detection logic specifically to
avoid padding the rule count with rules whose evidentiary basis is weaker
than what static COBOL flow analysis can actually support — see the R8/R9
docstrings for why that ceiling is taken seriously here.

R8 vs. R9 — two different flavours of "cross-program": R8 is cross-program
BY TRIGGER CONDITION — it simply does not fire unless flow.source_program
!= flow.sink_program, but nothing in principle stops an intra-program
analysis from being *defined*, it would just never find anything to report.
R9 is cross-program BY EVIDENTIARY NECESSITY — deciding it at all requires
the caller's CALL statement and the callee's full body simultaneously; no
reformulation of R9 is even expressible as a single-program analysis. This
distinction is the paper's clearest evidence for the claim that some
obligations require distributed evidence structurally, not just typically.

Article grounding (gdpr-info.eu, checked against the live text):
  - Art. 4(1): personal data = any information relating to an identified or
    identifiable natural person, e.g. by name, ID number, or other
    identifying factor. This is the baseline that makes ANY tagged PII
    field relevant to R1/R1B/R2/R3/R4/R4B/R7/R8, regardless of category.
  - Art. 5(1)(f): the "integrity and confidentiality" principle — personal
    data must be processed with appropriate security against unauthorised
    or unlawful processing and against accidental loss/damage.
  - Art. 32: the concrete security-of-processing obligation implementing
    Art. 5(1)(f) — appropriate technical/organisational measures,
    including pseudonymisation/encryption as a named example (32(1)(a)).
  - Art. 5(1)(e): the "storage limitation" principle — personal data kept
    in identifiable form no longer than necessary for the purposes it was
    processed for. A static tool cannot know the true retention period,
    but it CAN check whether the path to an at-rest sink shows any
    retention/expiry/purge marker at all — its total absence is evidence
    worth flagging, not proof of a violation (see R7's docstring).
  - Art. 6(1): processing is lawful ONLY if at least one of six bases
    applies — (a) consent, (b) contract, (c) legal obligation, (d) vital
    interests, (e) public task, (f) legitimate interests. A missing
    consent-flag in code is evidence of a missing basis-check, NOT proof
    that no lawful basis exists — (b)-(f) are not things a consent flag
    would represent, and a static tool cannot verify them. R2's wording
    reflects this rather than treating "no consent flag" as "unlawful".
  - Art. 6(4): where processing for a purpose other than the one for which
    the data was collected is not based on consent or Union/Member State
    law, the controller must assess compatibility with the original
    purpose (factors listed include the link between purposes, the
    context of collection, the nature of the data, and possible
    consequences). A static COBOL analysis cannot know true purposes, but
    a field crossing a program boundary into a sink whose function looks
    materially different from ordinary same-program processing (export,
    archival, messaging) is the closest thing to "further processing for
    a different purpose" that a data-flow graph can observe — see R8.
  - Art. 9(1): a CLOSED list of special categories (racial/ethnic origin,
    political opinions, religious/philosophical beliefs, trade union
    membership, genetic data, biometric data for unique identification,
    health data, sex life/sexual orientation) is prohibited by default.
    Art. 9(2) lists ten exceptions; only (a) explicit consent is something
    a static analysis can plausibly look for as a code-level guard, so R5
    only recognises that one. Masking/encryption does NOT cure an Art. 9
    problem (the prohibition is on the processing itself), so — unlike
    R1/R4 — R5 is not neutralised by `sanitised`.
  - Art. 10: personal data relating to criminal convictions/offences is a
    SEPARATE article from Art. 9 with its own condition (official
    authority or specific legal basis). A static tool cannot verify
    "official authority", so R6 flags any such field reaching any sink
    for manual review rather than asserting a definite violation.
  - Art. 44: the general principle anchoring Chapter V — any transfer to a
    third country/international organisation must comply with the
    conditions in Art. 45-49 (adequacy / safeguards / BCRs / derogations).
    A static COBOL analysis can observe that data reaches an
    external-looking sink; it cannot determine which Art. 45-49 mechanism
    (if any) governs that transfer, so R3 cites Art. 44 as the engaged
    principle rather than asserting which specific downstream article is
    satisfied or violated.

On not adding further rules beyond R9: the remaining GDPR obligations
(DPIAs, breach notification, records of processing, data-subject-rights
fulfilment, adequacy-decision bookkeeping) are properties of documents and
organisational process, not of a code data-flow path — Torre et al.'s own
pipeline checks these against structured metadata extracted from privacy
policies and legal documents, a fundamentally different input than COBOL
source. Forcing a rule onto one of them here would cite an article with no
real evidentiary chain behind it. These are intentionally left as
documented out-of-scope items (see the brief's Research Task 2) rather
than weak rules. R9 was added despite this ceiling specifically because
its evidentiary chain IS fully code-level (a CALL statement's argument
list and a callee's data-flow edges are both facts a parser can recover
with certainty) — it just happens to need two programs' worth of that
evidence at once rather than one.

Every Violation carries both:
  - `rationale`    — WHY this flow was mapped to this article: the
                      specific evidence found (source, sink, category,
                      guard/sanitiser/retention state on the path).
  - `remediation`  — WHAT to do about it.
These are kept as separate fields deliberately (see brief evaluation
standard: "article attribution... reported separately from detection, so
that a mapping failure is visible as such") — a reviewer should be able to
check the rationale against the source and agree or disagree with the
mapping without needing the remediation advice at all.

Every Violation also carries `locality` ("intra_program" | "cross_program")
and `boundary_crossings` (e.g. ["PROGA -> PROGB"]), computed for R1-R9 alike
from the same flow.source_program / flow.sink_program fields R8 already
relies on for its own trigger condition — so the evaluation harness can
score "cross-program vs. intra-program recall" per article, not just for
R8/R9 specifically.

Each per-flow rule is a function:

    rule_fn(flow: TaintFlow) -> Violation | None

R9 is the one exception — it is a structural scan over the CPG rather than
a function of a single TaintFlow (see its docstring for why), and is
invoked separately by RuleEngine.run().

The RuleEngine calls all per-flow rules over every TaintFlow, runs the R9
structural scan once over the CPG, and collects violations from both.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Callable

from ..cpg.graph_model import EdgeKind, NodeKind, SinkKind
from ..taint.engine import TaintFlow
from ..pii.tagger import (
    PII_ART9_SPECIAL_CATEGORIES,
    PII_ART10_CRIMINAL_DATA,
)


# ─── Category name-sets (pii_category on a flow is a .name string) ────────────

_ART9_CATEGORY_NAMES  = {c.name for c in PII_ART9_SPECIAL_CATEGORIES}
_ART10_CATEGORY_NAMES = {c.name for c in PII_ART10_CRIMINAL_DATA}


# ─── Violation record (frozen schema — matches JSON report exactly) ────────────

@dataclass
class Violation:
    """
    Matches the JSON schema in the brief exactly, plus additive fields
    (`rationale`, `retention_checked`) that extend it without changing any
    existing field's name or meaning.
    The report emitter serialises this to JSON.
    """
    violation_id:      str = ""
    rule_id:           str = ""
    gdpr_article:      str = ""
    severity:          str = "high"
    pii_field:         str = ""
    pii_category:      str = ""
    source_program:    str = ""
    source_copybook:   str = ""
    source_line:       int = 0
    sink_kind:         str = ""
    sink_program:      str = ""
    sink_line:         int = 0
    flow_path:         list[dict] = field(default_factory=list)
    sanitised:         bool = False
    consent_checked:   bool = False
    retention_checked: bool = False
    rationale:         str = ""
    remediation:       str = ""

    # -- Locality (added alongside R9) --------------------------------
    locality:            str = "unknown"   # "intra_program" | "cross_program"
    boundary_crossings:  list[str] = field(default_factory=list)


# ─── Rule implementations ─────────────────────────────────────────────────────

RuleFunction = Callable[[TaintFlow], Optional[Violation]]

_LOG_DISPLAY_SINKS = {SinkKind.LOGGING}
_AT_REST_SINKS     = {SinkKind.FILE_STORAGE, SinkKind.DATABASE}
_EXTERNAL_SINKS    = {SinkKind.NETWORK_TRANSFER, SinkKind.CONTENT_OR_SERVICE, SinkKind.MESSAGING}

# Sink kinds whose function looks materially different from ordinary
# same-program record-keeping — the observable proxy R8 uses for "a
# purpose other than the one data was collected for" (Art. 6(4)).
_PURPOSE_SHIFT_SINKS = {
    SinkKind.NETWORK_TRANSFER,
    SinkKind.CONTENT_OR_SERVICE,
    SinkKind.MESSAGING,
    SinkKind.DATABASE,
}


def _classify_locality(flow: TaintFlow) -> tuple[str, list[str]]:
    """
    Whether deciding this flow's obligation required evidence from more
    than one COBOL program, using the SAME resolved flow.source_program /
    flow.sink_program fields R8 already relies on for its own trigger
    condition (see rule_R8 below) -- no new plumbing, no CPG edge-walking
    needed here. A flow is cross_program when its source and sink
    programs differ and both are known; otherwise it is intra_program.
    """
    if flow.source_program and flow.source_program != flow.sink_program:
        return "cross_program", [f"{flow.source_program} -> {flow.sink_program}"]
    return "intra_program", []


def _base_violation(flow: TaintFlow, rule_id: str, article: str, severity: str) -> Violation:
    locality, boundary_crossings = _classify_locality(flow)
    return Violation(
        rule_id            = rule_id,
        gdpr_article       = article,
        severity           = severity,
        pii_field          = flow.pii_field,
        pii_category       = flow.pii_category,
        sink_kind          = flow.sink_kind.name.lower(),
        sink_program       = flow.sink_program,
        sink_line          = flow.sink_line,
        sanitised          = flow.sanitised,
        consent_checked    = flow.consent_checked,
        retention_checked  = flow.retention_checked,
        locality           = locality,
        boundary_crossings = boundary_crossings,
    )


def rule_R1(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 5(1)(f) — Integrity/confidentiality principle.
    Any personal data (Art. 4(1)) reaches a log/display output without
    masking. Reported separately from R1B (Art. 32) — see module docstring
    on why pooling the principle and its implementing obligation into one
    citation hides which article a reviewer should check evidence against.
    """
    if flow.sink_kind not in _LOG_DISPLAY_SINKS:
        return None
    if flow.sanitised:
        return None

    v = _base_violation(flow, "R1", "Art. 5(1)(f)", "high")
    v.rationale = (
        f"{flow.pii_field} (category: {flow.pii_category.lower()}) is "
        f"personal data under Art. 4(1). The taint path from its source "
        f"declaration reaches a {flow.sink_kind.name.lower()} sink in "
        f"{flow.sink_program} (line {flow.sink_line}) with no recognised "
        "masking/encryption operation (is_sanitiser) on any node between "
        "source and sink — so the disclosure is in the clear, engaging the "
        "integrity/confidentiality principle."
    )
    v.remediation = (
        f"Mask or encrypt {flow.pii_field} before writing to "
        f"the {flow.sink_kind.name.lower()} sink in {flow.sink_program}."
    )
    return v


def rule_R1B(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 32 — Security of processing (the concrete obligation implementing
    the Art. 5(1)(f) principle checked by R1). Same trigger condition as
    R1, reported as a distinct finding rather than pooled into it.
    """
    if flow.sink_kind not in _LOG_DISPLAY_SINKS:
        return None
    if flow.sanitised:
        return None

    v = _base_violation(flow, "R1B", "Art. 32", "high")
    v.rationale = (
        f"{flow.pii_field} reaches a {flow.sink_kind.name.lower()} sink in "
        f"{flow.sink_program} (line {flow.sink_line}) with no masking/"
        "encryption on the path — no technical measure appropriate to the "
        "risk (Art. 32(1)) was found protecting this disclosure."
    )
    v.remediation = (
        f"Apply an Art. 32(1)(a) measure (pseudonymisation or encryption) "
        f"to {flow.pii_field} before it reaches this sink."
    )
    return v


def rule_R2(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 6(1) — Lawfulness of processing.
    No basis-check indicator (the only proxy a static tool can look for is
    a consent-flag guard) was found on the path. This flags an ABSENCE OF
    DETECTABLE EVIDENCE of a lawful basis — consent is only one of six
    Art. 6(1) bases, so this is not proof processing is actually unlawful;
    it is a prompt to confirm which basis (a)-(f) applies and, if it is
    consent, that Art. 7's conditions are met.
    """
    if flow.consent_checked:
        return None

    v = _base_violation(flow, "R2", "Art. 6(1)", "medium")
    v.rationale = (
        f"{flow.pii_field} is processed on a path reaching {flow.sink_program} "
        f"(line {flow.sink_line}) with no recognised lawful-basis indicator "
        "(is_guard — e.g. a consent-flag check) on any node between source "
        "and sink. Consent is one of six Art. 6(1) bases, so this is an "
        "absence-of-evidence finding, not a positive finding of unlawfulness."
    )
    v.remediation = (
        f"No lawful-basis indicator found on the path to {flow.pii_field}'s "
        f"sink in {flow.sink_program}. Confirm which Art. 6(1) basis applies "
        "(consent, contract, legal obligation, vital interests, public task, "
        "or legitimate interests) and, if consent, that a check such as "
        "IF CONSENT-FLAG = 'Y' actually gates this path."
    )
    return v


def rule_R3(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 44 — General principle for transfers (Chapter V).
    Personal data reaches an external/cross-border-looking sink. Art. 44
    requires the Art. 45-49 conditions (adequacy decision / appropriate
    safeguards / BCRs / derogations) to be met for ANY such transfer; a
    static COBOL analysis can observe the transfer but not which mechanism
    (if any) is in place, so this is structural — it always fires when the
    sink looks external, and does not assert which Art. 45-49 article
    resolves it.
    """
    if flow.sink_kind not in _EXTERNAL_SINKS:
        return None

    v = _base_violation(flow, "R3", "Art. 44", "critical")
    v.rationale = (
        f"{flow.pii_field} flows to a sink in {flow.sink_program} "
        f"(line {flow.sink_line}) classified {flow.sink_kind.name.lower()} — "
        "the destination's name/target matched an external-transfer keyword "
        "(e.g. EXPORT/TRANSFER), so the data appears to leave the processing "
        "system. Art. 44 requires an Art. 45-49 mechanism for any such "
        "transfer; static analysis cannot confirm which, if any, applies."
    )
    v.remediation = (
        f"{flow.pii_field} appears to be transferred outside the "
        f"processing system from {flow.sink_program}. Confirm an Art. 45 "
        "adequacy decision, Art. 46 appropriate safeguards (e.g. SCCs), "
        "Art. 47 BCRs, or an Art. 49 derogation applies to this transfer."
    )
    return v


def rule_R4(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 5(1)(f) — Integrity/confidentiality principle (at-rest context).
    Personal data persisted to a file/database with no encryption marker
    on the path. Reported separately from R4B (Art. 32) for the same
    reason R1/R1B are split — see module docstring.
    """
    if flow.sink_kind not in _AT_REST_SINKS:
        return None
    if flow.sanitised:
        return None

    v = _base_violation(flow, "R4", "Art. 5(1)(f)", "high")
    v.rationale = (
        f"{flow.pii_field} is written to a {flow.sink_kind.name.lower()} sink "
        f"in {flow.sink_program} (line {flow.sink_line}) with no recognised "
        "masking/encryption operation (is_sanitiser) on the path — the data "
        "is persisted in the clear, engaging the integrity/confidentiality "
        "principle."
    )
    v.remediation = (
        f"{flow.pii_field} is written to persistent storage in {flow.sink_program} "
        "without an encryption marker on the path. Apply AES-256 or equivalent "
        "before the WRITE, or store only a pseudonymous key."
    )
    return v


def rule_R4B(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 32 — Security of processing (at-rest context; the concrete
    obligation implementing the Art. 5(1)(f) principle checked by R4).
    Same trigger condition as R4, reported as a distinct finding.
    """
    if flow.sink_kind not in _AT_REST_SINKS:
        return None
    if flow.sanitised:
        return None

    v = _base_violation(flow, "R4B", "Art. 32", "high")
    v.rationale = (
        f"{flow.pii_field} is persisted to a {flow.sink_kind.name.lower()} sink "
        f"in {flow.sink_program} (line {flow.sink_line}) with no encryption "
        "marker on the path — no technical measure appropriate to the risk "
        "(Art. 32(1)) was found protecting this data at rest."
    )
    v.remediation = (
        f"Apply an Art. 32(1)(a) measure (encryption at rest) to "
        f"{flow.pii_field}'s storage in {flow.sink_program}."
    )
    return v


def rule_R5(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 9 — Processing of special categories of personal data.
    Fields tagged with a category on Art. 9(1)'s closed list (racial/ethnic
    origin, political opinions, religious/philosophical beliefs, trade
    union membership, genetic data, biometric data for unique
    identification, health data, sex life/sexual orientation) are
    PROHIBITED by default. Of the ten Art. 9(2) exceptions, only (a)
    explicit consent is something a static analysis can plausibly detect
    as a code-level guard, so this rule fires unless that guard is present.
    NOT neutralised by `sanitised`: masking/encryption addresses Art. 32
    security, not the Art. 9 prohibition on the processing itself.
    """
    if flow.pii_category not in _ART9_CATEGORY_NAMES:
        return None
    if flow.consent_checked:
        return None

    v = _base_violation(flow, "R5", "Art. 9", "critical")
    v.rationale = (
        f"{flow.pii_field} is tagged category {flow.pii_category.lower()}, "
        "which is on Art. 9(1)'s closed special-category list. The path to "
        f"its sink in {flow.sink_program} (line {flow.sink_line}) shows no "
        "explicit-consent indicator (is_guard). Processing special-category "
        "data is prohibited by default absent one of the Art. 9(2) exceptions; "
        "masking the data downstream does not change this, since the "
        "prohibition is on the processing itself, not its security."
    )
    v.remediation = (
        f"{flow.pii_field} is special-category data under Art. 9(1) "
        f"({flow.pii_category.lower().replace('_', ' ')}) reaching a sink in "
        f"{flow.sink_program} with no explicit-consent indicator on the path. "
        "Processing is prohibited unless one of the Art. 9(2) exceptions "
        "applies — confirm which one, and if it is explicit consent (9(2)(a)), "
        "that a corresponding guard actually gates this path."
    )
    return v


def rule_R6(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 10 — Processing of personal data relating to criminal convictions
    and offences. A separate article from Art. 9 with its own condition:
    processing must be under the control of official authority or
    specifically authorised by law. A static tool cannot verify "official
    authority", so this always fires when such a field reaches any sink —
    it flags the field for manual legal review rather than asserting a
    definite violation.
    """
    if flow.pii_category not in _ART10_CATEGORY_NAMES:
        return None

    v = _base_violation(flow, "R6", "Art. 10", "high")
    v.rationale = (
        f"{flow.pii_field} is tagged category {flow.pii_category.lower()}, "
        "matching Art. 10's criminal-convictions/offences data, and reaches "
        f"a sink in {flow.sink_program} (line {flow.sink_line}). Art. 10 "
        "requires this processing be under official authority or a specific "
        "legal basis — properties static analysis cannot verify — so this "
        "is flagged for manual review rather than asserted as a violation."
    )
    v.remediation = (
        f"{flow.pii_field} appears to be criminal-conviction/offence data "
        f"(Art. 10) reaching a sink in {flow.sink_program}. Confirm this "
        "processing is under the control of official authority or "
        "specifically authorised by Union/Member State law."
    )
    return v


def rule_R7(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 5(1)(e) — Storage limitation.
    Personal data persisted to a file/database with no retention/expiry
    marker anywhere on the path (e.g. a purge routine, a RETENTION-DATE
    field, an ARCHIVE-UNTIL check). A static tool cannot know the true
    retention period or whether it is proportionate — this only checks
    whether ANY retention-related construct is present at all. Its total
    absence is evidence worth a reviewer's attention, not proof that data
    is kept unlawfully long.
    """
    if flow.sink_kind not in _AT_REST_SINKS:
        return None
    if flow.retention_checked:
        return None

    v = _base_violation(flow, "R7", "Art. 5(1)(e)", "medium")
    v.rationale = (
        f"{flow.pii_field} is written to a {flow.sink_kind.name.lower()} sink "
        f"in {flow.sink_program} (line {flow.sink_line}) with no retention, "
        "expiry, or purge marker (is_retention_marker) found on the path. "
        "This is an absence-of-evidence finding about the STORAGE PATH "
        "COBCheck can see — it does not confirm a retention policy is "
        "missing at the application or organisational level."
    )
    v.remediation = (
        f"No retention/expiry marker found on the path to {flow.pii_field}'s "
        f"storage in {flow.sink_program}. Confirm a retention period is "
        "defined for this record and, if enforced in code, that a "
        "recognisable marker (e.g. RETENTION-DATE, a PURGE routine) is on "
        "this path."
    )
    return v


def rule_R8(flow: TaintFlow) -> Optional[Violation]:
    """
    Art. 6(4) — Further processing for a purpose other than collection.
    Fires when a PII field crosses a PROGRAM boundary (source program !=
    sink program) into a sink whose function looks materially different
    from ordinary same-program record-keeping (external transfer,
    messaging, or database persistence) — the closest observable proxy a
    static data-flow graph has for "processing for a different purpose
    than the one data was collected for".

    This rule specifically depends on cross-program flow detection working
    — it is the one rule in this set where the multi-program capability is
    the entire evidentiary basis, not incidental to it (R3 also crosses
    sinks but doesn't require crossing a PROGRAM boundary to fire).

    Deliberately structural, like R6: Art. 6(4) itself only requires an
    assessment of purpose compatibility, not that further processing is
    automatically unlawful — factors like the link between purposes and
    the context of original collection are legal judgments a static tool
    cannot make. This flags the field for that assessment rather than
    asserting incompatibility.
    """
    if not flow.source_program:
        return None
    if flow.source_program == flow.sink_program:
        return None
    if flow.sink_kind not in _PURPOSE_SHIFT_SINKS:
        return None

    v = _base_violation(flow, "R8", "Art. 6(4)", "medium")
    v.source_program = flow.source_program
    v.rationale = (
        f"{flow.pii_field} originates in {flow.source_program} and crosses "
        f"a program boundary to a sink in {flow.sink_program} (line "
        f"{flow.sink_line}) classified {flow.sink_kind.name.lower()} — a "
        "function that looks materially different from ordinary same-"
        "program processing. This is the closest signal a data-flow graph "
        "can observe for further processing under a different purpose; it "
        "does not establish what either program's actual purpose is."
    )
    v.remediation = (
        f"Confirm the purpose {flow.sink_program} processes {flow.pii_field} "
        f"for is compatible with the purpose it was originally collected "
        f"for in {flow.source_program} (Art. 6(4) factors: the link between "
        "the two purposes, the context of original collection, the nature "
        "of the data, and possible consequences for the data subject). If "
        "incompatible, a new Art. 6(1) basis is needed for this path."
    )
    return v


# ─── R9 — structural rule, scans the CPG directly, not per-TaintFlow ──────────

def _find_call_site(cpg, caller_prog: str, callee_prog: str) -> int:
    """
    Best-effort lookup of the CALL statement's line number, for report
    readability only (not used in the R9 trigger condition itself). If a
    caller calls the same callee more than once, the first match found is
    used — a stated limitation.
    """
    for _, data in cpg.G.nodes(data=True):
        if data.get("kind") != NodeKind.CALL:
            continue
        if data.get("program") != caller_prog:
            continue
        target = str(data.get("call_target", "")).upper().strip("'\"")
        if target == callee_prog.upper():
            return data.get("line", 0)
    return 0


def rule_R9_call_boundary_minimisation(cpg) -> list[Violation]:
    """
    Art. 5(1)(c) — Data minimisation.
    Fires when a CALL ... USING statement passes a field into a callee
    that is (a) tagged as PII and (b) never appears as the source of any
    data-movement statement anywhere in the callee's own PROCEDURE
    DIVISION.

    THIS IS THE ONE RULE IN THE SET THAT CANNOT BE DECIDED FROM EITHER
    PROGRAM'S SOURCE ALONE, not merely one that often happens to involve
    two programs (R8's condition, while cross-program by construction
    too, is at least evaluable purely from the flow's recorded source/sink
    programs and sink kind — it doesn't need to inspect the callee's
    unused-field structure). Deciding R9 requires BOTH the caller's CALL
    statement (what fields were shared) AND the callee's full body (what
    was ever referenced) simultaneously — no single program's source
    contains both facts.

    Unlike R1-R8, this is NOT a function of a single TaintFlow: a field
    that is over-shared but never used produces no sink, and therefore
    never appears as a TaintFlow at all (TaintEngine only reports flows
    that REACH a sink — see taint/engine.py). RuleEngine.run() calls this
    function directly over the CPG, separately from the R1-R8 loop over
    flows.

    Method
    ───────
    cpg/builder.py's _add_call_edges pairs up same-named fields across a
    CALL ... USING boundary directly, one PDG edge per field, tagged
    operation == "CALL USING (field)" (added specifically because plain
    CONTAINS edges only propagate taint upward and would otherwise dead-
    end at the LINKAGE group — see that method's docstring). This rule
    scans those edges directly: for each (caller_field -> callee_field)
    pair, the callee field is flagged if it:
      1. carries a PII tag (assigned by PiiTagger — node["pii_fields"]
         is non-empty), and
      2. has zero outgoing PDG edges of its own within the callee — i.e.
         it is never used as the source of a MOVE/COMPUTE/WRITE-FROM/EXEC
         statement anywhere in the callee body.

    Stated limitation
    ───────────────────
    Condition 2 is a proxy for "never read downstream", built on the same
    PDG-edge convention the taint engine itself relies on for propagation.
    A field referenced ONLY inside an IF condition and never MOVEd is not
    currently modelled as having an outgoing PDG edge, and would be
    (incorrectly) flagged as unused. State this explicitly when reporting
    R9's precision, per this repo's evaluation standard of stating
    assumptions rather than leaving them implicit.

    A second, narrower limitation: the per-field aliasing edges this rule
    reads are only added one level deep (_group_child_items on the
    top-level record passed by the CALL), so a PII field nested inside a
    further sub-group of the passed record would not get its own alias
    edge and would not be checked by this rule. Not an issue for a flat
    copybook-shaped record (the common case and this repo's test corpus),
    but worth stating for any corpus with deeper LINKAGE nesting.

    Severity: "medium" — this is a positive, structural finding (not an
    absence-of-evidence proxy like R2/R7/R8), but data minimisation is a
    proportionality concern about unnecessary sharing, not a confirmed
    insecure disclosure — it is calibrated below R1/R1B/R4/R4B (which
    confirm PII actually reaching an unprotected sink) and at the same
    level as R8, the other structural cross-program-only finding.
    """
    findings: list[Violation] = []

    for src, dst, edge_data in cpg.G.edges(data=True):
        if edge_data.get("kind") != EdgeKind.PDG:
            continue
        if edge_data.get("operation") != "CALL USING (field)":
            continue

        caller_data = cpg.get(src)
        callee_data = cpg.get(dst)
        caller_prog = caller_data.get("program", "")
        callee_prog = callee_data.get("program", "")

        if not caller_prog or not callee_prog or caller_prog == callee_prog:
            continue

        pii_fields = callee_data.get("pii_fields", set())
        if not pii_fields:
            continue

        referenced = any(
            cdata.get("kind") == EdgeKind.PDG
            for _, _, cdata in cpg.G.out_edges(dst, data=True)
        )
        if referenced:
            continue

        field_name = callee_data.get("field_name") or str(dst)
        category = callee_data.get("pii_category")
        category_note = category.name if category is not None else "UNKNOWN"

        call_line = _find_call_site(cpg, caller_prog, callee_prog)

        v = Violation(
            rule_id            = "R9",
            gdpr_article       = "Art. 5(1)(c)",
            severity           = "medium",
            pii_field          = field_name,
            pii_category       = category_note,
            source_program     = caller_prog,
            source_copybook    = "",
            source_line        = call_line,
            sink_kind          = "call_boundary_unused",
            sink_program       = callee_prog,
            sink_line          = callee_data.get("line", 0),
            sanitised          = False,
            consent_checked    = False,
            retention_checked  = False,
            locality           = "cross_program",
            boundary_crossings = [f"{caller_prog} -> {callee_prog}"],
            flow_path=[
                {
                    "program": caller_prog,
                    "line": call_line,
                    "stmt": f"CALL {callee_prog} USING ...",
                },
                {
                    "program": callee_prog,
                    "line": callee_data.get("line", 0),
                    "stmt": f"LINKAGE {field_name} (never referenced)",
                },
            ],
            rationale=(
                f"{caller_prog} passes {field_name} to {callee_prog} via "
                f"CALL ... USING (line {call_line}). {field_name} carries "
                f"PII (category: {category_note.lower()}) and has zero "
                f"outgoing data-flow edges anywhere in {callee_prog}'s "
                "PROCEDURE DIVISION — it is never referenced downstream by "
                "the callee. Deciding this required both the CALL "
                "statement's argument list in the caller and the callee's "
                "full body, which is why this finding is cross_program by "
                "construction rather than by coincidence."
            ),
            remediation=(
                f"{callee_prog} receives {field_name} from {caller_prog} "
                f"via CALL ... USING but never references it. Stop "
                f"passing {field_name} into {callee_prog}, or pass a "
                "narrower LINKAGE structure that excludes fields the "
                "callee does not need (Art. 5(1)(c) data minimisation)."
            ),
        )
        findings.append(v)

    return findings


# ─── Rule engine ──────────────────────────────────────────────────────────────

ALL_RULES: list[RuleFunction] = [
    rule_R1, rule_R1B, rule_R2, rule_R3, rule_R4, rule_R4B,
    rule_R5, rule_R6, rule_R7, rule_R8,
]


class RuleEngine:
    """
    Applies all GDPR rules to a list of TaintFlow objects and returns
    a de-duplicated, numbered list of Violation records.

    Parameters
    ----------
    rules : list[RuleFunction]
        Per-flow rules to apply (default: ALL_RULES = R1-R8, ten findings
        total counting the R1/R1B and R4/R4B pairs). R9 is always run in
        addition to these — it is a structural CPG scan, not a per-flow
        rule, so it has no place in this list; see
        rule_R9_call_boundary_minimisation's docstring.
    """

    def __init__(self, rules: Optional[list[RuleFunction]] = None):
        self._rules = rules if rules is not None else ALL_RULES
        self._counter = 0

    def run(self, flows: list[TaintFlow], cpg) -> list[Violation]:
        """
        Apply rules to *flows* and return de-duplicated Violation list.

        Parameters
        ----------
        flows : list[TaintFlow]
        cpg   : CPG  (passed through to build flow_path details)
        """
        violations: list[Violation] = []
        seen: set[tuple] = set()  # dedup key

        for flow in flows:
            for rule_fn in self._rules:
                v = rule_fn(flow)
                if v is None:
                    continue

                # De-duplicate: same rule + field + sink line
                key = (v.rule_id, v.pii_field, v.sink_program, v.sink_line)
                if key in seen:
                    continue
                seen.add(key)

                # Assign ID
                self._counter += 1
                v.violation_id = f"V-{self._counter:04d}"

                # Fill source location from CPG
                src_data = cpg.get(flow.source_nid)
                v.source_program  = src_data.get("program", "")
                v.source_copybook = src_data.get("copybook", "")
                v.source_line     = src_data.get("line", 0)

                # Build flow_path list for the report
                v.flow_path = _build_flow_path(flow.path, cpg)

                violations.append(v)

        # R9: structural CALL-boundary scan, run once over the CPG
        for v in rule_R9_call_boundary_minimisation(cpg):
            key = (v.rule_id, v.pii_field, v.source_program, v.sink_program)
            if key in seen:
                continue
            seen.add(key)

            self._counter += 1
            v.violation_id = f"V-{self._counter:04d}"
            violations.append(v)

        return violations


def _build_flow_path(path: list[int], cpg) -> list[dict]:
    """
    Convert a list of CPG node IDs into the flow_path format used in the
    JSON report schema.
    """
    result = []
    for nid in path:
        data = cpg.get(nid)
        stmt = data.get("stmt")
        stmt_text = getattr(stmt, "__class__", type(stmt)).__name__
        if hasattr(stmt, "text"):
            stmt_text = stmt.text
        elif hasattr(stmt, "source"):
            stmt_text = (
                f"MOVE {stmt.source} TO "
                f"{', '.join(getattr(stmt, 'destinations', []))}"
            )
        elif hasattr(stmt, "target"):
            stmt_text = f"CALL {stmt.target}"
        result.append({
            "program": data.get("program", ""),
            "line":    data.get("line", 0),
            "stmt":    stmt_text,
        })
    return result   