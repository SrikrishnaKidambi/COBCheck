"""
cobcheck/gdpr/mapping.py
──────────────────────────
The article-mapping layer.

This is the pipeline stage the brief identifies as the open problem:
cross-program flow recovery (cobcheck/taint/engine.py) is treated as
solved infrastructure, and what remains is deciding, for each
recovered flow, WHICH GDPR obligation it evidences, WHY (with the
specific facts that justify the decision), and WHETHER deciding that
required evidence from more than one program.

Design principles
──────────────────
1. Every obligation this layer can attribute is defined once, in
   cobcheck/gdpr/obligation_registry.py. This module contains no
   article strings of its own — it only evaluates the
   `code_level_condition` of each `Obligation` against flow/CPG facts
   and, if it fires, builds an `ArticleAttribution` that cites the
   registry entry.

2. Detection and mapping are evaluated as separate questions, on
   separate evidence, and are reported separately:

     - flow.path / flow_path   (built in gdpr/rules.py, from the
       taint engine) answers "how did the data get here" — this is
       DETECTION evidence, produced entirely by cobcheck/taint.

     - ArticleAttribution.evidence answers "why does this fact
       trigger THIS article" — this is MAPPING evidence, produced
       entirely here. An attribution never reuses flow_path text as
       its evidence; it re-derives its own facts from flow/cpg state
       (sink kind, sanitised, consent_checked, pii_category, and — for
       R6 — CALL/LINKAGE/CONTAINS structure) so that a mapping error
       and a detection error remain independently visible, per the
       brief's core claim.

3. Locality is a property of the EVIDENCE required, not of the flow's
   raw path length. `classify_locality` walks the flow's path and
   asks whether the *programs* the path touches are more than one —
   not whether the path is long, not whether it uses a CALL edge for
   some unrelated reason. For R6 (data minimisation at the CALL
   boundary) locality is fixed at CROSS_PROGRAM by construction (see
   obligation_registry.OBLIGATIONS["OBL-5-1-C"]): no taint flow to a
   sink is even involved, so `classify_locality` does not apply to it
   and it is computed by a dedicated CPG-structural pass instead
   (`map_call_boundaries`).

Three arms, for the evaluation design in the brief
────────────────────────────────────────────────────
This separation is what lets the brief's three-arm comparison exist
in this codebase without three separate tools:

  - "LLM-only" arm: does not use this module at all (see
    cobcheck/pii/tagger.py's Groq fallback, which is the closest
    existing analogue — a full LLM-only baseline runner belongs in
    tests/integration or a future benchmark harness, not here).
  - "flow-recovery-only" arm: cobcheck.taint.engine.TaintEngine
    output, scored directly with no ArticleMapper applied.
  - "full pipeline": TaintEngine -> ArticleMapper -> RuleEngine, i.e.
    what run_pipeline() in cli.py executes end to end.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from ..cpg.graph_model import CPG, EdgeKind, NodeKind, SinkKind
from ..taint.engine import TaintFlow
from .obligation_registry import (
    OBLIGATIONS,
    Locality,
    Obligation,
)

logger = logging.getLogger(__name__)


# ─── Sink-kind groupings used by the code-level conditions ────────────────
#
# These mirror the groupings in obligation_registry.py's
# code_level_condition text exactly; kept here (not imported from
# gdpr/rules.py) so this module has no dependency on the report-schema
# layer, only on the CPG/taint layer beneath it.

_LOG_DISPLAY_SINKS = {SinkKind.LOGGING}
_AT_REST_SINKS = {SinkKind.FILE_STORAGE, SinkKind.DATABASE}
_EXTERNAL_SINKS = {
    SinkKind.NETWORK_TRANSFER,
    SinkKind.CONTENT_OR_SERVICE,
    SinkKind.MESSAGING,
}

# The two Privado-derived PiiCategory names (see cobcheck/pii/tagger.py)
# that fall within GDPR Art. 9(1)'s exhaustive special-category list.
# Kept as plain strings because TaintFlow.pii_category is already a
# string by the time it reaches this layer (see taint/engine.py).
_SPECIAL_CATEGORY_PII = {"HEALTH", "BIOMETRIC"}


# ─── Attribution record ────────────────────────────────────────────────────

@dataclass
class ArticleAttribution:
    """
    One obligation attributed to one recovered flow (or, for R6, one
    CALL-boundary fact), with its own independent evidence trail.
    """

    obligation_id: str
    rule_id: str
    article: str
    severity: str
    remediation: str

    locality: str                  # Locality.value: "intra_program" | "cross_program"
    boundary_crossings: list[str]  # e.g. ["PROGA -> PROGB via CALL/PDG"]
    evidence: list[str] = field(default_factory=list)
    mapping_basis: str = ""
    official_source: str = ""


# ─── Locality classification ───────────────────────────────────────────────

def classify_locality(
    cpg: CPG,
    path: list[int],
) -> tuple[Locality, list[str]]:
    """
    Decide whether deciding THIS flow required evidence from more than
    one COBOL program, and record the boundary(ies) crossed.

    A flow is CROSS_PROGRAM when its representative taint path (the
    same path already reconstructed by TaintEngine, over data-flow
    edges only — see taint/engine.py's _TAINT_EDGES) touches nodes
    belonging to more than one `program` attribute. This is a
    structural fact about the recovered path, not a guess: the path
    already only contains nodes connected by CALL / RETURN / FILE_IO /
    COPYBOOK / PDG / CONTAINS edges, so if two different `program`
    values appear on it, the data provably moved across a program
    boundary to get from source to sink.
    """
    programs_seen: list[str] = []
    boundary_crossings: list[str] = []
    prev_nid: Optional[int] = None
    prev_program: Optional[str] = None

    for nid in path:
        prog = cpg.get(nid).get("program") or "?"

        if prog not in programs_seen:
            programs_seen.append(prog)

        if prev_program is not None and prog != prev_program:
            edge_kinds: set[str] = set()
            edge_data = cpg.G.get_edge_data(prev_nid, nid) or {}
            for _, attrs in edge_data.items():
                kind = attrs.get("kind")
                if kind is not None:
                    edge_kinds.add(kind.name)
            boundary_crossings.append(
                f"{prev_program} -> {prog} via "
                f"{'/'.join(sorted(edge_kinds)) or 'unknown-edge'}"
            )

        prev_nid = nid
        prev_program = prog

    if len(programs_seen) > 1:
        return Locality.CROSS_PROGRAM, boundary_crossings

    return Locality.INTRA_PROGRAM, []


# ─── Per-flow (source-to-sink) obligations ─────────────────────────────────

class ArticleMapper:
    """
    Evaluates every in-scope Obligation's code_level_condition against
    recovered TaintFlow facts (map_flow) and against CALL-boundary
    structure (map_call_boundaries), and returns ArticleAttribution
    records with their own evidence and locality.
    """

    def __init__(
        self,
        obligations: Optional[dict[str, Obligation]] = None,
    ):
        self._obligations = obligations or OBLIGATIONS

    # ── R1 / R2 / R3 / R4 / R5 : flow-to-sink obligations ──────────────────

    def map_flow(
        self,
        flow: TaintFlow,
        cpg: CPG,
    ) -> list[ArticleAttribution]:
        locality, boundary_crossings = classify_locality(cpg, flow.path)
        attributions: list[ArticleAttribution] = []

        # OBL-5-1-F — Art. 5(1)(f) / 32(1): integrity & confidentiality
        if flow.sink_kind in _LOG_DISPLAY_SINKS and not flow.sanitised:
            attributions.append(
                self._attribute(
                    "OBL-5-1-F",
                    locality,
                    boundary_crossings,
                    evidence=[
                        f"sink_kind={flow.sink_kind.name}",
                        "sanitised=False (no mask/hash/encrypt node on "
                        "the taint path)",
                        f"pii_field={flow.pii_field}",
                    ],
                    severity="high",
                    remediation=(
                        f"Mask or encrypt {flow.pii_field} before "
                        f"writing to the {flow.sink_kind.name.lower()} "
                        f"sink in {flow.sink_program}."
                    ),
                )
            )

        # OBL-6-1 — Art. 6(1): lawfulness of processing
        if not flow.consent_checked:
            attributions.append(
                self._attribute(
                    "OBL-6-1",
                    locality,
                    boundary_crossings,
                    evidence=[
                        "consent_checked=False (no IF-guard referencing "
                        "consent/permission/authorisation on the taint "
                        "path)",
                        f"sink_kind={flow.sink_kind.name}",
                    ],
                    severity="high",
                    remediation=(
                        "Add a consent/lawful-basis guard (e.g. IF "
                        "CONSENT-FLAG = 'Y') before "
                        f"{flow.pii_field} reaches the sink in "
                        f"{flow.sink_program}."
                    ),
                )
            )

        # OBL-44-49 — Art. 44-49: third-country / external transfer
        if flow.sink_kind in _EXTERNAL_SINKS:
            attributions.append(
                self._attribute(
                    "OBL-44-49",
                    locality,
                    boundary_crossings,
                    evidence=[
                        f"sink_kind={flow.sink_kind.name} (external "
                        "interface — network, messaging, or "
                        "content/service sink)",
                        f"pii_field={flow.pii_field}",
                    ],
                    severity="critical",
                    remediation=(
                        f"{flow.pii_field} is transferred externally "
                        f"from {flow.sink_program}. Confirm an adequacy "
                        "decision, SCCs, or BCRs are in place, or "
                        "pseudonymise before the transfer."
                    ),
                )
            )

        # OBL-32-1-A — Art. 32(1)(a): security of processing, at rest
        if flow.sink_kind in _AT_REST_SINKS and not flow.sanitised:
            attributions.append(
                self._attribute(
                    "OBL-32-1-A",
                    locality,
                    boundary_crossings,
                    evidence=[
                        f"sink_kind={flow.sink_kind.name}",
                        "sanitised=False (no mask/hash/encrypt node on "
                        "the taint path)",
                    ],
                    severity="high",
                    remediation=(
                        f"{flow.pii_field} is written to persistent "
                        f"storage in {flow.sink_program} without "
                        "encryption. Apply AES-256 or equivalent before "
                        "the WRITE, or store only a pseudonymous key."
                    ),
                )
            )

        # OBL-9-1 — Art. 9(1): special categories of personal data
        if flow.pii_category in _SPECIAL_CATEGORY_PII:
            attributions.append(
                self._attribute(
                    "OBL-9-1",
                    locality,
                    boundary_crossings,
                    evidence=[
                        f"pii_category={flow.pii_category} (in the "
                        "Art. 9(1) special-category list)",
                        f"sink_kind={flow.sink_kind.name}",
                    ],
                    severity="critical",
                    remediation=(
                        f"{flow.pii_field} is a special category of "
                        "personal data (Art. 9(1)). Confirm an "
                        "Art. 9(2) exception applies and that "
                        "processing is documented before it reaches the "
                        f"sink in {flow.sink_program}."
                    ),
                )
            )

        return attributions

    def _attribute(
        self,
        obligation_id: str,
        locality: Locality,
        boundary_crossings: list[str],
        evidence: list[str],
        severity: str,
        remediation: str,
    ) -> ArticleAttribution:
        obl = self._obligations[obligation_id]
        return ArticleAttribution(
            obligation_id=obl.obligation_id,
            rule_id=obl.rule_id,
            article=obl.article,
            severity=severity,
            remediation=remediation,
            locality=locality.value,
            boundary_crossings=list(boundary_crossings),
            evidence=list(evidence),
            mapping_basis=obl.code_level_condition,
            official_source=obl.official_source,
        )

    # ── R6 : CALL-boundary data minimisation (cross-program by construction) ──

    def map_call_boundaries(
        self,
        cpg: CPG,
    ) -> list["CallBoundaryFinding"]:
        """
        Find PII fields shared across a CALL ... USING boundary that
        the callee's PROCEDURE DIVISION never actually references.

        This is the one obligation in the set that a within-program
        analysis cannot produce even in principle: it requires the
        caller's CALL statement (what was shared) AND the callee's
        full body (what was ever used), which are two different
        programs' source by definition.

        Method
        ───────
        For every CALL-USING PDG edge the CPG builder already recorded
        (operation == "CALL USING", connecting a caller's field node to
        the matching callee LINKAGE field node — see
        cpg/builder.py:_add_call_edges), expand the callee side to its
        elementary CONTAINS children (or treat it as elementary itself
        if it has none), and flag any child that:

          1. carries a PII tag (assigned earlier by PiiTagger), and
          2. has zero outgoing PDG edges of its own within the callee
             — i.e. it is never used as the source of a MOVE/COMPUTE/
             WRITE-FROM/EXEC statement anywhere in the callee body.

        Stated limitation
        ───────────────────
        Condition 2 is a proxy for "never read downstream", built on
        the same PDG-edge convention the taint engine itself relies on
        (see taint/engine.py's docstring: "AST and ordinary CFG edges
        are NOT automatically treated as data flow"). A field that is
        referenced ONLY inside an IF condition and never moved is not
        currently modelled as having an outgoing PDG edge, and would
        be (incorrectly) flagged as unused. This is stated here rather
        than silently accepted, per the brief's requirement to state
        injection/evaluation assumptions explicitly; the benchmark's
        oracle should score this obligation with that limitation in
        mind, and a future CFG-aware "referenced-in-condition" edge
        would close it.
        """
        findings: list[CallBoundaryFinding] = []
        obl = self._obligations["OBL-5-1-C"]

        for src, dst, edge_data in cpg.G.edges(data=True):
            if edge_data.get("kind") != EdgeKind.PDG:
                continue
            if edge_data.get("operation") != "CALL USING":
                continue

            caller_data = cpg.get(src)
            callee_data = cpg.get(dst)
            caller_prog = caller_data.get("program", "")
            callee_prog = callee_data.get("program", "")

            if not caller_prog or not callee_prog or caller_prog == callee_prog:
                continue

            children = [
                v
                for _, v, cdata in cpg.G.out_edges(dst, data=True)
                if cdata.get("kind") == EdgeKind.CONTAINS
            ]
            if not children:
                children = [dst]

            call_line, call_target = self._find_call_site(
                cpg, caller_prog, callee_prog
            )

            for child in children:
                child_data = cpg.get(child)
                pii_fields = child_data.get("pii_fields", set())
                if not pii_fields:
                    continue

                referenced = any(
                    cdata.get("kind") == EdgeKind.PDG
                    for _, _, cdata in cpg.G.out_edges(child, data=True)
                )
                if referenced:
                    continue

                field_name = child_data.get("field_name") or str(child)

                categories = child_data.get("pii_categories", {})
                category_note = ", ".join(
                    f"{f}={categories.get(f, 'UNKNOWN')}"
                    for f in sorted(pii_fields)
                )

                findings.append(
                    CallBoundaryFinding(
                        obligation_id=obl.obligation_id,
                        rule_id=obl.rule_id,
                        article=obl.article,
                        severity="medium",
                        pii_fields=sorted(pii_fields),
                        caller_program=caller_prog,
                        callee_program=callee_prog,
                        call_line=call_line,
                        callee_field_name=field_name,
                        callee_field_line=child_data.get("line", 0),
                        locality=Locality.CROSS_PROGRAM.value,
                        evidence=[
                            f"CALL {caller_prog} -> {callee_prog} passes "
                            f"a LINKAGE group containing {field_name}",
                            f"{field_name} carries PII: {category_note}",
                            f"{field_name} has zero outgoing data-flow "
                            f"edges anywhere in {callee_prog}'s "
                            "PROCEDURE DIVISION (never used downstream)",
                        ],
                        mapping_basis=obl.code_level_condition,
                        official_source=obl.official_source,
                        remediation=(
                            f"{callee_prog} receives {field_name} from "
                            f"{caller_prog} via CALL ... USING but never "
                            f"references it. Stop passing {field_name} "
                            f"into {callee_prog}, or pass a narrower "
                            "LINKAGE structure that excludes fields the "
                            "callee does not need "
                            "(Art. 5(1)(c) data minimisation)."
                        ),
                    )
                )

        return findings

    @staticmethod
    def _find_call_site(
        cpg: CPG,
        caller_prog: str,
        callee_prog: str,
    ) -> tuple[int, str]:
        """
        Best-effort lookup of the CALL statement's line number, for
        report readability only (not used in the mapping decision
        itself). If a caller issues more than one CALL to the same
        callee, the first match found is used — a stated limitation,
        not a silent one.
        """
        for nid, data in cpg.G.nodes(data=True):
            if data.get("kind") != NodeKind.CALL:
                continue
            if data.get("program") != caller_prog:
                continue
            target = str(data.get("call_target", "")).upper().strip("'\"")
            if target == callee_prog.upper():
                return data.get("line", 0), target
        return 0, callee_prog


@dataclass
class CallBoundaryFinding:
    """
    One R6 (Art. 5(1)(c)) finding: a PII field shared across a CALL
    boundary and never used by the callee.
    """

    obligation_id: str
    rule_id: str
    article: str
    severity: str

    pii_fields: list[str]
    caller_program: str
    callee_program: str
    call_line: int
    callee_field_name: str
    callee_field_line: int

    locality: str
    evidence: list[str]
    mapping_basis: str
    official_source: str
    remediation: str