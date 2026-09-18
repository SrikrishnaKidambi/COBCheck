"""
cobcheck/gdpr/obligation_registry.py
──────────────────────────────────────
The obligation set (Research Task 2 in the brief).

This module is the single citable source of truth for every GDPR
article COBCheck reasons about. It exists so the article-mapping
layer (cobcheck/gdpr/mapping.py) never invents or free-hands an
article string — every attribution the tool ever emits is required
to point at one `Obligation` entry defined here, and every entry
carries:

  * the official article/paragraph identifier,
  * a short PARAPHRASE of the obligation (never the verbatim legal
    text — see "On verbatim text" below), and
  * the exact CODE-LEVEL CONDITION COBCheck evaluates to decide the
    obligation, stated as a check over CPG/taint-flow facts.

This lets a rater (or a reviewer) check three independent things
separately: (1) is the article citation correct, (2) is the
paraphrase a faithful reading of that article, and (3) is the
code-level condition a defensible operationalisation of the
paraphrase. Conflating these was the failure mode the brief singles
out ("an analysis may recover a flow correctly and still attribute
the wrong obligation to it").

On verbatim text
─────────────────
COBCheck stores paraphrases and article/paragraph identifiers, not
reproductions of the Regulation's operative text. For the paper,
quote the official consolidated text directly from EUR-Lex (CELEX
32016R0679) using the article/paragraph identifiers below — that
text is definitionally the authority; nothing here should be cited
in place of it.

Locality
─────────
Each obligation is tagged with the kind of evidence its code-level
condition requires:

    INTRA_PROGRAM   the condition is fully decidable from the
                     source of a single COBOL program.
    CROSS_PROGRAM   the condition can ONLY be decided using facts
                     that live in two or more programs at once —
                     an intra-program analysis structurally cannot
                     produce this finding, not merely "usually
                     doesn't".
    EITHER          the condition is decidable intra-program, but
                     the flow that triggers it frequently (not
                     necessarily) crosses a program boundary in
                     practice; whether THIS finding was local or
                     cross-program is still evaluated per-flow by
                     the mapping layer (see classify_locality in
                     mapping.py) and recorded on the attribution.

This tag is what lets the evaluation (Metric: "cross-program vs.
intra-program recall") separate obligations that are cross-program
by construction (OBL-5-1-C) from obligations that merely happen to
straddle programs some of the time (OBL-5-1-F, OBL-6-1, OBL-32-1-A,
OBL-9-1) and from the one that is external-transfer by definition
(OBL-44-49).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


# ─── Locality ──────────────────────────────────────────────────────────────

class Locality(Enum):
    INTRA_PROGRAM = "intra_program"
    CROSS_PROGRAM = "cross_program"
    EITHER = "either"


# ─── Obligation record ────────────────────────────────────────────────────

@dataclass(frozen=True)
class Obligation:
    obligation_id: str
    rule_id: str
    article: str
    title: str
    paraphrase: str
    code_level_condition: str
    locality: Locality
    official_source: str
    in_scope: bool = True
    out_of_scope_reason: Optional[str] = None


_CELEX = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679"


def _src(article_anchor: str) -> str:
    """EUR-Lex CELEX 32016R0679, pointed at a specific article."""
    return f"{_CELEX}#{article_anchor}"


# ─── In-scope obligations ─────────────────────────────────────────────────
#
# Six obligations are in scope, matched 1:1 to the six rule IDs the
# report schema and README already advertise (R1-R4 carried over from
# the pre-mapping-layer version, R5-R6 added by this change).

OBLIGATIONS: dict[str, Obligation] = {

    "OBL-5-1-F": Obligation(
        obligation_id="OBL-5-1-F",
        rule_id="R1",
        article="Art. 5(1)(f) / Art. 32(1)",
        title="Integrity and confidentiality",
        paraphrase=(
            "Personal data must be processed with appropriate security, "
            "using technical measures such as pseudonymisation or "
            "encryption, protecting against unauthorised or unlawful "
            "access and disclosure."
        ),
        code_level_condition=(
            "A tainted PII field reaches a LOGGING sink (DISPLAY, or a "
            "WRITE whose record/file name matches a log/audit/report "
            "token) and no recognised sanitiser (mask/hash/encrypt) node "
            "lies on the taint path between source and sink."
        ),
        locality=Locality.EITHER,
        official_source=_src("art_5"),
    ),

    "OBL-6-1": Obligation(
        obligation_id="OBL-6-1",
        rule_id="R2",
        article="Art. 6(1)",
        title="Lawfulness of processing",
        paraphrase=(
            "Processing of personal data is lawful only where at least "
            "one of the Article 6(1) bases applies (e.g. consent, "
            "contract necessity, legal obligation, legitimate interest); "
            "absent a documented basis, a processing operation that "
            "discloses or persists personal data is not shown to be "
            "lawful."
        ),
        code_level_condition=(
            "A tainted PII field reaches any recognised sink and no "
            "recognised guard (an IF whose condition text references "
            "consent/permission/authorisation) lies on the taint path. "
            "COBCheck treats a present guard as evidence a lawful-basis "
            "check occurs, not as proof the basis is valid — the "
            "article is about the presence/absence of that check, which "
            "is what is decidable from source."
        ),
        locality=Locality.EITHER,
        official_source=_src("art_6"),
    ),

    "OBL-44-49": Obligation(
        obligation_id="OBL-44-49",
        rule_id="R3",
        article="Art. 44-49 (Chapter V)",
        title="Transfers of personal data to third countries or "
              "international organisations",
        paraphrase=(
            "A transfer of personal data to a recipient outside the "
            "Union (or to an international organisation) requires an "
            "adequacy decision, appropriate safeguards (e.g. SCCs, "
            "BCRs), or a Chapter V derogation; Chapter V does not "
            "distinguish who performs the transfer, only that personal "
            "data leaves the Union-side processing environment."
        ),
        code_level_condition=(
            "A tainted PII field reaches a sink classified as an "
            "external interface: NETWORK_TRANSFER (a WRITE/CALL whose "
            "name matches an external-transfer token such as EXPORT, "
            "API, HTTP, TRANSFER), CONTENT_OR_SERVICE, or MESSAGING. "
            "No neutraliser is structural for this obligation: the "
            "transfer itself is the triggering fact, and whether an "
            "adequacy mechanism was applied is not observable from "
            "COBOL source, so every such flow is reported (not silently "
            "cleared) for the compliance officer to confirm off-tool."
        ),
        locality=Locality.CROSS_PROGRAM,
        official_source=_src("art_44"),
    ),

    "OBL-32-1-A": Obligation(
        obligation_id="OBL-32-1-A",
        rule_id="R4",
        article="Art. 32(1)(a)",
        title="Security of processing — pseudonymisation and encryption",
        paraphrase=(
            "Controllers and processors must implement appropriate "
            "technical measures for the security of processing, "
            "including the pseudonymisation and encryption of personal "
            "data, appropriate to the risk."
        ),
        code_level_condition=(
            "A tainted PII field reaches persistent storage — a "
            "FILE_STORAGE WRITE (VSAM/sequential) or a DATABASE sink "
            "(EXEC SQL INSERT/UPDATE/MERGE, EXEC SQL IMS) — and no "
            "recognised sanitiser node lies on the taint path before "
            "the WRITE/EXEC."
        ),
        locality=Locality.EITHER,
        official_source=_src("art_32"),
    ),

    "OBL-9-1": Obligation(
        obligation_id="OBL-9-1",
        rule_id="R5",
        article="Art. 9(1)",
        title="Processing of special categories of personal data",
        paraphrase=(
            "Processing of data revealing racial or ethnic origin, "
            "political opinions, religious or philosophical beliefs, "
            "trade-union membership, genetic data, biometric data used "
            "for unique identification, health data, or data concerning "
            "a natural person's sex life or sexual orientation is "
            "prohibited unless an Article 9(2) exception applies."
        ),
        code_level_condition=(
            "A tainted field whose PII category was tagged HEALTH or "
            "BIOMETRIC (the two Privado-derived categories in "
            "COBCheck's taxonomy that fall within Art. 9(1)'s exhaustive "
            "list — see 'Out-of-scope categories' below) reaches any "
            "recognised sink. COBCheck deliberately does NOT map "
            "NATIONAL_ID to Art. 9: national identification numbers are "
            "not in the Art. 9(1) list; some Member States extend "
            "special-category-equivalent protection to them under "
            "Art. 87, but that is national law, is not uniform across "
            "the Union, and is out of scope for a GDPR-article mapping."
        ),
        locality=Locality.EITHER,
        official_source=_src("art_9"),
    ),

    "OBL-5-1-C": Obligation(
        obligation_id="OBL-5-1-C",
        rule_id="R6",
        article="Art. 5(1)(c)",
        title="Data minimisation",
        paraphrase=(
            "Personal data must be adequate, relevant, and limited to "
            "what is necessary in relation to the purposes for which "
            "it is processed."
        ),
        code_level_condition=(
            "A CALL ... USING statement passes a LINKAGE SECTION group "
            "into a callee, and at least one elementary field inside "
            "that group is (a) tagged as PII and (b) never appears as "
            "the source of any data-movement statement anywhere in the "
            "callee's own PROCEDURE DIVISION. Deciding this REQUIRES "
            "both the caller's CALL statement (what was shared) and the "
            "callee's full body (what was ever used) — no single "
            "program's source contains both facts, which is why this "
            "is the one obligation in the set whose locality is fixed "
            "at CROSS_PROGRAM rather than decided per-flow. See "
            "cobcheck/gdpr/mapping.py:map_call_boundaries for the "
            "stated limitations of this heuristic (fields referenced "
            "only inside IF conditions, never moved, are not currently "
            "modelled as 'used')."
        ),
        locality=Locality.CROSS_PROGRAM,
        official_source=_src("art_5"),
    ),
}


# ─── Out-of-scope obligations ─────────────────────────────────────────────
#
# Named explicitly, with the reason, per the brief's Research Task 2:
# "Articles out of scope are listed with the reason."

OUT_OF_SCOPE: dict[str, Obligation] = {

    "OBL-15": Obligation(
        obligation_id="OBL-15",
        rule_id="",
        article="Art. 15",
        title="Right of access by the data subject",
        paraphrase=(
            "A data subject has the right to obtain confirmation of, "
            "and access to, personal data concerning them."
        ),
        code_level_condition="",
        locality=Locality.EITHER,
        official_source=_src("art_15"),
        in_scope=False,
        out_of_scope_reason=(
            "Whether a data-subject-access-request workflow exists is a "
            "runtime/procedural fact about the organisation, not a "
            "property of a data flow recoverable from static COBOL "
            "source. No code-level condition distinguishes 'DSAR "
            "process exists' from 'does not exist' by inspecting a "
            "program."
        ),
    ),

    "OBL-17": Obligation(
        obligation_id="OBL-17",
        rule_id="",
        article="Art. 17",
        title="Right to erasure ('right to be forgotten')",
        paraphrase=(
            "A data subject has the right to obtain erasure of personal "
            "data concerning them without undue delay, subject to "
            "listed exceptions."
        ),
        code_level_condition="",
        locality=Locality.EITHER,
        official_source=_src("art_17"),
        in_scope=False,
        out_of_scope_reason=(
            "Erasure is evidenced by the ABSENCE of a record after a "
            "request, which is a database-state fact over time, not a "
            "flow fact recoverable from a single static analysis pass "
            "over source. Would require runtime/CDC evidence outside "
            "this tool's input model."
        ),
    ),

    "OBL-33": Obligation(
        obligation_id="OBL-33",
        rule_id="",
        article="Art. 33",
        title="Notification of a personal data breach to the "
              "supervisory authority",
        paraphrase=(
            "In the case of a personal data breach, the controller "
            "must notify the competent supervisory authority within 72 "
            "hours of becoming aware of it, unless the breach is "
            "unlikely to result in a risk to natural persons."
        ),
        code_level_condition="",
        locality=Locality.EITHER,
        official_source=_src("art_33"),
        in_scope=False,
        out_of_scope_reason=(
            "Triggered by an incident, not by a static property of "
            "source code. A COBOL program cannot be read to determine "
            "whether a breach occurred or whether the 72-hour clock was "
            "met."
        ),
    ),

    "OBL-25": Obligation(
        obligation_id="OBL-25",
        rule_id="",
        article="Art. 25",
        title="Data protection by design and by default",
        paraphrase=(
            "Controllers must implement appropriate technical and "
            "organisational measures designed to implement data-"
            "protection principles, and must ensure that, by default, "
            "only personal data necessary for each specific purpose is "
            "processed."
        ),
        code_level_condition="",
        locality=Locality.EITHER,
        official_source=_src("art_25"),
        in_scope=False,
        out_of_scope_reason=(
            "Art. 25 is a design-process obligation evaluated over an "
            "organisation's development lifecycle, not a single-flow "
            "property. Its default-minimisation limb overlaps OBL-5-1-C "
            "(Art. 5(1)(c)), which COBCheck maps directly at the "
            "CALL-boundary level; folding Art. 25 in on top would "
            "double-count the same evidence under a second article and "
            "was deliberately avoided rather than left implicit."
        ),
    ),
}


def all_obligations() -> dict[str, Obligation]:
    """In-scope obligations, keyed by obligation_id."""
    return dict(OBLIGATIONS)


def get(obligation_id: str) -> Obligation:
    return OBLIGATIONS[obligation_id]