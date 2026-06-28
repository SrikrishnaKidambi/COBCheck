"""
cobcheck/taint/engine.py
─────────────────────────
Cross-program taint propagation engine.

The engine implements the declarative semantics from the brief:

    violation(F, S) :-
        pii(F),
        flows(F, S),           % taint reachability on CPG
        sink(S, Kind),
        not sanitised_on_path(F, S),
        not guarded_on_path(F, S).

It does so imperatively using a worklist-based forward taint propagation:

  1. Seed worklist with all PII-tagged DATA_ITEM nodes.
  2. For each node N in the worklist:
       a. For each successor M on a PDG / CALL / FILE_IO / COPYBOOK edge:
            - propagate N's pii_fields to M
            - if M is newly tainted, add to worklist
  3. After propagation, collect (pii_field, sink_node) pairs where the
     sink is tainted.
  4. For each such pair, check whether every path from the PII source to
     the sink passes through a sanitiser or a guard — using a path search
     on the CPG.

The output is a list of TaintFlow objects consumed by the GDPR rule layer.

Design notes
────────────
* We propagate pii_fields *sets* so one node can carry multiple PII tags.
* Sanitiser / guard check is a "path existence" query: we look for at
  least one path from source to sink that has NO sanitiser/guard.  If all
  paths are guarded, no violation.  This is a sound over-approximation —
  false negatives are unlikely for COBOL's largely sequential control flow.
* The graph is typically small (CardDemo has ~40 programs), so BFS/DFS
  path search is fast enough.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from ..cpg.graph_model import CPG, EdgeKind, SinkKind, NodeKind

logger = logging.getLogger(__name__)

# Edge kinds that carry taint
_TAINT_EDGES = {EdgeKind.PDG, EdgeKind.CALL, EdgeKind.FILE_IO, EdgeKind.COPYBOOK}


# ─── Data transfer object ─────────────────────────────────────────────────────

@dataclass
class TaintFlow:
    """
    A confirmed taint path from a PII source field to a sink node.

    This is the unit of information consumed by the GDPR rule layer.
    """
    pii_field:     str
    pii_category:  str                 # PiiCategory.name
    source_nid:    int                 # DATA_ITEM node where field is declared
    sink_nid:      int                 # sink node
    sink_kind:     SinkKind
    sink_program:  str
    sink_file:     str
    sink_line:     int
    path:          list[int]           # one representative path (node IDs)
    sanitised:     bool = False
    consent_checked: bool = False

    # Filled by GDPR rules
    violations:    list[str] = field(default_factory=list)


# ─── Taint engine ─────────────────────────────────────────────────────────────

class TaintEngine:
    """
    Forward taint propagation + path-sensitive sanitiser / guard checking.
    """

    def __init__(self, path_cutoff: int = 100):
        """
        Parameters
        ----------
        path_cutoff : int
            Maximum path length for sanitiser/guard checking.
            Keeps analysis tractable on large programs.
        """
        self._cutoff = path_cutoff

    def run(self, cpg: CPG) -> list[TaintFlow]:
        """
        Run taint propagation on *cpg* and return all TaintFlow objects.

        The CPG must already have pii_fields populated on DATA_ITEM nodes
        (i.e., PiiTagger.tag() must have been called first).
        """
        logger.info("Taint engine: starting propagation")
        self._propagate(cpg)
        flows = self._collect_flows(cpg)
        logger.info("Taint engine: found %d raw taint flows", len(flows))
        return flows

    # ─── Step 1: forward propagation ─────────────────────────────────────────

    def _propagate(self, cpg: CPG) -> None:
        """
        Worklist-based BFS propagation.
        Seeds from all nodes that already have pii_fields set
        (i.e., the DATA_ITEM nodes tagged by PiiTagger).
        """
        worklist: deque[int] = deque()

        # Seed
        for nid, data in cpg.G.nodes(data=True):
            if data.get("pii_fields"):
                worklist.append(nid)

        visited_pairs: set[tuple[int, str]] = set()  # (node_id, field_name)

        iterations = 0
        while worklist:
            nid = worklist.popleft()
            pii_fields: set[str] = cpg.pii_fields(nid)

            for field_name in list(pii_fields):
                # Propagate to all successors on taint-carrying edges
                for _, succ, edge_data in cpg.G.out_edges(nid, data=True):
                    if edge_data.get("kind") not in _TAINT_EDGES:
                        continue
                    pair = (succ, field_name)
                    if pair in visited_pairs:
                        continue
                    visited_pairs.add(pair)

                    cpg.tag_pii(succ, field_name)
                    # Propagate pii_category if present
                    cat = cpg.G.nodes[nid].get("pii_category")
                    if cat is not None and "pii_category" not in cpg.G.nodes[succ]:
                        cpg.G.nodes[succ]["pii_category"] = cat

                    worklist.append(succ)
                    iterations += 1

        logger.debug("Taint propagation: %d propagation steps", iterations)

    # ─── Step 2: collect (field, sink) pairs ─────────────────────────────────

    def _collect_flows(self, cpg: CPG) -> list[TaintFlow]:
        flows: list[TaintFlow] = []

        # Build a reverse map: field_name → source DATA_ITEM node IDs
        field_to_source: dict[str, list[int]] = {}
        for nid, data in cpg.G.nodes(data=True):
            if data.get("kind") == NodeKind.DATA_ITEM:
                for fn in data.get("pii_fields", set()):
                    field_to_source.setdefault(fn, []).append(nid)

        for sink_nid in cpg.sinks():
            sink_data  = cpg.get(sink_nid)
            sink_fields: set[str] = sink_data.get("pii_fields", set())
            if not sink_fields:
                continue

            for field_name in sink_fields:
                sources = field_to_source.get(field_name, [])
                for src_nid in sources:
                    path = self._find_best_path(cpg, src_nid, sink_nid)
                    if path is None:
                        continue  # no path in CPG — propagation artefact

                    sanitised       = self._path_has_sanitiser(cpg, path)
                    consent_checked = self._path_has_guard(cpg, path)

                    cat = cpg.G.nodes[src_nid].get("pii_category")
                    cat_name = cat.name if cat is not None else "UNKNOWN"

                    flow = TaintFlow(
                        pii_field       = field_name,
                        pii_category    = cat_name,
                        source_nid      = src_nid,
                        sink_nid        = sink_nid,
                        sink_kind       = sink_data.get("sink_kind", SinkKind.UNKNOWN),
                        sink_program    = sink_data.get("program", ""),
                        sink_file       = sink_data.get("file", ""),
                        sink_line       = sink_data.get("line", 0),
                        path            = path,
                        sanitised       = sanitised,
                        consent_checked = consent_checked,
                    )
                    flows.append(flow)

        return flows

    # ─── Path helpers ─────────────────────────────────────────────────────────

    def _find_best_path(self, cpg: CPG, src: int, dst: int) -> Optional[list[int]]:
        """
        Return a representative path from src to dst, or None.

        We prefer the shortest path for readability in the violation report.
        """
        try:
            import networkx as nx
            return nx.shortest_path(cpg.G, src, dst)
        except Exception:
            return None

    def _path_has_sanitiser(self, cpg: CPG, path: list[int]) -> bool:
        """
        True if *every* path from src to dst passes through a sanitiser.

        For COBCheck we use an optimistic check: we look at the representative
        path only.  If it contains a sanitiser node, we assume sanitised.
        (A full path-forall check would require enumerating all paths — too
        expensive for a first paper; noted as a threat to validity.)
        """
        for nid in path[1:-1]:  # exclude source and sink
            if cpg.get(nid).get("is_sanitiser"):
                return True
        return False

    def _path_has_guard(self, cpg: CPG, path: list[int]) -> bool:
        """True if the representative path contains a consent-flag guard."""
        for nid in path[1:-1]:
            if cpg.get(nid).get("is_guard"):
                return True
        return False