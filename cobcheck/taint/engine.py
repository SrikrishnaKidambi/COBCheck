"""
cobcheck/taint/engine.py
─────────────────────────
Cross-program taint propagation engine.

COBCheck models privacy-relevant data flow as:

    PII Source
        ↓
    intra-program data movement
        ↓
    CALL / shared file / copybook propagation
        ↓
    recognised COBOL sink

The engine performs field-sensitive forward taint propagation over
data-flow carrying CPG edges.

Important design principles
───────────────────────────

1. Only data-flow edges carry taint.
   AST and ordinary CFG edges are NOT automatically treated as data flow.

2. Every taint value preserves its source provenance.
   This allows COBCheck to determine exactly which PII field reached
   which sink.

3. Multiple PII fields can independently taint the same node.

4. Sink categories are not interpreted here.
   The CPG builder is responsible for recognising COBOL constructs as
   sinks; this engine only determines whether PII reaches them.

5. Cross-program propagation is supported through CALL, FILE_IO and
   COPYBOOK edges.

6. Sanitisation and consent/guard information is collected separately
   from the actual data-flow propagation. The GDPR layer can therefore
   reason about the flow without losing the original evidence.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

import networkx as nx

from ..cpg.graph_model import CPG, EdgeKind, SinkKind, NodeKind


logger = logging.getLogger(__name__)


# ─── Taint-carrying edge kinds ────────────────────────────────────────────────

# These are the only edge kinds through which taint automatically propagates.
#
# AST edges:
#     represent syntactic containment, not data movement.
#
# CFG edges:
#     represent possible execution order, not necessarily data movement.
#
# PDG:
#     represents direct data dependence.
#
# CALL:
#     carries actual arguments into another program.
#
# FILE_IO:
#     carries data through shared/persistent files.
#
# COPYBOOK:
#     allows shared data definitions to be connected.
#
# RETURN:
#     carries returned data back to the caller when such an edge exists.
_TAINT_EDGES = {
    EdgeKind.PDG,
    EdgeKind.CALL,
    EdgeKind.RETURN,
    EdgeKind.FILE_IO,
    EdgeKind.COPYBOOK,
    EdgeKind.CONTAINS,
}


# ─── Data transfer object ─────────────────────────────────────────────────────

@dataclass
class TaintFlow:
    """
    One confirmed flow of a PII field from its source declaration to a sink.

    Each object represents:

        source field
            →
        propagated data-flow path
            →
        sink
    """

    pii_field: str
    pii_category: str

    source_nid: int
    sink_nid: int

    sink_kind: SinkKind
    sink_program: str
    sink_file: str
    sink_line: int

    # Representative taint path.
    path: list[int]

    # Flow metadata used later by the GDPR layer.
    sanitised: bool = False
    consent_checked: bool = False

    # Filled by GDPR rules.
    violations: list[str] = field(default_factory=list)


# ─── Taint engine ─────────────────────────────────────────────────────────────

class TaintEngine:
    """
    Field-sensitive forward taint propagation engine.

    The propagation state is:

        (node_id, pii_field)

    rather than simply:

        node_id

    This is important because multiple independent PII fields may reach
    the same intermediate node.
    """

    def __init__(self, path_cutoff: int = 100):
        """
        Parameters
        ----------
        path_cutoff:
            Maximum number of nodes explored when reconstructing a
            representative source-to-sink data-flow path.
        """
        self._cutoff = path_cutoff

        # Maps a PII field name to its original DATA_ITEM source nodes.
        self._field_sources: dict[str, set[int]] = {}

        # Maps a field name to its PII category.
        self._field_categories: dict[str, str] = {}

    # ─── Public entry point ───────────────────────────────────────────────────

    def run(self, cpg: CPG) -> list[TaintFlow]:
        """
        Run taint propagation and return all confirmed source-to-sink flows.

        Preconditions
        -------------
        The CPG must already contain:

        * PII tags assigned by PiiTagger.
        * PDG edges for COBOL data movement.
        * CALL edges for inter-program propagation.
        * FILE_IO edges for persistent/shared-file propagation.
        * recognised sink nodes.
        """

        logger.info("Taint engine: building source index")

        self._build_source_index(cpg)

        logger.info("Taint engine: starting field-sensitive propagation")

        self._propagate(cpg)

        flows = self._collect_flows(cpg)

        logger.info(
            "Taint engine: completed analysis; found %d source-to-sink flows",
            len(flows),
        )

        return flows

    # ─── Source indexing ──────────────────────────────────────────────────────

    def _build_source_index(self, cpg: CPG) -> None:
        """
        Record the original source node and category for every PII field.

        This prevents propagation from losing provenance when multiple
        PII fields reach the same intermediate node.
        """

        self._field_sources.clear()
        self._field_categories.clear()

        for nid, data in cpg.G.nodes(data=True):

            if data.get("kind") != NodeKind.DATA_ITEM:
                continue

            pii_fields = data.get("pii_fields", set())

            if not pii_fields:
                continue

            category = data.get("pii_category")

            if category is None:
                category_name = "UNKNOWN"

            elif hasattr(category, "name"):
                category_name = category.name

            else:
                category_name = str(category)

            for field_name in pii_fields:

                self._field_sources.setdefault(
                    field_name,
                    set(),
                ).add(nid)

                self._field_categories.setdefault(
                    field_name,
                    category_name,
                )

    # ─── Step 1: taint propagation ────────────────────────────────────────────

    def _propagate(self, cpg: CPG) -> None:
        """
        Perform worklist-based forward propagation.

        The worklist stores:

            (node_id, pii_field)

        This means each PII field is propagated independently.
        """

        worklist: deque[tuple[int, str]] = deque()

        # Track states already processed.
        visited: set[tuple[int, str]] = set()

        # ── Seed with original PII sources ────────────────────────────────────

        for field_name, source_nodes in self._field_sources.items():

            for source_nid in source_nodes:

                state = (source_nid, field_name)

                if state not in visited:

                    visited.add(state)
                    worklist.append(state)

        propagation_steps = 0

        # ── Forward worklist propagation ──────────────────────────────────────

        while worklist:

            current_nid, field_name = worklist.popleft()

            for _, successor_nid, edge_data in cpg.G.out_edges(
                current_nid,
                data=True,
            ):

                edge_kind = edge_data.get("kind")

                if edge_kind not in _TAINT_EDGES:
                    continue

                state = (successor_nid, field_name)

                if state in visited:
                    continue

                visited.add(state)

                # Persist the taint on the successor node.
                cpg.tag_pii(
                    successor_nid,
                    field_name,
                )

                # Preserve field category information without relying
                # on a single node-level category.
                successor_data = cpg.get(successor_nid)

                field_categories = successor_data.setdefault(
                    "pii_field_categories",
                    {},
                )

                field_categories[field_name] = (
                    self._field_categories.get(
                        field_name,
                        "UNKNOWN",
                    )
                )

                worklist.append(state)

                propagation_steps += 1

        logger.debug(
            "Taint propagation completed with %d propagation steps",
            propagation_steps,
        )

    # ─── Step 2: collect confirmed source-to-sink flows ───────────────────────

    def _collect_flows(self, cpg: CPG) -> list[TaintFlow]:
        """
        Find every tainted sink and reconstruct a representative data-flow
        path for each originating PII source.
        """

        flows: list[TaintFlow] = []

        # Prevent duplicate flows.
        seen_flows: set[tuple[str, int, int]] = set()

        for sink_nid in cpg.sinks():

            sink_data = cpg.get(sink_nid)

            tainted_fields = set(
                sink_data.get("pii_fields", set())
            )

            if not tainted_fields:
                continue

            sink_flows: list[TaintFlow] = []

            for field_name in sorted(tainted_fields):

                source_nodes = self._field_sources.get(
                    field_name,
                    set(),
                )

                for source_nid in source_nodes:

                    flow_key = (
                        field_name,
                        source_nid,
                        sink_nid,
                    )

                    if flow_key in seen_flows:
                        continue

                    path = self._find_taint_path(
                        cpg,
                        source_nid,
                        sink_nid,
                    )

                    if path is None:
                        continue

                    seen_flows.add(flow_key)

                    pii_category = (
                        self._field_categories.get(
                            field_name,
                            "UNKNOWN",
                        )
                    )

                    sanitised = self._path_has_sanitiser(
                        cpg,
                        path,
                    )

                    consent_checked = self._path_has_guard(
                        cpg,
                        path,
                    )

                    sink_kind = sink_data.get(
                        "sink_kind",
                        SinkKind.UNKNOWN,
                    )

                    sink_flows.append(
                        TaintFlow(
                            pii_field=field_name,
                            pii_category=pii_category,

                            source_nid=source_nid,
                            sink_nid=sink_nid,

                            sink_kind=sink_kind,
                            sink_program=sink_data.get(
                                "program",
                                "",
                            ),
                            sink_file=sink_data.get(
                                "file",
                                "",
                            ),
                            sink_line=sink_data.get(
                                "line",
                                0,
                            ),

                            path=path,

                            sanitised=sanitised,
                            consent_checked=consent_checked,
                        )
                    )

            # De-duplicate flows to this sink: if one flow's source
            # node lies on the path of another (more upstream) flow
            # to the same sink, both describe the same physical data
            # movement — e.g. CUST-SSN moved into WS-AUDIT-SSN before
            # a write, where WS-AUDIT-SSN also independently matches a
            # PII name pattern. Keep only the more original/upstream
            # source rather than reporting the same disclosure twice.
            dominated: set[int] = set()

            for i, fi in enumerate(sink_flows):
                for j, fj in enumerate(sink_flows):
                    if i == j:
                        continue
                    if fj.source_nid in fi.path:
                        dominated.add(j)

            for idx, flow in enumerate(sink_flows):
                if idx not in dominated:
                    flows.append(flow)

        return flows

    # ─── Taint-path reconstruction ────────────────────────────────────────────

    def _find_taint_path(
        self,
        cpg: CPG,
        source_nid: int,
        sink_nid: int,
    ) -> Optional[list[int]]:
        """
        Find a representative path using ONLY taint-carrying edges.

        This is deliberately different from:

            nx.shortest_path(cpg.G, ...)

        because the full CPG also contains AST and CFG edges that do not
        automatically represent movement of personal data.
        """

        if source_nid == sink_nid:
            return [source_nid]

        # Build a temporary graph containing only data-flow edges.
        flow_graph = nx.DiGraph()

        for src, dst, edge_data in cpg.G.edges(data=True):

            if edge_data.get("kind") in _TAINT_EDGES:

                flow_graph.add_edge(
                    src,
                    dst,
                )

        if (
            source_nid not in flow_graph
            or sink_nid not in flow_graph
        ):
            return None

        try:

            path = nx.shortest_path(
                flow_graph,
                source_nid,
                sink_nid,
            )

            if len(path) - 1 > self._cutoff:
                return None

            return path

        except (
            nx.NetworkXNoPath,
            nx.NodeNotFound,
        ):
            return None

    # ─── Path metadata ────────────────────────────────────────────────────────

    def _path_has_sanitiser(
        self,
        cpg: CPG,
        path: list[int],
    ) -> bool:
        """
        Return True when the representative flow path contains a recognised
        sanitisation or de-identification operation.
        """

        for nid in path[1:-1]:

            if cpg.get(nid).get("is_sanitiser"):
                return True

        return False

    def _path_has_guard(
        self,
        cpg: CPG,
        path: list[int],
    ) -> bool:
        """
        Return True when the representative flow path contains a recognised
        privacy/consent/access-control guard.

        The GDPR rule layer must still determine whether that guard is
        semantically sufficient for the particular article being evaluated.
        """

        for nid in path[1:-1]:

            if cpg.get(nid).get("is_guard"):
                return True

        return False