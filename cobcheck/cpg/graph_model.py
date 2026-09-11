"""
cobcheck/cpg/graph_model.py
────────────────────────────
Code Property Graph data model backed by NetworkX.

The graph combines:

    AST       syntactic containment
    CFG       control-flow relationships
    PDG       data-dependence relationships
    CALL      inter-program calls
    RETURN    inter-program return flow
    COPYBOOK  shared copybook relationships
    FILE_IO   shared-file relationships

Each node can also carry PII taint information and sink metadata.
"""

from __future__ import annotations

from enum import Enum, auto
from typing import Any, Optional

import networkx as nx


# ─── Node kinds ───────────────────────────────────────────────────────────────

class NodeKind(Enum):
    # Data Division
    DATA_ITEM = auto()

    # Ordinary COBOL statements
    MOVE = auto()
    COMPUTE = auto()
    CALL = auto()
    WRITE = auto()
    READ = auto()
    DISPLAY = auto()

    # External / subsystem statements
    EXEC_SQL = auto()
    EXEC_SQL_IMS = auto()
    EXEC_CICS = auto()

    # Control flow
    IF = auto()
    PERFORM = auto()

    # Fallback
    GENERIC = auto()

    # Structural
    ENTRY = auto()
    EXIT = auto()

    # Cross-program / storage abstractions
    CALL_SITE = auto()
    FILE_WRITE = auto()
    FILE_READ = auto()


# ─── Edge kinds ───────────────────────────────────────────────────────────────

class EdgeKind(Enum):
    AST = auto()
    CFG = auto()
    PDG = auto()

    CALL = auto()
    RETURN = auto()

    COPYBOOK = auto()
    FILE_IO = auto()

    # Structural containment: an elementary field to its immediately
    # enclosing group item (reconstructed from COBOL level numbers,
    # since DataItem is stored as a flat, declaration-ordered list
    # rather than a tree). Taint-carrying: a group's storage genuinely
    # contains its children's bytes, so a group populated only via
    # MOVEs into its individual elementary fields (no explicit WRITE
    # ... FROM) is still correctly seen as carrying whatever those
    # children carry.
    CONTAINS = auto()


# ─── Sink categories ──────────────────────────────────────────────────────────

class SinkKind(Enum):
    """
    Six sink categories adapted to COBOL.

    These correspond to the conceptual sink categories used in
    source-to-sink privacy analysis, while being represented through
    actual COBOL and mainframe constructs.
    """

    # 1. Logging / output disclosure
    LOGGING = auto()

    # 2. Persistent file storage
    FILE_STORAGE = auto()

    # 3. External or network transfer
    NETWORK_TRANSFER = auto()

    # 4. Message / queue transfer
    MESSAGING = auto()

    # 5. Persistent database operation
    DATABASE = auto()

    # 6. External content or service interface
    CONTENT_OR_SERVICE = auto()

    UNKNOWN = auto()


# ─── Node ID factory ──────────────────────────────────────────────────────────

class _NodeCounter:
    _n = 0

    @classmethod
    def next(cls) -> int:
        cls._n += 1
        return cls._n


def new_node_id() -> int:
    return _NodeCounter.next()


# ─── CPG wrapper ──────────────────────────────────────────────────────────────

class CPG:
    """
    Wrapper around NetworkX MultiDiGraph.

    Nodes store semantic information required by:

        PII identification
        source detection
        sink detection
        taint propagation
        GDPR rule evaluation
    """

    def __init__(self):
        self.G: nx.MultiDiGraph = nx.MultiDiGraph()

    # ─── Node operations ──────────────────────────────────────────────────────

    def add_node(
        self,
        kind: NodeKind,
        stmt: Any = None,
        program: str = "",
        file: str = "",
        line: int = 0,
        is_sink: bool = False,
        sink_kind: Optional[SinkKind] = None,
        is_source: bool = False,
        source_kind: Optional[str] = None,
        is_sanitiser: bool = False,
        is_guard: bool = False,
        **extra,
    ) -> int:
        nid = new_node_id()

        self.G.add_node(
            nid,
            kind=kind,
            stmt=stmt,
            program=program,
            file=file,
            line=line,

            # Taint information
            pii_fields=set(),
            pii_categories={},

            # Source information
            is_source=is_source,
            source_kind=source_kind,

            # Sink information
            is_sink=is_sink,
            sink_kind=sink_kind,

            # Privacy controls
            is_sanitiser=is_sanitiser,
            is_guard=is_guard,

            **extra,
        )

        return nid

    def get(self, nid: int) -> dict:
        return self.G.nodes[nid]

    # ─── Edge operations ──────────────────────────────────────────────────────

    def add_edge(
        self,
        src: int,
        dst: int,
        kind: EdgeKind,
        **attrs,
    ) -> None:
        self.G.add_edge(
            src,
            dst,
            kind=kind,
            **attrs,
        )

    def edges_of_kind(self, kind: EdgeKind):
        for source, destination, data in self.G.edges(data=True):
            if data.get("kind") == kind:
                yield source, destination, data

    # ─── PII tagging ──────────────────────────────────────────────────────────

    def tag_pii(
        self,
        nid: int,
        field_name: str,
        category: Optional[str] = None,
    ) -> None:
        node = self.G.nodes[nid]

        node["pii_fields"].add(field_name)

        if category:
            node["pii_categories"][field_name] = category

    def pii_fields(self, nid: int) -> set[str]:
        return self.G.nodes[nid].get(
            "pii_fields",
            set(),
        )

    def pii_category(
        self,
        nid: int,
        field_name: str,
    ) -> Optional[str]:
        return self.G.nodes[nid].get(
            "pii_categories",
            {},
        ).get(field_name)

    def is_pii_tainted(self, nid: int) -> bool:
        return bool(self.pii_fields(nid))

    # ─── Source queries ───────────────────────────────────────────────────────

    def sources(
        self,
        source_kind: Optional[str] = None,
    ):
        for nid, data in self.G.nodes(data=True):
            if not data.get("is_source"):
                continue

            if (
                source_kind is None
                or data.get("source_kind") == source_kind
            ):
                yield nid

    # ─── Sink queries ─────────────────────────────────────────────────────────

    def sinks(
        self,
        sink_kind: Optional[SinkKind] = None,
    ):
        for nid, data in self.G.nodes(data=True):
            if not data.get("is_sink"):
                continue

            if (
                sink_kind is None
                or data.get("sink_kind") == sink_kind
            ):
                yield nid

    # ─── Privacy-control queries ──────────────────────────────────────────────

    def sanitisers(self):
        for nid, data in self.G.nodes(data=True):
            if data.get("is_sanitiser"):
                yield nid

    def guards(self):
        for nid, data in self.G.nodes(data=True):
            if data.get("is_guard"):
                yield nid

    # ─── Path queries ─────────────────────────────────────────────────────────

    def has_path(
        self,
        src: int,
        dst: int,
    ) -> bool:
        try:
            return nx.has_path(
                self.G,
                src,
                dst,
            )

        except nx.NodeNotFound:
            return False

    def all_simple_paths(
        self,
        src: int,
        dst: int,
        cutoff: int = 50,
    ):
        try:
            yield from nx.all_simple_paths(
                self.G,
                src,
                dst,
                cutoff=cutoff,
            )

        except (
            nx.NetworkXNoPath,
            nx.NodeNotFound,
        ):
            return

    def nodes_on_path(
        self,
        path: list[int],
    ) -> list[dict]:
        return [
            self.G.nodes[nid]
            for nid in path
        ]

    # ─── Summary ──────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        sink_counts: dict[str, int] = {}

        for _, data in self.G.nodes(data=True):
            if data.get("is_sink"):
                sink = data.get("sink_kind")

                name = (
                    sink.name
                    if sink is not None
                    else "UNKNOWN"
                )

                sink_counts[name] = (
                    sink_counts.get(name, 0) + 1
                )

        source_count = sum(
            1
            for _, data in self.G.nodes(data=True)
            if data.get("is_source")
        )

        tainted_count = sum(
            1
            for _, data in self.G.nodes(data=True)
            if data.get("pii_fields")
        )

        return {
            "nodes": self.G.number_of_nodes(),
            "edges": self.G.number_of_edges(),
            "sources": source_count,
            "sinks": sum(sink_counts.values()),
            "sink_categories": sink_counts,
            "tainted": tainted_count,
        }

    def __repr__(self) -> str:
        summary = self.summary()

        return (
            f"<CPG "
            f"nodes={summary['nodes']} "
            f"edges={summary['edges']} "
            f"sources={summary['sources']} "
            f"sinks={summary['sinks']} "
            f"tainted={summary['tainted']}>"
        )