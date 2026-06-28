"""
cobcheck/cpg/graph_model.py
────────────────────────────
CPG (Code Property Graph) data model backed by NetworkX.

A CPG unifies three graphs over the same set of nodes:

  AST edges  — parent → child in the syntactic tree
  CFG edges  — control-flow predecessor → successor
  PDG edges  — data-dependence producer → consumer (def → use)

We add a fourth edge kind:

  CALL edges — call-site node → entry node of the called program

All four live in one NetworkX MultiDiGraph so you can ask cross-cutting
questions (e.g. "is there a taint path from node A to node B that
respects control flow?") with standard graph algorithms.

Node attributes (stored in G.nodes[node_id])
──────────────────────────────────────────────
  kind        : NodeKind enum
  stmt        : the AST node (DataItem, MoveStmt, …) — the raw payload
  program     : program_id string
  file        : absolute source path
  line        : source line number
  pii_fields  : set[str] — PII field names that taint this node (filled by taint engine)
  is_sink     : bool
  sink_kind   : SinkKind | None
  is_sanitiser: bool
  is_guard    : bool

Edge attributes (stored in G.edges)
─────────────────────────────────────
  kind : EdgeKind enum
"""

from __future__ import annotations

from enum import Enum, auto
from typing import Any, Optional
import networkx as nx


# ─── Enumerations ─────────────────────────────────────────────────────────────

class NodeKind(Enum):
    # Data Division
    DATA_ITEM   = auto()   # a COBOL data field declaration
    # Procedure Division statements
    MOVE        = auto()
    COMPUTE     = auto()
    CALL        = auto()
    WRITE       = auto()
    READ        = auto()
    DISPLAY     = auto()
    IF          = auto()
    PERFORM     = auto()
    GENERIC     = auto()
    # Structural
    ENTRY       = auto()   # program / paragraph / section entry point
    EXIT        = auto()   # program / paragraph / section exit
    # Cross-program
    CALL_SITE   = auto()   # the CALL statement node (duplicated as CALL_SITE for clarity)
    FILE_WRITE  = auto()   # PII written to a shared file
    FILE_READ   = auto()   # PII read from a shared file


class EdgeKind(Enum):
    AST      = auto()   # parent → child  (syntactic containment)
    CFG      = auto()   # predecessor → successor (control flow)
    PDG      = auto()   # def → use  (data dependence)
    CALL     = auto()   # call-site → callee entry
    RETURN   = auto()   # callee exit → call-site (return flow)
    COPYBOOK = auto()   # program → copybook data item (field sharing via COPY)
    FILE_IO  = auto()   # FILE_WRITE → FILE_READ (inter-program via shared file)


class SinkKind(Enum):
    LOG      = auto()   # WRITE to a log / report file
    DISPLAY  = auto()   # DISPLAY to terminal / SYSLST
    PRINT    = auto()   # WRITE to a print file
    FILE     = auto()   # WRITE to a VSAM / sequential file (at-rest)
    EXTERNAL = auto()   # EXEC CICS SEND, API call, cross-border transfer
    UNKNOWN  = auto()


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
    Thin wrapper around a NetworkX MultiDiGraph that enforces node/edge schemas
    and provides convenience query methods used by the taint engine and GDPR rules.

    The underlying graph is accessible as ``cpg.G`` for low-level operations.
    """

    def __init__(self):
        self.G: nx.MultiDiGraph = nx.MultiDiGraph()

    # ─── Node operations ──────────────────────────────────────────────────────

    def add_node(
        self,
        kind:          NodeKind,
        stmt:          Any        = None,
        program:       str        = "",
        file:          str        = "",
        line:          int        = 0,
        is_sink:       bool       = False,
        sink_kind:     Optional[SinkKind] = None,
        is_sanitiser:  bool       = False,
        is_guard:      bool       = False,
        **extra,
    ) -> int:
        nid = new_node_id()
        self.G.add_node(
            nid,
            kind         = kind,
            stmt         = stmt,
            program      = program,
            file         = file,
            line         = line,
            pii_fields   = set(),
            is_sink      = is_sink,
            sink_kind    = sink_kind,
            is_sanitiser = is_sanitiser,
            is_guard     = is_guard,
            **extra,
        )
        return nid

    def get(self, nid: int) -> dict:
        return self.G.nodes[nid]

    # ─── Edge operations ──────────────────────────────────────────────────────

    def add_edge(self, src: int, dst: int, kind: EdgeKind, **attrs) -> None:
        self.G.add_edge(src, dst, kind=kind, **attrs)

    def edges_of_kind(self, kind: EdgeKind):
        """Yield (src, dst, data) for all edges of a given kind."""
        for u, v, data in self.G.edges(data=True):
            if data.get("kind") == kind:
                yield u, v, data

    # ─── PII tagging ──────────────────────────────────────────────────────────

    def tag_pii(self, nid: int, field_name: str) -> None:
        self.G.nodes[nid]["pii_fields"].add(field_name)

    def pii_fields(self, nid: int) -> set[str]:
        return self.G.nodes[nid].get("pii_fields", set())

    def is_pii_tainted(self, nid: int) -> bool:
        return bool(self.pii_fields(nid))

    # ─── Sink / guard queries ─────────────────────────────────────────────────

    def sinks(self, sink_kind: Optional[SinkKind] = None):
        """Yield node IDs that are sinks (optionally filtered by kind)."""
        for nid, data in self.G.nodes(data=True):
            if data.get("is_sink"):
                if sink_kind is None or data.get("sink_kind") == sink_kind:
                    yield nid

    def sanitisers(self):
        for nid, data in self.G.nodes(data=True):
            if data.get("is_sanitiser"):
                yield nid

    def guards(self):
        for nid, data in self.G.nodes(data=True):
            if data.get("is_guard"):
                yield nid

    # ─── Path queries ─────────────────────────────────────────────────────────

    def has_path(self, src: int, dst: int) -> bool:
        """True if there is any directed path from src to dst in the CPG."""
        return nx.has_path(self.G, src, dst)

    def all_simple_paths(self, src: int, dst: int, cutoff: int = 50):
        """
        Yield all simple directed paths from src to dst.
        *cutoff* limits path length to avoid combinatorial explosion.
        """
        try:
            yield from nx.all_simple_paths(self.G, src, dst, cutoff=cutoff)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return

    def nodes_on_path(self, path: list[int]) -> list[dict]:
        """Return node attribute dicts for each node in path."""
        return [self.G.nodes[nid] for nid in path]

    # ─── Serialisation ────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Lightweight summary for logging / debugging."""
        sink_count = sum(1 for _, d in self.G.nodes(data=True) if d.get("is_sink"))
        tainted    = sum(1 for _, d in self.G.nodes(data=True) if d.get("pii_fields"))
        return {
            "nodes":     self.G.number_of_nodes(),
            "edges":     self.G.number_of_edges(),
            "sinks":     sink_count,
            "tainted":   tainted,
        }

    def __repr__(self) -> str:
        s = self.summary()
        return (f"<CPG nodes={s['nodes']} edges={s['edges']} "
                f"sinks={s['sinks']} tainted={s['tainted']}>")