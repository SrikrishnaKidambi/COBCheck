"""
cobcheck/pii/privado_rules.py
──────────────────────────────

Privado-inspired source rule support for COBCheck.

The rule system has two layers:

1. External Privado YAML rules
   If YAML files are placed in:

       cobcheck/pii/privado_source_rules/

   this module loads their source-rule metadata and patterns.

2. COBOL-adapted semantic fallback rules
   These provide COBOL-friendly matching when a Privado pattern is
   language-specific or when the external corpus is unavailable.

COBOL identifiers commonly use:

    CUSTOMER-NAME
    CUSTOMER_NAME
    CUSTOMER.NAME

while other languages may use:

    customerName
    customer.name

Therefore every identifier is normalized before matching.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional
import logging
import re

logger = logging.getLogger(__name__)


# ─── Privado's 22 documented source categories ───────────────────────────────

PRIVADO_SOURCE_CATEGORIES = (
    "Account Data",
    "Audio Visual Sensory Data",
    "Background Check Data",
    "Biometric Data",
    "Contact Data",
    "Education Background Data",
    "Financial Data",
    "Health Data",
    "Location Data",
    "National Identification Numbers",
    "Online Identifiers",
    "Personal Characteristics",
    "Personal Identification",
    "Professional Employment Background Data",
    "Purchase Data",
    "Social Media Data",
    "Spouse Family Dependend Data",
    "Technical Data",
    "Usage Data",
    "User Content Data",
    "Vehicle Data",
    "Workplace Monitoring Data",
)


# ─── Data model ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PrivadoSourceRule:
    rule_id: str
    name: str
    category: str
    is_sensitive: bool
    sensitivity: str
    patterns: tuple[str, ...]
    tags: dict[str, Any]


@dataclass(frozen=True)
class PrivadoMatch:
    rule_id: str
    rule_name: str
    category: str
    sensitivity: str
    matched_pattern: str
    source: str


# ─── COBOL identifier normalization ──────────────────────────────────────────

def normalize_identifier(value: str) -> str:
    """
    Convert identifiers into a common token form.

    Examples:

        CUSTOMER-NAME -> CUSTOMER NAME
        CUSTOMER_NAME -> CUSTOMER NAME
        CUSTOMER.NAME -> CUSTOMER NAME
        customerName  -> CUSTOMER NAME
    """

    if not value:
        return ""

    # Split basic camelCase before uppercasing.
    value = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)

    # COBOL and common source-code separators.
    value = re.sub(r"[-_./]+", " ", value)

    # Remove remaining punctuation.
    value = re.sub(r"[^A-Za-z0-9\s]", " ", value)

    value = re.sub(r"\s+", " ", value)

    return value.strip().upper()


def identifier_variants(identifier: str) -> tuple[str, ...]:
    """
    Produce several useful representations for matching.

    This lets patterns written for another identifier convention still
    have a chance of matching COBOL-style names.
    """

    normalized = normalize_identifier(identifier)

    if not normalized:
        return ()

    return tuple(
        dict.fromkeys(
            (
                identifier,
                identifier.upper(),
                normalized,
                normalized.replace(" ", "-"),
                normalized.replace(" ", "_"),
                normalized.replace(" ", ""),
            )
        )
    )


# ─── YAML loading ────────────────────────────────────────────────────────────

def _rules_directory() -> Path:
    return Path(__file__).resolve().parent / "privado_source_rules"


def _extract_rule_entries(document: Any) -> list[dict[str, Any]]:
    """
    Privado documentation describes `sources` as the top-level rule list.

    A defensive fallback for `data_dictionary` is retained because some
    custom/exported rule layouts may use that terminology.
    """

    if not isinstance(document, dict):
        return []

    entries = document.get("sources")

    if entries is None:
        entries = document.get("data_dictionary")

    if not isinstance(entries, list):
        return []

    return [
        entry
        for entry in entries
        if isinstance(entry, dict)
    ]


def load_privado_yaml_rules(
    rules_dir: Optional[Path] = None,
) -> list[PrivadoSourceRule]:
    """
    Load every YAML rule from the local Privado source-rule corpus.

    Missing or invalid individual files do not stop analysis.
    """

    if rules_dir is None:
        rules_dir = _rules_directory()

    if not rules_dir.exists():
        logger.info(
            "Privado rule directory not present: %s",
            rules_dir,
        )
        return []

    try:
        import yaml  # type: ignore
    except ImportError:
        logger.warning(
            "PyYAML is not installed; external Privado rules are disabled."
        )
        return []

    rules: list[PrivadoSourceRule] = []

    for path in sorted(rules_dir.rglob("*.yaml")):
        try:
            with path.open(
                "r",
                encoding="utf-8",
            ) as handle:
                document = yaml.safe_load(handle)

        except Exception as exc:
            logger.warning(
                "Could not read Privado rule file %s: %s",
                path,
                exc,
            )
            continue

        for entry in _extract_rule_entries(document):

            patterns = entry.get("patterns", [])

            if isinstance(patterns, str):
                patterns = [patterns]

            if not isinstance(patterns, list):
                patterns = []

            rule_id = str(entry.get("id", "")).strip()
            name = str(entry.get("name", "")).strip()
            category = str(entry.get("category", "")).strip()

            if not rule_id or not category:
                continue

            rules.append(
                PrivadoSourceRule(
                    rule_id=rule_id,
                    name=name,
                    category=category,
                    is_sensitive=bool(
                        entry.get("isSensitive", False)
                    ),
                    sensitivity=str(
                        entry.get("sensitivity", "")
                    ).strip(),
                    patterns=tuple(
                        str(pattern)
                        for pattern in patterns
                        if pattern
                    ),
                    tags=dict(
                        entry.get("tags", {})
                        or {}
                    ),
                )
            )

    logger.info(
        "Loaded %d external Privado source rules.",
        len(rules),
    )

    return rules


# ─── Regex adaptation ────────────────────────────────────────────────────────

_LANGUAGE_SPECIFIC_MARKERS = (
    "GET",
    "SET",
    "REQUEST",
    "RESPONSE",
    "CONTROLLER",
    "SERVICE",
    "ENTITY",
    "REPOSITORY",
    "PACKAGE",
    "IMPORT",
    "CLASS",
    "METHOD",
)


def _looks_like_language_api_pattern(pattern: str) -> bool:
    """
    Conservatively identify patterns that are probably tied to language APIs.

    Such patterns are not discarded globally because a regex may still
    contain useful identifier fragments. Instead this is used to decide
    whether normalized matching should be attempted.
    """

    upper = pattern.upper()

    return (
        "." in pattern
        and any(
            marker in upper
            for marker in _LANGUAGE_SPECIFIC_MARKERS
        )
    )


def _compile_pattern(
    pattern: str,
) -> Optional[re.Pattern[str]]:
    """
    Compile a Privado regex.

    Privado patterns may use inline flags such as (?i).
    Python supports most ordinary Java-style regex constructs used for
    identifier matching, but unsupported patterns are safely skipped.
    """

    try:
        return re.compile(pattern)

    except re.error:
        return None


def _match_external_rule(
    rule: PrivadoSourceRule,
    identifier: str,
) -> Optional[PrivadoMatch]:

    variants = identifier_variants(identifier)

    if not variants:
        return None

    for raw_pattern in rule.patterns:

        compiled = _compile_pattern(raw_pattern)

        if compiled is None:
            continue

        # Try the original identifier first because this is closest to
        # Privado's intended variable-name matching.
        for variant in variants:

            try:
                if compiled.search(variant):
                    return PrivadoMatch(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        category=rule.category,
                        sensitivity=rule.sensitivity,
                        matched_pattern=raw_pattern,
                        source="privado_yaml",
                    )
            except Exception:
                continue

        # Do not attempt extra transformations for clearly API-oriented
        # patterns; they are less likely to represent COBOL identifiers.
        if _looks_like_language_api_pattern(raw_pattern):
            continue

    return None


# ─── Complete COBOL-adapted semantic category coverage ───────────────────────

# These rules are intentionally token-based rather than API-based.
# They provide adaptation for COBOL naming conventions and ensure every
# Privado source category has a representation in deterministic matching.

_COBOL_CATEGORY_RULES: tuple[
    tuple[str, tuple[str, ...]]
] = (

    (
        "Account Data",
        (
            r"\bACCOUNT\b",
            r"\bACCT\b",
            r"\bLOGIN\b",
            r"\bUSER\s+ACCOUNT\b",
            r"\bSUBSCRIPTION\b",
            r"\bMEMBERSHIP\b",
        ),
    ),

    (
        "Audio Visual Sensory Data",
        (
            r"\bPHOTO\b",
            r"\bIMAGE\b",
            r"\bVIDEO\b",
            r"\bVOICE\b",
            r"\bAUDIO\b",
            r"\bRECORDING\b",
            r"\bFACIAL\s+IMAGE\b",
        ),
    ),

    (
        "Background Check Data",
        (
            r"\bBACKGROUND\s+CHECK\b",
            r"\bCRIMINAL\s+RECORD\b",
            r"\bCONVICTION\b",
            r"\bOFFENCE\b",
            r"\bSECURITY\s+CLEARANCE\b",
            r"\bCREDIT\s+CHECK\b",
        ),
    ),

    (
        "Biometric Data",
        (
            r"\bBIOMETRIC\b",
            r"\bFINGERPRINT\b",
            r"\bRETINA\b",
            r"\bIRIS\b",
            r"\bFACE\s+PRINT\b",
            r"\bVOICE\s+PRINT\b",
        ),
    ),

    (
        "Contact Data",
        (
            r"\bEMAIL\b",
            r"\bE\s+MAIL\b",
            r"\bPHONE\b",
            r"\bTELEPHONE\b",
            r"\bTEL\b",
            r"\bMOBILE\b",
            r"\bCELL\b",
            r"\bFAX\b",
            r"\bADDRESS\b",
            r"\bADDR\b",
            r"\bSTREET\b",
            r"\bPOSTAL\b",
            r"\bZIP\b",
            r"\bPOSTCODE\b",
        ),
    ),

    (
        "Education Background Data",
        (
            r"\bEDUCATION\b",
            r"\bSCHOOL\b",
            r"\bCOLLEGE\b",
            r"\bUNIVERSITY\b",
            r"\bDEGREE\b",
            r"\bQUALIFICATION\b",
            r"\bGPA\b",
            r"\bGRADE\b",
        ),
    ),

    (
        "Financial Data",
        (
            r"\bCARD\b",
            r"\bCREDIT\s+CARD\b",
            r"\bDEBIT\s+CARD\b",
            r"\bCCN\b",
            r"\bCVV\b",
            r"\bCVC\b",
            r"\bPAN\b",
            r"\bIBAN\b",
            r"\bSWIFT\b",
            r"\bBIC\b",
            r"\bBANK\b",
            r"\bROUTING\b",
            r"\bPAYMENT\b",
            r"\bSALARY\b",
            r"\bINCOME\b",
        ),
    ),

    (
        "Health Data",
        (
            r"\bPATIENT\b",
            r"\bMEDICAL\b",
            r"\bHEALTH\b",
            r"\bDIAGNOSIS\b",
            r"\bDIAG\b",
            r"\bMEDICATION\b",
            r"\bPRESCRIPTION\b",
            r"\bALLERGY\b",
            r"\bHOSPITAL\b",
            r"\bCLINIC\b",
            r"\bPHYSICIAN\b",
            r"\bDOCTOR\b",
            r"\bMRN\b",
        ),
    ),

    (
        "Location Data",
        (
            r"\bLOCATION\b",
            r"\bGEOLOCATION\b",
            r"\bGEO\b",
            r"\bGPS\b",
            r"\bLATITUDE\b",
            r"\bLONGITUDE\b",
            r"\bCOORDINATE\b",
        ),
    ),

    (
        "National Identification Numbers",
        (
            r"\bSSN\b",
            r"\bSIN\b",
            r"\bNIN\b",
            r"\bTIN\b",
            r"\bTFN\b",
            r"\bAADHAAR\b",
            r"\bPASSPORT\b",
            r"\bNATIONAL\s+ID\b",
            r"\bVOTER\s+ID\b",
            r"\bDRIVER\b",
            r"\bLICEN[CS]E\b",
        ),
    ),

    (
        "Online Identifiers",
        (
            r"\bIP\s+ADDRESS\b",
            r"\bIPADDR\b",
            r"\bMAC\s+ADDRESS\b",
            r"\bCOOKIE\b",
            r"\bSESSION\s+ID\b",
            r"\bDEVICE\s+ID\b",
            r"\bUSERNAME\b",
            r"\bUSER\s+NAME\b",
            r"\bHANDLE\b",
        ),
    ),

    (
        "Personal Characteristics",
        (
            r"\bAGE\b",
            r"\bGENDER\b",
            r"\bSEX\b",
            r"\bMARITAL\b",
            r"\bNATIONALITY\b",
            r"\bCITIZENSHIP\b",
            r"\bETHNICITY\b",
            r"\bRACE\b",
            r"\bRELIGION\b",
        ),
    ),

    (
        "Personal Identification",
        (
            r"\bNAME\b",
            r"\bSURNAME\b",
            r"\bFIRST\s+NAME\b",
            r"\bLAST\s+NAME\b",
            r"\bFULL\s+NAME\b",
            r"\bCUSTOMER\s+ID\b",
            r"\bCLIENT\s+ID\b",
            r"\bPERSON\s+ID\b",
            r"\bMEMBER\s+ID\b",
            r"\bPATIENT\s+ID\b",
            r"\bEMPLOYEE\s+ID\b",
            r"\bPOLICY\s+ID\b",
            r"\bCLAIM\s+ID\b",
        ),
    ),

    (
        "Professional Employment Background Data",
        (
            r"\bEMPLOYEE\b",
            r"\bEMPLOYER\b",
            r"\bJOB\b",
            r"\bOCCUPATION\b",
            r"\bPROFESSION\b",
            r"\bWORK\s+HISTORY\b",
            r"\bPAYROLL\b",
        ),
    ),

    (
        "Purchase Data",
        (
            r"\bPURCHASE\b",
            r"\bORDER\b",
            r"\bTRANSACTION\b",
            r"\bSHOPPING\b",
            r"\bPRODUCT\s+HISTORY\b",
        ),
    ),

    (
        "Social Media Data",
        (
            r"\bSOCIAL\s+MEDIA\b",
            r"\bPROFILE\b",
            r"\bTWEET\b",
            r"\bPOST\b",
            r"\bFOLLOWER\b",
            r"\bFRIEND\s+LIST\b",
        ),
    ),

    (
        "Spouse Family Dependend Data",
        (
            r"\bSPOUSE\b",
            r"\bFAMILY\b",
            r"\bDEPENDENT\b",
            r"\bCHILD\b",
            r"\bPARENT\b",
            r"\bNEXT\s+OF\s+KIN\b",
        ),
    ),

    (
        "Technical Data",
        (
            r"\bDEVICE\b",
            r"\bBROWSER\b",
            r"\bOPERATING\s+SYSTEM\b",
            r"\bOS\s+VERSION\b",
            r"\bHARDWARE\b",
            r"\bUSER\s+AGENT\b",
        ),
    ),

    (
        "Usage Data",
        (
            r"\bUSAGE\b",
            r"\bACTIVITY\b",
            r"\bCLICK\b",
            r"\bEVENT\b",
            r"\bACCESS\s+TIME\b",
            r"\bLOGIN\s+TIME\b",
        ),
    ),

    (
        "User Content Data",
        (
            r"\bMESSAGE\b",
            r"\bCOMMENT\b",
            r"\bCONTENT\b",
            r"\bTEXT\b",
            r"\bFEEDBACK\b",
            r"\bREVIEW\b",
            r"\bUPLOAD\b",
        ),
    ),

    (
        "Vehicle Data",
        (
            r"\bVEHICLE\b",
            r"\bVIN\b",
            r"\bREGISTRATION\b",
            r"\bLICENSE\s+PLATE\b",
            r"\bCAR\b",
        ),
    ),

    (
        "Workplace Monitoring Data",
        (
            r"\bWORKPLACE\s+MONITORING\b",
            r"\bATTENDANCE\b",
            r"\bWORK\s+HOURS\b",
            r"\bEMPLOYEE\s+ACTIVITY\b",
            r"\bMONITORING\b",
            r"\bTIME\s+SHEET\b",
        ),
    ),
)


_COMPILED_COBOL_RULES: tuple[
    tuple[str, tuple[re.Pattern[str], ...]]
] = tuple(
    (
        category,
        tuple(
            re.compile(pattern, re.IGNORECASE)
            for pattern in patterns
        ),
    )
    for category, patterns in _COBOL_CATEGORY_RULES
)


def _match_cobol_semantic_rules(
    identifier: str,
) -> Optional[PrivadoMatch]:

    normalized = normalize_identifier(identifier)

    if not normalized:
        return None

    for category, patterns in _COMPILED_COBOL_RULES:

        for pattern in patterns:

            if pattern.search(normalized):

                return PrivadoMatch(
                    rule_id=(
                        "COBCHECK.COBOL."
                        + re.sub(
                            r"[^A-Za-z0-9]+",
                            "",
                            category,
                        )
                    ),
                    rule_name=category,
                    category=category,
                    sensitivity="",
                    matched_pattern=pattern.pattern,
                    source="cobol_semantic",
                )

    return None


# ─── Public matcher ──────────────────────────────────────────────────────────

class PrivadoRuleMatcher:
    """
    Match COBOL identifiers against:

    1. Actual local Privado YAML rules.
    2. COBOL-adapted semantic rules.

    YAML rules are checked first so original Privado metadata is preserved
    whenever a rule matches.
    """

    def __init__(
        self,
        rules_dir: Optional[Path] = None,
    ):
        self._rules = load_privado_yaml_rules(
            rules_dir
        )

    @property
    def external_rule_count(self) -> int:
        return len(self._rules)

    def match(
        self,
        identifier: str,
    ) -> Optional[PrivadoMatch]:

        for rule in self._rules:

            match = _match_external_rule(
                rule,
                identifier,
            )

            if match is not None:
                return match

        return _match_cobol_semantic_rules(
            identifier
        )


_DEFAULT_MATCHER: Optional[
    PrivadoRuleMatcher
] = None


def get_default_matcher() -> PrivadoRuleMatcher:

    global _DEFAULT_MATCHER

    if _DEFAULT_MATCHER is None:
        _DEFAULT_MATCHER = PrivadoRuleMatcher()

    return _DEFAULT_MATCHER


def match_privado_source(
    identifier: str,
) -> Optional[PrivadoMatch]:

    return get_default_matcher().match(
        identifier
    )