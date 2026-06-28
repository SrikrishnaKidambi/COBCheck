# COBCheck

Static analysis tool for GDPR compliance in COBOL source code.  
Extends the Mocktail CPG architecture to detect PII flow violations mapped to specific GDPR articles.


## Architecture

```
COBOL source + copybooks
        │
        ▼
┌──────────────────┐
│  Parser Layer    │  ANTLR4 Python runtime → AST
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  CPG Builder     │  AST + CFG + PDG + Call Graph → NetworkX multigraph
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  PII Tagger      │  Name heuristics + PIC heuristics + LLM fallback (Groq)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Taint Engine    │  Cross-program flow: copybook / CALL / file I/O
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  GDPR Rules      │  R1 (Art.32) R2 (Art.6) R3 (Art.44) R4 (Art.32 at-rest)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Report Emitter  │  Structured JSON violation reports
└──────────────────┘
```

## Setup (need to be updated later)

### 1. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate ANTLR4 parser (one-time step — requires Java 11+)
```bash
./scripts/generate_parser.sh
```

### 3. Run on a COBOL codebase
```bash
python -m cobcheck.cli \
  --src path/to/cobol/src \
  --copybooks path/to/copybooks \
  --output violations.json
```

## Project Structure

```
cobcheck/
├── parser/          # ANTLR4-generated files + AST node wrappers
├── cpg/             # CPG builder (AST→CFG→PDG→CG), NetworkX graph model
├── pii/             # PII tagger: name heuristics, PIC heuristics, LLM fallback
├── taint/           # Cross-program taint engine
├── gdpr/            # GDPR rule definitions R1–R4
└── report/          # Violation schema + JSON emitter

tests/
├── fixtures/        # Sample .cbl and .cpy files for unit tests
├── unit/            # Per-layer unit tests
└── integration/     # End-to-end tests on CardDemo / GenApp
```

## GDPR Rules Implemented

| Rule | Article | Fires When |
|------|---------|------------|
| R1 | Art. 32 / 5(1)(f) | PII → log/display/print with no masking |
| R2 | Art. 6 | PII → any sink with no consent-flag check |
| R3 | Art. 44–49 | PII → external/cross-border sink |
| R4 | Art. 32 | PII persisted to file/VSAM with no encryption marker |