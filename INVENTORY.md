# AletheiaAI — inventory & gaps

## 1. Scanner (slither-vulndb) — ✅ SUDAH ADA
- **agent_adapter.py** — CLI entry, format unified/JSONL/SARIF/human, FP filters + scope filter (baru di-fix)
- **native_runner.py** — 26 native Slither detectors enriched + TAXONOMY_MAP
- **8 custom detectors** (PAT-*):
  - privileged_config (PAT-0001) ✅ library trace + getter filter (baru di-fix)
  - unchecked_transfer (PAT-0003)
  - div_before_mul (PAT-0005)
  - unbounded_storage_loop (PAT-0009)
  - oracle_dependency (PAT-0010)
  - reentrancy (PAT-0011)
  - liquidation_manipulation (PAT-0016)
  - dependency_version_pinning (PAT-0027)
- **12 analyses** — access_control, state_index, call_index, reachability, cfg, data_dependency, dll.

## 2. KB — ✅ SUDAH ADA
- **41K patterns** — knowledge_base.sqlite3 + jsonl.gz
- **59 universal specs** — /mnt/data/scratch/universal_specs_all.json (48 static-feasible, 11 manual)
- **Enriched** — batch1_enriched.json (8 custom), native_enriched.json (19 native), universal_kb.json (41 KB)

## 3. Tests — ✅ SUDAH ADA
- **86/86 pass** — tests/ covers detectors, KB, analyses, reporting, native mapping

## 4. Fixtures — ✅ SUDAH ADA
- positive/negative/mitigated + NativePositive.sol + per-analysis fixtures

## 5. Triage/Analyzer — ❌ BELUM ADA
- **FP filters** — baru ada 2 (uninitialized-storage, scope) di adapter, hardcoded
- **Access control validation** — ada analysis tapi ga di-output (PAT-0001 ke-fire di setter restricted tanpa verdict)
- **Ground truth** — belum otomatis (cari setter ungated yg ke-miss)
- **Conviction engine** — belum ada sama sekali

## 6. Reporter — ❌ BELUM ADA
- reporting.py — format saja (unified/JSONL/SARIF)
- **Template report per platform** (HackenProof/Immunefi/YesWeHack) — belum ada

## 7. Workflow — ❌ BELUM ADA
- 7-phase pipeline — masih manual (gua jalanin step by step)
- **Scope fetcher** — belum ada (gua buka browser/curl manual)
- **Repo cloner + artifact identity** — manual

## 8. Universal spec → detector builder — ❌ BELUM ADA
- 59 specs masih JSON — implementasi manual per detector

## 9. Multi-chain — ❌ BELUM ADA
- EVM aja (slither). Solana/Move/Rust masih nol

## 10. Data yang kebuang
- /mnt/data/scratch/*.py — 10+ script debug/analyze satu kali, ga pernah di-pack

---

## GAP SUMMARY
| Capability | Status | Prioritas |
|---|---|---|
| Scanner EVM | ✅ done | — |
| KB + 59 specs | ✅ done | — |
| FP filtering | ⚠️ partial (2 filter) | P1 |
| Access-control verdict | ❌ | P1 |
| Conviction engine | ❌ | P2 |
| Reporter per-platform | ❌ | P2 |
| Workflow orchestrator | ❌ | P1 |
| Spec→detector builder | ❌ | P2 |
| Multi-chain | ❌ | P3 |