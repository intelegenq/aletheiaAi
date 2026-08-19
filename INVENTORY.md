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

## 5. Triage/Analyzer — ✅ M3–M6 selesai
- FP filtering, scope safety, access-control/reachability evidence, root-cause correlation, conviction, dan triage severity aktif
- Unknown evidence tetap dipertahankan sebagai unknown dan memblokir report-ready bila kritis

## 6. Reporter — ✅ selesai
- Evidence-gated report JSON/Markdown untuk default, HackenProof, Immunefi, dan YesWeHack
- Report schema validation menolak finding yang belum verified, unknown, atau out-of-scope

## 7. Workflow — ✅ selesai
- Durable resumable pipeline dengan atomic checkpoint, retry, artifact manifest, AI planning, scan, verify, triage, review, dan report
- Target resolver mendukung local path dan shallow Git clone
- Scope manifest parser dan reproducible artifact identity tersedia

## 8. Universal spec → detector/analysis compiler — ✅ M8 selesai
- 59 universal specs sekarang dinormalisasi dari taxonomy 93 + semantic coverage
- 48 static-feasible dan 11 manual-review; status implementasi tetap dibedakan
- AI plan menerima spec selection, primitive requirement, provenance, dan coverage status
- Compiler menghasilkan execution contract: 23 detector, 25 analysis task, 11 manual review
- Workflow menyimpan `spec_execution_catalog.json` dan tidak mempromosikan candidate/manual menjadi detector

## 9. Multi-chain capability routing — ✅ M9 selesai
- Chain classifier untuk EVM, Solana/Anchor, Move, dan Rust
- Capability registry dan explicit engine routing
- Target non-EVM tidak dipaksa masuk scanner EVM; workflow menyelesaikan audit dengan status deferred tanpa false finding
- Implementasi scanner native Solana/Move/Rust tetap menjadi scope lanjutan, bukan dianggap sudah tersedia

## 10. Data yang kebuang
- /mnt/data/scratch/*.py — 10+ script debug/analyze satu kali, ga pernah di-pack

---

## GAP SUMMARY
| Capability | Status | Prioritas |
|---|---|---|
| Scanner EVM | ✅ done | — |
| KB + 59 specs | ✅ done | — |
| FP filtering | ✅ | — |
| Access-control verdict | ✅ | — |
| Conviction engine | ✅ | — |
| Reporter per-platform | ✅ | — |
| Workflow orchestrator | ✅ | — |
| Spec→detector/analysis compiler | ✅ | — |
| Multi-chain capability routing | ✅ | — |
| Multi-chain capability routing | ✅ | — |
