# Non-EVM corpus

Each ecosystem is evaluated in five fixture classes: `vulnerable`, `secure`,
`mitigated`, `ambiguous`, and `out_of_scope`. The executable, deterministic
corpus specifications are maintained by `test_non_evm_semantic.py`; each case
asserts source mapping, syntax-aware semantic evidence, candidate verdicts,
SARIF metadata, and that the EVM verifier is not invoked. Chain-native
reproduction fixtures remain optional because no compiler/node credentials are
bundled with the repository.
