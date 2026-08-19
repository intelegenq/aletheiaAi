# Capability matrix

| Ecosystem | Scanner | Rules | Verifier | Status |
|---|---:|---:|---|---|
| EVM | Slither/other existing adapters | existing | EVM conviction | supported |
| Anchor/Solana native Rust | source semantic | 25 | source/evidence gate | candidate-only |
| CosmWasm | source semantic | 10 | source/evidence gate | candidate-only |
| Cosmos SDK/IBC | source semantic | 12 | flow/source gate | candidate-only |
| FRAME | source semantic | 12 | source/evidence gate | candidate-only |
| Polkadot/Kusama XCM | source semantic | 15 | flow/source gate | candidate-only |
| Aptos Move | source semantic | 12 | source/evidence gate | candidate-only |
| Sui Move | source semantic | 15 | source/evidence gate | candidate-only |
| ink! | source semantic | 8 | source/evidence gate | candidate-only |
| Cairo/Starknet | source semantic | 10 | source/evidence gate | candidate-only |

`aletheia inventory` renders the live registry with engine, rule count, verifier state, and status. Optional chain compilers/provers are intentionally not dependencies and no RPC credentials are used.
