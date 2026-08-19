# Capability matrix

| Ecosystem | Scanner | Rules | Verifier | Status |
|---|---:|---:|---|---|
| EVM | Slither/other existing adapters | existing | EVM conviction | supported |
| Anchor/Solana native Rust | syntax-aware semantic | 25 | source/evidence gate | partial |
| CosmWasm | syntax-aware semantic | 10 | source/evidence gate | partial |
| Cosmos SDK/IBC | syntax-aware semantic | 12 | flow/source gate | partial |
| FRAME | syntax-aware semantic | 12 | source/evidence gate | partial |
| Polkadot/Kusama XCM | syntax-aware semantic | 15 | flow/source gate | partial |
| Aptos Move | syntax-aware semantic | 12 | source/evidence gate | partial |
| Sui Move | syntax-aware semantic | 15 | source/evidence gate | partial |
| ink! | syntax-aware semantic | 8 | source/evidence gate | partial |
| Cairo/Starknet | syntax-aware semantic | 10 | source/evidence gate | partial |

`aletheia inventory` renders the live registry with engine, rule count, verifier state, and status. Optional chain compilers/provers are intentionally not dependencies and no RPC credentials are used.
