# Non-EVM architecture

Non-EVM analysis uses a chain plugin selected from a project marker plus ecosystem identifiers, never an extension alone. A plugin supplies a target descriptor, source-backed semantic facts, mapped rules, and a verifier. Universal taxonomy is selection metadata; it never executes on its own. The bundled fallback is a tokenizer/parser that tracks token spans, balanced blocks, attributes, structs/fields, modules, and functions; rule facts are extracted only within those syntax boundaries.

The built-in semantic frontends cover Anchor, CosmWasm, Cosmos IBC, FRAME, XCM, Aptos Move, Sui Move, ink!, and Cairo/Starknet. Their syntax-aware scanner status is `partial`: scanners emit source-mapped candidates and the verifier returns `needs-review` unless chain-native reproduction evidence is supplied. Optional accelerators are Anchor/Cargo AST tooling, `wasmd`/Cosmos SDK tooling, Substrate metadata/compiler, Move compiler/Move Prover, and Scarb; none are required and no network/RPC credentials are used.

IBC flow is modelled as module → port/channel/connection → packet → sequence/timeout → relayer boundary → destination → acknowledgement → state transition. XCM is separate: origin parachain → origin conversion → instruction sequence → barrier/execution → reserve/teleport trust → sovereign mapping → destination call → state mutation. XCM is not IBC.

No non-EVM verification invokes Slither, Foundry, EVM forks, or the EVM conviction engine. Report generation receives only verified, in-scope findings; `needs-review` artifacts are separate.
