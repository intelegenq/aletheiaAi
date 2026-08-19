# Non-EVM architecture

Non-EVM analysis uses a chain plugin selected from a project marker plus ecosystem identifiers, never an extension alone. A plugin supplies a target descriptor, source-backed semantic facts, mapped rules, and a verifier. Universal taxonomy is selection metadata; it never executes on its own.

The built-in semantic frontends cover Anchor, CosmWasm, Cosmos IBC, FRAME, XCM, Aptos Move, Sui Move, ink!, and Cairo/Starknet. They are structural fallbacks when compiler AST/IR integrations are absent. Therefore their capability status is `candidate-only`: scanners emit source-mapped candidates and the verifier returns `needs-review` unless chain-native reproduction evidence is supplied.

IBC flow is modelled as module → port/channel/connection → packet → sequence/timeout → relayer boundary → destination → acknowledgement → state transition. XCM is separate: origin parachain → origin conversion → instruction sequence → barrier/execution → reserve/teleport trust → sovereign mapping → destination call → state mutation. XCM is not IBC.

No non-EVM verification invokes Slither, Foundry, EVM forks, or the EVM conviction engine. Report generation receives only verified, in-scope findings; `needs-review` artifacts are separate.
