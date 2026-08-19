"""Built-in non-EVM semantic plugins.

The parsers deliberately collect source-backed structural facts only.  They are
not a compiler replacement: every match is a candidate and the verifier never
promotes it without a chain-native reproduction.
"""
from __future__ import annotations
import re
from pathlib import Path
from .evidence import Evidence
from .models import Finding, SourceLocation
from .plugin_api import register
from .rule_contract import RuleDefinition
from .semantic_facts import SemanticFact, SemanticFactBundle
from .target_model import TargetDescriptor
from .verification_contract import VerificationCapabilities, ReproductionCapabilities, VerificationResult
from .syntax import parse

UNIVERSAL = {"authorization":"authorization-bypass", "origin":"signer/origin confusion",
             "asset":"accounting and asset-conservation failure", "cross":"cross-chain trust-boundary failure",
             "replay":"replay and sequence failure", "upgrade":"upgrade/migration control",
             "arithmetic":"arithmetic failure", "call":"arbitrary-external-call", "state":"storage/state lifecycle failure"}

RULES = {
"solana_anchor": ["unchecked-account", "account-info-validation", "missing-signer", "authority-binding", "pda-seeds-bump", "unsafe-init-if-needed", "reinitialization", "arbitrary-cpi-program", "unchecked-remaining-accounts", "duplicate-mutable-account", "account-substitution", "unsafe-close-destination", "signer-privilege-confusion", "unchecked-token-program", "unchecked-sysvar", "transfer-authority-mismatch", "arbitrary-token-account", "discriminator-confusion", "writable-account-abuse", "token-arithmetic-policy", "cpi-privilege-escalation", "stale-account-state", "replay-state-transition", "upgrade-authority", "rent-allocation"],
"cosmwasm": ["authorization", "funds-validation", "denom-confusion", "reply-authorization", "unsafe-migrate", "storage-init", "unchecked-query", "callback-flow", "decimal-accounting", "ibc-callback-trust"],
"cosmos_ibc": ["packet-replay", "unsafe-ack", "timeout-state", "port-channel-confusion", "channel-ordering", "denom-trace", "voucher-handling", "ics20-escrow", "middleware-bypass", "ica-authorization", "callback-origin", "commitment-lifecycle"],
"substrate_frame": ["origin-validation", "root-exposure", "dispatchable-authorization", "storage-mutation", "weight-bound", "fee-bypass", "unsigned-validation", "offchain-worker", "upgrade-authorization", "migration-version", "call-filter", "privileged-pallet"],
"parachain_xcm": ["multilocation-filter", "origin-conversion", "sovereign-privilege", "arbitrary-transact", "reserve-trust", "teleport-trust", "multiasset-confusion", "barrier-bypass", "trader-fee", "asset-transactor", "hrmp-xcmp-sender", "destination-validation", "relay-origin", "trapped-assets", "cross-chain-replay"],
"move_aptos": ["entry-authorization", "signer-capability", "resource-theft", "resource-ownership", "capability-leak", "coin-accounting", "event-state", "init-upgrade", "dependency-trust", "access-specifier", "resource-destruction", "replay-idempotency"],
"move_sui": ["entry-authorization", "signer-capability", "resource-theft", "resource-ownership", "uid-misuse", "shared-object", "arbitrary-transfer", "capability-leak", "coin-accounting", "event-state", "init-upgrade", "dependency-trust", "access-specifier", "object-destruction", "replay-idempotency"],
"ink": ["caller-authorization", "payable-value", "cross-contract-trust", "reentrancy", "storage-migration", "selector-confusion", "arithmetic-accounting", "upgrade-control"],
"cairo": ["caller-validation", "arbitrary-dispatcher", "l1l2-replay", "message-authentication", "class-replacement", "storage-lifecycle", "felt-range", "authorization", "oracle-freshness", "upgrade-control"],
}

CONFIG = {
"solana_anchor": ("solana", "rust", ("Anchor.toml",), ("#[derive(Accounts)]", "anchor_lang", "Context<"), {"account":"Account<|UncheckedAccount|AccountInfo", "signer":"Signer<'info>|is_signer", "authority":"authority|has_one", "pda":"seeds|bump", "cpi":"invoke|CpiContext", "remaining":"remaining_accounts", "lifecycle":"init_if_needed|init|close", "asset":"lamports|token::|transfer"}),
"cosmwasm": ("cosmos", "rust", ("Cargo.toml",), ("cosmwasm_std", "instantiate", "execute"), {"entry":"instantiate|execute|query", "sender":"MessageInfo|info.sender", "funds":"info.funds|Coin|denom", "storage":"Item<|Map<|storage", "admin":"admin|owner", "reply":"reply|SubMsg", "migrate":"migrate", "ibc":"ibc_", "query":"querier", "arithmetic":"Decimal|Uint"}),
"cosmos_ibc": ("cosmos", "rust", ("go.mod", "Cargo.toml"), ("ibc-go", "IbcPacket", "on_recv_packet"), {"packet":"packet|Packet", "port":"port_id|PortId", "channel":"channel_id|ChannelId", "sequence":"sequence|Sequence", "timeout":"timeout|Timeout", "ack":"acknowledgement|Acknowledgement", "denom":"denom_trace|DenomTrace", "ics20":"transfer|escrow|voucher", "middleware":"middleware|ICA", "state":"commitment|receipt"}),
"substrate_frame": ("substrate", "rust", ("Cargo.toml",), ("pallet::", "frame_support", "ensure_signed"), {"dispatch":"#[pallet::call]|#[pallet::call_index]", "origin":"ensure_signed|ensure_root|EnsureOrigin", "storage":"#[pallet::storage]|Storage", "weight":"#[pallet::weight]|Weight", "fee":"fee|Fee", "unsigned":"validate_unsigned|unsigned", "offchain":"offchain_worker", "upgrade":"on_runtime_upgrade|RuntimeUpgrade", "filter":"BaseCallFilter|Contains"}),
"parachain_xcm": ("polkadot", "rust", ("Cargo.toml",), ("xcm::", "MultiLocation", "Xcm("), {"location":"MultiLocation|Location", "asset":"MultiAsset|Assets", "origin":"OriginKind|origin conversion|Sovereign", "barrier":"Barrier|barrier", "trader":"Trader|trader", "transact":"Transact", "reserve":"ReserveAsset|reserve", "teleport":"Teleport", "peer":"HRMP|XCMP|parachain", "destination":"BuyExecution|DepositAsset|destination"}),
"move_aptos": ("move", "move", ("Move.toml",), ("aptos_framework", "aptos::", "signer"), {"entry":"public entry|entry fun", "signer":"&signer|signer", "resource":"move_to|move_from|borrow_global", "capability":"Capability|capability", "coin":"coin::|Coin<", "event":"event::|emit", "upgrade":"init_module|upgrade", "dependency":"use ", "state":"has key|resource"}),
"move_sui": ("move", "move", ("Move.toml",), ("sui::", "UID", "shared"), {"entry":"public entry|entry fun", "signer":"TxContext|ctx", "resource":"move_to|move_from|borrow_global", "uid":"UID|object::", "shared":"share_object|shared", "capability":"Capability|cap", "transfer":"transfer::", "coin":"coin::|balance::", "event":"event::|emit", "upgrade":r"init\(|upgrade", "state":"dynamic_field|delete"}),
"ink": ("substrate", "rust", ("Cargo.toml",), ("#[ink", "ink::contract"), {"caller":"self.env().caller|caller", "value":"transferred_value|payable", "storage":r"ink\s*\(\s*storage\s*\)|Mapping", "call":"build_call|try_invoke|invoke", "selector":"selector|Selector", "reentrancy":"reentrancy|locked", "upgrade":"set_code_hash|upgrade", "arithmetic":"checked_|saturating_|balance"}),
"cairo": ("starknet", "cairo", ("Scarb.toml",), ("#[starknet::contract]", "starknet::"), {"caller":"get_caller_address", "storage":r"#\[storage\]|Storage", "dispatcher":"Dispatcher|dispatcher", "message":"L1Handler|l1_handler|message", "class":"replace_class|class_hash", "felt":"felt252|u256|u128", "access":"component::|AccessControl", "oracle":"oracle|timestamp", "upgrade":"upgrade|replace_class"}),
}

def _taxonomy(rule: str) -> str:
    text = rule.lower()
    for word, taxonomy in UNIVERSAL.items():
        if word in text: return taxonomy
    return "authorization-bypass" if any(x in text for x in ("signer", "authority", "owner", "caller", "origin")) else "storage/state lifecycle failure"

class SourceSemanticPlugin:
    def __init__(self, ecosystem: str):
        self.ecosystem = ecosystem; self.chain_family, self.language, self.markers, self.identifiers, self.fact_patterns = CONFIG[ecosystem]
        self.ecosystems = (ecosystem,)

    def detect_target(self, root: Path):
        files = tuple(sorted((p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts), key=lambda p: str(p)))
        names = {p.name for p in files}; texts = "\n".join(p.read_text(encoding="utf-8", errors="ignore")[:20000] for p in files if p.suffix in {".rs", ".move", ".cairo", ".go"})
        marker_ok = any(marker in names for marker in self.markers)
        identifiers = sum(needle in texts for needle in self.identifiers)
        if not marker_ok or identifiers == 0: return None
        runtime = {"solana_anchor":"anchor", "cosmwasm":"cosmwasm", "cosmos_ibc":"cosmos-sdk/ibc", "substrate_frame":"frame", "parachain_xcm":"xcm", "move_aptos":"aptos", "move_sui":"sui", "ink":"ink!", "cairo":"starknet"}[self.ecosystem]
        return TargetDescriptor(root, self.chain_family, self.ecosystem, self.language, runtime, "high" if identifiers > 1 else "medium", tuple(self.identifiers[:identifiers]), files)

    def collect_semantic_facts(self, target):
        bundle = SemanticFactBundle(chain_family=self.chain_family, ecosystem=self.ecosystem,
            limitations=["Tokenizer/parser extraction is deterministic and source-span aware; compiler AST/IR acceleration is optional."])
        for path in target.files:
            if path.suffix not in {".rs", ".move", ".cairo", ".go"}: continue
            document = parse(path.read_text(encoding="utf-8", errors="ignore"))
            nodes = [*document.nodes, *(field for node in document.nodes for field in node.children)]
            for node in nodes:
                line = " ".join([*node.attributes, node.text()])
                for kind, expression in self.fact_patterns.items():
                    if re.search(expression, line, re.I):
                        bundle.facts.append(SemanticFact(kind, line.strip()[:500], str(path.relative_to(target.root)), node.start_line,
                            {"node_kind": node.kind, "node": node.name, "end_line": node.end_line,
                             "attributes": node.attributes, "syntax_aware": True}))
        return bundle

    def available_rules(self):
        return [RuleDefinition(f"{self.ecosystem}.{name}", name.replace("-", " ").title(), _taxonomy(name), name, (self._rule_fact(name),), ("A matching structural fact may be safely constrained elsewhere.",), ("source mapping", "chain semantic fact", "chain-native reproduction")) for name in RULES[self.ecosystem]]

    def _rule_fact(self, name: str) -> str:
        text = name.lower()
        aliases = (("signer", "signer"), ("authority", "authority"), ("origin", "origin"), ("pda", "pda"),
                   ("account", "account"), ("cpi", "cpi"), ("remaining", "remaining"), ("token", "asset"),
                   ("funds", "funds"), ("denom", "denom"), ("reply", "reply"), ("migrate", "migrate"),
                   ("query", "query"), ("packet", "packet"), ("ack", "ack"), ("timeout", "timeout"),
                   ("channel", "channel"), ("port", "port"), ("storage", "storage"), ("weight", "weight"),
                   ("fee", "fee"), ("unsigned", "unsigned"), ("offchain", "offchain"), ("location", "location"),
                   ("barrier", "barrier"), ("trader", "trader"), ("transact", "transact"), ("reserve", "reserve"),
                   ("teleport", "teleport"), ("uid", "uid"), ("shared", "shared"), ("transfer", "transfer"),
                   ("caller", "caller"), ("payable", "value"), ("selector", "selector"), ("dispatcher", "dispatcher"),
                   ("message", "message"), ("class", "class"), ("felt", "felt"), ("oracle", "oracle"), ("upgrade", "upgrade"),
                   ("init", "lifecycle"), ("reinitial", "lifecycle"), ("arithmetic", "arithmetic"))
        for needle, fact in aliases:
            if needle in text and fact in self.fact_patterns: return fact
        return next(iter(self.fact_patterns))

    def scan(self, target, facts, rules):
        findings=[]
        # Candidate rules require a source-backed fact. Mapping selection is intentionally narrow.
        for rule in rules:
            matches = facts.find(rule.required_facts[0])
            if not matches: continue
            fact=matches[0]
            findings.append(Finding(engine=f"{self.ecosystem}-semantic", detector=rule.rule_id, rule_id=rule.rule_id,
                title=rule.title, description=f"Candidate {rule.title}; requires chain-native semantic validation.", vulnerability_class=rule.taxonomy_id,
                severity=rule.severity, confidence="low", status="candidate", chain_family=self.chain_family, ecosystem=self.ecosystem, language=self.language, runtime=target.runtime,
                universal_taxonomy_id=rule.taxonomy_id, chain_pattern_id=rule.chain_pattern_id, source_location=SourceLocation(file=fact.file, line_start=fact.line, line_end=fact.line),
                evidence=[fact.value], semantic_evidence=[{"kind":fact.kind, "value":fact.value, "file":fact.file, "line":fact.line}], trust_boundary="chain-specific boundary requires review", attacker_control="unknown", asset_model="chain-native assets/state", cross_chain_context={"route": target.runtime} if self.ecosystem in {"cosmos_ibc", "parachain_xcm"} else {}, verification_status="candidate", verification_requirements=list(rule.verification_requirements), false_positive_conditions=list(rule.false_positive_conditions)))
        return findings

    def verifier_capabilities(self): return VerificationCapabilities(True, False, ("source mapping", "semantic evidence"))
    def reproduction_capabilities(self): return ReproductionCapabilities(False, ())
    def verify(self, finding, target, facts, evidence):
        mapped = bool(finding.source_location.file and finding.source_location.line_start and finding.semantic_evidence)
        checks = ["source mapping" if mapped else "missing source mapping", "semantic evidence" if mapped else "missing semantic evidence",
                  "attacker-controlled boundary is unresolved", "chain-specific sink/trust boundary reviewed"]
        if self.ecosystem == "cosmos_ibc": checks += ["packet sequence/timeout/port/channel/acknowledgement/state transition required"]
        if self.ecosystem == "parachain_xcm": checks += ["origin conversion/barrier/reserve-teleport/sovereign account/destination execution required"]
        return VerificationResult(finding.finding_id, self.chain_family, self.ecosystem, "needs-review", finding.source_location.__dict__ if mapped else {}, checks,
            limitations=["No chain-native local reproduction configured; candidate cannot be verified or rejected."])

for _ecosystem in CONFIG:
    register(SourceSemanticPlugin(_ecosystem))
