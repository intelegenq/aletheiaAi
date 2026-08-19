"""Small deterministic source parser used when chain compilers are absent.

It is intentionally a tokenizer/parser, not a regex scanner: tokens retain
line/column spans, delimiters are balanced, and attributes/fields/functions
are attached to their enclosing syntax node.  Language plugins interpret these
nodes according to their own semantics.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import re

TOKEN_RE = re.compile(r"(?:\#\[|::|=>|->|&&|\|\||==|!=|<=|>=|[A-Za-z_][A-Za-z0-9_]*|\d+|[^\s])")

@dataclass(frozen=True)
class Token:
    text: str; line: int; column: int

@dataclass
class SyntaxNode:
    kind: str; name: str; start_line: int; end_line: int
    tokens: list[Token] = field(default_factory=list)
    attributes: list[str] = field(default_factory=list)
    children: list["SyntaxNode"] = field(default_factory=list)
    def text(self) -> str: return " ".join(t.text for t in self.tokens)

@dataclass
class SyntaxDocument:
    tokens: list[Token]; nodes: list[SyntaxNode]
    def nodes_of(self, *kinds: str) -> list[SyntaxNode]: return [n for n in self.nodes if n.kind in kinds]

def tokenize(source: str) -> list[Token]:
    tokens=[]
    for line_no, raw in enumerate(source.splitlines(), 1):
        # Remove line comments while retaining all prior columns.
        code = raw.split("//", 1)[0]
        for match in TOKEN_RE.finditer(code): tokens.append(Token(match.group(), line_no, match.start()+1))
    return tokens

def _balanced(tokens: list[Token], start: int, opening: str="{", closing: str="}") -> int:
    depth=0
    for index in range(start, len(tokens)):
        if tokens[index].text == opening: depth += 1
        elif tokens[index].text == closing:
            depth -= 1
            if depth == 0: return index
    return len(tokens)-1

def parse(source: str) -> SyntaxDocument:
    tokens=tokenize(source); nodes=[]; attributes=[]; i=0
    while i < len(tokens):
        token=tokens[i]
        if token.text == "#[":
            end=next((j for j in range(i + 1, len(tokens)) if tokens[j].text == "]"), i)
            attributes.append(" ".join(x.text for x in tokens[i:end+1])); i=end+1; continue
        # Rust/Move/Cairo function forms: fn/fun followed by a name.
        if token.text in {"fn", "fun"} and i+1 < len(tokens):
            name=tokens[i+1].text; brace=next((j for j in range(i, len(tokens)) if tokens[j].text=="{"), None)
            end=_balanced(tokens, brace) if brace is not None else i+1
            nodes.append(SyntaxNode("function", name, token.line, tokens[end].line, tokens[i:end+1], attributes)); attributes=[]; i=end+1; continue
        if token.text in {"struct", "mod", "module", "pallet"} and i+1 < len(tokens):
            name=tokens[i+1].text; brace=next((j for j in range(i, len(tokens)) if tokens[j].text=="{"), None)
            end=_balanced(tokens, brace) if brace is not None else i+1
            kind="struct" if token.text=="struct" else "module"
            node=SyntaxNode(kind, name, token.line, tokens[end].line, tokens[i:end+1], attributes)
            # Fields are parsed from comma-separated segments within a struct.
            if kind=="struct" and brace is not None:
                segment=[]
                for field_token in tokens[brace+1:end+1]:
                    if field_token.text in {",", "}"}:
                        names=[x for x in segment if re.match(r"[A-Za-z_]", x.text)]
                        if names: node.children.append(SyntaxNode("field", names[0].text, segment[0].line, segment[-1].line, list(segment)))
                        segment=[]
                    else: segment.append(field_token)
            nodes.append(node); attributes=[]; i=end+1; continue
        i += 1
    return SyntaxDocument(tokens, nodes)
