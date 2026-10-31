"""Scope resolution and source-to-sink taint over a real JavaScript parse tree.

The regex analyser keys taint by *name*: one flat ``Dict[str, str]`` shared by
every function of a bundle. That works on a minified file where each identifier
happens to be unique, and fails on everything else — a local ``const hash`` is
indistinguishable from ``location.hash``, two ``render()`` bodies overwrite each
other, a destructuring declares no name the rules can see, and a closure that
reads an outer tainted variable is invisible because the variable is never
referenced at the sink.

This module replaces the guessing with resolution:

* **Symbols, not names.** Every binding gets an identity of
  ``(block, declared name, index)``, so shadowing and duplicated names are
  ordinary facts rather than hazards. A reference is resolved by walking the
  scope chain from its own position outward, which is what makes a closure read
  the outer variable it closes over.
* **Blocks.** A program, a function, a class field or a callback - each is a
  block with its own ``bindings`` and its references. ``Block.tainted_writes``
  lists the tainted values written to a sink *from code that block owns*, so a
  caller can tell which function holds the flow.
* **Taint as a fact, not a label.** ``Taint`` records where the value came from
  and the symbol that carried it, and is merged from the operands an expression
  is built out of.

``resolve_scopes`` never raises on bad JavaScript: tree-sitter recovers per
node, so a broken statement costs that statement and not the file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from tree_sitter import Language, Node, Parser

try:  # the grammar ships its compiled parser as a module-level constant
    import tree_sitter_javascript as _tsjs

    _LANGUAGE = Language(_tsjs.language())
except Exception:  # pragma: no cover - a missing grammar disables the engine
    _LANGUAGE = None


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Taint:
    """Where a value came from, and the symbol that carried it."""

    source: str
    symbol: str = ""

    def merge(self, other: Optional["Taint"]) -> "Taint":
        """Prefer the originating source; keep this carrier."""
        if other is None:
            return self
        return Taint(other.source, self.symbol or other.symbol)


@dataclass
class Binding:
    """One declaration: a symbol, not a name."""

    name: str
    block: int
    index: int = 0  # declaration order inside the block, for identity
    kind: str = "var"  # var | let | const | param | function | class | import
    taint: Optional[Taint] = None

    @property
    def symbol(self) -> str:
        return f"{self.block}:{self.name}:{self.index}"


@dataclass
class Reference:
    """A read of a name at a position, resolved to the binding it sees."""

    name: str
    offset: int
    block: int
    binding: Optional[Binding] = None


@dataclass
class TaintedWrite:
    """A tainted value written to a sink."""

    sink: str
    source: str
    family: str


@dataclass
class Block:
    """A program, function, class member or callback body."""

    index: int
    kind: str
    name: str = ""
    parent: Optional[int] = None
    children: List[int] = field(default_factory=list)
    bindings: List[Binding] = field(default_factory=list)
    references: List[Reference] = field(default_factory=list)
    tainted_writes: List[TaintedWrite] = field(default_factory=list)

    @property
    def symbol(self) -> str:
        return f"{self.parent}:{self.name or self.kind}:{self.index}"

    def binding(self, name: str) -> Optional[Binding]:
        for b in self.bindings:
            if b.name == name:
                return b
        return None


# ---------------------------------------------------------------------------
# Sources and sinks, expressed on the parse tree
# ---------------------------------------------------------------------------

# A source is matched on the node *kind* and, when the node is a property, its
# literal name. ``location.hash`` and ``window.name`` are member expressions;
# ``localStorage.getItem`` is a call whose member is named here. Matching the
# tree instead of the text is what stops ``const hash = 1`` from matching.
_SOURCE_MEMBERS: Dict[Tuple[str, str], str] = {
    ("location", "hash"): "location.hash",
    ("location", "search"): "location.search",
    ("location", "href"): "location.href",
    ("document", "URL"): "document.URL",
    ("document", "documentURI"): "document.documentURI",
    ("document", "referrer"): "document.referrer",
    ("window", "name"): "window.name",
}

_STORAGE_OBJECTS = {"localStorage": "localStorage", "sessionStorage": "sessionStorage"}
_STORAGE_METHODS = {"getItem", "setItem"}

# Property assignment sinks: ``el.innerHTML = value``.
_SINK_PROPERTIES: Dict[str, str] = {
    "innerHTML": "innerHTML",
    "outerHTML": "innerHTML",
    "src": "script_or_img_src",
    "href": "location_assign",
    "action": "form_action",
    "formaction": "form_action",
}

# Methods that parse their argument as markup or code.
_SINK_METHODS: Dict[str, Tuple[str, str]] = {
    "insertAdjacentHTML": ("insertAdjacentHTML", "html"),
    "write": ("document.write", "html"),
    "writeln": ("document.write", "html"),
    "html": ("jquery.html", "html"),
    "append": ("jquery.append", "html"),
    "prepend": ("jquery.prepend", "html"),
    "eval": ("eval", "code"),
    # AOT-compiled Angular passes the bound property name as an argument:
    # ``ɵɵproperty("innerHTML", value, …)``. The first argument names the sink,
    # the second is the value.
    "property": ("innerHTML", "html"),
}

# Callbacks that receive a value derived from a request, and the source label
# their parameter carries. The receiver decides: ``.then`` on ``fetch(...)`` is
# a response, ``.then`` on a promise of a number is not.
_RESPONSE_METHODS = {"then", "catch", "finally"}
_HTML_SINKS = {"innerHTML", "insertAdjacentHTML", "document.write", "jquery.html",
               "jquery.append", "jquery.prepend", "jquery_selector", "setAttribute_on",
               "inline_handler_assign"}


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _child(node: Node, field_name: str) -> Optional[Node]:
    return node.child_by_field_name(field_name)


def _params_of(fn: Node) -> List[Node]:
    """The parameter nodes of a function, in order.

    An arrow with one parameter stores it in ``parameter``; every other
    function, and a parenthesised arrow, uses ``parameters``. Reading only
    ``parameters`` left ``t => { … }`` with no parameter at all, so a callback
    that received a tainted value resolved it to nothing.
    """
    single = _child(fn, "parameter")
    if single is not None:
        return [single]
    group = _child(fn, "parameters")
    if group is None:
        return []
    return [c for c in group.children if c.type not in ("(", ")", ",")]


def _name_of(node: Node, src: bytes) -> str:
    """The literal name of an identifier/property node, '' when computed."""
    if node.type in ("identifier", "property_identifier",
                     "shorthand_property_identifier", "shorthand_property_identifier_pattern",
                     "private_property_identifier"):
        return _text(node, src)
    if node.type == "string":
        return _text(node, src)[1:-1]
    if node.type == "string_fragment":
        return _text(node, src)
    return ""


def _member_parts(node: Node, src: bytes) -> Tuple[str, str, str]:
    """``(base, property, kind)`` for a member/subscript expression.

    ``kind`` is ``dot`` for ``a.b``, ``sub`` for ``a["b"]`` and ``computed`` when
    the property is not a literal — the case that must never be guessed.
    """
    obj = _child(node, "object")
    prop = _child(node, "property")
    if node.type == "member_expression":
        return (
            _text(obj, src) if obj else "",
            _name_of(prop, src) if prop else "",
            "dot",
        )
    if node.type == "subscript_expression":
        if prop is not None and prop.type == "string":
            return (_text(obj, src) if obj else "", _name_of(prop, src), "sub")
        return (_text(obj, src) if obj else "", _text(prop, src) if prop else "", "computed")
    return ("", "", "computed")


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------


class _Resolver:
    """Builds blocks, bindings and tainted writes for one source text."""

    def __init__(self, src: str, block_index: int = 0):
        self.src_bytes = src.encode("utf-8")
        self.blocks: List[Block] = []
        self._next = block_index
        self._cursor = 0

    # -- block bookkeeping ------------------------------------------------

    def _new_block(self, kind: str, name: str, parent: Optional[int]) -> Block:
        b = Block(index=self._next, kind=kind, name=name, parent=parent)
        self._next += 1
        self.blocks.append(b)
        if parent is not None:
            self.blocks[parent].children.append(b.index)
        return b

    def _bind(self, block: Block, name: str, kind: str, taint: Optional[Taint]) -> Binding:
        existing = block.binding(name)
        if existing is not None:
            # A second declaration of the same name in one block (``var`` hoisted
            # twice) is the same symbol: merge the taint rather than fork it.
            if taint is not None:
                existing.taint = taint if existing.taint is None else existing.taint.merge(taint)
            return existing
        b = Binding(name=name, block=block.index, index=len(block.bindings), kind=kind, taint=taint)
        block.bindings.append(b)
        return b

    def _lookup(self, block_index: int, name: str) -> Optional[Binding]:
        """Resolve *name* from *block_index* outward — the scope chain."""
        seen = 0
        idx: Optional[int] = block_index
        while idx is not None and seen < 64:
            b = self.blocks[idx].binding(name)
            if b is not None:
                return b
            idx = self.blocks[idx].parent
            seen += 1
        return None

    # -- pass 1: declarations -------------------------------------------

    def declare(self, node: Node, block: Block) -> None:
        """Walk *node* and register every binding the block owns."""
        for child in node.children:
            t = child.type
            if t in ("function_declaration", "generator_function_declaration"):
                name = _child(child, "name")
                self._bind(block, _name_of(name, self.src_bytes), "function", None)
            elif t in ("class_declaration",):
                name = _child(child, "name")
                self._bind(block, _name_of(name, self.src_bytes), "class", None)
            elif t in ("variable_declaration", "lexical_declaration"):
                head = _text(child, self.src_bytes)
                kind = "const" if head.startswith("const") else ("let" if head.startswith("let") else "var")
                for decl in child.children:
                    if decl.type == "variable_declarator":
                        self._declare_pattern(_child(decl, "name"), block, kind)
                # A declarator's *value* can hold a nested function
                # (``const f = () => …``), whose names belong to its own block.
                for decl in child.children:
                    if decl.type != "variable_declarator":
                        continue
                    value = _child(decl, "value")
                    if value is not None and value.type in ("function_expression", "arrow_function"):
                        inner = self._new_block(value.type, "", block.index)
                        for p in _params_of(value):
                            self._declare_pattern(p, inner, "param")
                        body = _child(value, "body")
                        if body is not None:
                            self.declare(body, inner)
                continue
            elif t == "import_statement":
                for c in child.children:
                    if c.type == "import_clause":
                        self._declare_import(c, block)
            # A nested function owns its own block; stop here.
            elif t in ("function_expression", "arrow_function", "class_body", "class"):
                continue
            else:
                self.declare(child, block)

    def _declare_pattern(self, pat: Optional[Node], block: Block, kind: str) -> None:
        """Register every name a binding pattern declares."""
        if pat is None:
            return
        t = pat.type
        if t in ("identifier", "shorthand_property_identifier_pattern"):
            self._bind(block, _name_of(pat, self.src_bytes), kind, None)
        elif t == "object_pattern":
            for c in pat.children:
                if c.type == "shorthand_property_identifier_pattern":
                    self._bind(block, _name_of(c, self.src_bytes), kind, None)
                elif c.type == "pair_pattern":
                    # ``{ hash: h }`` declares ``h``, not ``hash``.
                    self._declare_pattern(_child(c, "value"), block, kind)
                elif c.type == "object_assignment_pattern":
                    self._declare_pattern(_child(c, "left"), block, kind)
                elif c.type == "rest_pattern":
                    for cc in c.children:
                        self._declare_pattern(cc, block, kind)
        elif t == "array_pattern":
            for c in pat.children:
                self._declare_pattern(c, block, kind)
        elif t in ("assignment_pattern", "rest_pattern"):
            self._declare_pattern(_child(pat, "left") or _child(pat, "name"), block, kind)

    def _declare_import(self, clause: Node, block: Block) -> None:
        for c in clause.children:
            if c.type == "identifier":
                self._bind(block, _name_of(c, self.src_bytes), "import", None)
            elif c.type == "named_imports":
                for spec in c.children:
                    if spec.type == "import_specifier":
                        local = _child(spec, "alias") or _child(spec, "name")
                        self._bind(block, _name_of(local, self.src_bytes), "import", None)

    # -- pass 2: flows ----------------------------------------------------

    def walk(self, node: Node, block: Block) -> None:
        """Describe every block below *node*, and the taint its statements carry."""
        t = node.type

        if t == "variable_declarator":
            self._declarator(node, block)
            return

        if t in ("assignment_expression",):
            self._assignment(node, block)
            return

        if t == "augmented_assignment_expression":
            # ``html += value`` keeps the html tainted only if the value is.
            self._assignment(node, block, augmented=True)
            return

        if t in ("function_declaration", "generator_function_declaration",
                 "function_expression", "arrow_function", "method_definition"):
            self._function(node, block)
            return

        if t == "class_declaration" or t == "class" or t == "class_body":
            self._class(node, block)
            return

        if t in ("call_expression", "new_expression"):
            self._call(node, block)
            # The receiver and the ordinary arguments still belong to this
            # block; a callback body was already analysed in its own block by
            # ``_bind_callback`` and must not be walked again here, or its sink
            # would be attributed to the caller instead of to the closure.
            fn = _child(node, "function") or (node.child(0) if node.child_count else None)
            if fn is not None:
                self.walk(fn, block)
            args = _child(node, "arguments")
            if args is not None:
                for a in args.children:
                    if a.type in ("(", ")", ","):
                        continue
                    if a.type in ("arrow_function", "function_expression"):
                        continue
                    self.walk(a, block)
            return

        for child in node.children:
            self.walk(child, block)

    def _declarator(self, node: Node, block: Block) -> None:
        name_node = _child(node, "name")
        value = _child(node, "value")
        # ``const {hash} = location``: the *object* is the source, so every name
        # the pattern declares is tainted — including through a rename.
        taint = self.taint_of(value, block) if value is not None else None
        if taint is None and name_node is not None and name_node.type in ("object_pattern", "array_pattern"):
            taint = self._pattern_source(name_node, value, block)
        if name_node is not None:
            self._apply_pattern(name_node, block, taint)
        if value is not None:
            self.walk(value, block)

    def _pattern_source(self, pat: Node, value: Optional[Node], block: Block) -> Optional[Taint]:
        """The source a destructuring reads from, when the object is one.

        ``const {hash} = location`` names no property the value expression can
        see, because the *pattern* carries it: the property being read is the
        pattern's, and the object ``location`` is the source. Kinds inside the
        pattern decide which source that is — ``location.hash`` wants ``hash``,
        ``location`` itself resolves to the page URL.
        """
        if value is None or value.type != "identifier":
            return None
        base = _name_of(value, self.src_bytes)
        if base == "location":
            # A property of ``location`` is read by whichever kind the pattern
            # binds; ``location`` itself is the page's URL.
            for c in pat.children:
                if _SOURCE_MEMBERS.get(("location", _name_of(c, self.src_bytes))):
                    return Taint(_SOURCE_MEMBERS[("location", _name_of(c, self.src_bytes))])
            return Taint("location.href")
        if base in _STORAGE_OBJECTS:
            return Taint(_STORAGE_OBJECTS[base])
        return None

    def _apply_pattern(self, pat: Node, block: Block, taint: Optional[Taint]) -> None:
        """Give every name a binding pattern declares the source's taint.

        ``const {hash} = location`` taints ``hash`` because the *object* is the
        source: the destructured property is read from it. A deeper property
        (``const {a:{b}} = x``) is tainted the same way when ``x`` is a source.
        """
        if pat.type in ("identifier", "shorthand_property_identifier_pattern"):
            self._bind(block, _name_of(pat, self.src_bytes), "var", taint)
            return
        if taint is None:
            return
        for c in pat.children:
            if c.type in ("object_pattern", "array_pattern"):
                self._apply_pattern(c, block, taint)
            elif c.type == "pair_pattern":
                self._apply_pattern(_child(c, "value") or c, block, taint)
            elif c.type == "object_assignment_pattern":
                self._apply_pattern(_child(c, "left") or c, block, taint)
            elif c.type == "rest_pattern":
                for cc in c.children:
                    self._apply_pattern(cc, block, taint)
            elif c.type in ("identifier", "shorthand_property_identifier_pattern"):
                self._bind(block, _name_of(c, self.src_bytes), "var", taint)

    def _assignment(self, node: Node, block: Block, augmented: bool = False) -> None:
        left = _child(node, "left")
        right = _child(node, "right")
        taint = self.taint_of(right, block) if right is not None else None

        if left is not None and left.type == "identifier":
            name = _name_of(left, self.src_bytes)
            b = self._lookup(block.index, name)
            if b is None:
                # An implicit global (no declaration anywhere in the file).
                b = self._bind(block, name, "var", None)
            if augmented and b.taint is not None and taint is not None:
                taint = b.taint.merge(taint)
            if taint is not None:
                b.taint = taint if b.taint is None else b.taint.merge(taint) if augmented else taint
            if right is not None:
                self.walk(right, block)
            return

        if left is not None and left.type in ("member_expression", "subscript_expression"):
            base, prop, kind = _member_parts(left, self.src_bytes)
            # A sink is only a sink when the property is written literally, and
            # ``obj[key] = value`` names no property: it is not followed.
            if kind != "computed" and taint is not None:
                sink = _SINK_PROPERTIES.get(prop)
                if prop and prop.startswith("on"):
                    sink = "inline_handler_assign"
                if sink:
                    block.tainted_writes.append(
                        TaintedWrite(sink=sink, source=taint.source, family=_family(sink))
                    )
            if right is not None:
                self.walk(right, block)
            return

        for child in node.children:
            self.walk(child, block)

    def _function(self, node: Node, block: Block) -> None:
        name_node = _child(node, "name")
        inner = self._new_block(node.type, _name_of(name_node, self.src_bytes) if name_node else "", block.index)
        for p in _params_of(node):
            self._declare_pattern(p, inner, "param")
        params = _child(node, "parameters") or _child(node, "parameter")
        body = _child(node, "body")
        if body is not None:
            if body.type == "statement_block":
                self.declare(body, inner)
                for child in body.children:
                    self.walk(child, inner)
                # Parameter shadows resolve to the parameter: a callback that
                # receives its value resolves through the chain, not the file.
                self._resolve_references(body, inner, params)
            else:
                # Concise arrow body: it is an expression, and its value is
                # tainted iff the expression is.
                self.walk(body, inner)
                self._resolve_references(body, inner, params)

    def _class(self, node: Node, block: Block) -> None:
        body = _child(node, "body") or (node if node.type == "class_body" else None)
        if body is None:
            return
        inner = self._new_block("class", "", block.index)
        for member in body.children:
            if member.type not in ("field_definition", "method_definition"):
                continue
            field_block = inner if member.type == "field_definition" else inner
            if member.type == "method_definition":
                self._function(member, inner)
            else:
                prop = _child(member, "property")
                value = _child(member, "value")
                taint = self.taint_of(value, field_block) if value is not None else None
                if prop is not None and taint is not None:
                    self._bind(field_block, _name_of(prop, self.src_bytes), "const", taint)
                if value is not None:
                    self.walk(value, field_block)

    def _call(self, node: Node, block: Block) -> None:
        fn = _child(node, "function") or node.child(0)
        args = _child(node, "arguments")
        if fn is None:
            return

        # (a) A sink method: ``el.insertAdjacentHTML('beforeend', v)``.
        if fn.type in ("member_expression", "subscript_expression"):
            base, prop, kind = _member_parts(fn, self.src_bytes)
            if kind != "computed" and prop in _SINK_METHODS:
                label, family = _SINK_METHODS[prop]
                value = self._sink_argument(prop, args, block)
                if value is not None:
                    block.tainted_writes.append(
                        TaintedWrite(sink=label, source=value.source, family=family)
                    )
            # (b) A response callback: its parameter receives the response when
            # the receiver is a request.
            if kind != "computed" and prop in _RESPONSE_METHODS and args is not None:
                cb = next((c for c in args.children if c.type in ("arrow_function", "function_expression")), None)
                if cb is not None and self._returns_a_response(_child(fn, "object")):
                    self._bind_callback(cb, block, Taint("fetch response"))

        # (c) jQuery's ``$(html)`` parses a string as markup.
        if fn.type == "identifier" and _name_of(fn, self.src_bytes) == "$" and args is not None:
            for c in args.children:
                if c.type not in ("(", ")"):
                    if self.taint_of(c, block) is not None:
                        block.tainted_writes.append(
                            TaintedWrite("jquery_selector", self.taint_of(c, block).source, "html")
                        )

    def _sink_argument(self, method: str, args: Optional[Node], block: Block) -> Optional[Taint]:
        if args is None:
            return None
        arg_nodes = [c for c in args.children if c.type not in ("(", ")", ",")]
        if method == "property":
            # ``ɵɵproperty("innerHTML", value)``: the first argument names the
            # property, and only ``innerHTML`` among them is a sink.
            if len(arg_nodes) >= 2:
                name = _name_of(arg_nodes[0], self.src_bytes)
                if name == "innerHTML":
                    return self.taint_of(arg_nodes[1], block)
            return None
        if method in ("insertAdjacentHTML", "write", "writeln"):
            idx = 1 if method == "insertAdjacentHTML" else 0
            return self.taint_of(arg_nodes[idx], block) if len(arg_nodes) > idx else None
        return self.taint_of(arg_nodes[0], block) if arg_nodes else None

    def _returns_a_response(self, receiver: Optional[Node]) -> bool:
        """True when a ``.then`` callback receives data derived from a request."""
        if receiver is None:
            return False
        if receiver.type == "call_expression":
            fn = _child(receiver, "function")
            if fn is None:
                return False
            if fn.type == "identifier":
                return _name_of(fn, self.src_bytes) == "fetch"
            if fn.type == "member_expression":
                _base, prop, kind = _member_parts(fn, self.src_bytes)
                if kind == "computed":
                    return False
                # ``r.json()`` / ``r.text()`` / ``r.blob()`` turn a response body
                # into the value the next callback receives.
                if prop in ("json", "text", "blob", "arrayBuffer", "formData"):
                    return True
                # A further link of the same chain: ``.then(...)`` yields a
                # promise of what its receiver yields, so the chain is walked
                # back to the request that started it.
                if prop in _RESPONSE_METHODS:
                    return self._returns_a_response(_child(fn, "object"))
                return False
        return False

    def _bind_callback(self, cb: Node, block: Block, taint: Taint) -> None:
        """Give the callback's first parameter *taint*, then analyse its body."""
        inner = self._new_block(cb.type, "", block.index)
        for i, p in enumerate(_params_of(cb)):
            self._declare_pattern(p, inner, "param")
            if i == 0 and p.type == "identifier":
                self._bind(inner, _name_of(p, self.src_bytes), "param", taint)
        body = _child(cb, "body")
        if body is not None:
            if body.type == "statement_block":
                self.declare(body, inner)
                for child in body.children:
                    self.walk(child, inner)
            else:
                self.walk(body, inner)

    def _resolve_references(self, body: Node, block: Block, params: Optional[Node]) -> None:
        """Record each identifier read inside *body* and the symbol it resolves to."""
        stack = [body]
        while stack:
            n = stack.pop()
            if n.type == "identifier" or n.type == "shorthand_property_identifier":
                parent_ok = n.parent is None or n.parent.type not in (
                    "member_expression", "variable_declarator", "pair_pattern",
                    "function_declaration", "property_identifier",
                )
                if parent_ok:
                    b = self._lookup(block.index, _name_of(n, self.src_bytes))
                    block.references.append(
                        Reference(name=_name_of(n, self.src_bytes), offset=n.start_byte,
                                  block=block.index, binding=b)
                    )
            stack.extend(reversed(n.children))

    # -- taint propagation -------------------------------------------------

    def taint_of(self, node: Optional[Node], block: Block, depth: int = 0) -> Optional[Taint]:
        """The source a value expression carries, or None."""
        if node is None or depth > 24:
            return None
        t = node.type

        if t == "parenthesized_expression":
            inner = next((c for c in node.children if c.type not in ("(", ")")), None)
            return self.taint_of(inner, block, depth + 1)

        if t == "identifier":
            b = self._lookup(block.index, _name_of(node, self.src_bytes))
            if b is not None and b.taint is not None:
                return Taint(b.taint.source, b.symbol)
            return None

        if t in ("member_expression", "subscript_expression"):
            base, prop, kind = _member_parts(node, self.src_bytes)
            if kind == "dot" and (_text(_child(node, "object"), self.src_bytes), prop) in _SOURCE_MEMBERS:
                return Taint(_SOURCE_MEMBERS[(_text(_child(node, "object"), self.src_bytes), prop)])
            obj = _child(node, "object")
            return self.taint_of(obj, block, depth + 1)

        if t == "call_expression":
            fn = _child(node, "function")
            if fn is not None and fn.type in ("member_expression", "subscript_expression"):
                base, prop, kind = _member_parts(fn, self.src_bytes)
                if base in _STORAGE_OBJECTS and prop in _STORAGE_METHODS:
                    return Taint(_STORAGE_OBJECTS[base])
                if kind == "computed":
                    return None
            # A call yields a value derived from its arguments or from its
            # receiver: ``decode(location.hash)`` keeps the argument's source,
            # and ``location.hash.slice(1)`` keeps the receiver's — a string
            # method returns a piece of the string it was called on.
            args = _child(node, "arguments")
            if args is not None:
                for a in args.children:
                    if a.type in ("(", ")", ","):
                        continue
                    tt = self.taint_of(a, block, depth + 1)
                    if tt is not None:
                        return tt
            if fn is not None and fn.type in ("member_expression", "subscript_expression"):
                obj = _child(fn, "object")
                return self.taint_of(obj, block, depth + 1)
            return None

        if t == "template_string":
            for sub in node.children:
                if sub.type == "template_substitution":
                    for c in sub.children:
                        tt = self.taint_of(c, block, depth + 1)
                        if tt is not None:
                            return tt
            return None

        if t in ("binary_expression", "ternary_expression", "await_expression",
                 "unary_expression", "sequence_expression"):
            found = None
            for c in node.children:
                tt = self.taint_of(c, block, depth + 1)
                if tt is not None:
                    found = tt if found is None else found.merge(tt)
            return found

        # Any other node: the first tainted operand below it.
        for c in node.children:
            tt = self.taint_of(c, block, depth + 1)
            if tt is not None:
                return tt
        return None


def _family(sink: str) -> str:
    if sink in _HTML_SINKS:
        return "html"
    if sink in ("eval", "setTimeout_string", "setInterval_string"):
        return "code"
    return "src"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def resolve_scopes(scripts: List[str]) -> List[Block]:
    """Return every block of *scripts*, with bindings and tainted writes.

    Scripts are resolved into one program scope, because a page's inline
    ``<script>`` elements share globals: a helper declared in the first and used
    in the second is one symbol. A grammar failure degrades to no blocks rather
    than raising — a scanner must never die on a page's JavaScript.
    """
    if _LANGUAGE is None or not scripts:
        return []
    source = "\n;\n".join(s for s in scripts if s and s.strip())
    if not source.strip():
        return []

    parser = Parser(_LANGUAGE)
    try:
        tree = parser.parse(source.encode("utf-8"))
    except Exception:  # pragma: no cover - defensive
        return []

    resolver = _Resolver(source)
    program = resolver._new_block("program", "", None)
    root = tree.root_node
    resolver.declare(root, program)
    for child in root.children:
        resolver.walk(child, program)
    resolver._resolve_references(root, program, None)
    return resolver.blocks
