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
import re
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
    # A function-valued binding keeps the node that defines it, so a call to the
    # name can be joined to the parameters of the function it actually reaches.
    value: Optional[Node] = None

    @property
    def symbol(self) -> str:
        return f"{self.block}:{self.name}:{self.index}"


@dataclass
class CallSite:
    """A call, with the callee name and the argument nodes as written.

    Kept so argument-to-parameter propagation can run after the whole program
    has been declared: the callee's binding may be declared below the call
    (hoisting), and a parameter's taint may be discovered by a later round.
    """

    name: str
    block: int
    args: List[Node] = field(default_factory=list)


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
    # Calls made in this block, kept for the argument-to-parameter join.
    calls: List["CallSite"] = field(default_factory=list)
    # The id of the function block this block's parameters belong to, when this
    # is a function body: the join needs it to find a caller's parameter.
    owner_function: Optional[int] = None
    # The function node whose body this block is, when it is one.
    value: Optional[Node] = None
    # Set once a caller has supplied taint to one of this block's parameters.
    taint_reached: bool = False

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

# ``document.location.hash`` is ``location.hash``: the same object, named by the
# path a reader took to it. Only the names a page can write to without a
# declaration are read as globals, and each one maps to the spelling the regex
# engine uses, so the two engines report one flow one way.
_GLOBAL_ALIASES = {"document", "window", "self", "top", "parent", "globalThis"}

_QUALIFIED_SOURCES: Dict[Tuple[str, str], str] = {
    ("location", "hash"): "location.hash",
    ("location", "search"): "location.search",
    ("location", "href"): "location.href",
}

_STORAGE_OBJECTS = {"localStorage": "localStorage", "sessionStorage": "sessionStorage"}
_STORAGE_METHODS = {"getItem", "setItem"}

# Property assignment sinks: ``el.innerHTML = value``.
#
# ``src`` and ``href`` are the same property for two different consequences.
# On a ``<script>``, ``<iframe>`` or ``<img>`` the value is a URL the browser
# fetches, and a URL payload is a script URL or a ``javascript:`` navigation,
# never an HTML string that would land in the element's markup. Anywhere else —
# ``location.href``, an ``<a>`` — the value is navigated to. The families are
# kept apart because the payload builder chooses differently for each.
_SINK_PROPERTIES: Dict[str, str] = {
    "innerHTML": "innerHTML",
    "outerHTML": "innerHTML",
    "src": "script_or_img_src",
    "href": "location_assign",
    "action": "form_action",
    "formaction": "form_action",
}

# The property when the receiver navigates to a URL rather than loading markup.
_SINK_PROPERTIES_URL: Dict[str, str] = {
    "src": "frame_src",
    "href": "location_assign",
}

# A ``src`` set on one of these loads a document the browser navigates to, so
# the payload is a ``javascript:`` URL rather than markup. The ``location``
# object is the same consequence reached without an element.
_NAVIGATING_ELEMENTS = {"iframe", "frame", "embed", "object"}
_NAVIGATING_RECEIVERS = {"location"}

# Methods that parse their argument as markup or code.
_SINK_METHODS: Dict[str, Tuple[str, str]] = {
    "insertAdjacentHTML": ("insertAdjacentHTML", "html"),
    "write": ("document.write", "html"),
    "writeln": ("document.write", "html"),
    "html": ("jquery.html", "html"),
    "append": ("jquery.append", "html"),
    "prepend": ("jquery.prepend", "html"),
    # AOT-compiled Angular passes the bound property name as an argument:
    # ``ɵɵproperty("innerHTML", value, …)``. The first argument names the sink,
    # the second is the value.
    "property": ("innerHTML", "html"),
}

# A sink method whose *function* carries the key above, rather than its name:
# ``eval`` is called as the identifier ``eval``, and a bare call has no member
# to read a property off. Keyed by function name.
_SINK_FUNCTIONS: Dict[str, Tuple[str, str]] = {
    "eval": ("eval", "code"),
    "setTimeout": ("eval", "code"),
    "setInterval": ("eval", "code"),
    "Function": ("Function_ctor", "code"),
}

# Callbacks that receive a value derived from a request, and the source label
# their parameter carries. The receiver decides: ``.then`` on ``fetch(...)`` is
# a response, ``.then`` on a promise of a number is not.
_RESPONSE_METHODS = {"then", "catch", "finally"}
# The observable equivalent: the callback is handed the request's result.
_SUBSCRIPTION_METHODS = {"subscribe"}
# Angular's explicit announcement that a value was *not* sanitised. The
# ``[innerHTML]`` binding it feeds is inert with the sanitiser and executable
# without it, so the call marks the value as markup. ``bypassSecurityTrustUrl``
# marks it as a URL the browser will follow instead.
_TRUST_SINKS = {
    "bypassSecurityTrustHtml": ("innerHTML", "html"),
    "bypassSecurityTrustUrl": ("location_assign", "src"),
}
# Methods that send a request. ``http.get(url).subscribe(…)`` hands the
# callback a response, so the verb is what names it — but only when the object
# it is called on is itself named like a request client, or every ``.get`` in a
# bundle would become a source.
_HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}


def _looks_like_request(base: str) -> bool:
    """Whether a name reads as a client that sends requests.

    The vocabulary is deliberately about *requests*, not about "anything with a
    dot": ``interval.get`` must stay untainted, and the only way to tell it from
    ``http.get`` is the name of the object it is called on.
    """
    return bool(
        re.search(
            r"(?i)(http|api|request|client|xhr|fetch|ajax|backend|server|resource)",
            base,
        )
    )


def _is_verb_prefix(prop: str) -> bool:
    """``getExport`` / ``postData``: a verb glued in front of a noun."""
    head = re.match(r"(?i)^(get|post|put|patch|delete|head|fetch|load|request)", prop)
    return head is not None and len(prop) > head.end()


_HTML_SINKS = {"innerHTML", "insertAdjacentHTML", "document.write", "jquery.html",
               "jquery.append", "jquery.prepend", "jquery_selector", "setAttribute_on",
               "inline_handler_assign"}


def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _span(node: Node) -> Tuple[str, int, int]:
    """The identity of a parse node across two reads of the same tree."""
    return (node.type, node.start_byte, node.end_byte)


def _is_code_string(node: Node, src: bytes) -> bool:
    """Whether *node* produces a string a timer would run as code.

    A literal is code only if it interpolates or concatenates something,
    which the resolver sees through taint; an identifier, member or call is a
    value the analysis cannot type, so it is read as text — the conservative
    choice for ``setTimeout``, since a function argument is never a string.
    """
    return node.type in ("template_string", "binary_expression", "call_expression",
                         "identifier", "member_expression", "subscript_expression",
                         "ternary_expression", "parenthesized_expression", "await_expression")


def _created_element_type(node: Optional[Node], src: bytes) -> Optional[str]:
    """The tag name in ``document.createElement("script")``, if *node* is one.

    ``createElement`` names the element in a string argument. Only a literal is
    read — ``createElement(tag)`` names nothing the analysis can prove, and a
    guess here would choose a payload family for the wrong element.
    """
    if node is None or node.type != "call_expression":
        return None
    fn = _child(node, "function") or (node.child(0) if node.child_count else None)
    if fn is None or fn.type not in ("member_expression", "subscript_expression"):
        return None
    _base, prop, kind = _member_parts(fn, src)
    if kind == "computed" or prop != "createElement":
        return None
    for arg in _arguments_of(_child(node, "arguments")):
        if arg.type in ("string", "template_string"):
            text = _text(arg, src).strip("'\"`")
            return text.lower() or None
        return None
    return None


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


# -- call-site argument to parameter propagation ----------------------------
#
# A bundle's sink almost never reads a source directly: it is
# ``function h2(c){ a.innerHTML = c }`` called as ``h2(location.search)``. The
# body alone proves nothing about ``c``, which is why the tree engine reported
# no flow at all on the Juice Shop's main.js while the regex engine reported
# about twelve by name. What is missing is the join between a call and the
# function it names, done on symbols rather than on text.

# How many rounds of "a caller taints this parameter" to run. One round covers
# ``h2(location.search)``; a second covers a helper that hands the value on.
# The cap exists because a relation that keeps finding new taint is a sign of a
# mis-join, not of depth worth paying for.
_PROPAGATION_ROUNDS = 3


def _param_binding(param: Node) -> Optional[Node]:
    """The identifier a simple parameter declares (``c``), not a default form."""
    return param if param.type == "identifier" else None


def _param_default(param: Node) -> Optional[Node]:
    """The default value of ``v = …``, if the parameter has one."""
    if param.type == "assignment_pattern":
        return _child(param, "right")
    return None


def _arguments_of(args: Optional[Node]) -> List[Node]:
    """The argument nodes of a call, one node per argument."""
    if args is None:
        return []
    return [c for c in args.children if c.type not in ("(", ")", ",")]


def _writes_its_parameter(fn: Node, src: bytes) -> bool:
    """Whether any sink in *fn* takes one of its own parameters as its value.

    This is the gate that keeps the join honest on a minified bundle. Call sites
    are recorded for every identifier call, and a bundle declares thousands of
    one-letter helpers (``s2``, ``dh``, ``e``) that a later *parameter* also
    happens to be named after: joining those would taint a parameter by a name
    collision. A function is a candidate only when the sink is fed by a
    parameter of that same function, which the body itself proves.
    """
    names = set()
    for p in _params_of(fn):
        if p.type == "identifier":
            names.add(_text(p, src))
        elif p.type == "assignment_pattern":
            left = _child(p, "left")
            if left is not None and left.type == "identifier":
                names.add(_text(left, src))
    if not names:
        return False
    body = _child(fn, "body")
    if body is None:
        return False
    # A parameter reaches a sink in one of two shapes: used directly as the
    # value the sink parses, or held in a local that is then assigned to one.
    # Both are followed, because ``el.insertAdjacentHTML("beforeend", html)``
    # names the method through a member and ``x.innerHTML = c`` does not.
    reaching = set(names)
    for _round in range(3):
        grew = False
        stack = [body]
        while stack:
            n = stack.pop()
            if n.type == "call_expression":
                call_fn = _child(n, "function") or (n.child(0) if n.child_count else None)
                args = _child(n, "arguments")
                if call_fn is not None and args is not None:
                    prop = _text(call_fn, src)
                    if call_fn.type in ("member_expression", "subscript_expression"):
                        _, prop, _kind = _member_parts(call_fn, src)
                    if prop in _SINK_METHODS or prop in _SINK_PROPERTIES:
                        for a in _arguments_of(args):
                            if a.type == "identifier" and _text(a, src) in reaching:
                                return True
            elif n.type in ("assignment_expression", "variable_declarator"):
                left = _child(n, "left") if n.type == "assignment_expression" else _child(n, "name")
                right = _child(n, "right") if n.type == "assignment_expression" else _child(n, "value")
                if left is not None and right is not None and right.type == "identifier":
                    if _text(right, src) in reaching:
                        if left.type in ("member_expression", "subscript_expression"):
                            _, prop, _kind = _member_parts(left, src)
                            if prop in _SINK_PROPERTIES:
                                return True
                        elif left.type == "identifier" and _text(left, src) not in reaching:
                            reaching.add(_text(left, src))
                            grew = True
            stack.extend(n.children)
        if not grew:
            break
    return False


def _enclosing_function_block(blocks: List[Block], block: Block) -> Optional[Block]:
    """The block of the function whose body *block* is, walking outward."""
    seen = 0
    current: Optional[Block] = block
    while current is not None and seen < 32:
        if current.kind in ("function_declaration", "function_expression", "arrow_function",
                            "generator_function_declaration", "method_definition"):
            return current
        current = blocks[current.parent] if current.parent is not None else None
        seen += 1
    return None


def _taint_parameters_by_call(resolver: "_Resolver") -> None:
    """Join every call site to the parameters it supplies, and repeat.

    A parameter is tainted when *any* caller passes a tainted argument to its
    position. One caller passing a source is enough: the function is a sink
    reachable from a URL for that page, whatever the other callers do. The
    parameter of a function no caller reaches stays untainted, which is what
    keeps ``h2("<b>x</b>")`` from being reported.

    The function body was analysed before its parameter was known to hold a
    source, so the body is walked once more after the join: the sink inside it
    is the same statement, now with evidence behind its argument.
    """
    blocks = resolver.blocks
    for _round in range(_PROPAGATION_ROUNDS):
        changed = False
        for owner in blocks:
            for call in list(owner.calls):
                target = resolver._lookup(owner.index, call.name)
                if target is None or target.value is None:
                    continue
                fblock = next(
                    (b for b in blocks if b.value is target.value
                     and b.kind == target.value.type),
                    None,
                )
                if fblock is None:
                    continue
                # A name collision is not a join: only a function whose sink is
                # fed by its own parameter can be tainted from a call site.
                if not _writes_its_parameter(target.value, resolver.src_bytes):
                    continue
                params = _params_of(target.value)
                for i, param in enumerate(params):
                    supplied = call.args[i] if i < len(call.args) else _param_default(param)
                    if supplied is None:
                        continue
                    t = resolver.taint_of(supplied, owner)
                    if t is None:
                        continue
                    # ``v`` and ``v = ""`` both bind a name; a pattern form names
                    # several and is left to the declaration pass.
                    plain = param
                    if param.type == "assignment_pattern":
                        plain = _child(param, "left") or param
                    if plain.type != "identifier":
                        continue
                    bound = fblock.binding(_text(plain, resolver.src_bytes))
                    if bound is None or bound.taint is not None:
                        continue
                    bound.taint = t
                    changed = True
        for fblock in list(blocks):
            if fblock.taint_reached or fblock.value is None:
                continue
            if not any(b.kind == "param" and b.taint is not None for b in fblock.bindings):
                continue
            fblock.taint_reached = True
            body = _child(fblock.value, "body")
            if body is None:
                continue
            # The body may already carry its sinks: a callback claimed by a
            # promise was walked once while its parameter was bound. Walking it
            # again records the same statement twice, so the block starts from
            # whatever the join itself has not produced yet.
            del fblock.tainted_writes[:]
            if body.type == "statement_block":
                for child in body.children:
                    resolver.walk(child, fblock)
            else:
                resolver.walk(body, fblock)
            changed = True
        if not changed:
            break


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
        # Field taint, keyed by the class that owns the field. A field is not a
        # global name: two components that each declare ``userData`` hold two
        # different values, and keying by name alone is exactly the collision
        # that makes the regex analyser credit flows from unrelated code.
        self._fields: Dict[Tuple[int, str], Taint] = {}
        # The class body each class-declaring name refers to, so ``new S()``
        # and ``this`` inside ``S`` resolve to the same set of fields.
        self._class_of_name: Dict[str, int] = {}
        # Field writes noticed while walking, applied once the whole program has
        # been read. Each write keeps the block it was made in, because that is
        # the scope its value resolves in — ``this.userData = t.userData`` means
        # nothing in the class body, where ``t`` is not visible.
        self._field_writes: List[Tuple[Node, int, str, int]] = []
        # The root of the parsed program and its block, kept for the sink index
        # the field pass builds lazily.
        self._root: Optional[Node] = None
        self._program: Optional[Block] = None
        self._sink_sites: Optional[Dict[str, List[Tuple[Node, "Block"]]]] = None
        # ``(type, start, end)`` -> the block whose value is that node.
        self._by_span: Dict[Tuple[str, int, int], Block] = {}

    # -- block bookkeeping ------------------------------------------------

    def _new_block(self, kind: str, name: str, parent: Optional[int]) -> Block:
        b = Block(index=self._next, kind=kind, name=name, parent=parent)
        self._next += 1
        self.blocks.append(b)
        if parent is not None:
            self.blocks[parent].children.append(b.index)
        return b

    def _set_value(self, block: Block, node: Node) -> None:
        """Attach *node* to *block* and index it for ``_block_of``.

        The index has to follow the value: the scope keyed on a variable
        declarator and the walk keyed on the function it wraps assign the same
        block at different moments, and a lookup that missed one of them would
        create a duplicate block and split a scope in two.
        """
        block.value = node
        self._by_span[_span(node)] = block

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

    # -- field identity ---------------------------------------------------

    def _owning_class(self, block_index: int) -> Optional[int]:
        """The innermost class block enclosing *block_index*, if any.

        ``this`` inside a method belongs to the class that declares it, however
        deeply a callback is nested in that method, so a field write made in a
        subscription callback resolves to the enclosing class rather than to
        the callback it sits in.
        """
        idx: Optional[int] = block_index
        seen = 0
        while idx is not None and seen < 64:
            if self.blocks[idx].kind == "class":
                return idx
            idx = self.blocks[idx].parent
            seen += 1
        return None

    def _field_owner(self, node: Optional[Node], block: Block) -> Optional[int]:
        """The class whose field *node* names, or None when it names none.

        ``this.userData`` is a field of the enclosing class. ``s.userData`` is a
        field of the class ``s`` was constructed from. Anything else — an object
        literal's property, a computed member, a name that is not a class — is
        not a field, and guessing here is what produces flows from nothing.
        """
        if node is None or node.type not in ("member_expression", "subscript_expression"):
            return None
        base, prop, kind = _member_parts(node, self.src_bytes)
        if kind == "computed" or not prop:
            return None
        if base == "this":
            return self._owning_class(block.index)
        b = self._lookup(block.index, base)
        if b is not None and b.kind == "class":
            return self._class_of_name.get(base)
        if b is not None and b.value is not None:
            # ``var s = new S()``: the instance holds the fields of its class,
            # so the field is identified by the class body, not by the variable.
            return self._class_body_of_expression(b.value, block)
        return self._class_of_name.get(base)

    def _receiver_is_a_url(self, base: str, block: Block) -> bool:
        """Whether a ``src``/``href`` set on *base* is a navigation, not markup.

        True only when the receiver is *proven* to be an element the browser
        navigates to — ``var f = document.createElement("iframe")`` followed
        back to its initializer, or the ``location`` object itself. Anything
        else, including a receiver the analysis cannot trace, keeps the generic
        markup reading: a flow reported under a coarse label is still a flow,
        and a flow withheld on a guess is the false negative this engine exists
        to remove.
        """
        if base in _NAVIGATING_RECEIVERS:
            return True
        b = self._lookup(block.index, base)
        if b is None or b.value is None:
            return False
        element = _created_element_type(b.value, self.src_bytes)
        return element in _NAVIGATING_ELEMENTS if element else False

    def _class_body_of_expression(self, node: Node, block: Block) -> Optional[int]:
        """The class body a field expression's owner resolves to, if it is one.

        Only two shapes resolve: ``new S(…)`` in the variable's initializer, and
        a ternary that picks between constructors. Anything else — a value that
        came back from a function, a property of something else — is not proven
        to be an instance, and a field read off it is left untainted.
        """
        if node.type == "new_expression":
            ctor = _child(node, "constructor") or (node.child(1) if node.child_count > 1 else None)
            if ctor is not None and ctor.type == "identifier":
                return self._class_of_name.get(_name_of(ctor, self.src_bytes))
            return None
        if node.type in ("ternary_expression", "parenthesized_expression"):
            for c in node.children:
                found = self._class_body_of_expression(c, block)
                if found is not None:
                    return found
        return None

    # -- pass 1: declarations -------------------------------------------

    def declare(self, node: Node, block: Block) -> None:
        """Walk *node* and register every binding the block owns."""
        for child in node.children:
            t = child.type
            if t in ("function_declaration", "generator_function_declaration"):
                name = _child(child, "name")
                bound = self._bind(block, _name_of(name, self.src_bytes), "function", None)
                # The node is what a call to the name is joined to.
                bound.value = child
            elif t in ("class_declaration",):
                name = _child(child, "name")
                bound = self._bind(block, _name_of(name, self.src_bytes), "class", None)
                # The node is what an instance is resolved through: ``new S()``
                # holds the fields the class ``S`` declares, not its own.
                bound.value = child
            elif t in ("variable_declaration", "lexical_declaration"):
                head = _text(child, self.src_bytes)
                kind = "const" if head.startswith("const") else ("let" if head.startswith("let") else "var")
                for decl in child.children:
                    if decl.type == "variable_declarator":
                        self._declare_pattern(_child(decl, "name"), block, kind)
                # Marking must follow declaration: the binding it promotes is
                # the one just created, not one that does not exist yet.
                self._merge_duplicate_functions(child, block)
                # A declarator's *value* can hold a nested function
                # (``const f = () => …``), whose names belong to its own block.
                for decl in child.children:
                    if decl.type != "variable_declarator":
                        continue
                    value = _child(decl, "value")
                    if value is None or value.type not in ("function_expression", "arrow_function"):
                        continue
                    # ``const f = () => …`` makes ``f`` callable by name: a call to
                    # it is joined to the parameters of the function it holds.
                    target = _child(decl, "name")
                    if target is not None and target.type == "identifier":
                        holder = self._bind(block, _name_of(target, self.src_bytes), kind, None)
                        holder.value = value
                    inner = self._new_block(value.type, "", block.index)
                    self._set_value(inner, value)
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

    def _merge_duplicate_functions(self, decl: Node, block: Block) -> None:
        """Record a top-level ``var a = …`` as a second definition of ``a``.

        A bundle flattened to one scope declares the same minified name many
        times, each behind its own guard: ``if (typeof f === "function") …``.
        Lexically that is one binding whose last write wins, and every earlier
        flow disappears. Operationally each definition runs the first time its
        guard holds, so the analysis keeps them all and marks the name
        *multi-defined*. A write to such a name is retained, because the
        analysis cannot prove *which* definition will receive it — the
        alternative is reporting nothing, which is what the bundle produced.
        """
        if block.parent is not None:
            return
        for candidate in decl.children:
            if candidate.type != "variable_declarator":
                continue
            name = _child(candidate, "name")
            value = _child(candidate, "value")
            if name is None or name.type != "identifier" or value is None:
                continue
            if value.type not in ("function_expression", "arrow_function"):
                continue
            label = _name_of(name, self.src_bytes)
            existing = block.binding(label)
            if existing is not None:
                # Any second function-valued declaration of the same name in
                # one block promotes it: the analysis can no longer say which
                # body a later write belongs to, so it keeps all of them.
                existing.kind = "multi"

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
                    # A callback handed directly is claimed by ``_bind_callback``
                    # when the receiver is a promise or a subscription, and
                    # analysed as its own block otherwise. One nested a level
                    # deeper, inside an options object, meets ``_function``
                    # through the generic branch and must obey the same rule,
                    # which ``_function`` enforces by filling a block it finds
                    # rather than creating a second one.
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
            # ``var s = new S()``: the initializer is what lets a field read off
            # the instance be identified as the class's field. Only a plain
            # identifier keeps it; a pattern declares several names and would
            # attribute one initializer to all of them.
            if name_node.type == "identifier":
                bound = block.binding(_name_of(name_node, self.src_bytes))
                if bound is not None and bound.value is None:
                    bound.value = value
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
            # ``location = url`` is not a variable write: the identifier names
            # the global navigator, and assigning to it navigates the page.
            if b is None and name in _NAVIGATING_RECEIVERS and taint is not None:
                block.tainted_writes.append(
                    TaintedWrite(sink="location_assign", source=taint.source, family="src")
                )
                if right is not None:
                    self.walk(right, block)
                return
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
            # ``document.location = url`` names the navigator's *object*, not a
            # property of it. The member read then walks to ``document`` and
            # finds no source, so the assignment is recognised here instead.
            head, _, tail = base.rpartition(".")
            navigator = tail or head
            if prop == "location" and navigator in _GLOBAL_ALIASES and taint is not None:
                block.tainted_writes.append(
                    TaintedWrite(sink="location_assign", source=taint.source, family="src")
                )
                if right is not None:
                    self.walk(right, block)
                return
            # The value a field now holds. Recorded by node, not applied here:
            # the class that owns the field may not have been walked yet, and
            # the value has to resolve in the block it was written in.
            owner = self._field_owner(left, block)
            if owner is not None and right is not None:
                self._field_writes.append((right, owner, prop, block.index))
            # A sink is only a sink when the property is written literally, and
            # ``obj[key] = value`` names no property: it is not followed. The
            # receiver decides which property — a ``src`` set on a created
            # ``<script>`` or ``<iframe>`` is navigated, not rendered, and a URL
            # payload there has to be a script URL rather than markup.
            if kind != "computed" and taint is not None:
                sink = _SINK_PROPERTIES.get(prop)
                if prop in ("src", "href") and self._receiver_is_a_url(base, block):
                    sink = _SINK_PROPERTIES_URL.get(prop)
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
        # A promise or subscription callback already has its block, created by
        # ``_bind_callback`` so its parameter could hold the response before the
        # body was read. The body is filled in here rather than in a second
        # block, which is what keeps the taint and the sink on one symbol.
        inner = self._block_of(node)
        if inner is None:
            inner = self._new_block(node.type, _name_of(name_node, self.src_bytes) if name_node else "", block.index)
            self._set_value(inner, node)
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
        # The class body is the identity a field belongs to. ``class S`` and
        # ``new S()`` both resolve here, which is what lets a field written as
        # ``this.userData`` be read as ``s.userData`` later.
        self._set_value(inner, body)
        name = _child(node, "name") or _child(node, "class") or _child(node, "left")
        if name is not None and name.type == "identifier":
            self._class_of_name[_name_of(name, self.src_bytes)] = inner.index
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
        # Every call by name is kept: the function it reaches may be declared
        # below (hoisting) or gain tainted parameters from a later round.
        if fn.type == "identifier":
            block.calls.append(
                CallSite(
                    name=_name_of(fn, self.src_bytes),
                    block=block.index,
                    args=_arguments_of(args),
                )
            )
        self._record_sinks(node, block)

    def _record_sinks(self, node: Node, block: Block) -> None:
        """Record the sinks this call reaches, and nothing else.

        Separated from ``_call`` so the field pass can revisit statements for
        their sinks without registering a second call site: a call counted
        twice would let the parameter join treat one argument as two.
        """
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
            # (d) ``request.subscribe({next: v => …})``: the Angular idiom for
            # the same thing. The callback is named in the options object rather
            # than passed directly, so it is reached through ``next``/``error``.
            if kind != "computed" and prop in _SUBSCRIPTION_METHODS and args is not None:
                cb = None
                for a in args.children:
                    if a.type == "object":
                        for pair in a.children:
                            key = _child(pair, "key")
                            if key is not None and _name_of(key, self.src_bytes) == "next":
                                cb = _child(pair, "value")
                                break
                    elif a.type in ("arrow_function", "function_expression"):
                        cb = a
                # Only a subscription on something that is a request delivers a
                # response. ``interval.subscribe`` ticks a number, and crediting
                # it would make every observable in a bundle a source.
                if (
                    cb is not None
                    and cb.type in ("arrow_function", "function_expression")
                    and self._returns_a_response(_child(fn, "object"))
                ):
                    self._bind_callback(cb, block, Taint("fetch response"))
            # (e) ``sanitizer.bypassSecurityTrustHtml(`<b>${v}</b>`)``:
            # Angular's sanitiser is opt-out, and this call is the opt-out. The
            # value becomes markup at whatever ``[innerHTML]`` binding it is
            # returned into, so the call itself is the sink.
            if kind != "computed" and prop in _TRUST_SINKS and args is not None:
                label, family = _TRUST_SINKS[prop]
                for c in args.children:
                    if c.type in ("(", ")"):
                        continue
                    value = self.taint_of(c, block)
                    if value is not None:
                        block.tainted_writes.append(
                            TaintedWrite(sink=label, source=value.source, family=family)
                        )

        # (c) jQuery's ``$(html)`` parses a string as markup.
        if fn.type == "identifier" and _name_of(fn, self.src_bytes) == "$" and args is not None:
            for c in args.children:
                if c.type not in ("(", ")"):
                    if self.taint_of(c, block) is not None:
                        block.tainted_writes.append(
                            TaintedWrite("jquery_selector", self.taint_of(c, block).source, "html")
                        )
            return

        # (f) ``eval(v)``, ``Function(v)``, ``setTimeout(v)`` run a string as
        # code. ``setTimeout`` and ``setInterval`` only when handed a string: a
        # function argument is a callback, and the timer runs it, not its text.
        if fn.type == "identifier":
            entry = _SINK_FUNCTIONS.get(_name_of(fn, self.src_bytes))
            if entry is not None and args is not None:
                label, family = entry
                first = next((c for c in args.children if c.type not in ("(", ")", ",")), None)
                if first is not None and (label != "eval" or _is_code_string(first, self.src_bytes)):
                    value = self.taint_of(first, block)
                    if value is not None:
                        block.tainted_writes.append(
                            TaintedWrite(sink=label, source=value.source, family=family)
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
                # ``http.get(url)`` / ``api.post(url, body)``: the verb names the
                # request. A bare ``.get`` on something unrelated is the price
                # of that — which is why the base has to be request-shaped too.
                if prop in _HTTP_VERBS or _is_verb_prefix(prop):
                    # ``http.get`` and ``this.http.get`` name a client alike; the
                    # base is read to its last segment, because ``this.svc`` is a
                    # property of ``this`` and ``this`` names nothing on its own.
                    base = _text(_child(fn, "object"), self.src_bytes)
                    if not base:
                        return False
                    return _looks_like_request(base.rsplit(".", 1)[-1])
                return False
        return False

    def _bind_callback(self, cb: Node, block: Block, taint: Taint) -> None:
        """Create the callback's block and bind its first parameter to *taint*.

        The body is deliberately left to ``walk``, which reaches the callback
        on its own and is the one place that decides whether a function already
        has a block. Walking it here as well analysed every promise callback
        twice: two blocks, two sinks, one statement.
        """
        inner = self._block_of(cb)
        if inner is not None:
            # The same callback is examined by every link of the chain it sits
            # in; the first link that recognised it already bound its parameter.
            return
        inner = self._new_block(cb.type, "", block.index)
        self._set_value(inner, cb)
        for i, p in enumerate(_params_of(cb)):
            self._declare_pattern(p, inner, "param")
            if i == 0 and p.type == "identifier":
                self._bind(inner, _name_of(p, self.src_bytes), "param", taint)

    def _sinks_reading(self, field: Tuple[int, str]) -> List[Tuple[Node, Block]]:
        """Every sink statement in the program that reads ``.prop`` off a field.

        Built on first use by one pass over the tree and cached, because the
        alternative — re-walking the program for each field that becomes
        tainted — is quadratic on a bundle and took minutes on ``main.js``.
        A candidate is a statement that both carries a sink (an assignment to a
        sink property, or a call to a sink method) and mentions the property
        name. Mentioning it is a necessary condition, not a sufficient one:
        ``_replay_statement`` decides, using the ordinary taint rules.
        """
        if self._sink_sites is None:
            index: Dict[str, List[Tuple[Node, Block]]] = {}
            stack: List[Tuple[Node, Block]] = [(self._root, self._program)]
            while stack:
                node, block = stack.pop()
                arg = _sink_argument_node(node)
                if arg is not None:
                    for prop in _properties_in(arg):
                        index.setdefault(prop, []).append((node, block))
                if node.type in ("arrow_function", "function_expression",
                                 "method_definition", "function_declaration",
                                 "generator_function_declaration", "class_declaration"):
                    inner = self._block_of(node)
                    body = _child(node, "body")
                    if node.type == "class_declaration":
                        inner = self._block_of(body) if body is not None else None
                    if inner is not None:
                        stack.append((body if body is not None else node, inner))
                    continue
                for child in node.children:
                    stack.append((child, block))
            self._sink_sites = index
        return self._sink_sites.get(field[1], [])

    def _replay_statement(self, node: Node, block: Block) -> None:
        """Record the sink of one statement now that its argument can resolve."""
        if node.type == "assignment_expression":
            self._assignment(node, block)
            return
        self._record_sinks(node, block)

    def _block_of(self, node: Node) -> Optional[Block]:
        """The block already created for *node*, matched by position.

        Tree-sitter hands out a fresh wrapper for the same node each time it is
        read, so ``id()`` says nothing; the byte range does. The range is held
        in an index rather than searched for: a bundle makes thousands of these
        lookups, and a scan of every block per lookup turned a 19-second
        analysis into a two-minute one.
        """
        return self._by_span.get(_span(node))

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
            # The qualified spelling the regex engine reports, so the two
            # engines name one flow one way: ``location.hash`` is
            # ``document.location.hash`` reached through ``document``.
            # The path is read from the right: the head has to be a global, and
            # the tail has to be ``location`` — ``document.location.hash`` and
            # ``window.location.hash`` both name the one object.
            head, _, tail = base.rpartition(".")
            if _QUALIFIED_SOURCES.get((tail or head, prop)) is not None:
                if (head or tail) in _GLOBAL_ALIASES:
                    return Taint(_QUALIFIED_SOURCES[(tail or head, prop)])
            # A field holds the value last written to it. Without this, a
            # component that stores a response and writes the field elsewhere
            # reports nothing: the taint dies at ``this.userData``.
            owner = self._field_owner(node, block)
            if owner is not None:
                held = self._fields.get((owner, prop))
                if held is not None:
                    return held
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
    original_source = source
    try:
        tree = parser.parse(source.encode("utf-8"))
    except Exception:  # pragma: no cover - defensive
        return []

    if tree.root_node.has_error:
        # A grammar cannot recover from every syntax error, and one broken
        # script would otherwise blind the whole page: the analysis answers
        # "no flow" rather than "unknown". Each entry is retried alone, and the
        # ones that parse are analysed together, which is what a page actually
        # is — several scripts sharing globals.
        readable = []
        skipped = 0
        for script in scripts:
            if not script or not script.strip():
                continue
            try:
                part = parser.parse(script.encode("utf-8"))
            except Exception:  # pragma: no cover - defensive
                continue
            if part.root_node.has_error:
                skipped += 1
            else:
                readable.append(script)
        # Rejoin whenever anything was dropped. A file is passed whole rather
        # than as entries, so "one entry was dropped" is common and must not
        # leave the broken text in the source the resolver reads.
        if skipped and readable:
            source = "\n;\n".join(readable)
            tree = Parser(_LANGUAGE).parse(source.encode("utf-8"))
            if tree.root_node.has_error:
                # Join separators can be read as a new error in a file that
                # ends inside an expression; the whole parse is then the better
                # of the two answers rather than a third guess.
                source = original_source
                tree = Parser(_LANGUAGE).parse(source.encode("utf-8"))

    resolver = _Resolver(source)
    program = resolver._new_block("program", "", None)
    root = tree.root_node
    resolver._root = root
    resolver._program = program
    resolver.declare(root, program)
    for child in root.children:
        resolver.walk(child, program)
    resolver._resolve_references(root, program, None)
    _apply_field_writes(resolver, root, program)
    _taint_parameters_by_call(resolver)
    return resolver.blocks


def _apply_field_writes(resolver: "_Resolver", root: Node, program: Block) -> None:
    """Commit field writes to the fields that hold them, and read them back.

    The write records are walked once, in creation order, which is source
    order: a write can only read a field that an earlier statement set. One
    pass is enough for the ordinary shapes, and it is what keeps a 1.2 MB
    bundle at seconds — the first version re-walked the whole program on every
    round.

    A sink that writes a field recorded nothing while the body was first read,
    because the field held no value yet. Those statements are collected in that
    same pass and replayed directly, which costs one visit per sink and never
    touches a declaration or a call site.
    """
    if not resolver._field_writes:
        return
    deferred: List[Tuple[Node, Block]] = []
    for right, owner, prop, writer in resolver._field_writes:
        block = resolver.blocks[writer]
        taint = resolver.taint_of(right, block)
        if taint is None:
            continue
        held = resolver._fields.get((owner, prop))
        resolver._fields[(owner, prop)] = taint if held is None else held.merge(taint)
        deferred.extend(resolver._sinks_reading((owner, prop)))
    seen = set()
    for node, block in deferred:
        key = (node.start_byte, node.end_byte, block.index)
        if key in seen:
            continue
        seen.add(key)
        resolver._replay_statement(node, block)


def _sink_argument_node(node: Node) -> Optional[Node]:
    """The value node of a sink statement, or None if *node* is not one."""
    if node.type == "assignment_expression":
        left = _child(node, "left")
        if left is None or left.type not in ("member_expression", "subscript_expression"):
            return None
        return _child(node, "right")
    if node.type == "call_expression":
        fn = _child(node, "function") or (node.child(0) if node.child_count else None)
        if fn is None or fn.type not in ("member_expression", "subscript_expression"):
            return None
        args = _child(node, "arguments")
        if args is None:
            return None
        values = [c for c in args.children if c.type not in ("(", ")", ",")]
        return values[0] if values else None
    return None


def _properties_in(node: Node) -> List[str]:
    """Every property name mentioned anywhere inside *node*.

    The index keys a sink statement by the property names it reads, so the
    value node is searched once. Sinks read short expressions — an identifier
    or a member — so this stays cheap.
    """
    out: List[str] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "property_identifier":
            out.append(n.text.decode("utf-8", "replace"))
        stack.extend(n.children)
    return out

