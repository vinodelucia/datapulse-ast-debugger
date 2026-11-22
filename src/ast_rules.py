"""AST-based rule detectors for Python, SQL (SQLGlot), R, and JavaScript/TypeScript (Tree-sitter).

Returns None when an AST cannot be built (triggering linear fallback in src/rules.py),
or a list of (category, line_offset, detail, severity_override) tuples when AST parsing succeeds.
"""

import ast
import logging
import re
from typing import Any, List, Optional, Tuple

from src.privacy import scan_secrets

logger = logging.getLogger(__name__)

FindingTuple = Tuple[str, int, str, Optional[str]]

try:
    import sqlglot
    from sqlglot import exp as sql_exp
    HAS_SQLGLOT = True
except Exception:
    HAS_SQLGLOT = False

try:
    from tree_sitter_languages import get_parser
    HAS_TREE_SITTER = True
except Exception:
    HAS_TREE_SITTER = False

_TS_PARSERS: dict = {}

_SQL_DML_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
_SECRET_VAR_RE = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|private[_-]?key)"
)
_PLACEHOLDER_RE = re.compile(
    r"(?i)x{4,}|\*{3,}|changeme|your[_-]|example|placeholder|<[^>]+>|process\.env|dummy|\btest\b|\[REDACTED"
)
_UNSAFE_REGEX_RE = re.compile(r"\((?:[^()\s]*)[+*]\)[+*?{]")


def _get_ts_parser(grammar: str) -> Optional[Any]:
    if not HAS_TREE_SITTER:
        return None
    if grammar not in _TS_PARSERS:
        try:
            _TS_PARSERS[grammar] = get_parser(grammar)
        except Exception as exc:
            logger.debug("Tree-sitter parser indisponível para %s: %s", grammar, exc)
            _TS_PARSERS[grammar] = None
    return _TS_PARSERS[grammar]


def _attr_chain_root(node: ast.AST) -> str:
    cur: Optional[ast.AST] = node
    while cur is not None:
        if isinstance(cur, ast.Attribute):
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        elif isinstance(cur, ast.Name):
            return cur.id
        else:
            break
    return ""


def _attr_chain_has(node: ast.AST, attr_name: str) -> bool:
    cur: Optional[ast.AST] = node
    while cur is not None:
        if isinstance(cur, ast.Attribute):
            if cur.attr == attr_name:
                return True
            cur = cur.value
        elif isinstance(cur, ast.Call):
            if isinstance(cur.func, ast.Attribute) and cur.func.attr == attr_name:
                return True
            cur = cur.func
        else:
            break
    return False


def _is_sql_string(text: str) -> bool:
    return bool(_SQL_DML_RE.search(text))


def _contains_sql_concat(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        has_var = any(isinstance(v, ast.FormattedValue) for v in node.values)
        if not has_var:
            return False
        literal_text = " ".join(
            v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)
        )
        return _is_sql_string(literal_text)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left_sql = isinstance(node.left, ast.Constant) and isinstance(node.left.value, str) and _is_sql_string(node.left.value)
        right_sql = isinstance(node.right, ast.Constant) and isinstance(node.right.value, str) and _is_sql_string(node.right.value)
        both_const = isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant)
        return (left_sql or right_sql) and not both_const
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        recv = node.func.value
        return isinstance(recv, ast.Constant) and isinstance(recv.value, str) and _is_sql_string(recv.value)
    return False


# --------------------------------------------------------------------- Python
def detect_python_ast(code: str) -> Optional[List[FindingTuple]]:
    """Detecta vulnerabilidades e antipadrões de dados usando stdlib `ast`."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None

    findings: List[FindingTuple] = []

    def _visit_node(node: ast.AST, in_loop: bool = False) -> None:
        line_off = max(0, getattr(node, "lineno", 1) - 1)

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            all_defaults = list(node.args.defaults) + [
                d for d in node.args.kw_defaults if d is not None
            ]
            for default in all_defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    findings.append(("Python_Mutable_Default_Arg", max(0, default.lineno - 1), "", None))
            for stmt in node.body:
                _visit_node(stmt, in_loop=False)
            return

        if isinstance(node, ast.For):
            # Check iterrows() on loop iterator
            for sub in ast.walk(node.iter):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "iterrows":
                    findings.append(("Pandas_Iterrows_Bottleneck", line_off, "", None))
            _visit_node(node.iter, in_loop=in_loop)
            for stmt in node.body:
                _visit_node(stmt, in_loop=True)
            for stmt in node.orelse:
                _visit_node(stmt, in_loop=in_loop)
            return

        if isinstance(node, ast.While):
            for stmt in node.body:
                _visit_node(stmt, in_loop=True)
            for stmt in node.orelse:
                _visit_node(stmt, in_loop=in_loop)
            return

        if isinstance(node, ast.ExceptHandler):
            is_bare = node.type is None
            is_pass_only = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
            if is_bare or is_pass_only:
                findings.append(("Silent_Exception_Swallowing", line_off, "", None))

        if isinstance(node, (ast.JoinedStr, ast.BinOp)):
            if _contains_sql_concat(node):
                findings.append(("SQL_Injection_Vulnerability", line_off, "", None))

        if isinstance(node, ast.Assign):
            # Hardcoded secret check on simple target names or known provider tokens
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                val = node.value.value
                if len(val) >= 8 and not _PLACEHOLDER_RE.search(val):
                    matched_secret = bool(scan_secrets(val))
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name) and (_SECRET_VAR_RE.search(tgt.id) or matched_secret):
                            findings.append(("Python_Hardcoded_Secret", line_off, tgt.id, None))
            # Chained indexing df[mask][col] = val
            for tgt in node.targets:
                if isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Subscript):
                    root_name = _attr_chain_root(tgt.value.value)
                    is_df_name = bool(re.search(r"(?i)(?:df|data|frame|table)", root_name))
                    slice_src = ast.dump(tgt.value.slice)
                    has_mask = any(k in slice_src for k in ("Compare", "BoolOp", "isin", "isna", "notna"))
                    if is_df_name or has_mask:
                        findings.append(("Pandas_ChainedIndexing_Warning", line_off, "", None))

        if isinstance(node, ast.AnnAssign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value
            if isinstance(node.target, ast.Name) and _SECRET_VAR_RE.search(node.target.id):
                if len(val) >= 8 and not _PLACEHOLDER_RE.search(val):
                    findings.append(("Python_Hardcoded_Secret", line_off, node.target.id, None))

        if isinstance(node, ast.Call):
            if _contains_sql_concat(node):
                findings.append(("SQL_Injection_Vulnerability", line_off, "", None))

            func = node.func
            kw_map = {kw.arg: kw.value for kw in node.keywords if kw.arg}

            if isinstance(func, ast.Name):
                if func.id in ("eval", "exec"):
                    findings.append(("Python_Eval_Exec_Injection", line_off, func.id, None))
                elif func.id == "Popen" and isinstance(kw_map.get("shell"), ast.Constant) and kw_map["shell"].value is True:
                    findings.append(("Subprocess_Shell_Injection_Risk", line_off, "", None))
                elif func.id == "udf":
                    findings.append(("PySpark_Python_UDF_Overhead", line_off, "", None))
                elif func.id == "read_csv":
                    if not any(k in kw_map for k in ("dtype", "usecols", "chunksize")):
                        findings.append(("Pandas_ReadCsv_Unoptimized", line_off, "", None))
                elif func.id == "render_template_string" and node.args:
                    if not isinstance(node.args[0], ast.Constant):
                        findings.append(("Python_SSTI_Template_Injection", line_off, func.id, None))
                elif func.id == "urlopen" and node.args:
                    if not isinstance(node.args[0], ast.Constant):
                        findings.append(("Python_SSRF_Dynamic_Request", line_off, "urlopen", None))

            elif isinstance(func, ast.Attribute):
                attr = func.attr
                root = _attr_chain_root(func.value)
                has_defused_xml = "defusedxml" in code

                if root == "subprocess" and isinstance(kw_map.get("shell"), ast.Constant) and kw_map["shell"].value is True:
                    findings.append(("Subprocess_Shell_Injection_Risk", line_off, "", None))
                elif root in ("requests", "httpx") and attr in ("get", "post", "put", "delete", "head", "request"):
                    url_arg = kw_map.get("url") or (node.args[0] if node.args else None)
                    is_upper_const = (
                        isinstance(url_arg, ast.Attribute) and url_arg.attr.isupper()
                    ) or (isinstance(url_arg, ast.Name) and url_arg.id.isupper())
                    if url_arg is not None and not isinstance(url_arg, ast.Constant) and not is_upper_const:
                        findings.append(("Python_SSRF_Dynamic_Request", line_off, f"{root}.{attr}", None))
                elif root == "urllib" and attr == "urlopen":
                    url_arg = kw_map.get("url") or (node.args[0] if node.args else None)
                    if url_arg is not None and not isinstance(url_arg, ast.Constant):
                        findings.append(("Python_SSRF_Dynamic_Request", line_off, "urllib.urlopen", None))
                elif root in ("jinja2", "mako") and attr == "Template" and node.args:
                    if not isinstance(node.args[0], ast.Constant):
                        findings.append(("Python_SSTI_Template_Injection", line_off, f"{root}.Template", None))
                elif not has_defused_xml and (
                    (root in ("ET", "ElementTree", "lxml", "etree", "minidom") and attr in ("parse", "fromstring", "parseString"))
                    or (root == "xml" and attr in ("parse", "fromstring", "parseString"))
                ):
                    findings.append(("Python_XXE_Unsafe_XML", line_off, f"{root}.{attr}", None))
                elif attr in ("load", "loads") and root in ("pickle", "marshal"):
                    findings.append(("Python_Insecure_Deserialization", line_off, f"{root}.{attr}", None))
                elif attr == "load" and root == "yaml":
                    loader = kw_map.get("Loader")
                    loader_name = (
                        loader.id if isinstance(loader, ast.Name)
                        else loader.attr if isinstance(loader, ast.Attribute)
                        else ""
                    )
                    if loader_name not in ("SafeLoader", "CSafeLoader", "BaseLoader"):
                        findings.append(("Python_Insecure_Deserialization", line_off, "yaml.load", None))
                elif attr == "concat" and root in ("pd", "pandas") and in_loop:
                    findings.append(("Pandas_Concat_In_Loop", line_off, "", None))
                elif attr == "append" and in_loop and "df" in root.lower():
                    findings.append(("Pandas_Concat_In_Loop", line_off, "", None))
                elif attr == "apply":
                    axis_node = kw_map.get("axis")
                    if isinstance(axis_node, ast.Constant) and axis_node.value in (1, "columns"):
                        findings.append(("Pandas_Apply_Axis1_Slow", line_off, "", None))
                elif attr == "collect" and root not in ("gc", "tracemalloc", "metrics"):
                    if not _attr_chain_has(func.value, "limit"):
                        findings.append(("PySpark_Collect_Driver_OOM", line_off, "", None))
                elif attr == "toPandas":
                    if not _attr_chain_has(func.value, "limit"):
                        findings.append(("PySpark_Collect_Driver_OOM", line_off, "", None))
                elif attr in ("iter_rows", "map_elements"):
                    findings.append(("Polars_Row_Iteration_Bottleneck", line_off, attr, None))
                elif attr == "udf" and root in ("F", "functions"):
                    findings.append(("PySpark_Python_UDF_Overhead", line_off, "", None))
                elif attr == "read_csv":
                    if not any(k in kw_map for k in ("dtype", "usecols", "chunksize")):
                        findings.append(("Pandas_ReadCsv_Unoptimized", line_off, "", None))

            if isinstance(kw_map.get("inplace"), ast.Constant) and kw_map["inplace"].value is True:
                findings.append(("Pandas_Inplace_Deprecated", line_off, "", None))

        for child in ast.iter_child_nodes(node):
            _visit_node(child, in_loop=in_loop)

    _visit_node(tree, in_loop=False)
    return findings


# ------------------------------------------------------------------------ SQL
_SQL_MAX_PARSE_CHARS = 25_000


def detect_sql_ast(code: str, dialect: Optional[str] = None) -> Optional[List[FindingTuple]]:
    """Detecta antipadrões SQL usando AST multi-dialeto do SQLGlot."""
    if not HAS_SQLGLOT or len(code) > _SQL_MAX_PARSE_CHARS:
        return None
    try:
        expressions = sqlglot.parse(code, read=dialect)
    except Exception:
        return None
    if not expressions or any(e is None for e in expressions):
        return None

    findings: List[FindingTuple] = []

    for expr in expressions:
        # 1. UPDATE / DELETE without WHERE
        if isinstance(expr, (sql_exp.Update, sql_exp.Delete)) and expr.args.get("where") is None:
            findings.append(("SQL_Mutation_Without_Where", 0, "", None))

        # 2. SELECT * + CROSS JOIN (CRITICAL) vs SELECT * sem filtro (MEDIUM)
        if isinstance(expr, sql_exp.Select):
            has_star = any(isinstance(p, sql_exp.Star) for p in expr.expressions)
            joins = expr.args.get("joins") or []
            has_cross = any((j.kind or "").upper() == "CROSS" for j in joins)
            if has_star and has_cross:
                findings.append(("SQL_FullTableScan", 0, "SELECT * com CROSS JOIN", "CRITICAL"))
            elif has_star and expr.args.get("where") is None and expr.args.get("limit") is None:
                findings.append(("SQL_SelectStar_NoFilter", 0, "", None))

            if expr.args.get("distinct") and joins and expr.args.get("group") is None:
                findings.append(("SQL_Distinct_With_Join", 0, "", None))

        # 3. JOIN without ON / USING (non-NATURAL, and not explicit CROSS JOIN)
        has_explicit_cross = bool(re.search(r"\bCROSS\s+JOIN\b", code, re.IGNORECASE))
        for join in expr.find_all(sql_exp.Join):
            kind = (join.kind or "").upper()
            if kind == "NATURAL" or (kind == "CROSS" and has_explicit_cross):
                continue
            if join.args.get("on") is None and join.args.get("using") is None:
                findings.append(("SQL_Cartesian_Join_Missing_On", 0, "", None))

        # 4. NOT IN (SELECT ...)
        for not_node in expr.find_all(sql_exp.Not):
            inner = not_node.this
            if isinstance(inner, sql_exp.In) and inner.args.get("query") is not None:
                findings.append(("SQL_NotIn_Subquery", 0, "", None))

        # 5. LIKE '%...' leading wildcard
        for like_node in expr.find_all((sql_exp.Like, sql_exp.ILike)):
            pat = like_node.expression
            if isinstance(pat, sql_exp.Literal) and pat.is_string and str(pat.this).startswith("%"):
                findings.append(("SQL_FullTableScan", 0, "LIKE '%...'", "HIGH"))

        # 6. Function/CAST applied to column inside WHERE or JOIN ON
        predicate_roots: List[sql_exp.Expression] = list(expr.find_all(sql_exp.Where))
        for join in expr.find_all(sql_exp.Join):
            on_expr = join.args.get("on")
            if isinstance(on_expr, sql_exp.Expression):
                predicate_roots.append(on_expr)

        cmp_types = (
            sql_exp.EQ, sql_exp.NEQ, sql_exp.GT, sql_exp.GTE,
            sql_exp.LT, sql_exp.LTE, sql_exp.Like, sql_exp.ILike, sql_exp.In,
        )
        for root in predicate_roots:
            for cmp_node in root.find_all(cmp_types):
                sides = [cmp_node.this, cmp_node.expression] if hasattr(cmp_node, "expression") else [cmp_node.this]
                for side in sides:
                    if isinstance(side, (sql_exp.Func, sql_exp.Anonymous, sql_exp.Cast)):
                        if side.find(sql_exp.Column) is not None:
                            findings.append(("SQL_NonSargable_Predicate", 0, "", None))
                            break

        # 7. UNION without ALL
        for union_node in expr.find_all(sql_exp.Union):
            if union_node.args.get("distinct", True):
                findings.append(("SQL_Union_Without_All", 0, "", None))

    return findings


# -------------------------------------------------------------------------- R
def detect_r_ast(code: str) -> Optional[List[FindingTuple]]:
    """Detecta antipadrões R via Tree-sitter AST."""
    parser = _get_ts_parser("r")
    if parser is None:
        return None
    src = code.encode("utf-8", errors="replace")
    tree = parser.parse(src)
    if tree.root_node.has_error:
        return None

    def _text(n: Any) -> str:
        return src[n.start_byte : n.end_byte].decode("utf-8", errors="replace")

    findings: List[FindingTuple] = []
    stack = [(tree.root_node, False)]

    while stack:
        node, in_loop = stack.pop()
        line_off = node.start_point[0]

        if node.type == "for":
            vec = node.child_by_field_name("vector")
            if vec is not None and re.search(r"^\s*1\s*:\s*(?:nrow|ncol|length)\s*\(", _text(vec)):
                findings.append(("R_Unsafe_Seq_Range", line_off, "", None))
            body = node.child_by_field_name("body")
            if body is not None:
                stack.append((body, True))
            continue

        if node.type in ("while", "repeat"):
            for ch in node.children:
                stack.append((ch, True))
            continue

        if node.type == "call":
            fn = node.child_by_field_name("function")
            fn_name = _text(fn) if fn else ""
            if fn_name == "attach":
                findings.append(("R_Attach_Namespace_Pollution", line_off, "", None))
            elif fn_name == "sapply":
                findings.append(("R_Sapply_Type_Unsafe", line_off, "", None))
            elif in_loop and fn_name in ("rbind", "cbind"):
                findings.append(("R_Vectorization_Missing", line_off, fn_name, None))

        if in_loop and node.type in ("left_assignment", "equals_assignment"):
            lhs = node.child_by_field_name("name")
            rhs = node.child_by_field_name("value")
            if lhs is not None and rhs is not None and rhs.type == "call":
                rhs_fn = rhs.child_by_field_name("function")
                if rhs_fn and _text(rhs_fn) == "c":
                    lhs_name = _text(lhs)
                    args = rhs.child_by_field_name("arguments")
                    if args and any(_text(ch) == lhs_name for ch in args.children if ch.type == "identifier"):
                        findings.append(("R_Vectorization_Missing", line_off, "c()", None))

        if node.type == "identifier" and _text(node) in ("T", "F"):
            parent = node.parent
            skip = False
            if parent is not None:
                if parent.type in ("default_argument", "default_parameter", "left_assignment") and parent.child_by_field_name("name") == node:
                    skip = True
                elif parent.type == "call" and parent.child_by_field_name("function") == node:
                    skip = True
            if not skip:
                findings.append(("R_T_F_Symbol_Usage", line_off, _text(node), None))

        if node.type == "binary":
            if re.search(r"^\s*1\s*:\s*(?:nrow|ncol|length)\s*\(", _text(node)):
                findings.append(("R_Unsafe_Seq_Range", line_off, "", None))

        for ch in reversed(node.children):
            stack.append((ch, in_loop))

    return findings


# ------------------------------------------------------ JavaScript / TypeScript
_JS_FUNC_NODES = {
    "function_declaration",
    "generator_function_declaration",
    "method_definition",
    "arrow_function",
    "function_expression",
    "function",
}
_JS_LOOP_NODES = {"for_statement", "for_in_statement", "while_statement", "do_statement"}
_JS_HTTP_SINKS = {"fetch", "axios.get", "axios.post", "axios.request", "http.get", "https.get", "got"}


def detect_js_ast(code: str) -> Optional[List[FindingTuple]]:
    """Detecta vulnerabilidades e antipadrões JS/TS via Tree-sitter AST."""
    for grammar in ("tsx", "javascript"):
        parser = _get_ts_parser(grammar)
        if parser is None:
            continue
        src = code.encode("utf-8", errors="replace")
        tree = parser.parse(src)
        if not tree.root_node.has_error:
            break
    else:
        return None

    def _text(n: Any) -> str:
        return src[n.start_byte : n.end_byte].decode("utf-8", errors="replace")

    findings: List[FindingTuple] = []
    has_proto_guard = bool(
        re.search(r"__proto__|Object\.hasOwn|hasOwnProperty|Object\.create\(null\)", code)
    )

    def _walk(node: Any, in_loop: bool, in_try: bool) -> None:
        line_off = node.start_point[0]
        ntype = node.type

        # Do not cross nested inner function boundaries for loop/try state after root
        if ntype in _JS_FUNC_NODES and node != tree.root_node and node.parent != tree.root_node:
            # Recurse with fresh function-local loop/try state
            for ch in node.children:
                _walk(ch, in_loop=False, in_try=False)
            return

        if ntype in _JS_LOOP_NODES:
            is_for_await = ntype == "for_in_statement" and _text(node).lstrip().startswith("for await")
            body = node.child_by_field_name("body")
            for ch in node.children:
                _walk(ch, in_loop=(not is_for_await and ch == body), in_try=in_try)
            return

        if ntype == "try_statement":
            body = node.child_by_field_name("body")
            for ch in node.children:
                _walk(ch, in_loop=in_loop, in_try=(in_try or ch == body))
            return

        if ntype == "await_expression" and in_loop:
            findings.append(("JS_Await_In_Loop", line_off, "", None))

        if ntype == "regex":
            pat_node = node.child_by_field_name("pattern")
            pat_text = _text(pat_node) if pat_node else _text(node)
            if _UNSAFE_REGEX_RE.search(pat_text):
                findings.append(("JS_ReDoS_Unsafe_Regex", line_off, "", None))

        if ntype == "template_string":
            if any(ch.type == "template_substitution" for ch in node.children):
                if _is_sql_string(_text(node)):
                    findings.append(("SQL_Injection_Vulnerability", line_off, "", None))

        if ntype == "binary_expression":
            txt = _text(node)
            if "+" in txt and _is_sql_string(txt):
                if any(ch.type == "string" for ch in node.children) and any(
                    ch.type != "string" for ch in node.children if ch.is_named
                ):
                    findings.append(("SQL_Injection_Vulnerability", line_off, "", None))

        if ntype in ("variable_declarator", "pair"):
            name_node = node.child_by_field_name("name") or node.child_by_field_name("key")
            val_node = node.child_by_field_name("value")
            if name_node and val_node and val_node.type == "string":
                raw_val = _text(val_node).strip("'\"`")
                if len(raw_val) >= 8 and not _PLACEHOLDER_RE.search(raw_val):
                    if _SECRET_VAR_RE.search(_text(name_node)) or scan_secrets(raw_val):
                        findings.append(("JS_Hardcoded_Secret", line_off, _text(name_node), None))

        if ntype == "assignment_expression":
            left = node.child_by_field_name("left")
            if left is not None:
                left_txt = _text(left)
                if "__proto__" in left_txt or "constructor.prototype" in left_txt:
                    findings.append(("JS_Prototype_Pollution", line_off, "", None))
                elif left.type == "subscript_expression":
                    inner_obj = left.child_by_field_name("object")
                    idx_outer = left.child_by_field_name("index")
                    if inner_obj is not None and inner_obj.type == "subscript_expression":
                        idx_inner = inner_obj.child_by_field_name("index")
                        dynamic_idx = (idx_outer and idx_outer.type != "string") or (
                            idx_inner and idx_inner.type != "string"
                        )
                        if dynamic_idx and not has_proto_guard:
                            findings.append(("JS_Prototype_Pollution", line_off, "", None))

        if ntype == "new_expression":
            ctor = node.child_by_field_name("constructor")
            args = node.child_by_field_name("arguments")
            if ctor is not None:
                ctor_name = _text(ctor)
                if ctor_name == "Function":
                    findings.append(("JS_Eval_Code_Injection", line_off, "", None))
                elif ctor_name == "RegExp" and args is not None:
                    named_args = [c for c in args.children if c.is_named]
                    if named_args and named_args[0].type not in ("string", "regex"):
                        findings.append(("JS_Dynamic_RegExp", line_off, "", None))

        if ntype == "call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn is not None:
                fn_text = _text(fn)
                args_text = _text(args) if args else ""

                if fn.type == "identifier" and fn_text == "eval":
                    findings.append(("JS_Eval_Code_Injection", line_off, "", None))

                if fn_text in ("exec", "execSync") or re.search(r"\b(?:child_process|cp)\.exec(?:Sync)?$", fn_text):
                    if args is not None:
                        named_args = [c for c in args.children if c.is_named]
                        if named_args:
                            first_arg = named_args[0]
                            has_interp = (
                                (first_arg.type == "template_string" and any(c.type == "template_substitution" for c in first_arg.children))
                                or first_arg.type == "binary_expression"
                            )
                            if has_interp:
                                findings.append(("JS_Command_Injection", line_off, "", None))

                if fn_text in _JS_HTTP_SINKS and re.search(r"\breq\.(?:query|body|params)\b", args_text):
                    findings.append(("JS_SSRF_Dynamic_Fetch", line_off, fn_text, None))

                if fn_text in ("ejs.render", "pug.render", "handlebars.compile") and args is not None:
                    named_args = [c for c in args.children if c.is_named]
                    if named_args and named_args[0].type != "string":
                        findings.append(("JS_SSTI_Template_Injection", line_off, fn_text, None))

                if re.search(r"^(?:fs|fsp)\.(?:readFileSync|writeFileSync|appendFileSync|readdirSync|statSync|mkdirSync|unlinkSync)$", fn_text) or fn_text in ("execSync", "spawnSync"):
                    findings.append(("JS_Sync_IO_Blocking_EventLoop", line_off, fn_text, None))

                if fn_text == "JSON.parse" and not in_try:
                    findings.append(("JS_Unsafe_JSON_Parse", line_off, "", None))

                if fn.type == "member_expression":
                    prop = fn.child_by_field_name("property")
                    if prop is not None and _text(prop) == "then":
                        parent = node.parent
                        handled_by_parent = False
                        cur = parent
                        while cur is not None:
                            if cur.type in ("return_statement", "await_expression"):
                                handled_by_parent = True
                                break
                            if cur.type == "member_expression":
                                p_prop = cur.child_by_field_name("property")
                                if p_prop is not None and _text(p_prop) == "catch":
                                    handled_by_parent = True
                                    break
                            if cur.type in _JS_FUNC_NODES:
                                break
                            cur = cur.parent
                        if not handled_by_parent and not in_try:
                            findings.append(("JS_Unhandled_Promise_Rejection", line_off, "", None))

        for ch in node.children:
            _walk(ch, in_loop=in_loop, in_try=in_try)

    _walk(tree.root_node, in_loop=False, in_try=False)
    return findings


def detect_ast_findings(
    language: str, code: str, sql_dialect: Optional[str] = None
) -> Optional[List[FindingTuple]]:
    """Despacha para o detector AST da linguagem. Retorna None se precisar de fallback linear."""
    if language == "python":
        return detect_python_ast(code)
    if language == "sql":
        return detect_sql_ast(code, dialect=sql_dialect)
    if language == "r":
        return detect_r_ast(code)
    if language == "javascript":
        return detect_js_ast(code)
    return None
