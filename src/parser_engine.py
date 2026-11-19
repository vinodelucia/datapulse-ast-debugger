import ast
import hashlib
import logging
import os
import re
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

warnings.filterwarnings("ignore", category=FutureWarning, module="tree_sitter")

logger = logging.getLogger(__name__)

try:
    from tree_sitter_languages import get_language, get_parser
    HAS_TREE_SITTER = True
except Exception:
    HAS_TREE_SITTER = False

try:
    import sqlglot
    from sqlglot import exp as sql_exp
    HAS_SQLGLOT = True
except Exception:
    HAS_SQLGLOT = False


class AccessPoint:
    """Representa um ponto de acesso seguro mapeado no código via AST."""

    def __init__(
        self,
        file_path: str,
        language: str,
        node_type: str,
        name: str,
        start_line: int,
        end_line: int,
        code_snippet: str,
        ast_sexp: str,
        cyclomatic_complexity: int = 1,
        lines_of_code: Optional[int] = None,
    ):
        self.file_path = file_path
        self.language = language
        self.node_type = node_type
        self.name = name
        self.start_line = start_line
        self.end_line = end_line
        self.code_snippet = code_snippet
        self.ast_sexp = ast_sexp
        self.cyclomatic_complexity = max(1, int(cyclomatic_complexity))
        self.lines_of_code = (
            lines_of_code if lines_of_code is not None else max(1, end_line - start_line + 1)
        )
        parent = Path(file_path).parent.name
        short_path = f"{parent}/{Path(file_path).name}" if parent else Path(file_path).name
        self.access_id = f"{language}:{short_path}:{name}:L{start_line}-L{end_line}"
        self.ast_hash = hashlib.sha256(ast_sexp.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


class MultiLangASTParser:
    """Motor não-invasivo de parsing para Python, SQL, R e JavaScript/TypeScript."""

    SUPPORTED_EXTENSIONS = {
        ".py": "python",
        ".sql": "sql",
        ".r": "r",
        ".R": "r",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".jsx": "javascript",
        ".ts": "javascript",
        ".tsx": "javascript",
    }

    # Gramática Tree-sitter usada por extensão (TS/TSX possuem gramáticas próprias)
    GRAMMAR_BY_EXT = {
        ".py": "python",
        ".sql": "sql",
        ".r": "r",
        ".R": "r",
        ".js": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "tsx",
    }

    # Diretórios ignorados na varredura recursiva (dependências, builds e caches)
    IGNORED_DIRS = {
        "node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build",
        ".next", "coverage", ".datapulse_memory", ".pytest_cache",
    }

    # Nós-alvo que definem 'Pontos de Acesso' relevantes para dados em cada gramática
    TARGET_NODES = {
        "python": ["function_definition"],  # classes/with analisados via seus métodos (evita duplicatas)
        "sql": [
            "select",
            "statement",
            "create_table_statement",
            "create_view_statement",
            "update_statement",
            "delete_statement",
            "insert_statement",
            "cte",
            "select_statement",
            "create_table",
        ],
        # R: apenas atribuições cujo valor é uma função (evita milhares de nós call/operator)
        "r": ["binary_operator", "left_assignment"],
        "javascript": [
            "function_declaration",
            "generator_function_declaration",
            "method_definition",
            "variable_declarator",  # filtrado: apenas quando recebe arrow/function expression
        ],
    }

    JS_FUNCTION_VALUES = {"arrow_function", "function_expression", "function", "generator_function"}
    MAX_FILE_BYTES = 2_000_000  # arquivos maiores (bundles/dumps) são ignorados
    MAX_SQLGLOT_BYTES = 250_000

    _CC_NODES = {
        "python": {
            "if_statement", "elif_clause", "for_statement", "while_statement",
            "except_clause", "with_statement", "conditional_expression",
            "boolean_operator", "case_clause", "list_comprehension",
            "dictionary_comprehension", "set_comprehension", "generator_expression",
        },
        "javascript": {
            "if_statement", "for_statement", "for_in_statement", "while_statement",
            "do_statement", "catch_clause", "switch_case", "ternary_expression",
        },
        "r": {"if", "for", "while", "repeat"},
        "sql": {"case_expression", "when_clause", "and", "or", "join"},
    }

    def __init__(self):
        self.parsers: Dict[str, Any] = {}
        if HAS_TREE_SITTER:
            for grammar in set(self.GRAMMAR_BY_EXT.values()):
                try:
                    self.parsers[grammar] = get_parser(grammar)
                except Exception as exc:
                    logger.warning("Falha ao carregar gramática Tree-sitter %s: %s", grammar, exc)
                    self.parsers[grammar] = None

    @staticmethod
    def compute_file_sha256(file_path: str) -> str:
        """Lê o arquivo em modo binário Read-Only e retorna seu SHA-256 hex digest."""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @classmethod
    def compute_cyclomatic_complexity(cls, node: Any, language: str) -> int:
        """Calcula a complexidade ciclomática aproximada de um nó Tree-sitter."""
        branch_types = cls._CC_NODES.get(language, set())
        branches = 0
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type in branch_types:
                branches += 1
            elif language == "javascript" and current.type == "binary_expression":
                for child in current.children:
                    if not child.is_named and child.type in ("&&", "||", "??"):
                        branches += 1
                        break
            elif language == "r" and current.type == "binary":
                for child in current.children:
                    if not child.is_named and child.type in ("&", "&&", "|", "||"):
                        branches += 1
                        break
            stack.extend(current.children)
        return 1 + branches

    def parse_directory_readonly(
        self,
        directory_path: str,
        languages: Optional[List[str]] = None,
        extra_ignore_dirs: Optional[List[str]] = None,
        sql_dialect: Optional[str] = None,
    ) -> List[AccessPoint]:
        """Escaneia recursivamente um diretório em modo Read-Only e extrai todos os pontos de acesso."""
        base_path = Path(directory_path)
        if not base_path.exists():
            return []

        ignored = set(self.IGNORED_DIRS)
        if extra_ignore_dirs:
            for item in extra_ignore_dirs:
                cleaned = item.strip().strip("/\\")
                if cleaned:
                    ignored.add(cleaned)

        allowed_langs = set(languages) if languages else set(self.SUPPORTED_EXTENSIONS.values())
        all_access_points: List[AccessPoint] = []

        for root, dirs, files in os.walk(base_path):
            dirs[:] = sorted(
                d for d in dirs
                if d not in ignored
                and str(Path(root, d).relative_to(base_path)).replace("\\", "/") not in ignored
            )
            for name in sorted(files):
                if name.endswith((".min.js", ".d.ts")):
                    continue
                file_path = Path(root) / name
                rel_file = str(file_path.relative_to(base_path)).replace("\\", "/")
                if rel_file in ignored or name in ignored:
                    continue
                ext = self._normalized_suffix(file_path)
                if ext is None:
                    continue
                if self.SUPPORTED_EXTENSIONS[ext] in allowed_langs:
                    all_access_points.extend(
                        self.parse_file_readonly(str(file_path), sql_dialect=sql_dialect)
                    )

        return all_access_points

    def _normalized_suffix(self, path: Path) -> Optional[str]:
        """Retorna a extensão suportada (case-insensitive), ou None."""
        if path.suffix in self.SUPPORTED_EXTENSIONS:
            return path.suffix
        lowered = path.suffix.lower()
        return lowered if lowered in self.SUPPORTED_EXTENSIONS else None

    def parse_file_readonly(
        self, file_path: str, sql_dialect: Optional[str] = None
    ) -> List[AccessPoint]:
        """Lê o arquivo em modo estritamente read-only e extrai pontos de acesso."""
        path = Path(file_path)
        ext = self._normalized_suffix(path) if path.exists() else None
        if ext is None:
            return []

        lang = self.SUPPORTED_EXTENSIONS[ext]

        # Leitura binária segura sem avaliação/importação do código
        if path.stat().st_size > self.MAX_FILE_BYTES:
            return []
        with open(path, "rb") as f:
            source_bytes = f.read()
        if source_bytes.startswith(b"\xef\xbb\xbf"):  # remove BOM UTF-8
            source_bytes = source_bytes[3:]

        file_path_str = str(path).replace("\\", "/")

        if lang == "sql" and HAS_SQLGLOT and len(source_bytes) <= self.MAX_SQLGLOT_BYTES:
            sql_points = self._parse_sql_with_sqlglot(
                source_bytes, file_path_str, dialect=sql_dialect
            )
            if sql_points:
                return sql_points

        parser = self.parsers.get(self.GRAMMAR_BY_EXT.get(ext, lang))
        if parser is not None:
            tree = parser.parse(source_bytes)
            root_node = tree.root_node
            if lang != "sql" or not root_node.has_error:
                access_points: List[AccessPoint] = []
                self._traverse_ast(
                    node=root_node,
                    source_bytes=source_bytes,
                    file_path=file_path_str,
                    lang=lang,
                    results=access_points,
                )
                if access_points:
                    return access_points

        return self._fallback_parse(source_bytes, file_path_str, lang)

    @staticmethod
    def _split_sql_statements(text: str) -> List[Tuple[str, int, int]]:
        """Divide um arquivo SQL por ';' ignorando literais de string e comentários."""
        statements: List[Tuple[str, int, int]] = []
        n = len(text)
        start = 0
        i = 0
        in_single = False
        in_double = False
        in_backtick = False
        in_line_comment = False
        in_block_comment = False

        def _flush(raw_slice: str, offset: int) -> None:
            stripped = raw_slice.strip()
            if not stripped:
                return
            leading_ws = len(raw_slice) - len(raw_slice.lstrip())
            start_line = text[: offset + leading_ws].count("\n") + 1
            end_line = start_line + stripped.count("\n")
            statements.append((stripped, start_line, end_line))

        while i < n:
            ch = text[i]
            nxt = text[i + 1] if i + 1 < n else ""

            if in_line_comment:
                if ch == "\n":
                    in_line_comment = False
            elif in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 1
            elif in_single:
                if ch == "\\" and nxt:
                    i += 1
                elif ch == "'" and nxt == "'":
                    i += 1
                elif ch == "'":
                    in_single = False
            elif in_double:
                if ch == '"':
                    in_double = False
            elif in_backtick:
                if ch == "`":
                    in_backtick = False
            else:
                if ch == "-" and nxt == "-":
                    in_line_comment = True
                    i += 1
                elif ch == "/" and nxt == "*":
                    in_block_comment = True
                    i += 1
                elif ch == "'":
                    in_single = True
                elif ch == '"':
                    in_double = True
                elif ch == "`":
                    in_backtick = True
                elif ch == ";":
                    _flush(text[start:i], start)
                    start = i + 1
            i += 1

        if start < n:
            _flush(text[start:n], start)
        return statements

    @classmethod
    def _parse_sql_with_sqlglot(
        cls, source_bytes: bytes, file_path: str, dialect: Optional[str] = None
    ) -> List[AccessPoint]:
        """Extrai AccessPoints SQL via AST multi-dialeto do SQLGlot."""
        if not HAS_SQLGLOT:
            return []
        text = source_bytes.decode("utf-8", errors="replace")
        results: List[AccessPoint] = []
        cc_types = (sql_exp.If, sql_exp.Case, sql_exp.And, sql_exp.Or, sql_exp.Join)

        for stmt, start_line, end_line in cls._split_sql_statements(text):
            try:
                expr = sqlglot.parse_one(stmt, read=dialect)
            except Exception as exc:
                logger.debug("SQLGlot falhou no statement em %s:%d: %s", file_path, start_line, exc)
                continue
            if expr is None:
                continue

            if isinstance(expr, sql_exp.Select):
                node_type = "cte" if expr.args.get("with_") else "select_statement"
            elif isinstance(expr, sql_exp.Create):
                node_type = "create_table_statement"
            elif isinstance(expr, sql_exp.Update):
                node_type = "update_statement"
            elif isinstance(expr, sql_exp.Delete):
                node_type = "delete_statement"
            elif isinstance(expr, sql_exp.Insert):
                node_type = "insert_statement"
            else:
                node_type = type(expr).__name__.lower()

            table = expr.find(sql_exp.Table)
            name = table.name if table and table.name else f"query_at_line_{start_line}"

            walked = list(expr.walk())
            ast_sig = "|".join(type(n).__name__ for n in walked)
            cc = 1 + sum(1 for n in walked if isinstance(n, cc_types))

            results.append(
                AccessPoint(
                    file_path=file_path,
                    language="sql",
                    node_type=node_type,
                    name=name,
                    start_line=start_line,
                    end_line=end_line,
                    code_snippet=stmt,
                    ast_sexp=ast_sig,
                    cyclomatic_complexity=cc,
                )
            )
        return results

    def _traverse_ast(
        self,
        node: Any,
        source_bytes: bytes,
        file_path: str,
        lang: str,
        results: List[AccessPoint],
    ) -> None:
        """Percorre a AST de forma iterativa (sem recursão) identificando blocos lógicos."""
        target_types = self.TARGET_NODES.get(lang, [])
        seen_ranges = set()
        stack = [node]

        while stack:
            current = stack.pop()
            if self._is_access_point_node(current, lang, target_types):
                start_line = current.start_point[0] + 1
                end_line = current.end_point[0] + 1
                key = (start_line, end_line)
                if key not in seen_ranges:  # statement/select com mesmo intervalo = 1 ponto
                    seen_ranges.add(key)
                    snippet = source_bytes[current.start_byte : current.end_byte].decode(
                        "utf-8", errors="replace"
                    )
                    node_name = self._extract_node_name(current, source_bytes, lang, start_line)
                    cc = self.compute_cyclomatic_complexity(current, lang)
                    results.append(
                        AccessPoint(
                            file_path=file_path,
                            language=lang,
                            node_type=current.type,
                            name=node_name,
                            start_line=start_line,
                            end_line=end_line,
                            code_snippet=snippet,
                            ast_sexp=self._structural_signature(current),
                            cyclomatic_complexity=cc,
                        )
                    )
            stack.extend(reversed(current.children))

        results.sort(key=lambda ap: (ap.start_line, ap.end_line))

    def _is_access_point_node(self, node: Any, lang: str, target_types: List[str]) -> bool:
        if node.type not in target_types:
            return False
        if lang == "javascript" and node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            return value is not None and value.type in self.JS_FUNCTION_VALUES
        if lang == "r":
            return any(child.type == "function_definition" for child in node.children)
        return True

    @staticmethod
    def _structural_signature(node: Any) -> str:
        """Assinatura estrutural SEM texto do código (apenas tipos de nós e profundidade).

        Evita vazar nomes/literais no hash enviado na telemetria e independe de node.sexp().
        """
        parts: List[str] = []
        stack = [(node, 0)]
        while stack:
            current, depth = stack.pop()
            if current.is_named:
                parts.append(f"{depth}:{current.type}")
            for child in reversed(current.children):
                stack.append((child, depth + 1))
        return "|".join(parts)

    def _extract_node_name(self, node: Any, source_bytes: bytes, lang: str, line: int) -> str:
        for child in node.children:
            if child.type in (
                "identifier", "name", "table_reference", "object_name",
                "property_identifier", "type_identifier",
            ):
                return (
                    source_bytes[child.start_byte : child.end_byte]
                    .decode("utf-8", errors="ignore")
                    .strip()
                )
        return f"block_at_line_{line}"

    def _fallback_parse(
        self, source_bytes: bytes, file_path: str, lang: str
    ) -> List[AccessPoint]:
        """Fallback determinístico via stdlib AST (Python) ou análise estrutural (SQL/R/JS)."""
        text = source_bytes.decode("utf-8", errors="replace")
        lines = text.splitlines()
        results: List[AccessPoint] = []

        if lang == "python":
            try:
                tree = ast.parse(text)
                cc_nodes = (
                    ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler,
                    ast.With, ast.AsyncWith, ast.IfExp, ast.BoolOp,
                    ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp,
                )
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        start_line = node.lineno
                        end_line = getattr(node, "end_lineno", start_line) or start_line
                        snippet = "\n".join(lines[start_line - 1 : end_line])
                        walked = list(ast.walk(node))
                        sexp = "|".join(f"{type(n).__name__}" for n in walked)
                        cc = 1 + sum(1 for n in walked if isinstance(n, cc_nodes))
                        results.append(
                            AccessPoint(
                                file_path=file_path,
                                language=lang,
                                node_type="function_definition",
                                name=node.name,
                                start_line=start_line,
                                end_line=end_line,
                                code_snippet=snippet,
                                ast_sexp=sexp,
                                cyclomatic_complexity=cc,
                            )
                        )
                return sorted(results, key=lambda x: x.start_line)
            except SyntaxError as exc:
                logger.debug("Fallback ast.parse falhou em %s: %s", file_path, exc)

        if lang == "javascript":
            pattern = re.compile(
                r"(?m)^[ \t]*(?:export\s+)?(?:default\s+)?(?:async\s+)?"
                r"(?:function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("
                r"|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b[^(]*\(|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>))"
            )
            for match in pattern.finditer(text):
                func_name = match.group(1) or match.group(2)
                brace_pos = text.find("{", match.end())
                if brace_pos == -1:
                    continue
                depth, end_pos = 0, brace_pos
                for idx in range(brace_pos, len(text)):
                    if text[idx] == "{":
                        depth += 1
                    elif text[idx] == "}":
                        depth -= 1
                        if depth == 0:
                            end_pos = idx + 1
                            break
                snippet = text[match.start():end_pos].strip()
                start_line = text[: match.start()].count("\n") + 1
                end_line = start_line + snippet.count("\n")
                results.append(
                    AccessPoint(
                        file_path=file_path,
                        language=lang,
                        node_type="function_declaration",
                        name=func_name,
                        start_line=start_line,
                        end_line=end_line,
                        code_snippet=snippet,
                        ast_sexp=f"(function_declaration len={len(snippet) // 20})",
                    )
                )
            return results

        if lang == "sql":
            pattern = re.compile(
                r"(?im)^\s*(WITH\s+\w+\s+AS|SELECT\b|UPDATE\s+[\w.\"`\[\]]+|DELETE\s+FROM\s+[\w.\"`\[\]]+|CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|VIEW)\s+[\w\.]+).*?(?:;|\Z)",
                re.DOTALL,
            )
            for match in pattern.finditer(text):
                snippet = match.group(0).strip()
                start_line = text[: match.start()].count("\n") + 1
                end_line = start_line + snippet.count("\n")
                first_token = snippet.split()[0].upper()
                if first_token == "CREATE":
                    node_type = "create_table_statement"
                elif first_token == "UPDATE":
                    node_type = "update_statement"
                elif first_token == "DELETE":
                    node_type = "delete_statement"
                else:
                    node_type = "select"
                name_match = re.search(
                    r"(?:FROM|INTO|TABLE|VIEW|UPDATE|WITH)\s+([a-zA-Z0-9_\.]+)", snippet, re.IGNORECASE
                )
                name = name_match.group(1) if name_match else f"query_at_line_{start_line}"
                sexp = f"({node_type} len={len(snippet) // 20})"
                results.append(
                    AccessPoint(
                        file_path=file_path,
                        language=lang,
                        node_type=node_type,
                        name=name,
                        start_line=start_line,
                        end_line=end_line,
                        code_snippet=snippet,
                        ast_sexp=sexp,
                    )
                )
            return results

        if lang == "r":
            pattern = re.compile(
                r"(?m)^\s*([a-zA-Z0-9_\.]+)\s*<-\s*function\s*\([^)]*\)\s*\{",
            )
            for match in pattern.finditer(text):
                func_name = match.group(1)
                start_line = text[: match.start()].count("\n") + 1
                brace_depth = 0
                end_pos = match.end() - 1
                for idx in range(match.end() - 1, len(text)):
                    if text[idx] == "{":
                        brace_depth += 1
                    elif text[idx] == "}":
                        brace_depth -= 1
                        if brace_depth == 0:
                            end_pos = idx + 1
                            break
                snippet = text[match.start() : end_pos].strip()
                end_line = start_line + snippet.count("\n")
                sexp = f"(function_definition len={len(snippet) // 20})"
                results.append(
                    AccessPoint(
                        file_path=file_path,
                        language=lang,
                        node_type="function_definition",
                        name=func_name,
                        start_line=start_line,
                        end_line=end_line,
                        code_snippet=snippet,
                        ast_sexp=sexp,
                    )
                )
            return results

        return results
