import ast
import hashlib
import os
import re
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

warnings.filterwarnings("ignore", category=FutureWarning, module="tree_sitter")

try:
    from tree_sitter_languages import get_language, get_parser
    HAS_TREE_SITTER = True
except Exception:
    HAS_TREE_SITTER = False


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
    ):
        self.file_path = file_path
        self.language = language
        self.node_type = node_type
        self.name = name
        self.start_line = start_line
        self.end_line = end_line
        self.code_snippet = code_snippet
        self.ast_sexp = ast_sexp
        parent = Path(file_path).parent.name
        short_path = f"{parent}/{Path(file_path).name}" if parent else Path(file_path).name
        self.access_id = f"{language}:{short_path}:{name}:L{start_line}-L{end_line}"
        self.ast_hash = hashlib.sha256(ast_sexp.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return self.__dict__


class MultiLangASTParser:
    """Motor não-invasivo de parsing para Python, SQL e R."""

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

    def __init__(self):
        self.parsers: Dict[str, Any] = {}
        if HAS_TREE_SITTER:
            for grammar in set(self.GRAMMAR_BY_EXT.values()):
                try:
                    self.parsers[grammar] = get_parser(grammar)
                except Exception:
                    self.parsers[grammar] = None

    def parse_directory_readonly(
        self, directory_path: str, languages: Optional[List[str]] = None
    ) -> List[AccessPoint]:
        """Escaneia recursivamente um diretório em modo Read-Only e extrai todos os pontos de acesso."""
        base_path = Path(directory_path)
        if not base_path.exists():
            return []

        allowed_langs = set(languages) if languages else set(self.SUPPORTED_EXTENSIONS.values())
        all_access_points: List[AccessPoint] = []

        for root, dirs, files in os.walk(base_path):
            dirs[:] = sorted(d for d in dirs if d not in self.IGNORED_DIRS)
            for name in sorted(files):
                if name.endswith((".min.js", ".d.ts")):
                    continue
                file_path = Path(root) / name
                ext = self._normalized_suffix(file_path)
                if ext is None:
                    continue
                if self.SUPPORTED_EXTENSIONS[ext] in allowed_langs:
                    all_access_points.extend(self.parse_file_readonly(str(file_path)))

        return all_access_points

    def _normalized_suffix(self, path: Path) -> Optional[str]:
        """Retorna a extensão suportada (case-insensitive), ou None."""
        if path.suffix in self.SUPPORTED_EXTENSIONS:
            return path.suffix
        lowered = path.suffix.lower()
        return lowered if lowered in self.SUPPORTED_EXTENSIONS else None

    def parse_file_readonly(self, file_path: str) -> List[AccessPoint]:
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

        parser = self.parsers.get(self.GRAMMAR_BY_EXT.get(ext, lang))
        if parser is not None:
            tree = parser.parse(source_bytes)
            root_node = tree.root_node

            access_points: List[AccessPoint] = []
            self._traverse_ast(
                node=root_node,
                source_bytes=source_bytes,
                file_path=str(path).replace("\\", "/"),
                lang=lang,
                results=access_points,
            )
            if access_points:
                return access_points

        return self._fallback_parse(source_bytes, str(path).replace("\\", "/"), lang)

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
        """Fallback determinístico via stdlib AST (Python) ou análise estrutural (SQL/R)."""
        text = source_bytes.decode("utf-8", errors="replace")
        lines = text.splitlines()
        results: List[AccessPoint] = []

        if lang == "python":
            try:
                tree = ast.parse(text)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        start_line = node.lineno
                        end_line = getattr(node, "end_lineno", start_line) or start_line
                        snippet = "\n".join(lines[start_line - 1 : end_line])
                        node_type = (
                            "class_definition"
                            if isinstance(node, ast.ClassDef)
                            else "function_definition"
                        )
                        sexp = "|".join(
                            f"{type(n).__name__}" for n in ast.walk(node)
                        )  # apenas tipos de nós, sem nomes/literais
                        results.append(
                            AccessPoint(
                                file_path=file_path,
                                language=lang,
                                node_type=node_type,
                                name=node.name,
                                start_line=start_line,
                                end_line=end_line,
                                code_snippet=snippet,
                                ast_sexp=sexp,
                            )
                        )
                return sorted(results, key=lambda x: x.start_line)
            except SyntaxError:
                pass

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
                r"(?im)^\s*(WITH\s+\w+\s+AS|SELECT\b|CREATE\s+(?:OR\s+REPLACE\s+)?TABLE\s+[\w\.]+).*?(?:;|\Z)",
                re.DOTALL,
            )
            for match in pattern.finditer(text):
                snippet = match.group(0).strip()
                start_line = text[: match.start()].count("\n") + 1
                end_line = start_line + snippet.count("\n")
                first_token = snippet.split()[0].upper()
                node_type = "create_table_statement" if first_token == "CREATE" else "select"
                name_match = re.search(
                    r"(?:FROM|INTO|TABLE|WITH)\s+([a-zA-Z0-9_\.]+)", snippet, re.IGNORECASE
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
