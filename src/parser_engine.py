import ast
import hashlib
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
        self.access_id = f"{language}:{Path(file_path).name}:{name}:L{start_line}-L{end_line}"
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
        "python": ["function_definition", "class_definition", "with_statement"],
        "sql": [
            "select",
            "statement",
            "create_table_statement",
            "cte",
            "select_statement",
            "create_table",
        ],
        "r": ["function_definition", "binary_operator", "call", "left_assignment"],
        "javascript": [
            "function_declaration",
            "generator_function_declaration",
            "method_definition",
            "variable_declarator",  # filtrado: apenas quando recebe arrow/function expression
        ],
    }

    JS_FUNCTION_VALUES = {"arrow_function", "function_expression", "function", "generator_function"}

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

        for file_path in sorted(base_path.rglob("*")):
            rel_parts = file_path.relative_to(base_path).parts[:-1]
            if any(part in self.IGNORED_DIRS for part in rel_parts):
                continue
            if file_path.name.endswith((".min.js", ".d.ts")):
                continue
            if file_path.is_file() and file_path.suffix in self.SUPPORTED_EXTENSIONS:
                lang = self.SUPPORTED_EXTENSIONS[file_path.suffix]
                if lang in allowed_langs:
                    all_access_points.extend(self.parse_file_readonly(str(file_path)))

        return all_access_points

    def parse_file_readonly(self, file_path: str) -> List[AccessPoint]:
        """Lê o arquivo em modo estritamente read-only e extrai pontos de acesso."""
        path = Path(file_path)
        if not path.exists() or path.suffix not in self.SUPPORTED_EXTENSIONS:
            return []

        lang = self.SUPPORTED_EXTENSIONS[path.suffix]

        # Leitura binária segura sem avaliação/importação do código
        with open(path, "rb") as f:
            source_bytes = f.read()

        parser = self.parsers.get(self.GRAMMAR_BY_EXT.get(path.suffix, lang))
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
        """Percorre a árvore sintática recursivamente identificando blocos lógicos."""
        target_types = self.TARGET_NODES.get(lang, [])

        is_target = node.type in target_types
        if is_target and lang == "javascript" and node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            is_target = value is not None and value.type in self.JS_FUNCTION_VALUES

        if is_target:
            start_line = node.start_point[0] + 1
            end_line = node.end_point[0] + 1
            snippet = source_bytes[node.start_byte : node.end_byte].decode(
                "utf-8", errors="replace"
            )

            node_name = self._extract_node_name(node, source_bytes, lang, start_line)
            ast_sexp = node.sexp() if hasattr(node, "sexp") else f"({node.type} {node_name})"

            ap = AccessPoint(
                file_path=file_path,
                language=lang,
                node_type=node.type,
                name=node_name,
                start_line=start_line,
                end_line=end_line,
                code_snippet=snippet,
                ast_sexp=ast_sexp,
            )
            results.append(ap)

        for child in node.children:
            self._traverse_ast(child, source_bytes, file_path, lang, results)

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
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        start_line = node.lineno
                        end_line = getattr(node, "end_lineno", start_line) or start_line
                        snippet = "\n".join(lines[start_line - 1 : end_line])
                        node_type = (
                            "class_definition"
                            if isinstance(node, ast.ClassDef)
                            else "function_definition"
                        )
                        sexp = ast.dump(node, include_attributes=False)
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
                        ast_sexp=f"(function_declaration (identifier {func_name}))",
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
                sexp = f"({node_type} (target {name}) (length {len(snippet)}))"
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
                sexp = f"(function_definition (identifier {func_name}))"
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
