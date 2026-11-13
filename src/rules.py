"""Motor de regras estáticas determinísticas (offline) do DataPulse.

Cada regra é avaliada sobre o código SEM comentários; vence a de maior severidade
(em vez de "primeiro match vence"). Uma linha `datapulse: ignore` dentro do trecho
suprime os achados daquele ponto de acesso.
"""

import re
from dataclasses import dataclass
from typing import Callable, List, Optional

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass(frozen=True)
class Rule:
    language: str
    severity: str
    category: str
    check: Callable[[str], bool]
    chain_of_thought: str
    summary: str
    fix: str


# ---------------------------------------------------------------- utilidades
def strip_comments(language: str, code: str) -> str:
    if language == "python":
        return re.sub(r"(?m)(?<![\"'\w])#.*$", "", code)
    if language == "sql":
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
        return re.sub(r"(?m)--.*$", "", code)
    if language == "r":
        return re.sub(r"(?m)#.*$", "", code)
    if language == "javascript":
        code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
        return re.sub(r"(?m)(?<![:\"'\w])//.*$", "", code)
    return code


def rx(pattern: str, flags: int = 0) -> Callable[[str], bool]:
    compiled = re.compile(pattern, flags)
    return lambda code: compiled.search(code) is not None


def _balanced_block(text: str, open_pos: int) -> str:
    depth = 0
    for idx in range(open_pos, len(text)):
        if text[idx] == "{":
            depth += 1
        elif text[idx] == "}":
            depth -= 1
            if depth == 0:
                return text[open_pos : idx + 1]
    return text[open_pos:]


# ------------------------------------------------------------------- Python
_PY_DF_NAME = re.compile(r"(?mi)^\s*(\w*(?:df|data|frame|table)\w*)\[([^\n\]]+)\]\[[^\n]+\]\s*=(?!=)")
_PY_ANY_CHAIN = re.compile(r"(?m)^\s*\w+\[([^\n\]]+)\]\[[^\n]+\]\s*=(?!=)")


def _py_chained_indexing(code: str) -> bool:
    if _PY_DF_NAME.search(code):
        return True
    return any(re.search(r"==|!=|>=|<=|[<>]|\.isin\(|\.isna\(|\.notna\(", m.group(1)) for m in _PY_ANY_CHAIN.finditer(code))


def _py_read_csv_unoptimized(code: str) -> bool:
    for match in re.finditer(r"\bread_csv\(([^)]*)\)", code):
        if not re.search(r"\b(?:dtype|usecols|chunksize)\s*=", match.group(1)):
            return True
    return False


def _py_exception_swallowed(code: str) -> bool:
    return bool(
        re.search(r"except\b[^\n:]*:\s*(?:#[^\n]*)?\n?\s*pass\b", code)
        or re.search(r"(?m)^\s*except\s*:", code)
    )


def _py_concat_in_loop(code: str) -> bool:
    """pd.concat/df.append dentro de for/while (análise por indentação, tempo linear)."""
    lines = code.splitlines()
    call = re.compile(r"\b(?:pd|pandas)\.concat\(|\b\w*df\w*\.append\(")
    for idx, line in enumerate(lines):
        header = re.match(r"^([ \t]*)(?:for|while)\b.*:\s*$", line)
        if not header:
            continue
        base = len(header.group(1).expandtabs(4))
        for body in lines[idx + 1 :]:
            if not body.strip():
                continue
            if len(body) - len(body.lstrip()) <= base:
                break
            if call.search(body):
                return True
    return False


PYTHON_RULES: List[Rule] = [
    Rule("python", "CRITICAL", "SQL_Injection_Vulnerability",
         rx(r"""(?is)\b(?:f|rf|fr)(?:"|')[^\n]*?\b(?:SELECT|INSERT|UPDATE|DELETE)\b|"""
            r"""\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n"']*["']\s*\+\s*\w|"""
            r"""["'][^"'\n]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]*["']\s*\.format\("""),
         "Interpolação direta de string em query SQL dentro de função Python.",
         "Construção de query SQL via f-string/concatenação/format expõe o pipeline a SQL Injection.",
         "cursor.execute('SELECT * FROM users WHERE user_id = :uid', {'uid': user_id})"),
    Rule("python", "HIGH", "Subprocess_Shell_Injection_Risk",
         rx(r"(?s)(?:subprocess\.\w+|Popen)\s*\([^)]*shell\s*=\s*True"),
         "Chamada subprocess com shell=True identificada no nó AST.",
         "Subprocesso com `shell=True` permite injeção de comandos se houver entrada externa.",
         "subprocess.run(['cmd', 'arg1', 'arg2'], shell=False, check=True)"),
    Rule("python", "HIGH", "Pandas_Iterrows_Bottleneck",
         rx(r"(?m)^\s*for\b[^\n]*\bin\b[^\n]*\.iterrows\(\)"),
         "Laço `for` itera linha a linha via .iterrows(), com boxing de Series a cada linha.",
         "Loop explícito com `.iterrows()` sobre DataFrame causa degradação severa de CPU e memória.",
         "df['tax'] = df['price'] * 0.15  # operação vetorizada\ndf['net_total'] = df['price'] + df['tax']"),
    Rule("python", "HIGH", "Pandas_Concat_In_Loop", _py_concat_in_loop,
         "pd.concat/DataFrame.append dentro de laço copia o DataFrame inteiro a cada iteração (custo quadrático).",
         "`pd.concat`/`DataFrame.append` em laço tem custo O(N²); acumule em lista e concatene uma vez.",
         "frames = [process(chunk) for chunk in chunks]\nresult = pd.concat(frames, ignore_index=True)"),
    Rule("python", "MEDIUM", "Pandas_ChainedIndexing_Warning", _py_chained_indexing,
         "Indexação encadeada df[mask][col] = valor no lado esquerdo de uma atribuição.",
         "Indexação encadeada pode operar sobre cópia temporária e gerar `SettingWithCopyWarning` silencioso.",
         "df.loc[df['status'] == 'ACTIVE', 'discount'] = 0.10"),
    Rule("python", "MEDIUM", "Pandas_Apply_Axis1_Slow",
         rx(r"\.apply\([^)]*\baxis\s*=\s*(?:1|[\"']columns[\"'])"),
         "`DataFrame.apply(axis=1)` executa uma função Python por linha.",
         "`apply(axis=1)` é lento (laço Python por linha); prefira operações vetorizadas.",
         "df['total'] = df['price'] * df['qty']  # vetorizado"),
    Rule("python", "LOW", "Silent_Exception_Swallowing", _py_exception_swallowed,
         "Bloco except silenciando exceções (bare except ou `pass`).",
         "Captura silenciosa de exceção oculta falhas de pipeline e dificulta a rastreabilidade.",
         "except Exception as exc:\n    logger.warning('Falha controlada: %s', exc)"),
    Rule("python", "LOW", "Pandas_Inplace_Deprecated", rx(r"\binplace\s*=\s*True\b"),
         "`inplace=True` não evita cópias e está em processo de depreciação.",
         "`inplace=True` não traz ganho de memória e será depreciado; reatribua o resultado.",
         "df = df.dropna()"),
    Rule("python", "LOW", "Pandas_ReadCsv_Unoptimized", _py_read_csv_unoptimized,
         "read_csv sem dtype, usecols nem chunksize.",
         "`read_csv` sem `dtype`/`usecols`/`chunksize` pode consumir memória excessiva em arquivos grandes (informativo).",
         "df = pd.read_csv(path, usecols=['id', 'price'], dtype={'id': 'int32'})"),
]

# ---------------------------------------------------------------------- SQL
def _sql_mutation_without_where(code: str) -> bool:
    for stmt in code.split(";"):
        s = stmt.strip()
        if re.match(r"(?is)^(?:update\s+[\w.\"`\[\]]+\s+set\b|delete\s+from\s+[\w.\"`\[\]]+)", s) and not re.search(
            r"(?i)\bwhere\b", s
        ):
            return True
    return False


_SQL_FUNC_ON_COLUMN = re.compile(
    r"(?i)\b(?:DATE|LOWER|UPPER|YEAR|MONTH|TRIM|CAST|SUBSTR|SUBSTRING)\s*\(\s*[A-Za-z_][\w.]*[^()]{0,40}\)\s*(?:=|<>|!=|<=|>=|<|>|LIKE\b|IN\b)"
)


def _sql_non_sargable(code: str) -> bool:
    """Função sobre coluna em WHERE/ON (busca linear: só varre após a primeira cláusula de filtro)."""
    start = re.search(r"(?i)\b(?:where|on)\b", code)
    return bool(start and _SQL_FUNC_ON_COLUMN.search(code, start.end()))


SQL_RULES: List[Rule] = [
    Rule("sql", "CRITICAL", "SQL_Mutation_Without_Where", _sql_mutation_without_where,
         "UPDATE/DELETE sem cláusula WHERE afeta todas as linhas da tabela.",
         "`UPDATE`/`DELETE` sem `WHERE` altera ou apaga a tabela inteira.",
         "UPDATE t SET status = 'X' WHERE id = :id;"),
    Rule("sql", "CRITICAL", "SQL_FullTableScan", rx(r"(?is)\bselect\s+\*.*\bcross\s+join\b"),
         "SELECT * combinado com CROSS JOIN gera produto cartesiano e Full Table Scan.",
         "`SELECT *` com `CROSS JOIN` gera produto cartesiano, forçando Full Table Scan e I/O massivo.",
         "SELECT o.order_id, c.customer_id\nFROM analytics.fact_orders o\nJOIN analytics.dim_customers c ON c.customer_id = o.customer_id\nWHERE o.created_at >= CURRENT_DATE - INTERVAL '30 days';"),
    Rule("sql", "HIGH", "SQL_NotIn_Subquery", rx(r"(?is)\bnot\s+in\s*\(\s*select\b"),
         "NOT IN (subquery) retorna vazio se a subquery contiver NULL e costuma ter plano ruim.",
         "`NOT IN (SELECT ...)` falha silenciosamente com NULLs; prefira `NOT EXISTS`.",
         "WHERE NOT EXISTS (SELECT 1 FROM other o WHERE o.id = t.id)"),
    Rule("sql", "HIGH", "SQL_FullTableScan", rx(r"(?is)\blike\s+'%[^']"),
         "Predicado LIKE com curinga à esquerda não usa índice B-tree.",
         "`LIKE '%...'` (leading wildcard) é não-sargable e força Full Table Scan.",
         "WHERE email_domain = 'enterprise.com'  -- coluna derivada/indexada"),
    Rule("sql", "MEDIUM", "SQL_NonSargable_Predicate", _sql_non_sargable,
         "Função aplicada à coluna no predicado impede o uso de índice.",
         "Função sobre coluna em WHERE/ON (ex.: `DATE(col) = ...`) é não-sargable.",
         "WHERE created_at >= '2026-01-01' AND created_at < '2026-01-02'"),
    Rule("sql", "MEDIUM", "SQL_SelectStar_NoFilter",
         lambda c: bool(re.search(r"(?is)\bselect\s+\*", c)) and not re.search(r"(?i)\b(?:where|limit|top|fetch)\b", c),
         "SELECT * sem WHERE/LIMIT lê todas as colunas de todas as linhas.",
         "`SELECT *` sem filtro nem limite lê a tabela inteira com todas as colunas.",
         "SELECT col_a, col_b FROM t WHERE created_at >= CURRENT_DATE - INTERVAL '30 days';"),
]

# ------------------------------------------------------------------------ R
R_RULES: List[Rule] = [
    Rule("r", "HIGH", "R_Vectorization_Missing",
         lambda c: bool(re.search(r"\bfor\s*\(", c))
         and bool(re.search(r"\b(?:rbind|cbind)\s*\(|\b(\w+)\s*<-\s*c\(\s*\1\b", c)),
         "Objeto cresce a cada iteração do laço (rbind/cbind/c), copiando o vetor inteiro.",
         "Crescimento iterativo (`rbind`/`c`) em laço `for` gera custo O(N²) de memória; vetorize ou pré-aloque.",
         "normalize_metrics <- function(df) {\n  df$z_score <- (df$value - mean(df$value, na.rm = TRUE)) / sd(df$value, na.rm = TRUE)\n  df\n}"),
    Rule("r", "LOW", "R_Unsafe_Seq_Range", rx(r"\b1\s*:\s*(?:nrow|ncol|length)\s*\("),
         "`1:length(x)`/`1:nrow(df)` itera de forma errada quando o tamanho é 0.",
         "`1:n` falha com tamanho 0 (itera 1,0); use `seq_len()`/`seq_along()`.",
         "for (i in seq_len(nrow(df))) { ... }"),
]

# --------------------------------------------------------------- JavaScript
_JS_SECRET = re.compile(
    r"(?i)\b\w*(?:password|passwd|secret|api[_-]?key|token|private[_-]?key)\w*\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
)
_JS_PLACEHOLDER = re.compile(r"(?i)x{4,}|\*{3,}|changeme|your[_-]|example|placeholder|<[^>]+>|process\.env|dummy|test")


def _js_hardcoded_secret(code: str) -> bool:
    return any(not _JS_PLACEHOLDER.search(m.group(1)) for m in _JS_SECRET.finditer(code))


def _js_unhandled_promise(code: str) -> bool:
    if not re.search(r"\.then\s*\(", code):
        return False
    if re.search(r"\.catch\s*\(|\btry\s*\{|\breturn\b[^\n;]*\.then\s*\(|\bawait\b[^\n;]*\.then\s*\(", code):
        return False
    return True


def _js_await_in_loop(code: str) -> bool:
    for match in re.finditer(r"\b(for|while)\s*(await\s*)?\(", code):
        if match.group(2):  # for await (...) é intencional
            continue
        brace = code.find("{", match.end())
        if brace == -1:
            continue
        if re.search(r"\bawait\b", _balanced_block(code, brace)):
            return True
    return False


JS_RULES: List[Rule] = [
    Rule("javascript", "CRITICAL", "JS_Eval_Code_Injection",
         rx(r"(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\("),
         "Chamada a eval()/new Function() identificada na AST; entrada externa vira execução arbitrária.",
         "`eval()` / `new Function()` permite execução arbitrária de código (Code Injection).",
         "const result = JSON.parse(input); // ou lookup em tabela de funções permitidas"),
    Rule("javascript", "CRITICAL", "JS_Command_Injection",
         rx(r"(?:(?<![\w$.])|child_process\.)exec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|[^)\n]*['\"]\s*\+)"),
         "child_process.exec com string interpolada/concatenada: o shell interpreta a entrada.",
         "`child_process.exec` com template literal ou concatenação permite injeção de comandos de shell.",
         "const { execFile } = require('node:child_process');\nexecFile('git', ['log', '--', userPath], cb);"),
    Rule("javascript", "CRITICAL", "SQL_Injection_Vulnerability",
         rx(r"(?is)`\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{|['\"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*['\"]\s*\+"),
         "Query SQL montada via template literal/concatenação com valor dinâmico.",
         "Construção de query SQL por interpolação em JavaScript expõe a aplicação a SQL Injection.",
         "const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);"),
    Rule("javascript", "HIGH", "JS_Hardcoded_Secret", _js_hardcoded_secret,
         "Literal com nome de credencial atribuído diretamente no código-fonte.",
         "Credencial/segredo hardcoded no código pode vazar via repositório ou bundle.",
         "const apiKey = process.env.API_KEY; // carregue de variável de ambiente / secret manager"),
    Rule("javascript", "HIGH", "JS_ReDoS_Unsafe_Regex", rx(r"\((?:[^()\s]*)[+*]\)[+*?{]"),
         "Regex com quantificador aninhado: risco de backtracking catastrófico.",
         "Expressão regular com quantificadores aninhados é vulnerável a ReDoS e pode travar o event loop.",
         "const safe = /^[a-z0-9]+$/i; // evite grupos aninhados com + ou *"),
    Rule("javascript", "MEDIUM", "JS_Sync_IO_Blocking_EventLoop",
         rx(r"\b(?:fs|fsp)\.(?:readFileSync|writeFileSync|appendFileSync|readdirSync|statSync|mkdirSync|unlinkSync)\b|(?<![\w$.])(?:execSync|spawnSync)\s*\("),
         "API síncrona de fs/child_process dentro de função: bloqueia o event loop do Node.",
         "I/O síncrono (`fs.*Sync`) em handlers bloqueia o event loop e derruba o throughput.",
         "const { readFile } = require('node:fs/promises');\nconst data = await readFile(path, 'utf8');"),
    Rule("javascript", "MEDIUM", "JS_Unhandled_Promise_Rejection", _js_unhandled_promise,
         "Cadeia .then() sem .catch() nem try/catch: rejeições sem tratamento.",
         "Promise encadeada sem `.catch()` pode gerar `unhandledRejection` e derrubar o processo Node.",
         "try {\n  const data = await fetchData();\n} catch (err) {\n  logger.error(err);\n}"),
    Rule("javascript", "MEDIUM", "JS_Await_In_Loop", _js_await_in_loop,
         "`await` dentro de laço serializa operações independentes.",
         "`await` em laço executa uma operação por vez; use `Promise.all` quando forem independentes.",
         "const results = await Promise.all(items.map((item) => process(item)));"),
    Rule("javascript", "LOW", "JS_Dynamic_RegExp", rx(r"new\s+RegExp\(\s*[A-Za-z_$]"),
         "RegExp construída a partir de variável.",
         "`new RegExp(variavel)` com entrada externa pode causar ReDoS; valide/escape o padrão.",
         "const re = new RegExp(escapeRegExp(userInput));"),
]

ALL_RULES = {
    "python": PYTHON_RULES,
    "sql": SQL_RULES,
    "r": R_RULES,
    "javascript": JS_RULES,
}

_IGNORE_MARKER = re.compile(r"datapulse:\s*ignore", re.IGNORECASE)


def evaluate(language: str, code: str) -> Optional[Rule]:
    """Retorna a regra de maior severidade que dispara em `code` (ou None)."""
    if _IGNORE_MARKER.search(code):
        return None
    cleaned = strip_comments(language, code)
    best: Optional[Rule] = None
    for rule in ALL_RULES.get(language, []):
        try:
            hit = rule.check(cleaned)
        except re.error:
            hit = False
        if hit and (best is None or SEVERITY_ORDER[rule.severity] > SEVERITY_ORDER[best.severity]):
            best = rule
    return best
