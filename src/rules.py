"""Motor de regras estáticas (AST + fallback linear) do DataPulse.

Combina detectores estruturais em `src/ast_rules.py` (Python stdlib AST, SQLGlot AST,
Tree-sitter R e JS/TS) com fallback determinístico linear em tempo O(N).
Suporta múltiplos achados por AccessPoint (`evaluate_all`) e supressão via `datapulse: ignore`.
"""

import re
from dataclasses import dataclass, replace
from typing import Callable, Dict, Iterable, List, Optional

from src.ast_rules import detect_ast_findings

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


@dataclass(frozen=True)
class RuleMatch:
    rule: Rule
    line_offset: int = 0
    detail: str = ""


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


def _never(_code: str) -> bool:
    return False


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
    Rule("python", "CRITICAL", "Python_Eval_Exec_Injection",
         rx(r"(?<![.\w])(?:eval|exec)\s*\("),
         "Chamada direta a eval()/exec() permite execução arbitrária de código.",
         "Uso de `eval()`/`exec()` expõe o pipeline a Code Injection crítico (Ruff S307).",
         "import ast\nresult = ast.literal_eval(user_input)"),
    Rule("python", "CRITICAL", "Python_Insecure_Deserialization",
         rx(r"\b(?:pickle|marshal)\.loads?\(|\byaml\.load\("),
         "Desserialização insegura via pickle/marshal ou yaml.load sem SafeLoader.",
         "Desserialização com `pickle`/`marshal`/`yaml.load` permite execução arbitrária (Ruff S301/S506).",
         "data = yaml.safe_load(raw)  # ou json.loads(raw)"),
    Rule("python", "CRITICAL", "Python_SSTI_Template_Injection", _never,
         "Renderização de template a partir de string dinâmica controlada pelo usuário.",
         "SSTI em `jinja2.Template`/`render_template_string`/`mako.Template` permite execução remota de código.",
         "return render_template('report.html', name=user_name)  # use arquivo de template estático"),
    Rule("python", "HIGH", "Python_SSRF_Dynamic_Request", _never,
         "Requisição HTTP de saída recebe URL dinâmica sem validação de allowlist.",
         "URL dinâmica em `requests`/`httpx`/`urllib.urlopen` pode expor a aplicação a SSRF.",
         "parsed = urlparse(url)\nif parsed.hostname not in ALLOWED_HOSTS: raise ValueError('Blocked')"),
    Rule("python", "HIGH", "Python_XXE_Unsafe_XML", _never,
         "Parser XML padrão (ElementTree/lxml/minidom) sem proteção contra entidades externas.",
         "Parsing XML sem `defusedxml` pode expor o serviço a XXE e Billion Laughs.",
         "import defusedxml.ElementTree as ET\ntree = ET.fromstring(xml_bytes)"),
    Rule("python", "HIGH", "Subprocess_Shell_Injection_Risk",
         rx(r"(?s)(?:subprocess\.\w+|Popen)\s*\([^)]*shell\s*=\s*True"),
         "Chamada subprocess com shell=True identificada no nó AST.",
         "Subprocesso com `shell=True` permite injeção de comandos se houver entrada externa (Ruff S602).",
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
    Rule("python", "HIGH", "PySpark_Collect_Driver_OOM",
         rx(r"(?<!gc)\.collect\(\)|\.toPandas\(\)"),
         "`.collect()` / `.toPandas()` traz todos os dados distribuídos para a memória do driver.",
         "Chamada `.collect()`/`.toPandas()` sem `.limit()` pode causar `OutOfMemoryError` no driver Spark.",
         "sample_rows = spark_df.limit(1000).collect()  # ou grave em Parquet/Delta particionado"),
    Rule("python", "HIGH", "Polars_Row_Iteration_Bottleneck",
         rx(r"\.(?:iter_rows|map_elements)\("),
         "Iteração linha a linha em Polars quebra o motor paralelo em Rust.",
         "`.iter_rows()`/`.map_elements()` desativa vetorização e paralelizacão nativa do Polars.",
         "df = df.lazy().with_columns((pl.col('price') * 0.15).alias('tax')).collect()"),
    Rule("python", "HIGH", "Python_Hardcoded_Secret", _never,
         "Credencial atribuída como string literal no código-fonte.",
         "Segredo/senha hardcoded no código-fonte pode vazar no histórico Git (Ruff S105).",
         "api_key = os.environ['API_KEY']"),
    Rule("python", "MEDIUM", "Pandas_ChainedIndexing_Warning", _py_chained_indexing,
         "Indexação encadeada df[mask][col] = valor no lado esquerdo de uma atribuição.",
         "Indexação encadeada pode operar sobre cópia temporária e gerar `SettingWithCopyWarning` silencioso.",
         "df.loc[df['status'] == 'ACTIVE', 'discount'] = 0.10"),
    Rule("python", "MEDIUM", "Pandas_Apply_Axis1_Slow",
         rx(r"\.apply\([^)]*\baxis\s*=\s*(?:1|[\"']columns[\"'])"),
         "`DataFrame.apply(axis=1)` executa uma função Python por linha.",
         "`apply(axis=1)` é lento (laço Python por linha); prefira operações vetorizadas.",
         "df['total'] = df['price'] * df['qty']  # vetorizado"),
    Rule("python", "MEDIUM", "PySpark_Python_UDF_Overhead",
         rx(r"(?:@\s*|\bF\.|\bfunctions\.)udf\b"),
         "UDF Python no PySpark força serialização entre JVM e processos Python por linha.",
         "Python UDF em PySpark gera gargalo de serialização; prefira `pyspark.sql.functions` nativas.",
         "from pyspark.sql import functions as F\ndf = df.withColumn('norm', F.lower(F.trim(F.col('name'))))"),
    Rule("python", "MEDIUM", "Python_Mutable_Default_Arg", _never,
         "Valor padrão mutável (list/dict/set) é compartilhado entre todas as chamadas da função.",
         "Argumento padrão mutável (`[]`, `{}`) causa vazamento de estado entre chamadas (Ruff B006).",
         "def add_item(item, items=None):\n    items = [] if items is None else items"),
    Rule("python", "LOW", "Silent_Exception_Swallowing", _py_exception_swallowed,
         "Bloco except silenciando exceções (bare except ou `pass`).",
         "Captura silenciosa de exceção oculta falhas de pipeline e dificulta a rastreabilidade (Ruff S110).",
         "except Exception as exc:\n    logger.warning('Falha controlada: %s', exc)"),
    Rule("python", "LOW", "Pandas_Inplace_Deprecated", rx(r"\binplace\s*=\s*True\b"),
         "`inplace=True` não evita cópias e está em processo de depreciação.",
         "`inplace=True` não traz ganho de memória e será depreciado; reatribua o resultado.",
         "df = df.dropna()"),
    Rule("python", "LOW", "Pandas_ReadCsv_Unoptimized", _py_read_csv_unoptimized,
         "read_csv sem dtype, usecols nem chunksize.",
         "`read_csv` sem `dtype`/`usecols`/`chunksize` pode consumir memória excessiva em arquivos grandes.",
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
         "`UPDATE`/`DELETE` sem `WHERE` altera ou apaga a tabela inteira (SQLFluff/sqlcheck).",
         "UPDATE t SET status = 'X' WHERE id = :id;"),
    Rule("sql", "CRITICAL", "SQL_FullTableScan", rx(r"(?is)\bselect\s+\*.*\bcross\s+join\b"),
         "SELECT * combinado com CROSS JOIN gera produto cartesiano e Full Table Scan.",
         "`SELECT *` com `CROSS JOIN` gera produto cartesiano, forçando Full Table Scan e I/O massivo.",
         "SELECT o.order_id, c.customer_id\nFROM analytics.fact_orders o\nJOIN analytics.dim_customers c ON c.customer_id = o.customer_id\nWHERE o.created_at >= CURRENT_DATE - INTERVAL '30 days';"),
    Rule("sql", "HIGH", "SQL_Cartesian_Join_Missing_On", _never,
         "JOIN sem cláusula ON ou USING gera produto cartesiano acidental.",
         "`JOIN` sem `ON`/`USING` produz produto cartesiano (SQLFluff).",
         "SELECT a.id FROM a JOIN b ON b.id = a.id;"),
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
         "`SELECT *` sem filtro nem limite lê a tabela inteira com todas as colunas (SQLFluff AM04).",
         "SELECT col_a, col_b FROM t WHERE created_at >= CURRENT_DATE - INTERVAL '30 days';"),
    Rule("sql", "LOW", "SQL_Distinct_With_Join", _never,
         "SELECT DISTINCT com JOIN sem GROUP BY frequentemente mascara junção 1:N incompleta.",
         "`SELECT DISTINCT` combinado com `JOIN` sem `GROUP BY` pode ocultar duplicatas de junção e gerar sort caro.",
         "SELECT a.id FROM a WHERE EXISTS (SELECT 1 FROM b WHERE b.id = a.id);"),
    Rule("sql", "LOW", "SQL_Union_Without_All", rx(r"(?is)\bunion\b(?!\s+all\b)"),
         "UNION executa DISTINCT implícito em todo o resultado; UNION ALL evita ordenação/deduplicação.",
         "`UNION` sem `ALL` força deduplicação cara; use `UNION ALL` quando duplicatas são aceitas ou impossíveis.",
         "SELECT id FROM t1 UNION ALL SELECT id FROM t2;"),
]

# ------------------------------------------------------------------------ R
R_RULES: List[Rule] = [
    Rule("r", "HIGH", "R_Vectorization_Missing",
         lambda c: bool(re.search(r"\bfor\s*\(", c))
         and bool(re.search(r"\b(?:rbind|cbind)\s*\(|\b(\w+)\s*<-\s*c\(\s*\1\b", c)),
         "Objeto cresce a cada iteração do laço (rbind/cbind/c), copiando o vetor inteiro.",
         "Crescimento iterativo (`rbind`/`c`) em laço `for` gera custo O(N²) de memória; vetorize ou pré-aloque.",
         "normalize_metrics <- function(df) {\n  df$z_score <- (df$value - mean(df$value, na.rm = TRUE)) / sd(df$value, na.rm = TRUE)\n  df\n}"),
    Rule("r", "MEDIUM", "R_T_F_Symbol_Usage", _never,
         "`T` e `F` são variáveis mutáveis em R, enquanto `TRUE`/`FALSE` são palavras reservadas.",
         "Uso de `T`/`F` em vez de `TRUE`/`FALSE` pode ser sobrescrito em runtime (lintr `T_and_F_symbol_linter`).",
         "mean(x, na.rm = TRUE)"),
    Rule("r", "MEDIUM", "R_Attach_Namespace_Pollution", rx(r"\battach\s*\("),
         "`attach()` injeta colunas no search path global e causa colisões silenciosas.",
         "`attach()` polui o escopo global e gera conflito de variáveis; use `with()` ou `$`.",
         "with(df, mean(value))"),
    Rule("r", "LOW", "R_Unsafe_Seq_Range", rx(r"\b1\s*:\s*(?:nrow|ncol|length)\s*\("),
         "`1:length(x)`/`1:nrow(df)` itera de forma errada quando o tamanho é 0.",
         "`1:n` falha com tamanho 0 (itera 1,0); use `seq_len()`/`seq_along()` (lintr `seq_linter`).",
         "for (i in seq_len(nrow(df))) { ... }"),
    Rule("r", "LOW", "R_Sapply_Type_Unsafe", rx(r"\bsapply\s*\("),
         "`sapply()` simplifica o tipo de retorno de forma imprevisível conforme o tamanho dos dados.",
         "`sapply()` não garante o tipo de retorno; use `vapply()` ou `purrr::map_*` (lintr `undesirable_function`).",
         "vapply(df, mean, numeric(1))"),
]

# --------------------------------------------------------------- JavaScript
_JS_SECRET = re.compile(
    r"(?i)\b\w*(?:password|passwd|secret|api[_-]?key|token|private[_-]?key)\w*\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
)
_JS_PLACEHOLDER = re.compile(r"(?i)x{4,}|\*{3,}|changeme|your[_-]|example|placeholder|<[^>]+>|process\.env|dummy|\btest\b")


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
    Rule("javascript", "CRITICAL", "JS_Prototype_Pollution", _never,
         "Atribuição dinâmica aninhada `obj[a][b] = v` ou acesso direto a `__proto__` sem guarda.",
         "Atribuição com chaves dinâmicas sem validar `__proto__`/`constructor` expõe a Prototype Pollution.",
         "if (key === '__proto__' || key === 'constructor') continue;\nif (Object.hasOwn(target, key)) target[key][sub] = val;"),
    Rule("javascript", "CRITICAL", "JS_SSTI_Template_Injection", _never,
         "Template compilado/renderizado com string dinâmica em `ejs.render`/`pug.render`/`handlebars.compile`.",
         "SSTI em engine de template JS/Node permite execução remota de código no servidor.",
         "res.render('profile', { username: req.query.name });  // passe apenas dados para template estático"),
    Rule("javascript", "HIGH", "JS_SSRF_Dynamic_Fetch", _never,
         "Chamada HTTP de saída recebe URL vinda diretamente de req.query/req.body/req.params.",
         "URL externa controlada pelo usuário em `fetch`/`axios`/`http.get` expõe o servidor a SSRF.",
         "const allowedHosts = new Set(['api.trusted.internal']);\nconst url = new URL(req.query.url);\nif (!allowedHosts.has(url.host)) throw new Error('Blocked');"),
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
    Rule("javascript", "MEDIUM", "JS_Unsafe_JSON_Parse", _never,
         "`JSON.parse()` fora de bloco `try/catch` derruba o handler em payload malformado.",
         "`JSON.parse()` sem `try/catch` pode lançar `SyntaxError` não tratado em entrada externa.",
         "try {\n  const data = JSON.parse(raw);\n} catch (err) {\n  return null;\n}"),
    Rule("javascript", "LOW", "JS_Dynamic_RegExp", rx(r"new\s+RegExp\(\s*[A-Za-z_$]"),
         "RegExp construída a partir de variável.",
         "`new RegExp(variavel)` com entrada externa pode causar ReDoS; valide/escape o padrão.",
         "const re = new RegExp(escapeRegExp(userInput));"),
]

COMPLEXITY_RULE = Rule(
    "any",
    "MEDIUM",
    "High_Cyclomatic_Complexity",
    _never,
    "Quantidade elevada de desvios condicionais e laços no mesmo ponto de acesso.",
    "Complexidade ciclomática acima do limite configurado; divida o bloco em funções menores e testáveis.",
    "# Extraia blocos condicionais em funções auxiliares coesas com retorno antecipado.",
)

ALL_RULES: Dict[str, List[Rule]] = {
    "python": PYTHON_RULES,
    "sql": SQL_RULES,
    "r": R_RULES,
    "javascript": JS_RULES,
}

# Catálogo indexado por (language, category) e fallback por category
_RULE_BY_LANG_CAT: Dict[tuple, Rule] = {}
_RULE_BY_CAT: Dict[str, Rule] = {COMPLEXITY_RULE.category: COMPLEXITY_RULE}
for _lang, _rules in ALL_RULES.items():
    for _r in _rules:
        _RULE_BY_LANG_CAT.setdefault((_lang, _r.category), _r)
        _RULE_BY_CAT.setdefault(_r.category, _r)

_IGNORE_ALL_RE = re.compile(r"datapulse:\s*ignore(?!\s*\[)", re.IGNORECASE)
_IGNORE_SPEC_RE = re.compile(r"datapulse:\s*ignore\[([^\]]+)\]", re.IGNORECASE)


def _suppressed_categories(code: str) -> Optional[set]:
    """Retorna None para suprimir tudo, ou conjunto de categorias suprimidas."""
    if _IGNORE_ALL_RE.search(code):
        return None
    suppressed: set = set()
    for match in _IGNORE_SPEC_RE.finditer(code):
        for item in match.group(1).split(","):
            name = item.strip()
            if name:
                suppressed.add(name)
    return suppressed


def evaluate_all(
    language: str,
    code: str,
    disable_rules: Optional[Iterable[str]] = None,
    min_severity: str = "LOW",
    complexity_threshold: int = 12,
    cyclomatic_complexity: Optional[int] = None,
    sql_dialect: Optional[str] = None,
) -> List[RuleMatch]:
    """Avalia todas as regras aplicáveis (AST primeiro, fallback linear se parse falhar)."""
    suppressed = _suppressed_categories(code)
    if suppressed is None:
        return []

    disabled = set(disable_rules or ()) | suppressed
    min_rank = SEVERITY_ORDER.get(min_severity, 1)

    matches: List[RuleMatch] = []
    ast_hits = detect_ast_findings(language, code, sql_dialect=sql_dialect)

    if ast_hits is not None:
        for cat, line_off, detail, sev_override in ast_hits:
            base_rule = _RULE_BY_LANG_CAT.get((language, cat)) or _RULE_BY_CAT.get(cat)
            if base_rule is None:
                continue
            rule = replace(base_rule, severity=sev_override) if sev_override else base_rule
            matches.append(RuleMatch(rule=rule, line_offset=line_off, detail=detail))
    else:
        cleaned = strip_comments(language, code)
        for rule in ALL_RULES.get(language, []):
            try:
                hit = rule.check(cleaned)
            except re.error:
                hit = False
            if hit:
                matches.append(RuleMatch(rule=rule, line_offset=0))

    if cyclomatic_complexity is not None and cyclomatic_complexity > complexity_threshold:
        summary = (
            f"Complexidade ciclomática {cyclomatic_complexity} excede o limite de "
            f"{complexity_threshold}; extraia funções menores para reduzir acoplamento."
        )
        cc_rule = replace(COMPLEXITY_RULE, language=language, summary=summary)
        matches.append(RuleMatch(rule=cc_rule, line_offset=0, detail=f"CC={cyclomatic_complexity}"))

    # Deduplica por categoria mantendo maior severidade e menor offset de linha
    best_by_cat: Dict[str, RuleMatch] = {}
    for m in matches:
        cat = m.rule.category
        if cat in disabled or SEVERITY_ORDER[m.rule.severity] < min_rank:
            continue
        prev = best_by_cat.get(cat)
        if prev is None:
            best_by_cat[cat] = m
        else:
            prev_rank = SEVERITY_ORDER[prev.rule.severity]
            new_rank = SEVERITY_ORDER[m.rule.severity]
            if (new_rank, -m.line_offset) > (prev_rank, -prev.line_offset):
                best_by_cat[cat] = m

    ordered = sorted(
        best_by_cat.values(),
        key=lambda m: (-SEVERITY_ORDER[m.rule.severity], m.line_offset),
    )
    return ordered


def evaluate(language: str, code: str) -> Optional[Rule]:
    """Retorna a regra de maior severidade que dispara em `code` (ou None)."""
    matches = evaluate_all(language, code)
    return matches[0].rule if matches else None
