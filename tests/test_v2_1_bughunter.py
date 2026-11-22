from pathlib import Path

from scripts.leak_guard import scan_repository_for_leaks
from src.privacy import redact_sensitive, scan_secrets
from src.rules import evaluate


def test_expanded_secret_catalog_redaction_and_scanner():
    # Tokens sintetizados via concatenação para não disparar push protection no arquivo de teste
    google_key = "AIza" + "B" * 35
    slack_tok = "xoxb-" + "1234567890-abcdef123456"
    hf_tok = "hf_" + "A" * 32
    npm_tok = "npm_" + "Z" * 36
    basic_url = "https://" + "admin:supersecret" + "@db.internal.local/api"
    priv_hdr = "-----BEGIN " + "RSA PRIVATE KEY-----"

    blob = f"{google_key} {slack_tok} {hf_tok} {npm_tok} {basic_url} {priv_hdr}"
    hits = scan_secrets(blob)
    patterns = {h["pattern"] for h in hits}
    assert {"GOOGLE_API_KEY", "SLACK_TOKEN", "HUGGINGFACE_TOKEN", "NPM_TOKEN", "BASIC_AUTH_URL", "PRIVATE_KEY_HEADER"} <= patterns

    redacted = redact_sensitive(blob)
    for raw in (google_key, slack_tok, hf_tok, npm_tok, "admin:supersecret", "RSA PRIVATE KEY"):
        assert raw not in redacted


def test_python_ssrf_ssti_xxe_and_non_false_positives():
    # True positives
    assert evaluate("python", "def f(req):\n    return requests.get(req.args['url'])").category == "Python_SSRF_Dynamic_Request"
    assert evaluate("python", "def f(u):\n    return urllib.request.urlopen(u)").category == "Python_SSRF_Dynamic_Request"
    assert evaluate("python", "def f(tpl):\n    return render_template_string(tpl)").category == "Python_SSTI_Template_Injection"
    assert evaluate("python", "def f(tpl):\n    return jinja2.Template(tpl).render()").category == "Python_SSTI_Template_Injection"
    assert evaluate("python", "def f(raw):\n    return ET.fromstring(raw)").category == "Python_XXE_Unsafe_XML"

    # Non-false-positives (triage guards)
    assert evaluate("python", 'def f():\n    return requests.get("https://api.example.com/health")') is None
    assert evaluate("python", 'def f():\n    return jinja2.Template("Hello {{ name }}").render(name="Ana")') is None
    assert evaluate("python", "import defusedxml.ElementTree as ET\ndef f(raw):\n    return ET.fromstring(raw)") is None


def test_js_ssti_and_provider_token_detection():
    assert evaluate("javascript", "function f(req) { return ejs.render(req.body.tpl); }").category == "JS_SSTI_Template_Injection"
    assert evaluate("javascript", 'function f() { return ejs.render("<p>ok</p>"); }') is None

    # Provider token caught even on generic variable name
    hf_tok = "hf_" + "C" * 32
    assert evaluate("python", f"def f():\n    val = '{hf_tok}'\n    return val").category == "Python_Hardcoded_Secret"
    assert evaluate("javascript", f"function f() {{ const val = '{hf_tok}'; return val; }}").category == "JS_Hardcoded_Secret"


def test_leak_guard_passes_on_repository():
    leaks = scan_repository_for_leaks(Path(__file__).resolve().parent.parent)
    assert leaks == []
