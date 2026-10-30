"""Static checks, Python only in v1.

All checks are heuristics over source text / AST. They are documented as
such: a finding means 'look here', not 'this is certainly exploitable'.
That is why the gate defaults to high severity + high confidence only.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from .models import Finding

# --- secret patterns: known formats are high confidence, generic names medium ---
SECRET_PATTERNS = [
    ("sk-[A-Za-z0-9]{20,}", "OpenAI-style API key literal"),
    ("AKIA[0-9A-Z]{16}", "AWS access key literal"),
    ("github_pat_[A-Za-z0-9_]{20,}", "GitHub personal access token literal"),
    ("ghp_[A-Za-z0-9]{20,}", "GitHub token literal"),
    ("xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token literal"),
]

GENERIC_SECRET_RE = re.compile(
    r"(?i)\b(api_key|apikey|secret|password|passwd|token)\s*=\s*['\"][^'\"]{8,}['\"]"
)
SANITISERS = {"sanitize", "sanitise", "escape", "validate", "allowlist", "allow_list", "strip_tags", "clean_input"}
SOURCE_CALLS = {"input"}
SOURCE_ATTRS = {"argv", "args", "form", "data", "text", "content"}
SINK_NAMES = {"generate", "complete", "chat", "run", "invoke", "ask", "prompt", "create"}


def _finding(check_id, severity, confidence, path, line, message, snippet=""):
    return Finding(check_id, severity, confidence, str(path), line, message, snippet)


def _is_allowlisted_call(node: ast.AST) -> bool:
    """True if the expression mentions an allowlist / validation helper."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id.lower() in SANITISERS:
            return True
        if isinstance(child, ast.Attribute) and child.attr.lower() in SANITISERS:
            return True
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if "allowlist" in child.value.lower() or "allowed_commands" in child.value.lower():
                return True
    return False


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _expr_is_tainted(expr: ast.AST, tainted: dict[str, int]) -> bool:
    """True if an argument expression carries tracked taint.

    Mirrors the taint model used by AGENT001: a tainted Name, a formatted
    string interpolating one, or a list/tuple containing one. A plain
    variable (e.g. a function parameter) is NOT tainted by this model —
    see the PY003 limits in the README — so it is not flagged here.
    """
    if isinstance(expr, ast.Name):
        return expr.id in tainted
    if isinstance(expr, ast.JoinedStr):
        return any(
            isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name)
            and v.value.id in tainted
            for v in expr.values
        )
    if isinstance(expr, (ast.List, ast.Tuple)):
        return any(_expr_is_tainted(elt, tainted) for elt in expr.elts)
    return False


def _call_full(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = func.value
        if isinstance(base, ast.Name):
            return f"{base.id}.{func.attr}"
        return func.attr
    return ""


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: Path, lines: list[str]):
        self.path = path
        self.lines = lines
        self.findings: list[Finding] = []
        # variable name -> "tainted" (from an untrusted source, not sanitised)
        self.tainted: dict[str, int] = {}

    def _line(self, node):
        return getattr(node, "lineno", 1)

    def _snippet(self, node):
        n = self._line(node)
        if 1 <= n <= len(self.lines):
            return self.lines[n - 1].strip()
        return ""

    def _add(self, check_id, severity, confidence, node, message):
        self.findings.append(
            _finding(check_id, severity, confidence, self.path, self._line(node), message, self._snippet(node))
        )

    def visit_Assign(self, node: ast.Assign):
        # Track taint: x = input() / requests.get(...) / open(...).read() / argv / request.*
        value = node.value
        tainted = False
        if isinstance(value, ast.Call):
            name = _call_name(value)
            full = _call_full(value)
            if name in SOURCE_CALLS or "requests.get" in full or "requests.post" in full:
                tainted = True
            if isinstance(value.func, ast.Attribute) and value.func.attr in ("read", "read_text"):
                tainted = True
        if isinstance(value, ast.Attribute) and value.attr in SOURCE_ATTRS:
            tainted = True
        if isinstance(value, ast.Subscript):
            # request.form["x"], sys.argv[1], data["prompt"] etc.
            tainted = True
        if not tainted:
            # Taint propagation: x = f"...{tainted}..." / y = process(tainted)
            for child in ast.walk(value):
                if isinstance(child, ast.Name) and child.id in self.tainted:
                    tainted = True
                    break
        if tainted and not _is_allowlisted_call(value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted[target.id] = self._line(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        name = _call_name(node)
        full = _call_full(node)

        # SHELL001: shell execution
        if name in ("system", "popen") or full in ("os.system", "os.popen"):
            arg = node.args[0] if node.args else None
            if isinstance(arg, ast.Name) and arg.id in self.tainted:
                self._add("SHELL001", "high", "high", node,
                          "Shell command built from untrusted/tainted input without an allowlist.")
            elif isinstance(arg, ast.Constant):
                self._add("SHELL001", "medium", "high", node,
                          "os.system/os.popen shell execution; check the command is not attacker-controlled.")
            else:
                self._add("SHELL001", "high", "medium", node,
                          "Shell execution with a non-literal command; verify an allowlist is enforced.")
        if name == "run" and full.startswith("subprocess"):
            shell_true = any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords if kw.arg == "shell"
            )
            if shell_true:
                arg = node.args[0] if node.args else None
                if isinstance(arg, ast.Name) and arg.id in self.tainted:
                    self._add("SHELL001", "high", "high", node,
                              "subprocess with shell=True on tainted input without an allowlist.")
                elif _is_allowlisted_call(node):
                    pass  # allowlisted call: deliberately not flagged
                else:
                    self._add("SHELL001", "high", "medium", node,
                              "subprocess with shell=True; use a list argv and an allowlist instead.")
            # broad file delete via subprocess rm -rf
            if isinstance(node.args[0], ast.Constant) if node.args else False:
                pass

        # PY003: subprocess execution from unsanitised input, no shell=True
        # needed. Without a shell, a tainted string is still the executable
        # (or a tainted list element is still an argv entry) the attacker
        # chooses, so this is not covered by SHELL001. shell=True + run is
        # deliberately skipped here: SHELL001 already flags that case, and
        # a second finding on the same line would be duplicate noise.
        if name in ("run", "call", "check_call", "check_output", "Popen") \
                and full.startswith("subprocess"):
            shell_true = any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords if kw.arg == "shell"
            )
            if not (name == "run" and shell_true) \
                    and node.args and _expr_is_tainted(node.args[0], self.tainted) \
                    and not _is_allowlisted_call(node):
                self._add("PY003", "high", "high", node,
                          "subprocess call with a tainted command/argv and no allowlist; "
                          "even without shell=True the attacker controls which program "
                          "runs or which arguments it receives. Use an allowlisted "
                          "command mapping and a literal argv list instead.")

        # TOOL001: agent tool permission without allowlist
        if name in ("run", "execute", "invoke") and _is_allowlisted_call(node) is False:
            # only flag when the surrounding call mentions a tool/agent and a shell
            text = self._snippet(node).lower()
            if "tool" in text and ("shell" in text or "bash" in text):
                self._add("TOOL001", "medium", "medium", node,
                          "Agent tool execution mentioning a shell; confirm tools are allowlisted.")

        # FILE001: broad file write/delete from a variable path
        if name in ("remove", "unlink", "rmtree") or full in ("os.remove", "os.unlink", "shutil.rmtree"):
            arg = node.args[0] if node.args else None
            if isinstance(arg, ast.Name):
                self._add("FILE001", "high", "medium", node,
                          "File delete with a variable path; confirm the path is confined to an allowed directory.")
        if name == "write_text" or full.endswith(".write_text"):
            base = node.func.value if isinstance(node.func, ast.Attribute) else None
            if isinstance(base, ast.Name) and base.id in self.tainted:
                self._add("FILE001", "high", "medium", node,
                          "File write to a tainted path; confirm the path is confined to an allowed directory.")
        if name == "open":
            mode = ""
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = str(kw.value.value)
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
            if "w" in mode or "a" in mode:
                arg = node.args[0] if node.args else None
                if isinstance(arg, ast.Name) and arg.id in self.tainted:
                    self._add("FILE001", "high", "medium", node,
                              "File write to a tainted path; confirm the path is confined to an allowed directory.")
                elif isinstance(arg, ast.Name):
                    # A variable path is worth a look even when taint cannot
                    # be proven (e.g. a function parameter); medium confidence
                    # means it is reported but does not fail the default gate.
                    self._add("FILE001", "medium", "medium", node,
                              "File write to a variable path; confirm the path is confined to an allowed directory.")

        # TOOL002: explicit allow_shell / broad tool flags
        for kw in node.keywords:
            if kw.arg in ("allow_shell", "allow_bash", "allow_exec") and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                self._add("TOOL002", "high", "high", node,
                          "Agent/tool explicitly allows shell execution; restrict to an allowlisted command set.")
            if kw.arg == "tools" and isinstance(kw.value, (ast.List, ast.Tuple)):
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Constant) and str(elt.value).lower() in ("shell", "bash", "exec", "terminal"):
                        self._add("TOOL002", "high", "medium", node,
                                  "Agent is given a raw shell tool; prefer narrow, allowlisted tools.")

        # AGENT001: tainted input into an LLM/agent sink without sanitisation
        if name in SINK_NAMES or full.endswith((".generate", ".complete", ".create", ".run", ".invoke")):
            # only treat as a sink when it looks like an LLM/agent call, not every .run()
            text = self._snippet(node).lower()
            is_llm = any(k in text for k in ("llm", "agent", "client", "chat", "model", "prompt", "completion"))
            if is_llm or name in ("generate", "complete", "chat"):
                for arg in node.args + [kw.value for kw in node.keywords]:
                    if isinstance(arg, ast.Name) and arg.id in self.tainted and not _is_allowlisted_call(node):
                        self._add("AGENT001", "high", "high", node,
                                  f"Untrusted input '{arg.id}' flows into an LLM/agent call without sanitisation; "
                                  "treat external text as data, never as instructions.")
                    if isinstance(arg, ast.JoinedStr):
                        for v in arg.values:
                            if isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name) \
                                    and v.value.id in self.tainted and not _is_allowlisted_call(node):
                                self._add("AGENT001", "high", "high", node,
                                          f"Untrusted input '{v.value.id}' interpolated into a prompt without sanitisation.")
        self.generic_visit(node)


def scan_file(path: Path) -> list[Finding]:
    """Scan one Python file. Returns findings (may be empty)."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    lines = text.splitlines()
    findings: list[Finding] = []

    # SECRET001 / SECRET002: literal secrets (text-level, so config files also work)
    for i, line in enumerate(lines, start=1):
        for pattern, label in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append(_finding("SECRET001", "high", "high", path, i,
                                         f"Possible secret literal in code/config: {label}. Move it to an env var / secret store."))
                break
        else:
            if GENERIC_SECRET_RE.search(line) and "os.environ" not in line and "getenv" not in line:
                findings.append(_finding("SECRET002", "medium", "medium", path, i,
                                         "Generic secret-looking assignment with a literal value; prefer an env var."))

    # AST checks for .py files
    if path.suffix == ".py":
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return findings
        visitor = _Visitor(path, lines)
        visitor.visit(tree)
        findings.extend(visitor.findings)

    # JS/TS checks: text-level, deliberately narrow (eval / child_process / Function)
    if path.suffix in (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"):
        js_patterns = [
            (r"\beval\s*\(", "JS001", "high", "high", "eval() executes a string as code; prefer structured parsing / allowlisted dispatch."),
            (r"child_process.*\.\s*(exec|execSync|spawnSync)\s*\(", "JS002", "high", "high", "child_process shell execution; prefer execFile/spawn with an argument array and no shell."),
            (r"\bnew\s+Function\s*\(", "JS003", "high", "medium", "new Function() executes a string as code, like eval(); prefer a real function."),
        ]
        for i, line in enumerate(lines, start=1):
            for pattern, check_id, sev, conf, msg in js_patterns:
                if re.search(pattern, line):
                    findings.append(_finding(check_id, sev, conf, path, i, msg))
                    break
    return findings
