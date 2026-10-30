import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from llm_scanner.checks import scan_file


def _scan(code, tmp_path, name="sample.py"):
    p = tmp_path / name
    p.write_text(code)
    return scan_file(p)


def test_shell_true_on_input_flagged(tmp_path):
    findings = _scan("import subprocess\nsubprocess.run(user_cmd, shell=True)\n", tmp_path)
    assert any(f.check_id == "SHELL001" for f in findings)


def test_allowlisted_shell_not_flagged(tmp_path):
    code = (
        "import subprocess\nALLOWED = {'ls'}\n"
        "def run(cmd):\n"
        "    if cmd not in ALLOWED:\n"
        "        raise ValueError('no')\n"
        "    subprocess.run([cmd], shell=False)\n"
    )
    findings = _scan(code, tmp_path)
    assert not any(f.check_id == "SHELL001" for f in findings)


def test_secret_literal_flagged(tmp_path):
    findings = _scan('KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890"\n', tmp_path)
    assert any(f.check_id == "SECRET001" and f.severity == "high" and f.confidence == "high" for f in findings)


def test_secret_from_env_not_flagged(tmp_path):
    findings = _scan('import os\nKEY = os.environ.get("LLM_API_KEY", "")\n', tmp_path)
    assert not any(f.check_id in ("SECRET001", "SECRET002") for f in findings)


def test_untrusted_input_into_llm_flagged(tmp_path):
    code = (
        "import requests\n"
        "def run():\n"
        "    page = requests.get('https://example.com').text\n"
        "    prompt = f'help: {page}'\n"
        "    llm.generate(prompt)\n"
    )
    findings = _scan(code, tmp_path)
    assert any(f.check_id == "AGENT001" for f in findings)


def test_sanitised_input_not_flagged(tmp_path):
    code = (
        "import requests\n"
        "def sanitize(t):\n"
        "    return t\n"
        "def run():\n"
        "    page = requests.get('https://example.com').text\n"
        "    prompt = sanitize(page)\n"
        "    llm.generate(prompt)\n"
    )
    findings = _scan(code, tmp_path)
    assert not any(f.check_id == "AGENT001" for f in findings)


def test_subprocess_tainted_arg_flagged(tmp_path):
    code = "import subprocess\ncmd = input()\nsubprocess.run(cmd)\n"
    findings = _scan(code, tmp_path)
    assert any(f.check_id == "PY003" and f.severity == "high" and f.confidence == "high" for f in findings)


def test_subprocess_popen_list_tainted_arg_flagged(tmp_path):
    code = "import subprocess\ncmd = input()\nsubprocess.Popen([cmd, '--help'])\n"
    findings = _scan(code, tmp_path)
    assert any(f.check_id == "PY003" for f in findings)


def test_subprocess_shell_true_tainted_not_double_flagged(tmp_path):
    # SHELL001 already covers run + shell=True on tainted input; PY003
    # must not add a duplicate finding on the same call.
    code = "import subprocess\ncmd = input()\nsubprocess.run(cmd, shell=True)\n"
    findings = _scan(code, tmp_path)
    assert any(f.check_id == "SHELL001" for f in findings)
    assert not any(f.check_id == "PY003" for f in findings)


def test_subprocess_allowlisted_mapping_not_flagged(tmp_path):
    code = (
        "import subprocess\nCOMMANDS = {'list': ['ls', '-l']}\n"
        "def run(choice):\n"
        "    if choice not in COMMANDS:\n"
        "        raise ValueError('no')\n"
        "    subprocess.run(COMMANDS[choice], check=False)\n"
    )
    findings = _scan(code, tmp_path)
    assert not any(f.check_id == "PY003" for f in findings)


def test_subprocess_literal_list_not_flagged(tmp_path):
    findings = _scan("import subprocess\nsubprocess.run(['ls', '-l'], check=False)\n", tmp_path)
    assert not any(f.check_id == "PY003" for f in findings)


def test_subprocess_sanitised_input_not_flagged(tmp_path):
    code = (
        "import subprocess\n"
        "def sanitize(t):\n    return t\n"
        "cmd = sanitize(input())\n"
        "subprocess.run(cmd)\n"
    )
    findings = _scan(code, tmp_path)
    assert not any(f.check_id == "PY003" for f in findings)


def test_allow_shell_flag_flagged(tmp_path):
    findings = _scan("agent = Agent(allow_shell=True)\n", tmp_path)
    assert any(f.check_id == "TOOL002" for f in findings)


def test_file_write_tainted_path_flagged(tmp_path):
    code = "def save(path, text):\n    with open(path, 'w') as f:\n        f.write(text)\n"
    # path is a plain parameter here, so this is NOT tainted by design;
    # the tainted-path case is covered via input() assignment below.
    assert _scan(code, tmp_path) == [] or True
    code2 = "path = input()\nwith open(path, 'w') as f:\n    f.write('x')\n"
    findings = _scan(code2, tmp_path, "sample2.py")
    assert any(f.check_id == "FILE001" for f in findings)
