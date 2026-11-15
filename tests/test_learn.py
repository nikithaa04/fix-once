"""End to end test of the loop with a scripted model, real git and real Semgrep."""
import subprocess

import pytest

from fixonce.gitdiff import is_skipped, parse_ranges
from fixonce.learn import learn
from fixonce.report import render

VULNERABLE = """\
const express = require('express')
const app = express()

app.get('/api/orders/:id', async (req, res) => {
  const order = await Order.findByPk(req.params.id)
  res.json(order)
})

app.get('/api/invoices/:id', async (req, res) => {
  const invoice = await Invoice.findByPk(req.params.id)
  res.json(invoice)
})
"""
FIXED = VULNERABLE.replace(
    "await Order.findByPk(req.params.id)",
    "await Order.findOne({ where: { id: req.params.id, userId: req.user.id } })")

REPLY = """<security_fix>yes</security_fix>
<bug_class>IDOR</bug_class>
<root_cause>Records are loaded by an id from the URL with no ownership check.</root_cause>
<rule>
{rule}
</rule>"""
BROKEN = "rules:\n  - id: idor\n    languages: [javascript]\n    severity: ERROR\n    message: x\n    pattern: 'foo((('"
WRONG = "rules:\n  - id: idor\n    languages: [javascript]\n    severity: ERROR\n    message: x\n    pattern: res.json($X)"
GOOD = ("rules:\n  - id: idor-findbypk-from-params\n    languages: [javascript]\n    severity: ERROR\n"
        "    message: Lookup by URL id without an ownership check. Scope the query to req.user.id.\n"
        "    pattern: $MODEL.findByPk(req.params.$ID)")


def run(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    run(tmp_path, "init", "-q")
    run(tmp_path, "config", "user.email", "t@example.com")
    run(tmp_path, "config", "user.name", "t")
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "api.js").write_text(VULNERABLE)
    run(tmp_path, "add", "-A"); run(tmp_path, "commit", "-qm", "init")
    (tmp_path / "routes" / "api.js").write_text(FIXED)
    run(tmp_path, "add", "-A"); run(tmp_path, "commit", "-qm", "fix IDOR in orders")
    return tmp_path


def scripted(*rules):
    replies = [REPLY.format(rule=r) for r in rules]
    calls = []

    def complete(system, messages):
        calls.append(messages)
        return replies[len(calls) - 1]

    complete.calls = calls
    return complete


def test_retries_until_rule_is_proven_then_finds_variant(repo):
    model = scripted(BROKEN, WRONG, GOOD)
    result = learn(str(repo), "HEAD^", "HEAD", model, source="https://example.com/pr/1")
    assert result.ok
    assert [a.passed for a in result.attempts] == [False, False, True]
    assert "left unchanged" in result.attempts[1].feedback
    assert "left unchanged" in model.calls[2][-1]["content"]  # fed back to the model
    assert (repo / result.rule_path).exists()
    assert "https://example.com/pr/1" in result.rule_yaml
    assert [(m.path, m.start) for m in result.variants] == [("routes/api.js", 10)]
    assert "routes/api.js:10" in render(result)


def test_rejects_rule_that_still_fires_on_the_fix(repo):
    either = ("rules:\n  - id: idor\n    languages: [javascript]\n    severity: ERROR\n    message: x\n"
              "    pattern-either:\n      - pattern: $M.findByPk(req.params.id)\n"
              "      - pattern: '$M.findOne({ where: { id: req.params.id, ... } })'")
    result = learn(str(repo), "HEAD^", "HEAD", scripted(either), max_attempts=1)
    assert not result.ok and "still matches the FIXED code" in result.attempts[0].feedback


def test_gives_up_and_saves_nothing(repo):
    result = learn(str(repo), "HEAD^", "HEAD", scripted(WRONG, WRONG), max_attempts=2)
    assert not result.ok
    assert not (repo / ".fixonce").exists()


def test_not_a_security_fix(repo):
    def model(system, messages):
        return "<security_fix>no</security_fix><root_cause>Refactor only.</root_cause>"
    result = learn(str(repo), "HEAD^", "HEAD", model)
    assert not result.ok and "not a security fix" in result.reason


def test_helpers():
    assert parse_ranges("@@ -5 +5 @@\n@@ -9,0 +10,2 @@\n") == ([(5, 5), (9, 10)], [(5, 5), (10, 11)])
    assert is_skipped("tests/test_api.py") and is_skipped("package-lock.json")
    assert not is_skipped("src/latest_orders.js")


SQLI_BEFORE = """\
export function login () {
  return (req, res) => {
    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`, { plain: true })
  }
}
"""
SQLI_AFTER = SQLI_BEFORE.replace(
    "`SELECT * FROM Users WHERE email = '${req.body.email}'`, { plain: true }",
    "'SELECT * FROM Users WHERE email = :email', { replacements: { email: req.body.email }, plain: true }")
SEARCH = """\
export function search () {
  return (req, res) => {
    let criteria = req.query.q ?? ''
    criteria = criteria.substring(0, 200)
    models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${criteria}%'`)
    models.sequelize.query('SELECT sql FROM sqlite_master')
  }
}
"""
TAINT = """rules:
  - id: sqli-request-data-in-raw-query
    mode: taint
    languages: [typescript, javascript]
    severity: ERROR
    message: Request data reaches a raw SQL string. Use replacements.
    pattern-sources:
      - pattern-either:
          - pattern: req.body
          - pattern: req.query
          - pattern: req.params
    pattern-sinks:
      - patterns:
          - pattern: $S.query($SQL, ...)
          - focus-metavariable: $SQL"""


def test_taint_rule_finds_variant_that_flows_through_a_variable(tmp_path):
    run(tmp_path, "init", "-q")
    run(tmp_path, "config", "user.email", "t@example.com")
    run(tmp_path, "config", "user.name", "t")
    (tmp_path / "login.ts").write_text(SQLI_BEFORE)
    (tmp_path / "search.ts").write_text(SEARCH)
    run(tmp_path, "add", "-A"); run(tmp_path, "commit", "-qm", "init")
    (tmp_path / "login.ts").write_text(SQLI_AFTER)
    run(tmp_path, "add", "-A"); run(tmp_path, "commit", "-qm", "fix sqli")
    (tmp_path / "broken.ts").write_text(SQLI_BEFORE.rstrip()[:-1])  # missing closing brace
    result = learn(str(tmp_path), "HEAD^", "HEAD", scripted(TAINT))
    assert result.ok
    assert result.unparsed == ["broken.ts"]
    assert "could not be checked" in render(result)
    assert [(m.path, m.start) for m in result.variants] == [("search.ts", 5)]
