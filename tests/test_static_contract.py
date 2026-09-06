from pathlib import Path

SOURCE = Path("contracts/BugBountyScopeOracle.py").read_text(encoding="utf-8")

def test_runner_header_is_pinned():
    lines = SOURCE.splitlines()
    assert lines[0] == "# v0.2.16"
    assert lines[1] == '# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }'

def test_requester_cannot_supply_evidence_url():
    signature = SOURCE.split("def request_scope_check", 1)[1].split(") ->", 1)[0]
    assert "url" not in signature.lower()
    assert "source" not in signature.lower()

def test_contract_derives_https_source_and_checks_digest():
    assert 'return "https://" + source_host + policy_path' in SOURCE
    assert "gl.nondet.web.get(policy_url)" in SOURCE
    assert "hashlib.sha256(response.body)" in SOURCE
    assert "FETCHED_POLICY_DIGEST_MISMATCH" in SOURCE

def test_identity_binding_and_fail_closed_verdicts_exist():
    assert '"PROGRAM_ID: " + program_key in policy_text' in SOURCE
    assert '"REPRESENTED_DOMAIN: " + represented_domain in policy_text' in SOURCE
    assert 'verdict = "UNAVAILABLE"' in SOURCE
    assert 'verdict = "AMBIGUOUS"' in SOURCE
    assert 'gl.message.sender_address != self.owner' in SOURCE
    assert '"PROGRAM_KEY_ALREADY_REGISTERED"' in SOURCE

def test_no_custody_or_frontend_logic():
    assert "emit_transfer" not in SOURCE
    assert "payable" not in SOURCE
    assert "frontend" not in SOURCE.lower()
