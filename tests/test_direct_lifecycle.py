import hashlib
import json

PROGRAM = "BB-DEMO"
DOMAIN = "example.com"
SOURCE = "raw.githubusercontent.com"
POLICY_COMMIT = "247669210e425bd68858752665948170105a0354"
PATH = "/Azaria723/BugBountyScopeOracle/" + POLICY_COMMIT + "/evidence/demo-policy.txt"
POLICY = b"""PROGRAM_ID: BB-DEMO
REPRESENTED_DOMAIN: example.com

IN SCOPE
- api.example.com
- *.sandbox.example.com

OUT OF SCOPE
- status.example.com
- Any hostname not explicitly listed above.

Rules: exclusions override inclusions. The wildcard covers proper subdomains only.
"""
SILENT_POLICY = b"""PROGRAM_ID: BB-DEMO
REPRESENTED_DOMAIN: example.com

IN SCOPE
- api.example.com

This snapshot does not state a default rule for unlisted assets.
"""

def sha(body):
    return hashlib.sha256(body).hexdigest()

def deploy(direct_vm, direct_deploy, controller):
    direct_vm.strict_mocks = True
    direct_vm.check_pickling = True
    with direct_vm.prank(controller):
        return direct_deploy("contracts/BugBountyScopeOracle.py")

def register(direct_vm, contract, controller, digest=None):
    with direct_vm.prank(controller):
        assert contract.register_program(PROGRAM, DOMAIN, SOURCE, PATH, digest or sha(POLICY)) == 0

def request(direct_vm, contract, requester, asset):
    with direct_vm.prank(requester):
        assert contract.request_scope_check(0, asset) == 0

def mock_policy(direct_vm, body=POLICY, status=200):
    direct_vm.mock_web(r"https://raw\.githubusercontent\.com/Azaria723/BugBountyScopeOracle/247669210e425bd68858752665948170105a0354/evidence/demo-policy\.txt$", {"status": status, "body": body})

def record(contract):
    return json.loads(contract.get_check(0))

def test_explicit_asset_is_in_scope(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    register(direct_vm, contract, direct_alice)
    request(direct_vm, contract, direct_bob, "api.example.com")
    mock_policy(direct_vm)
    direct_vm.mock_llm(r"Determine whether.*", json.dumps({"verdict": "IN_SCOPE"}))
    assert contract.assess_scope(0) == "IN_SCOPE"
    result = record(contract)
    assert result["verdict"] == "IN_SCOPE"
    assert json.loads(result["diagnostics"])["policy_digest"] == "MATCH"

def test_explicit_exclusion_is_out_of_scope(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    register(direct_vm, contract, direct_alice)
    request(direct_vm, contract, direct_bob, "status.example.com")
    mock_policy(direct_vm)
    direct_vm.mock_llm(r"Determine whether.*", json.dumps({"verdict": "OUT_OF_SCOPE"}))
    assert contract.assess_scope(0) == "OUT_OF_SCOPE"

def test_proper_wildcard_subdomain_is_in_scope(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    register(direct_vm, contract, direct_alice)
    request(direct_vm, contract, direct_bob, "dev.sandbox.example.com")
    mock_policy(direct_vm)
    direct_vm.mock_llm(r"Determine whether.*", json.dumps({"verdict": "IN_SCOPE"}))
    assert contract.assess_scope(0) == "IN_SCOPE"

def test_lookalike_suffix_is_not_treated_as_scope(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    register(direct_vm, contract, direct_alice)
    request(direct_vm, contract, direct_bob, "example.com.attacker.org")
    mock_policy(direct_vm)
    direct_vm.mock_llm(r"Determine whether.*", json.dumps({"verdict": "OUT_OF_SCOPE"}))
    assert contract.assess_scope(0) == "OUT_OF_SCOPE"

def test_digest_mismatch_fails_closed_even_if_model_would_approve(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    register(direct_vm, contract, direct_alice)
    request(direct_vm, contract, direct_bob, "api.example.com")
    mock_policy(direct_vm, POLICY + b"tampered")
    assert contract.assess_scope(0) == "UNAVAILABLE"
    result = record(contract)
    assert result["reason_code"] == "FETCHED_POLICY_DIGEST_MISMATCH"
    assert json.loads(result["diagnostics"])["policy_digest"] == "MISMATCH"

def test_identity_mismatch_fails_closed(direct_vm, direct_deploy, direct_alice, direct_bob):
    wrong = POLICY.replace(b"REPRESENTED_DOMAIN: example.com", b"REPRESENTED_DOMAIN: attacker.org")
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    register(direct_vm, contract, direct_alice, sha(wrong))
    request(direct_vm, contract, direct_bob, "api.example.com")
    mock_policy(direct_vm, wrong)
    assert contract.assess_scope(0) == "UNAVAILABLE"
    assert record(contract)["reason_code"] == "PROGRAM_IDENTITY_MISMATCH"

def test_source_outage_is_unavailable(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    register(direct_vm, contract, direct_alice)
    request(direct_vm, contract, direct_bob, "api.example.com")
    mock_policy(direct_vm, status=503)
    assert contract.assess_scope(0) == "UNAVAILABLE"
    assert record(contract)["reason_code"] == "SOURCE_UNAVAILABLE"

def test_unknown_model_output_becomes_ambiguous(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    register(direct_vm, contract, direct_alice)
    request(direct_vm, contract, direct_bob, "api.example.com")
    mock_policy(direct_vm)
    direct_vm.mock_llm(r"Determine whether.*", json.dumps({"verdict": "AUTO_ACCEPT"}))
    assert contract.assess_scope(0) == "AMBIGUOUS"
    assert record(contract)["reason_code"] == "POLICY_CLASSIFICATION_AMBIGUOUS"

def test_policy_silence_is_recorded_as_ambiguous(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    register(direct_vm, contract, direct_alice, sha(SILENT_POLICY))
    request(direct_vm, contract, direct_bob, "unknown.example.com")
    mock_policy(direct_vm, SILENT_POLICY)
    direct_vm.mock_llm(r"Determine whether.*", json.dumps({"verdict": "AMBIGUOUS"}))
    assert contract.assess_scope(0) == "AMBIGUOUS"

def test_invalid_inputs_and_controller_guard_preserve_state(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    with direct_vm.prank(direct_alice):
        assert contract.register_program(PROGRAM, DOMAIN, "localhost", PATH, sha(POLICY)) == "INVALID_SOURCE_HOST"
        assert contract.register_program(PROGRAM, DOMAIN, SOURCE, "/../secret", sha(POLICY)) == "INVALID_POLICY_PATH"
    assert json.loads(contract.get_counts())["program_count"] == 0
    register(direct_vm, contract, direct_alice)
    with direct_vm.prank(direct_bob):
        assert contract.request_scope_check(0, "https://api.example.com") == "INVALID_ASSET_HOST"
        assert contract.deactivate_program(0) == "CONTROLLER_ONLY"
    assert json.loads(contract.get_program(0))["active"] == 1

def test_only_owner_can_register_and_duplicates_are_rejected(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    with direct_vm.prank(direct_bob):
        assert contract.register_program(PROGRAM, DOMAIN, SOURCE, PATH, sha(POLICY)) == "OWNER_ONLY"
    register(direct_vm, contract, direct_alice)
    with direct_vm.prank(direct_alice):
        assert contract.register_program(PROGRAM, "other.example", SOURCE, PATH, sha(POLICY)) == "PROGRAM_KEY_ALREADY_REGISTERED"
        assert contract.register_program("OTHER", DOMAIN, SOURCE, PATH, sha(POLICY)) == "REPRESENTED_DOMAIN_ALREADY_REGISTERED"
    assert json.loads(contract.get_counts())["program_count"] == 1

def test_deactivation_blocks_pending_assessment(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = deploy(direct_vm, direct_deploy, direct_alice)
    register(direct_vm, contract, direct_alice)
    request(direct_vm, contract, direct_bob, "api.example.com")
    with direct_vm.prank(direct_alice):
        assert contract.deactivate_program(0) == "PROGRAM_DEACTIVATED"
    assert contract.assess_scope(0) == "PROGRAM_INACTIVE"
    assert record(contract)["status"] == 0
