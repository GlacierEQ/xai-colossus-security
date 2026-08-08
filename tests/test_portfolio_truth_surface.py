from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

REQUIRED_PATHS = (
    "security/hydra_immune.py",
    "tests/test_hydra.py",
    "tests/test_portfolio_truth_surface.py",
    "scripts/ci/verify_portfolio_core.sh",
)

FORBIDDEN_STALE_CLAIMS = (
    "src/security_engine.py",
    "enforcing zero-trust access control",
    "Dynamic network isolation",
    "mTLS certificate authority management",
    "Security audit trail logging recording all administrative actions immutably",
    "cluster_security_status()",
    "Core security node on APEX Highway mesh",
    "autonomous mitigation",
)


def test_readme_points_to_present_core_paths() -> None:
    text = README.read_text(encoding="utf-8")

    for relative_path in REQUIRED_PATHS:
        assert (ROOT / relative_path).exists(), relative_path
        assert relative_path in text


def test_readme_preserves_non_affiliation_and_execution_boundary() -> None:
    text = README.read_text(encoding="utf-8")

    assert "not affiliated with xAI" in text
    assert "not evidence of deployment" in text
    assert '"executed": false' in text
    assert '"requires_external_authority": true' in text
    assert "does not reduce the active threat level" in text
    assert "Only explicit acknowledged resolution does" in text


def test_private_experiments_are_preserved_but_excluded() -> None:
    text = README.read_text(encoding="utf-8")

    assert "a38d6b705b7e11ac6ecee927fce9ba884cb3723e" in text
    assert "6e3b97637dec2c15a32eb87248f272ee4cd8e6bd" in text
    assert "not** counted as verified components" in text
    assert "No repository is deleted or collapsed" in text


def test_stale_platform_claims_do_not_return() -> None:
    text = README.read_text(encoding="utf-8")

    for stale_claim in FORBIDDEN_STALE_CLAIMS:
        assert stale_claim not in text


def test_verified_core_never_labels_response_proposals_as_execution() -> None:
    source = (ROOT / "security" / "hydra_immune.py").read_text(encoding="utf-8")

    assert '"action": "PROPOSE_RESPONSE"' in source
    assert '"executed": False' in source
    assert '"requires_external_authority": True' in source
    assert '"external_actions_executed": 0' in source
    assert "AUTO_MITIGATE" not in source
