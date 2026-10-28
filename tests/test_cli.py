import json

from click.testing import CliRunner

from phishscope.cli import cli


def test_analyze_terminal(samples):
    result = CliRunner().invoke(cli, ["analyze", str(samples / "phish_paypal_credential.eml")])
    assert result.exit_code == 0, result.output
    assert "MALICIOUS" in result.output
    assert "Reputation checks skipped" in result.output


def test_analyze_json(samples):
    result = CliRunner().invoke(cli, ["analyze", str(samples / "legit_github_notice.eml"), "--json"], env={"VT_API_KEY": ""})
    data = json.loads(result.stdout)
    assert data["verdict"] == "Clean"


def test_multiple_files_json(samples):
    files = [str(p) for p in sorted(samples.glob("*.eml"))]
    result = CliRunner().invoke(cli, ["analyze", *files, "--json"], env={"VT_API_KEY": ""})
    assert len(json.loads(result.stdout)) == 3


def test_html_output(samples, tmp_path):
    out = tmp_path / "report.html"
    result = CliRunner().invoke(cli, ["analyze", str(samples / "malware_invoice_attachment.eml"), "--html", str(out)], env={"VT_API_KEY": ""})
    assert result.exit_code == 0, result.output
    assert "Invoice_10293.pdf.exe" in out.read_text()


def test_exit_code(samples):
    runner = CliRunner(env={"VT_API_KEY": ""})
    assert runner.invoke(cli, ["analyze", str(samples / "legit_github_notice.eml"), "--exit-code"]).exit_code == 0
    assert runner.invoke(cli, ["analyze", str(samples / "phish_paypal_credential.eml"), "--exit-code"]).exit_code == 3


def test_iocs(samples):
    result = CliRunner().invoke(cli, ["iocs", str(samples / "phish_paypal_credential.eml")])
    assert "bit[.]ly" in result.output
