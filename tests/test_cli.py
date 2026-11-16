import json
from pathlib import Path

from m365ai import cli
from m365ai.providers import Provider

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


class FakeProvider(Provider):
    name = "fake"

    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    def complete(self, system, user):
        self.calls.append((system, user))
        return self.reply


def test_extract_powershell_from_code_block():
    reply = "Here you go:\n```powershell\nGet-Mailbox\n```\nDone."
    assert cli.extract_powershell(reply) == "Get-Mailbox\n"


def test_extract_powershell_without_code_block():
    assert cli.extract_powershell("Get-Team") == "Get-Team\n"


def test_check_exit_codes(capsys):
    safe = str(EXAMPLES / "safe-teams-phone-report.ps1")
    risky = str(EXAMPLES / "risky-cleanup.ps1")
    assert cli.main(["check", safe, "--fail-on", "high"]) == 0
    assert cli.main(["check", risky, "--fail-on", "high"]) == 2
    assert cli.main(["check", risky]) == 0  # no gate -> report only


def test_check_json_output(capsys):
    risky = str(EXAMPLES / "risky-cleanup.ps1")
    cli.main(["check", risky, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[risky]["risk"] == "high"
    assert data[risky]["findings"]


def test_check_missing_file(capsys):
    assert cli.main(["check", "does-not-exist.ps1"]) == 1


def test_generate_writes_file_and_reports(tmp_path, monkeypatch, capsys):
    fake = FakeProvider("```powershell\nRemove-MgUser -UserId $UserId\n```")
    monkeypatch.setattr(cli, "get_provider", lambda *a, **k: fake)
    out = tmp_path / "script.ps1"

    assert cli.main(["generate", "delete a user", "-o", str(out)]) == 0
    assert out.read_text() == "Remove-MgUser -UserId $UserId\n"
    printed = capsys.readouterr().out
    assert "HIGH" in printed and "M365-001" in printed
    assert fake.calls[0][1] == "delete a user"


def test_explain_sends_script(tmp_path, monkeypatch, capsys):
    fake = FakeProvider("This script lists mailboxes.")
    monkeypatch.setattr(cli, "get_provider", lambda *a, **k: fake)
    script = tmp_path / "s.ps1"
    script.write_text("Get-Mailbox")

    assert cli.main(["explain", str(script)]) == 0
    assert "Get-Mailbox" in fake.calls[0][1]
    assert "This script lists mailboxes." in capsys.readouterr().out


def test_no_provider_configured(monkeypatch, capsys):
    for var in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AZURE_OPENAI_API_KEY", "M365AI_PROVIDER"]:
        monkeypatch.delenv(var, raising=False)
    assert cli.main(["generate", "anything"]) == 1
    assert "No AI provider configured" in capsys.readouterr().err
