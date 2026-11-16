from pathlib import Path

import pytest

from m365ai.safety import scan, strip_comments

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def rule_ids(script: str) -> set[str]:
    return {f.rule_id for f in scan(script).findings}


def test_safe_example_has_no_findings():
    report = scan((EXAMPLES / "safe-teams-phone-report.ps1").read_text())
    assert report.findings == []
    assert report.risk == "low"
    assert report.modules == ["MicrosoftTeams"]


def test_risky_example_is_high_risk():
    report = scan((EXAMPLES / "risky-cleanup.ps1").read_text())
    assert report.risk == "high"
    ids = {f.rule_id for f in report.findings}
    for expected in ["SEC-001", "SEC-002", "SEC-003", "SEC-004", "M365-001",
                     "M365-004", "M365-005", "DEP-001", "SEC-005"]:
        assert expected in ids, f"{expected} not detected"


@pytest.mark.parametrize("line, rule", [
    ("Remove-Mailbox -Identity jdoe", "M365-001"),
    ("Remove-MgGroup -GroupId $id", "M365-001"),
    ("New-ComplianceSearchAction -SearchName 'x' -Purge -PurgeType HardDelete", "M365-002"),
    ("Set-OrganizationConfig -OAuth2ClientProfileEnabled $false", "M365-004"),
    ("Revoke-MgUserSignInSession -UserId $u", "M365-006"),
    ("Disable-Mailbox jdoe -Confirm:$false", "M365-007"),
    ("Invoke-Expression $cmd", "SEC-003"),
    ("Add-MailboxPermission -Identity ceo -User bob -AccessRights FullAccess", "SEC-006"),
    ("Set-ExecutionPolicy Unrestricted", "SEC-007"),
    ("Connect-AzureAD", "DEP-002"),
    ("Get-MsolUser -All", "DEP-001"),
    ("Connect-MgGraph", "BP-001"),
])
def test_individual_rules(line, rule):
    assert rule in rule_ids(line)


def test_comments_are_ignored():
    script = "# Remove-Mailbox -Identity jdoe\n<#\nRemove-MgUser -UserId x\n#>\nGet-Mailbox\n"
    assert scan(script).findings == []


def test_hash_inside_string_is_not_a_comment():
    code = dict(strip_comments('Write-Host "Ticket #42"; Remove-Team -GroupId $g'))
    assert "Remove-Team" in code[1]


def test_backtick_continuation_is_joined():
    script = "Get-Mailbox -ResultSize Unlimited `\n  | Set-Mailbox -HiddenFromAddressListsEnabled $true\n"
    assert "M365-005" in rule_ids(script)


def test_filtered_bulk_change_is_not_flagged_as_bulk():
    script = "Get-Mailbox -Filter \"Department -eq 'Sales'\" | Set-Mailbox -CustomAttribute1 Sales"
    assert "M365-005" not in rule_ids(script)


def test_generic_remove_not_duplicated_when_specific_rule_hits():
    ids = [f.rule_id for f in scan("Remove-MgUser -UserId x").findings]
    assert "M365-001" in ids and "M365-006" not in ids


def test_graph_connect_with_scopes_passes_and_scopes_are_listed():
    report = scan('Connect-MgGraph -Scopes "User.Read.All","Group.Read.All"')
    assert "BP-001" not in {f.rule_id for f in report.findings}
    assert report.graph_scopes == ["User.Read.All", "Group.Read.All"]


def test_whatif_hint_cleared_when_whatif_present():
    assert "BP-002" in rule_ids("Remove-Mailbox jdoe")
    assert "BP-002" not in rule_ids("Remove-Mailbox jdoe -WhatIf")


def test_at_or_above():
    report = scan("Disable-Mailbox jdoe -WhatIf")
    assert report.risk == "medium"
    assert report.at_or_above("medium")
    assert not report.at_or_above("high")
