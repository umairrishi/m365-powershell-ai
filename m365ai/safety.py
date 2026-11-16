"""Static safety scanner for Microsoft 365 PowerShell scripts.

Works fully offline: no AI and no M365 connection needed. It reads a script
and reports:

* risky operations (deletes, tenant-wide changes, bulk pipelines, purges)
* security problems (plain-text secrets, Invoke-Expression, remote downloads)
* deprecated modules (MSOnline, AzureAD)
* which modules and Graph scopes the script needs

The rules are pattern-based on purpose. They are fast, predictable and easy
to review, and they work as a gate in CI or a pre-commit hook.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Iterable

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    pattern: re.Pattern
    message: str
    advice: str


@dataclass
class Finding:
    rule_id: str
    severity: str
    line: int
    code: str
    message: str
    advice: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    graph_scopes: list[str] = field(default_factory=list)

    @property
    def risk(self) -> str:
        if not self.findings:
            return "low"
        top = max(SEVERITY_ORDER[f.severity] for f in self.findings)
        level = [k for k, v in SEVERITY_ORDER.items() if v == top][0]
        return "low" if level == "info" else level

    def count(self, severity: str) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    def at_or_above(self, severity: str) -> bool:
        threshold = SEVERITY_ORDER[severity]
        return any(SEVERITY_ORDER[f.severity] >= threshold for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "risk": self.risk,
            "modules": self.modules,
            "graph_scopes": self.graph_scopes,
            "findings": [asdict(f) for f in self.findings],
        }


def _r(rule_id, severity, pattern, message, advice) -> Rule:
    return Rule(rule_id, severity, re.compile(pattern, re.IGNORECASE), message, advice)


RULES: list[Rule] = [
    # --- Destructive operations -------------------------------------------
    _r("M365-001", "high",
       r"\bRemove-(Mailbox|MgUser|MgGroup|Team|UnifiedGroup|DistributionGroup|MsolUser|AzureADUser|MgTeam|SPOSite|PnPTenantSite)\b",
       "Deletes users, groups, teams, mailboxes or sites.",
       "Run with -WhatIf first and confirm you have a backup or that soft-delete applies."),
    _r("M365-002", "high",
       r"\bNew-ComplianceSearchAction\b[^\n]*-Purge\b",
       "Purges mail found by a compliance search across mailboxes.",
       "Check the search results first and prefer -PurgeType SoftDelete."),
    _r("M365-003", "high",
       r"\bSearch-Mailbox\b[^\n]*-DeleteContent\b",
       "Permanently deletes mailbox content.",
       "Search-Mailbox is retired. Use a compliance search, and review the hits before purging."),
    _r("M365-004", "high",
       r"\b(Set-CsTenantFederationConfiguration|Set-OrganizationConfig|Set-CsTeamsClientConfiguration|Set-SPOTenant|Update-MgPolicyAuthorizationPolicy|Set-CsExternalAccessPolicy\s+-Identity\s+Global)\b",
       "Changes a tenant-wide setting that affects every user.",
       "Record the current value with the matching Get- cmdlet so you can roll back."),
    _r("M365-005", "high",
       r"Get-\w+[^\n|]*-ResultSize\s+Unlimited[^\n]*\|\s*(ForEach-Object\s*\{[^}]*)?(Set|Remove|Disable|Revoke)-\w+",
       "Bulk change: every object returned is modified with no filter.",
       "Add -Filter or Where-Object, test on a few objects, and export a before-state."),
    _r("M365-006", "medium",
       r"\b(Remove|Disable|Revoke)-\w+",
       "Removes, disables or revokes something.",
       "Make sure the target is right and try -WhatIf where the cmdlet supports it."),
    _r("M365-007", "medium",
       r"-Confirm:\s*\$false",
       "Turns off the confirmation prompt.",
       "Keep confirmations on while testing; only suppress them in reviewed automation."),

    # --- Security problems --------------------------------------------------
    _r("SEC-001", "high",
       r"ConvertTo-SecureString\b[^\n]*-AsPlainText",
       "A secret is written in plain text in the script.",
       "Use certificate auth, a managed identity, or Get-Credential / a secret vault."),
    _r("SEC-002", "high",
       r"(password|passwd|clientsecret|client_secret|apikey|api_key)\s*=\s*['\"][^'\"]{4,}['\"]",
       "Looks like a hardcoded password or secret.",
       "Move secrets out of the script (Azure Key Vault, SecretManagement module)."),
    _r("SEC-003", "high",
       r"\b(Invoke-Expression|iex)\b",
       "Runs a string as code (Invoke-Expression).",
       "Call cmdlets directly; Invoke-Expression is a common injection path."),
    _r("SEC-004", "high",
       r"(DownloadString|DownloadFile|Invoke-WebRequest|iwr|Invoke-RestMethod)\b[^\n]*(\||;)\s*(iex|Invoke-Expression)",
       "Downloads code from the internet and runs it.",
       "Download, review and sign scripts before running them."),
    _r("SEC-005", "medium",
       r"\bSet-Mailbox\b[^\n]*-(ForwardingSmtpAddress|ForwardingAddress)\b",
       "Sets mail forwarding, a common data exfiltration path.",
       "Confirm the destination is approved and check your outbound forwarding policy."),
    _r("SEC-006", "medium",
       r"\bAdd-MailboxPermission\b[^\n]*FullAccess",
       "Grants full access to another person's mailbox.",
       "Grant the least access needed and log the change."),
    _r("SEC-007", "medium",
       r"Set-ExecutionPolicy\s+(Unrestricted|Bypass)",
       "Lowers the PowerShell execution policy.",
       "Prefer RemoteSigned, or -Scope Process for a one-off run."),

    # --- Deprecated modules ---------------------------------------------------
    _r("DEP-001", "medium",
       r"\b(Connect-MsolService|Import-Module\s+MSOnline|Get-Msol\w+|Set-Msol\w+|New-Msol\w+)\b",
       "Uses the retired MSOnline module.",
       "Move to the Microsoft Graph PowerShell SDK (Microsoft.Graph)."),
    _r("DEP-002", "medium",
       r"\b(Connect-AzureAD|Import-Module\s+AzureAD|Get-AzureAD\w+|Set-AzureAD\w+|New-AzureAD\w+)\b",
       "Uses the retired AzureAD module.",
       "Move to the Microsoft Graph PowerShell SDK (Microsoft.Graph)."),
    _r("DEP-003", "low",
       r"\bNew-PSSession\b[^\n]*ConfigurationName\s+Microsoft\.Exchange",
       "Uses Exchange Online remote PowerShell (basic auth), which is retired.",
       "Use Connect-ExchangeOnline from the ExchangeOnlineManagement module."),

    # --- Good-practice hints --------------------------------------------------
    _r("BP-001", "info",
       r"Connect-MgGraph(?![^\n]*-Scopes)(?![^\n]*-CertificateThumbprint)(?![^\n]*-Identity)(?![^\n]*-ClientSecretCredential)",
       "Connect-MgGraph has no -Scopes, so it uses whatever consent already exists.",
       "Ask for the least-privilege scopes the script needs."),
]

# Destructive cmdlets that support -WhatIf; missing it is worth a hint.
_WHATIF_CANDIDATES = re.compile(
    r"\b(Remove-(Mailbox|DistributionGroup|UnifiedGroup|MailboxPermission)|Set-Mailbox|Disable-Mailbox)\b",
    re.IGNORECASE,
)

_MODULE_HINTS = [
    (re.compile(r"\bConnect-MicrosoftTeams\b|\b\w+-Cs\w+|\b\w+-Team(User|Channel)?\b", re.I), "MicrosoftTeams"),
    (re.compile(r"\bConnect-ExchangeOnline\b|\b\w+-(Mailbox\w*|DistributionGroup\w*|UnifiedGroup\w*|OrganizationConfig|TransportRule)\b", re.I), "ExchangeOnlineManagement"),
    (re.compile(r"\bConnect-IPPSSession\b|\b\w+-Compliance\w+|\b\w+-(DlpCompliance|Label|RetentionCompliance)\w*\b", re.I), "ExchangeOnlineManagement (Purview / IPPS)"),
    (re.compile(r"\bConnect-MgGraph\b|\b\w+-Mg\w+", re.I), "Microsoft.Graph"),
    (re.compile(r"\bConnect-SPOService\b|\b\w+-SPO\w+", re.I), "Microsoft.Online.SharePoint.PowerShell"),
    (re.compile(r"\bConnect-PnPOnline\b|\b\w+-PnP\w+", re.I), "PnP.PowerShell"),
]

_SCOPES = re.compile(r"Connect-MgGraph[^\n]*-Scopes\s+((?:['\"]?[\w.]+['\"]?\s*,?\s*)+)", re.I)


def strip_comments(script: str) -> list[tuple[int, str]]:
    """Return (line_number, code) pairs with comments removed.

    Handles block comments (<# ... #>) and line comments (# ...). A # inside
    a quoted string is kept, which avoids most false negatives.
    """
    no_blocks = re.sub(r"<#.*?#>", lambda m: "\n" * m.group(0).count("\n"), script, flags=re.S)
    out = []
    for i, raw in enumerate(no_blocks.splitlines(), start=1):
        out.append((i, _strip_line_comment(raw)))
    return out


def _strip_line_comment(line: str) -> str:
    quote = None
    for idx, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#":
            return line[:idx].rstrip()
    return line.rstrip()


def _join_continuations(lines: Iterable[tuple[int, str]]) -> list[tuple[int, str]]:
    """Join lines ending in a backtick or pipe so multi-line commands scan as one."""
    joined: list[tuple[int, str]] = []
    buf, start = "", None
    for num, code in lines:
        if start is None:
            start = num
        stripped = code.rstrip()
        if stripped.endswith("`"):
            buf += stripped[:-1] + " "
            continue
        if stripped.endswith("|"):
            buf += stripped + " "
            continue
        buf += code
        joined.append((start, buf))
        buf, start = "", None
    if buf:
        joined.append((start or 0, buf))
    return joined


def scan(script: str) -> Report:
    """Scan a PowerShell script and return a Report."""
    report = Report()
    lines = _join_continuations(strip_comments(script))
    code_only = "\n".join(code for _, code in lines)

    high_lines: set[int] = set()
    for rule in sorted(RULES, key=lambda r: -SEVERITY_ORDER[r.severity]):
        for num, code in lines:
            if not code.strip() or not rule.pattern.search(code):
                continue
            # Don't double-report the generic "remove/disable" rule on a line
            # that already has a more specific high-severity finding.
            if rule.id == "M365-006" and num in high_lines:
                continue
            report.findings.append(Finding(rule.id, rule.severity, num, code.strip(), rule.message, rule.advice))
            if rule.severity == "high":
                high_lines.add(num)

    for num, code in lines:
        if _WHATIF_CANDIDATES.search(code) and not re.search(r"-WhatIf\b", code, re.I):
            report.findings.append(Finding(
                "BP-002", "info", num, code.strip(),
                "Destructive cmdlet without -WhatIf.",
                "Add -WhatIf for a dry run, then remove it once the output looks right.",
            ))

    report.findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.line))

    for pattern, module in _MODULE_HINTS:
        if pattern.search(code_only) and module not in report.modules:
            report.modules.append(module)

    for match in _SCOPES.finditer(code_only):
        for scope in re.findall(r"[\w]+\.[\w.]+", match.group(1)):
            if scope not in report.graph_scopes:
                report.graph_scopes.append(scope)

    return report
