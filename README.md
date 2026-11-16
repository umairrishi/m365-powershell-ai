# m365-powershell-ai

**An AI assistant for Microsoft 365 admins.** Describe a task in plain English and get a production-quality PowerShell script for Teams, Exchange Online, Entra ID or SharePoint. Every script goes through a built-in **safety scanner** before you run it.

![tests](https://img.shields.io/badge/tests-30%20passing-brightgreen) ![python](https://img.shields.io/badge/python-3.9%2B-blue) ![dependencies](https://img.shields.io/badge/dependencies-none-lightgrey) ![license](https://img.shields.io/badge/license-MIT-green)

```text
$ m365ai generate "Find Teams users who are voice-enabled but have no phone number, export to CSV"
```

## Why I built this

AI models are good at writing PowerShell, but a confident-looking script can still delete a user, open federation tenant-wide, or use a module Microsoft retired years ago. In M365 administration, one bad pipeline can touch every mailbox in the tenant.

This tool pairs AI generation with a deterministic, offline safety check, so a human reviews the risky lines before anything runs. It is built from 15+ years of running Microsoft 365, Teams and Exchange environments.

## Features

| Command | What it does | Needs AI? |
|---|---|---|
| `m365ai generate "<task>"` | Writes a script using current modules, least-privilege Graph scopes, `-WhatIf` support, rollback info and error handling | Yes |
| `m365ai explain script.ps1` | Explains any script in plain English: what it changes, who is affected, risks, roles needed | Yes |
| `m365ai check script.ps1` | Safety-scans scripts: destructive cmdlets, tenant-wide changes, bulk pipelines, plain-text secrets, `Invoke-Expression`, deprecated MSOnline/AzureAD | **No, works offline** |

- **Works with Claude, OpenAI or Azure OpenAI.** Azure OpenAI lets organizations keep AI traffic inside their own tenant.
- **No dependencies.** Pure Python standard library.
- **CI-ready.** `m365ai check --fail-on high` exits with code 2, so it can block risky scripts in a pipeline or pre-commit hook.
- **JSON output** for dashboards and automation (`--json`).

## Safety scanner demo

`examples/risky-cleanup.ps1` packs in mistakes that show up in real admin scripts. The scanner catches them without any AI or tenant connection:

```text
$ m365ai check examples/risky-cleanup.ps1 --fail-on high
== examples/risky-cleanup.ps1 ==
Overall risk: HIGH
Modules:      MicrosoftTeams, ExchangeOnlineManagement, Microsoft.Graph

[HIGH  ] SEC-002 line 5: Looks like a hardcoded password or secret.
         > $password = "Summer2026!"
         fix: Move secrets out of the script (Azure Key Vault, SecretManagement module).
[HIGH  ] M365-005 line 15: Bulk change: every object returned is modified with no filter.
         > Get-Mailbox -ResultSize Unlimited | Set-Mailbox -HiddenFromAddressListsEnabled $true -Confirm:$false
         fix: Add -Filter or Where-Object, test on a few objects, and export a before-state.
[HIGH  ] M365-004 line 22: Changes a tenant-wide setting that affects every user.
         > Set-CsTenantFederationConfiguration -AllowFederatedUsers $true -AllowPublicUsers $true
         fix: Record the current value with the matching Get- cmdlet so you can roll back.
[HIGH  ] SEC-004 line 25: Downloads code from the internet and runs it.
         > (New-Object Net.WebClient).DownloadString("https://example.com/helper.ps1") | iex
         fix: Download, review and sign scripts before running them.
[MEDIUM] DEP-001 line 4: Uses the retired MSOnline module.
         > Import-Module MSOnline
         fix: Move to the Microsoft Graph PowerShell SDK (Microsoft.Graph).
[MEDIUM] SEC-005 line 12: Sets mail forwarding, a common data exfiltration path.
...
Findings: 8 high, 4 medium, 3 info
```

The read-only report in `examples/safe-teams-phone-report.ps1` passes with no findings.

## Quick start

```bash
git clone https://github.com/umairrishi/m365-powershell-ai.git
cd m365-powershell-ai
pip install -e .

# Offline safety check, no API key needed
m365ai check examples/risky-cleanup.ps1
```

To generate and explain scripts, set **one** provider:

```bash
# Claude (Anthropic)
export ANTHROPIC_API_KEY="sk-ant-..."

# or OpenAI
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="<model name>"

# or Azure OpenAI
export AZURE_OPENAI_ENDPOINT="https://<resource>.openai.azure.com"
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_DEPLOYMENT="<deployment name>"
```

On Windows PowerShell use `$env:ANTHROPIC_API_KEY = "sk-ant-..."` instead of `export`.

```bash
m365ai generate "Block external chat for users in the Contractors group" -o block-contractors.ps1
m365ai explain block-contractors.ps1
```

Optional settings: `M365AI_PROVIDER` (`anthropic`, `openai`, `azure`) and `M365AI_MODEL`, or the `--provider` and `--model` flags.

## Use it as a CI gate

```yaml
- run: pip install m365-powershell-ai  # or pip install -e .
- run: m365ai check scripts/*.ps1 --fail-on high
```

## Rules

| ID | Severity | Detects |
|---|---|---|
| M365-001 | High | Deleting users, groups, Teams, mailboxes, sites |
| M365-002 | High | Compliance search purge |
| M365-003 | High | `Search-Mailbox -DeleteContent` |
| M365-004 | High | Tenant-wide changes (federation, org config, SharePoint tenant, authorization policy) |
| M365-005 | High | Unfiltered bulk pipelines (`-ResultSize Unlimited \| Set-...`) |
| M365-006 | Medium | Other Remove / Disable / Revoke cmdlets |
| M365-007 | Medium | `-Confirm:$false` |
| SEC-001/002 | High | Plain-text passwords and secrets |
| SEC-003/004 | High | `Invoke-Expression`, download-and-run |
| SEC-005 | Medium | Mailbox forwarding (exfiltration risk) |
| SEC-006 | Medium | FullAccess mailbox permissions |
| SEC-007 | Medium | Lowering the execution policy |
| DEP-001/002 | Medium | Retired MSOnline and AzureAD modules |
| DEP-003 | Low | Retired Exchange remote PowerShell sessions |
| BP-001 | Info | `Connect-MgGraph` without least-privilege `-Scopes` |
| BP-002 | Info | Destructive Exchange cmdlets without `-WhatIf` |

The scanner also lists the modules and Microsoft Graph scopes each script needs.

## Project layout

```text
m365ai/
  cli.py        command-line interface (generate, explain, check)
  safety.py     offline rule-based safety scanner
  providers.py  Claude, OpenAI and Azure OpenAI clients (standard library only)
  prompts.py    system prompts with M365 best practices
examples/       a safe and a risky sample script
tests/          pytest suite (runs without API keys)
```

## Run the tests

```bash
pip install -e ".[dev]"
pytest
```

## Roadmap

- [ ] PSScriptAnalyzer integration for syntax checks
- [ ] Auto-fix suggestions (add `-WhatIf`, swap MSOnline cmdlets for Graph equivalents)
- [ ] VS Code extension
- [ ] Teams Phone / Direct Routing script templates

## Disclaimer

AI-generated scripts can be wrong. Always review scripts and test them in a non-production tenant with `-WhatIf` first. The safety scanner is a helper, not a guarantee.

## Author

**Umair Rishi**, Microsoft Teams Cloud Solution Architect and MS-700 certified Teams Administrator.
[LinkedIn](https://www.linkedin.com/in/umair-rishi-4086b441a)

## License

[MIT](LICENSE)
