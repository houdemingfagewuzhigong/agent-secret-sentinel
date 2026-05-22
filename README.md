# Agent Secret Sentinel

Find leaked tokens and risky MCP config before an AI coding agent reads your repo.

Agent Secret Sentinel is a zero-dependency Python CLI for teams adopting coding agents, MCP servers, and local automation. It scans source files, `.env`-style config, and MCP JSON/TOML/YAML for high-risk patterns such as GitHub tokens, OpenAI keys, generic secret assignments, shell evaluators, and remote scripts piped into a shell.

## Why this exists

AI coding agents make repositories more powerful, but they also expand the blast radius of one forgotten token or one permissive MCP server. This tool gives you a fast preflight check before you open a repo to an agent, publish a demo, or invite contributors.

## Quick Start

```bash
python3 sentinel.py scan .
```

Fail a CI job when high or critical issues are found:

```bash
python3 sentinel.py scan . --fail-on high
```

Print JSON for automation:

```bash
python3 sentinel.py scan . --json
```

## Example Output

```text
[CRITICAL] GitHub fine-grained token
  .env:1
  GITHUB_TOKEN=github_pat_...redacted
  fix: Revoke the token, rotate it, and move the replacement to a local secret store.
```

## What It Checks

- GitHub fine-grained and classic tokens
- OpenAI-style API keys
- Generic secret assignments such as `API_KEY=...`
- MCP config that invokes `bash -c`, `sh -c`, or similar shell evaluators <!-- sentinel: allow -->
- Remote install commands such as `curl ... | bash` <!-- sentinel: allow -->
- Broad home-directory access in agent config

## Suggested Agent Workflow

Run this before letting an agent operate on a repo:

```bash
python3 sentinel.py scan /path/to/project --fail-on medium
```

Then fix or explicitly quarantine the findings. For real credentials, rotate them. Removing them from the current working tree is not enough if they were committed.

## Roadmap

- GitHub Action wrapper
- Baseline file for accepted risks
- MCP config parser with tool-level allowlists
- SARIF output for code scanning

## License

MIT
