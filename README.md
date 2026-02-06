<div align="center">

# 🐜 Anty

**Developer-first security scanner**

Like a team of security reviewers reading your code.

[![CI](https://github.com/voulspiros/Anty/actions/workflows/ci.yml/badge.svg)](https://github.com/voulspiros/Anty/actions/workflows/ci.yml)
[![Release](https://github.com/voulspiros/Anty/actions/workflows/release.yml/badge.svg)](https://github.com/voulspiros/Anty/releases)

</div>

---

Anty scans your source code for security issues. It works **locally**, never uploads your code, and gives **fast feedback**.

## Install

**macOS / Linux:**
```bash
curl -fsSL https://voulspiros.github.io/Anty/install.sh | sh
```

**Windows (PowerShell):**
```powershell
irm https://voulspiros.github.io/Anty/install.ps1 | iex
```

Restart terminal after install on Windows.
Then run:
```bash
anty
```

<details>
<summary>Alternative install methods</summary>

**Direct URLs** (if GitHub Pages is not available):
```bash
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/voulspiros/Anty/main/install.sh | sh

# Windows PowerShell
irm https://raw.githubusercontent.com/voulspiros/Anty/main/install.ps1 | iex
```

**From source:**
```bash
cargo install --path .
```

**Manual download:**
Download the binary for your platform from [Releases](https://github.com/voulspiros/Anty/releases).

</details>

## Usage

```bash
# Scan current directory
anty scan .

# Scan a specific path
anty scan ./src

# JSON output
anty scan . --format json

# Write report to file
anty scan . --out report.json

# Run only specific agents
anty scan . --agents secrets

# Fail in CI if HIGH+ issues found
anty scan . --fail-on HIGH

# Quiet mode (errors only)
anty scan . -q

# See available agents
anty list-rules

# Create config file
anty init
```

## What It Finds

Anty runs multiple independent **security agents**, each focused on a specific domain:

### 🔑 Secrets Agent
Hardcoded secrets, API keys, tokens, and credentials:
- AWS Access Keys & Secret Keys
- GitHub Personal Access Tokens
- Stripe, OpenAI, Slack, SendGrid, Twilio keys
- Database connection strings with passwords
- Private keys (RSA, EC, DSA)
- Hardcoded passwords and JWT secrets
- Generic API key patterns

### ⚠️ Dangerous Functions Agent
Dangerous function calls and code patterns:
- `eval()` / `exec()` usage
- SQL injection (string concat, template literals, f-strings)
- Unsafe deserialization (`pickle.loads`, `yaml.load`)
- XSS patterns (`innerHTML`, `dangerouslySetInnerHTML`)
- Weak cryptography (MD5, SHA-1)
- Shell injection (`shell=True`)

### ⚙️ Config Issues Agent
Dangerous configurations and misconfigurations:
- CORS wildcard (`origin: '*'`)
- Debug mode enabled in production
- TLS/SSL verification disabled
- Insecure cookie settings
- Hardcoded HTTP URLs for sensitive endpoints
- Binding to `0.0.0.0`

## Output

**Terminal** (default) — colored, human-readable:
```
🔍 Anty v0.1.0 — Scanned 342 files in 0.34s

 CRITICAL  src/config/db.ts:14
           Hardcoded database password in source code
           → DB_PASSWORD = "admin123!"
           ⮕ Use environment variables or a secrets manager

 HIGH      src/api/users.ts:87
           SQL query built with string concatenation
           → query("SELECT * FROM users WHERE id = " + userId)
           ⮕ Use parameterized queries

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Found 12 issues: 2 critical, 3 high, 5 medium, 2 low
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**JSON** (`--format json`) — machine-readable, stable schema for CI/CD integration.

## Configuration

Create `.anty.toml` in your project root:

```toml
[scan]
exclude = ["tests/fixtures/**", "**/*.test.*"]

[agents]
# enable = ["secrets", "dangerous-functions"]
# disable = ["config-issues"]

[output]
format = "terminal"
# min_severity = "MEDIUM"
```

Or run `anty init` to generate a default config.

## CI/CD Integration

**GitHub Actions (Linux/macOS):**
```yaml
- name: Security Scan
  run: |
    curl -fsSL https://raw.githubusercontent.com/voulspiros/Anty/main/install.sh | sh
    export PATH="$HOME/.anty/bin:$PATH"
    anty scan . --fail-on HIGH --format json --out anty-report.json
```

**GitHub Actions (Windows):**
```yaml
- name: Security Scan
  shell: pwsh
  run: |
    irm https://raw.githubusercontent.com/voulspiros/Anty/main/install.ps1 | iex
    anty scan . --fail-on HIGH --format json --out anty-report.json
```

Exit codes:
- `0` — No issues (or below `--fail-on` threshold)
- `1` — Issues found at or above threshold
- `2` — Scan error

## Core Principles

- **Local-first** — your code never leaves your machine
- **No code storage** — nothing is uploaded or stored
- **Fast** — parallel scanning with Rust
- **Single binary** — no runtime dependencies
- **Privacy-respecting** — no telemetry, no tracking

## License

MIT
