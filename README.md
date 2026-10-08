# AegisExec

**Defensive Linux AI-Agent Action Broker**  
*Built by onkar-cybersec*

---

> **Notice & Scope:**  
> AegisExec is a defensive security tool designed to mediate and constrain local operations requested by AI agents. It is **not** an attack tool and makes **no claim** to solve all AI alignment or prevent all AI misuse. This project was developed with AI-assisted software engineering practices and designed for deployment on security-oriented Linux environments such as Kali Linux, Parrot Security OS, Debian, and Ubuntu. Tested on Python 3.10.

---

## 1. Threat Model & Security Architecture

```
┌─────────────────────────────────┐
│   Untrusted AI Agent / Client   │
│  (LLM, ReAct loop, tool-caller) │
└────────────────┬────────────────┘
                 │ Submits structured JSON ActionRequest (v1.0)
                 ▼
┌─────────────────────────────────┐
│     AegisExec Trusted Broker    │
│  - Strict v1.0 Schema Validator │
│  - Path Boundary & TOCTOU Guard │
│  - Tool Manifest Integrity TOFU │
│  - Default-Deny Policy Engine   │
└────────────────┬────────────────┘
                 │ If ALLOWED: mediates execution
                 ▼
┌────────────────────────────────────────────────────────┐
│             Defensive Enforcement Layer                │
│                                                        │
│  [read_text / list_dir]       [run_python]             │
│   - Descriptor O_NOFOLLOW      - Read-only snapshot    │
│   - Regular file fstat check   - Linux Bubblewrap      │
│   - Binary bounded reads       - Namespaces unshared   │
│   - No symlink-following       - Read-only binds       │
│   - Exclude secret metadata    - Zero network egress   │
│                                - --cap-drop ALL        │
│                                - PR_SET_NO_NEW_PRIVS   │
│                                - Host streaming cap    │
│                                - Descendant SIGKILL    │
└────────────────────────────────────────────────────────┘
```

### Threat Assumptions
1. **Untrusted Client:** The AI agent (or the prompts feeding it) may hallucinate, experience prompt injection, attempt path traversal, request sensitive keys, or attempt unauthorized code execution.
2. **Mediation Boundary Invariant:** The broker is effective **only** for operations routed through it. If an agent executes arbitrary host shell commands outside this broker, AegisExec cannot protect the system.
3. **Fail-Closed Execution:** Any schema violation, unknown JSON field, policy conflict, path ambiguity, or missing sandbox prerequisite immediately halts execution with status `DENIED`.

---

## 2. The Five Defensive Controls

| # | Defense | Threat Addressed | Mechanism |
|---|---|---|---|
| **1** | **Workspace Isolation & Sensitive-File Denial** | Directory traversal, parent directory swaps, symlink escapes, credential exfiltration (`.ssh`, `.aws`, `.env`, `/etc/shadow`) | Validates raw path strings (rejects raw `..` before normalization). Uses descriptor-relative `O_NOFOLLOW` resolution (`openat` semantics) for each component. Verifies `fstat` regular-file status. For Python execution, builds a bounded read-only sanitized snapshot, rejecting internal/parent symlinks and excluding credentials. |
| **2** | **Outbound Data Transfer Denial** | Covert network exfiltration, reverse shells, C2 beaconing | In v1 sandbox, all networking is disabled via `--unshare-net`. Sockets fail with `Network is unreachable`. |
| **3** | **Unsafe Command & Executable Denial** | Shell injection (`sh -c`, `bash -c`, `eval`, arbitrary user binaries) | No shell invocation (`shell=False`). The broker denies arbitrary executable requests. `run_python` executes strictly through `/usr/bin/python3` via a fixed trusted worker harness (`worker.py`). Inside the sandbox, minimal read-only system binds and dropped capabilities prevent executing unauthorized binaries. |
| **4** | **Privileged Action Denial** | Privilege escalation, container breakouts, root abuse | Sandboxed processes run with `--cap-drop ALL` and automatic `PR_SET_NO_NEW_PRIVS`. Approval tokens are checked but **never** act as a magic override for filesystem boundaries or sandboxing invariants. Approval-required operations fail closed until cryptographic verification is configured. |
| **5** | **Tool Manifest Integrity Drift** | Prompt injection via tool poisoning, stealth capability expansions | Canonical SHA-256 baselining (Trust-On-First-Use) with alphabetical serialization. `verify` generates a human-readable diff detecting description alterations and added capabilities before runtime. Never executes tools during verification. |

---

## 3. Enforcement vs. Simulation Distinction

* **Actual Linux Enforcement (`aegisexec run`):** Runs natively on Linux using kernel namespaces (`/usr/bin/bwrap`), process groups, resource limits, host-authoritative streaming byte caps, and read-only sanitized workspace snapshots. Requires Linux and Bubblewrap.
* **Policy Explorer & Preview Web UI:** A lightweight TypeScript/React companion interface providing interactive synthetic previews, rule evaluation demos, and manifest diff inspections. **This browser companion is strictly a simulation and policy viewer, NOT actual Linux kernel enforcement.**

---

## 4. Installation & Prerequisites

### System Requirements
* **OS:** Linux (Kali Linux 2023+, Parrot OS 5+, Ubuntu 22.04+, Debian 12+)
* **Python:** Python 3.10+ (tested on Python 3.10)
* **Sandboxing:** `bubblewrap` package (`/usr/bin/bwrap`)

### Quick Setup on Kali / Parrot / Ubuntu

```bash
# 1. Install Bubblewrap system package
sudo apt-get update && sudo apt-get install -y bubblewrap libcap2-bin

# 2. Clone the repository
git clone https://github.com/onkar-cybersec/aegisexec.git
cd aegisexec

# 3. Create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 4. Install AegisExec in editable mode
pip install --upgrade pip
pip install -e .
```

---

## 5. CLI Commands & Usage

### 1. `aegisexec doctor`
Inspects host kernel, Bubblewrap binary (`/usr/bin/bwrap`), unprivileged user namespaces, Python interpreter, and mounts:
```bash
aegisexec doctor
```

### 2. `aegisexec init`
Initializes a clean workspace with starter policies, sample requests, and baseline manifests:
```bash
aegisexec init --dir my_workspace
```

### 3. `aegisexec check`
Evaluates an action request against a policy without executing:
```bash
aegisexec check fixtures/requests/valid_read.json --policy fixtures/policies/strict.json
```

### 4. `aegisexec run`
Evaluates policy and executes operation under Bubblewrap isolation:
```bash
aegisexec run fixtures/requests/valid_read.json --policy fixtures/policies/strict.json
```

### 5. `aegisexec pin`
Computes canonical SHA-256 baseline for a tool manifest (TOFU):
```bash
aegisexec pin fixtures/tools/tools_v1.json -o baseline.json
```

### 6. `aegisexec verify`
Verifies manifest against baseline, flagging description changes or added tools:
```bash
aegisexec verify fixtures/tools/tools_v1_drifted.json --baseline fixtures/tools/baseline_v1.json
```

### 7. `aegisexec report`
Generates structured security audit reports in JSON or self-contained HTML:
```bash
# Generate self-contained HTML report
aegisexec report audit.jsonl --format html -o report.html

# Generate JSON summary
aegisexec report audit.jsonl --format json
```

---

## 6. Supported Operations

| Operation | Parameters | Scope & Isolation |
|---|---|---|
| `read_text` | `path` (string), `max_bytes` (int, opt) | Read-only file access inside designated workspace. Uses descriptor-relative `O_NOFOLLOW` resolution; verifies `fstat` regular-file status; performs bounded binary reads. Blocks sensitive credentials, raw traversal (`..`), and special files. |
| `list_dir` | `path` (string), `max_depth` (int), `include_hidden` (bool) | Safe traversal of directory structure within workspace. Non-symlink following; excludes credential and sensitive metadata. |
| `run_python` | `code` (string) OR `script_path` (string), `timeout_seconds` (float), `args` (list) | Executes Python code strictly inside Linux Bubblewrap container mounting a bounded read-only sanitized snapshot. Minimal read-only binds (`/usr`, `/lib`), private `/tmp`, private `/dev`, private `/proc`, zero network, `--cap-drop ALL`, automatic `PR_SET_NO_NEW_PRIVS`, bounded memory and host-streamed output byte caps with descendant process group SIGKILL. |

---

## 7. Known Limitations & Scope Notes

1. **TOCTOU Limitations:** File path validation and subsequent opening can theoretically be susceptible to Time-Of-Check to Time-Of-Use race conditions if a concurrent unconfined host process replaces directories with symlinks during the check. To mitigate this, AegisExec employs descriptor-relative `O_NOFOLLOW` (`openat`) component resolution, fstat checks, and builds isolated read-only snapshots before Python execution.
2. **AI Misuse:** AegisExec constrains system interaction. It cannot prevent an AI from producing syntactically valid but logically flawed analysis or misleading text within its bounded output.
3. **Trust-On-First-Use (TOFU):** Manifest baselines detect version-to-version drift and expansion. They do not constitute a cryptographic code-signing infrastructure with third-party certificate authority revocation.
4. **Approval Infrastructure:** In v1, approval-required operations fail closed until cryptographic signature verification backend is integrated.

---

## 8. Test Execution

Run the built-in test suite:
```bash
python3 -m unittest discover -s tests -v
```

Linux integration tests automatically detect host Bubblewrap and user namespace availability:
* If running on Linux with working Bubblewrap namespaces, all integration tests execute.
* In CI environments (`REQUIRE_SANDBOX=1`), missing sandboxing causes test failure rather than skipping.
* When testing on non-Linux or container environments without namespaces, integration tests skip honestly with explicit diagnostic reasons and are never reported as passes.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.  
Copyright (c) 2026 onkar-cybersec.
