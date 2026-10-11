# Variant analysis in the MCP ecosystem: how one bug pattern spreads

> A short methodology write-up. The Model Context Protocol (MCP) server ecosystem
> is young and growing fast, and a single insecure pattern — a tool that accepts a
> **file path and uses it without confinement** — keeps reappearing across servers,
> especially those sharing a template or an author. This is how to turn one public
> CVE into a map of likely siblings, with a benign method and responsible
> disclosure. It uses only public CVEs for the walkthrough; one new finding it
> produced is under responsible disclosure and is referenced anonymously.

---

## 1. The ecosystem, and the pattern

MCP servers expose "tools" an LLM/agent can call. Many of them read and write
files on behalf of the agent. The recurring bug is simple:

> A tool takes a `path` / `filename` / `output_path` argument and passes it
> straight to `open()`, `cv2.imread()`, a document loader, or a save function —
> with **no base-directory confinement** (no `realpath` + `commonpath` check, no
> rejection of absolute paths or `..`). Result: **arbitrary file read/write**
> (CWE-22).

Two conditions set the severity:

1. **Transport.** MCP servers can run over `stdio` (local, one user) or over
   `sse` / `streamable-http` (a network listener). Over a network transport with
   no authentication, the file-path bug becomes **remote** arbitrary file
   read/write. Over stdio it is still reachable through **indirect prompt
   injection** (a poisoned document/web page the agent reads can steer a tool
   call), which is why it is still treated as a vulnerability.
2. **Confinement.** Whether any base directory is enforced at all.

Public examples (all CVE-assigned):

| Server | CVE | Note |
|---|---|---|
| excel-mcp-server | CVE-2026-40576 | arbitrary file R/W over SSE/HTTP |
| excel-mcp-server | CVE-2026-85661 | path confinement missing even in stdio mode |
| Office-Word-MCP-Server | CVE-2026-65695 | absolute/`..` paths to open & save |
| Office-PowerPoint-MCP-Server | (path traversal) | same pattern, output paths |

In one industry roundup, 30+ MCP CVEs were filed in a single two-month window,
~43% exec/shell injection and ~10% path traversal.

## 2. The method: variant analysis

A patched (or even unpatched) CVE is not the end of a bug — it is a **fingerprint**.
When a bug has a template, look for the template's other instances:

1. **Pick a fingerprint.** Here: "tool takes a file path → `open`/`imread`/save,
   no confinement," plus "supports a network transport."
2. **Find instances that share a lineage.** The fastest lead is **same author /
   same template**. If a maintainer publishes many servers with the same
   scaffold, a bug in one is likely in the others. (Enumerate an author's repos
   with the GitHub API; filter to the right language and the "mcp" ones.)
3. **Triage each by the two severity conditions.** Grep each candidate for the
   transport selector (`MCP_TRANSPORT` / `mcp.run(transport=...)`) and for a
   confinement helper (`realpath`, `commonpath`, `is_relative_to`, a base dir).
   - Network transport + no confinement → strong.
   - stdio-only + no confinement → weaker (local / prompt-injection only).
   - By-design capability (e.g. a "terminal" server whose job is to run commands)
     → not a vulnerability; discard.
4. **Confirm with a local, benign PoC**, write a patch, disclose privately.

This is cheap (minutes per candidate with grep) and it scales: one fingerprint,
many targets.

## 3. What it produced

Walking an author's MCP servers this way, most split cleanly:

- Servers whose transport is hard-coded to `stdio` → the file-path bug is
  local-only; lower severity.
- A "run commands" server → command execution is the intended feature; not a bug.
- One **actively-used Python server that both supports a network transport and
  confines no paths** → the same arbitrary file read/write class as the public
  CVEs above. That one is **under responsible disclosure** (private report +
  proposed patch); details and the CVE will be linked here once it is fixed.

The point is not the single finding — it is that the method turned "one public
CVE" into a ranked list of candidates in an afternoon, and the ranking (by
transport + confinement) predicted which ones mattered.

## 4. The fix pattern

Every one of these is closed the same way — confine paths to a base directory:

```python
def resolve_safe_path(user_path: str, base_dir: str) -> str:
    base = os.path.realpath(base_dir)
    full = os.path.realpath(os.path.join(base, user_path))
    if os.path.commonpath([full, base]) != base:
        raise ValueError("path escapes the allowed directory")
    return full
```

Apply it to **every** path argument (read and write), make the base directory
configurable (an env var), reject absolute paths and `..`, and never bind the
network transport to `0.0.0.0` without authentication. For template/scaffold
authors: fix the template, because the bug propagates with it.

## 5. What I took away

1. **Variant analysis beats random hunting.** A fingerprint + a lineage (shared
   author/template) is a far better EV than grepping arbitrary repos.
2. **Triage is a two-axis question here**: transport (reachability) × confinement
   (the bug). Both are one grep each.
3. The young end of an ecosystem (new MCP servers) is where the un-audited
   instances live — and where the same closed bug is still open next door.

---

*Walkthrough uses public CVEs only. The new finding produced by this method is
under responsible disclosure and is intentionally not identified here until it is
fixed. Related: my small ML/LLM SAST rules — [mlsast](https://github.com/Tag59/mlsast).*
