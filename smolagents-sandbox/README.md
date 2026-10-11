# Anatomy of an LLM-agent sandbox: how smolagents hardened its Python executor (CVE-2025-5120)

> [smolagents](https://github.com/huggingface/smolagents) (Hugging Face) runs
> **code written by the LLM**: a `CodeAgent` asks the model for Python and
> executes it. Because the model's output can be steered by an attacker (prompt
> injection, a poisoned tool result, a malicious task), that executor is a
> security boundary. This is a study of **how that boundary works, why the
> classic escape no longer works, and where the residual risk is** — reproduced
> locally against the current release. CVE-2025-5120 is public and fixed; this
> is an educational analysis, not a new disclosure.

| | |
|---|---|
| **Target** | smolagents `LocalPythonExecutor` |
| **Class** | Sandbox escape → RCE (CWE-94) |
| **Reference CVE** | CVE-2025-5120 (CVSS 9.9), fixed in 1.17.0 |
| **This analysis** | current `main` (post-fix) — the escape is blocked; here's the mechanism |

---

## 1. Why a sandbox at all

A `CodeAgent` turns a task into Python and runs it to call tools and compute
answers. If that Python ran unrestricted, anyone who can influence the model's
output — a prompt injection hidden in a web page the agent reads, a malicious
document, a crafted tool result — could run arbitrary code on the host. So
smolagents ships `LocalPythonExecutor`: a **custom AST interpreter** that walks
the parsed code node by node and only allows a curated subset.

> Hugging Face is explicit that this is best-effort: for untrusted code you
> should use a container/VM/remote sandbox. CVE-2025-5120 is why.

## 2. The controls (current release)

Reading `src/smolagents/local_python_executor.py`:

- **No raw `eval`/`exec`/`compile`/`import`** — the interpreter evaluates the AST
  itself; there is no Python `eval` of the user string.
- **Dunder attribute access is blocked.** Both the AST attribute handler and the
  `getattr` builtin (`nodunder_getattr`) reject any name that starts *and* ends
  with `__`. This kills the classic `().__class__.__bases__[0].__subclasses__()`
  chain.
- **Import allowlist.** Only a short list may be imported: `collections`,
  `datetime`, `itertools`, `math`, `queue`, `random`, `re`, `stat`,
  `statistics`, `time`, `unicodedata`.
- **Blocklists.** `DANGEROUS_MODULES` (os, sys, subprocess, io, socket,
  pathlib, shutil, pty, multiprocessing, builtins) and `DANGEROUS_FUNCTIONS`
  (eval/exec/compile/globals/locals/`__import__`, os.system/os.popen,
  posix.system).
- **Resource limits** (operations, loop iterations, wall-clock) against DoS.

## 3. The classic escape — and why it now fails

The dunder block stops the usual tricks, so the next idea is: the allowlist lets
me `import random`; can I reach a *blocked* module through `random`'s own
attributes using only **non-dunder** hops (which the sandbox permits)?

A small reachability probe ([`reachability_probe.py`](reachability_probe.py))
walks each allowed module's non-dunder attribute graph looking for a blocked
module. It finds several:

```
import random      → random._os          → module os
import queue       → queue.threading._os → module os
import collections → collections._sys    → module sys
import statistics  → statistics.sys      → module sys
```

`_os` is single-underscore, not dunder, so `nodunder_getattr` allows it. On
paper, `random._os.system("id")` should run a command. Against the current
release it does **not**:

```python
from smolagents.local_python_executor import (
    evaluate_python_code, BASE_PYTHON_TOOLS, BASE_BUILTIN_MODULES)

evaluate_python_code(
    'import random; random._os.system("touch /tmp/pwned")',
    static_tools=dict(BASE_PYTHON_TOOLS),
    authorized_imports=list(BASE_BUILTIN_MODULES),
)
# -> InterpreterError: Forbidden access to module: os   (and /tmp/pwned is NOT created)
```

### Why: the check runs on *every* sub-expression

The decisive detail is that `@safer_eval` wraps **`evaluate_ast`** — the
recursive core — not just the top-level call. So `check_safer_result` runs on
the result of **every** node:

```python
def check_safer_result(result, static_tools=None, authorized_imports=None):
    if isinstance(result, ModuleType):
        if not check_import_authorized(result.__name__, authorized_imports):
            raise InterpreterError(f"Forbidden access to module: {result.__name__}")
    ...
    elif isinstance(result, (FunctionType, BuiltinFunctionType)):
        # reject os.system, eval, exec, ...
```

Evaluating `random._os.system(...)` first evaluates the sub-expression
`random._os`. That sub-expression's *value* is the `os` **module object**, and
because `evaluate_ast` is wrapped, that intermediate value is checked — and `os`
isn't an authorized import, so it is rejected **before** `.system` is ever
reached. Reachability is necessary but not sufficient: the per-step result check
closes the gap that CVE-2025-5120 exploited.

## 4. Where the residual risk is (honest)

The per-step check is principled, but it is a *type-based* filter, so its edges
are worth knowing — not as a working exploit (I did not find one), but as the
frontier and as reasons not to trust the boundary:

- `check_safer_result` inspects `ModuleType`, module-like dicts, and
  `FunctionType`/`BuiltinFunctionType`. It does **not** special-case
  `MethodType`, method-wrappers, `functools.partial`, or **class/`type`**
  objects. A dangerous capability reachable as one of those types, via a path
  where **no** intermediate value is a blocked module or a listed function,
  would slip past the type check.
- `DANGEROUS_FUNCTIONS` is a **short denylist** (a handful of os/builtins
  entries). Many RCE-capable callables (`os.exec*`, `os.spawn*`, `subprocess.*`,
  …) are not listed; they are only unreachable because getting to them requires
  a blocked **module** intermediate. The safety therefore rests on the module
  check, not the function denylist — denylists are inherently incomplete.
- `setattr`, `type`, and `getattr` are exposed builtins; object-construction and
  attribute-mutation primitives are a classic source of sandbox surprises.

The honest conclusion matches Hugging Face's own guidance: **do not treat
`LocalPythonExecutor` as a security boundary for untrusted code.** Run the agent's
code in a container, VM, or remote sandbox, and keep the in-process interpreter
as defense-in-depth, not the only wall.

## 5. Defensive lessons

1. **Check intermediate results, not just the final value.** Wrapping the
   recursive evaluator (not only the entry point) is exactly what turned a 9.9
   escape into a dead end. Allow-/deny-lists at the boundary are not enough if an
   inner step can hand back a privileged object.
2. **Prefer allowlists to denylists**, and make the allowlist about *values/types
   reachable*, not just *imports typed*. Reachability analysis (the probe here)
   is a cheap way to audit it.
3. **Type-based result filters have edges** (bound methods, partials, classes).
   A capability-based or process-isolation model is more robust than
   enumerating dangerous types.
4. For LLM agents specifically: the model's output is attacker-influenced input.
   An in-process "sandbox" is a speed bump; isolation is the control.

## 6. What I learned

- Reproduced the reachability that CVE-2025-5120 abused, and showed empirically
  that the current release blocks it — and *why* (per-step `check_safer_result`).
- The strongest defense here isn't the denylist; it's checking the result of
  every evaluation step. That's a transferable pattern for any expression sandbox.
- Static analysis points at the `exec`/interpreter sink instantly; understanding
  whether it is actually escapable is the real work — and sometimes the honest
  answer is "the maintainers already closed it."

---

*Educational analysis of public CVE-2025-5120, reproduced locally against my own
install. No working new escape is provided; the residual notes are defensive
observations, not an exploit. File/line references reflect the source as read and
may shift across releases.*
