#!/usr/bin/env python3
"""
Reachability probe for the smolagents LocalPythonExecutor sandbox.

The sandbox blocks dunder attribute access (names that start AND end with "__")
and blocks importing dangerous modules (os, sys, subprocess, ...). But it allows
single-underscore attributes and allows importing a short allowlist of modules.

This probe asks: starting from an ALLOWED module, can we reach a BLOCKED module
(os/sys/subprocess/...) or a dangerous callable, using only NON-dunder attribute
hops — i.e. hops the sandbox would permit? If yes, that path is a candidate
sandbox escape (the allowlist of imports becomes moot).

Pure reachability analysis over stdlib objects. Nothing dangerous is executed.
"""
import types
from collections import deque

ALLOWED = [
    "collections", "datetime", "itertools", "math", "queue",
    "random", "re", "stat", "statistics", "time", "unicodedata",
]
# What we'd like to reach (the sandbox's DANGEROUS_MODULES).
TARGET_MODULES = {"os", "sys", "subprocess", "builtins", "posix",
                  "io", "shutil", "socket", "multiprocessing", "pty"}


def allowed_name(name: str) -> bool:
    # Mirror nodunder_getattr: only names that start AND end with "__" are blocked.
    return not (name.startswith("__") and name.endswith("__"))


def find_path(root_name, root_obj, max_depth=5, max_nodes=60000):
    seen = set()
    q = deque([(root_obj, [root_name], 0)])
    nodes = 0
    while q and nodes < max_nodes:
        obj, path, depth = q.popleft()
        if id(obj) in seen or depth > max_depth:
            continue
        seen.add(id(obj))
        nodes += 1
        if isinstance(obj, types.ModuleType):
            nm = getattr(obj, "__name__", "")
            if nm in TARGET_MODULES and len(path) > 1:
                return path, nm
        for name in dir(obj):
            if not allowed_name(name):
                continue
            try:
                child = getattr(obj, name)
            except Exception:
                continue
            # follow modules and objects; skip most callables to limit noise,
            # but DO follow modules even if callable.
            if isinstance(child, types.ModuleType) or not callable(child):
                q.append((child, path + [name], depth + 1))
    return None, None


if __name__ == "__main__":
    import importlib
    print("Searching for non-dunder paths  ALLOWED module -> BLOCKED module\n")
    hits = 0
    for m in ALLOWED:
        try:
            mod = importlib.import_module(m)
        except Exception as e:
            print(f"  (could not import {m}: {e})")
            continue
        path, reached = find_path(m, mod)
        if path:
            hits += 1
            print(f"  [{m:12}] reaches '{reached}' via: {'.'.join(path)}")
    if not hits:
        print("  No reachable blocked module found within bounds.")
    else:
        print(f"\n{hits} allowed module(s) tunnel to a blocked module. "
              "Next: verify the smolagents interpreter actually allows the hops,\n"
              "and whether a dangerous CALL (vs returned result) is checked.")
