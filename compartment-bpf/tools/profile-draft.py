#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Draft compartment-bpf profiles from systemd and dpkg metadata.

This tool is intentionally conservative. It does not try to prove a
profile correct and it does not observe daemon behavior. It creates a
human-readable draft that must be reviewed and VM-tested before use.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import stat
import subprocess
import sys
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


CONFIG_PREFIXES = (
    "/etc/",
    "/usr/lib/systemd/",
    "/lib/systemd/",
    "/usr/lib/tmpfiles.d/",
    "/lib/tmpfiles.d/",
    "/usr/lib/sysusers.d/",
    "/lib/sysusers.d/",
    "/usr/lib/modules-load.d/",
    "/lib/modules-load.d/",
    "/usr/lib/udev/rules.d/",
    "/lib/udev/rules.d/",
    "/usr/share/dbus-1/system.d/",
    "/usr/share/polkit-1/actions/",
    "/usr/share/polkit-1/rules.d/",
)

EXEC_PREFIXES = (
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/libexec/",
    "/usr/lib/systemd/scripts/",
    "/lib/systemd/scripts/",
)

MUTABLE_PREFIXES = (
    "/run/",
    "/var/run/",
    "/var/lib/",
    "/var/log/",
    "/var/cache/",
    "/var/spool/",
    "/tmp/",
)

BROAD_SEAL_PATHS = {
    "/",
    "/etc",
    "/etc/systemd",
    "/etc/systemd/system",
    "/usr",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib/systemd",
    "/usr/lib/systemd/system",
    "/lib",
    "/lib/systemd",
    "/lib/systemd/system",
    "/bin",
    "/sbin",
}

VIRTUAL_PREFIXES = (
    "/proc/",
    "/sys/",
    "/dev/",
)

STATE_DIR_PROPERTIES = {
    "StateDirectory": "/var/lib",
    "LogsDirectory": "/var/log",
    "CacheDirectory": "/var/cache",
    "RuntimeDirectory": "/run",
}

ABS_PATH_RE = re.compile(r"(?<![A-Za-z0-9._%+-])/(?:[A-Za-z0-9._+@%=-]+/)*[A-Za-z0-9._+@%=-]+")

# The daemon's load_conf reads each profile line into char line[2048] via
# fgets and refuses any line that fills the buffer without a trailing '\n'
# (compartment-bpf.c::load_conf). A stripped rendered line therefore must
# stay <= 2046 bytes (one byte for '\n', one for '\0'). The rendered seal
# line is `seal <path-padded-to-48> full`, so the per-path ceiling is:
#   2046 - len("seal ") - 1 - len("full") = 2046 - 5 - 1 - 4 = 2036.
# Paths longer than this MUST NOT be emitted as seal lines or the daemon
# will reject the profile at load time.
MAX_SEAL_PATH_BYTES = 2036


@dataclass
class Candidate:
    path: str
    reason: str
    source: str
    flags: str = "full"  # §C-13: per-candidate flag set used by render().


@dataclass
class Draft:
    name: str
    unit: str | None = None
    packages: list[str] = field(default_factory=list)
    versions: OrderedDict[str, str] = field(default_factory=OrderedDict)
    exec_starts: list[str] = field(default_factory=list)
    seals: OrderedDict[str, Candidate] = field(default_factory=OrderedDict)
    writable: OrderedDict[str, Candidate] = field(default_factory=OrderedDict)
    skipped: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    liveness: str | None = None
    default_flags: str = "full"  # §C-13


def run(argv: list[str], *, allow_fail: bool = True) -> str:
    try:
        proc = subprocess.run(
            argv,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        if allow_fail:
            return ""
        raise
    except subprocess.TimeoutExpired:
        if allow_fail:
            return ""
        raise

    if proc.returncode != 0 and not allow_fail:
        raise RuntimeError(proc.stderr.strip() or f"{argv[0]} exited {proc.returncode}")
    if proc.returncode != 0:
        return ""
    return proc.stdout


def parse_key_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def split_systemd_list(value: str) -> list[str]:
    if not value or value == "n/a":
        return []
    out: list[str] = []
    for raw in value.split():
        item = raw.strip()
        if not item:
            continue
        while item and item[0] in "-+!:":
            item = item[1:]
        if item:
            out.append(item)
    return out


def parse_execstart(value: str) -> list[str]:
    paths: list[str] = []
    if not value:
        return paths

    for match in re.finditer(r"path=([^ ;]+)", value):
        paths.append(match.group(1))

    if paths:
        return unique(paths)

    for part in value.split(";"):
        part = part.strip()
        if part.startswith("argv[]="):
            first = command_first_path(part[len("argv[]=") :])
            if first:
                paths.append(first)

    if not paths:
        first = command_first_path(value)
        if first:
            paths.append(first)

    return unique(paths)


def command_first_path(command: str, *, source: str | None = None) -> str | None:
    command = command.strip()
    if not command:
        return None
    try:
        words = shlex.split(command)
    except ValueError:
        # POSIX-shell tokenisation failed (unbalanced quote, stray
        # backslash, etc.). Fall back to whitespace split and warn
        # the operator that the resulting profile may be incomplete.
        # §C-17.
        sys.stderr.write(
            f"profile-draft: WARNING: ExecStart{' for ' + source if source else ''} "
            f"could not be parsed by shlex; falling back to whitespace split. "
            f"The resulting profile may be incomplete; review by hand.\n"
        )
        words = command.split()
    for word in words:
        while word and word[0] in "-+!:@":
            word = word[1:]
        if word.startswith("/"):
            return word
    return None


EXEC_DIRECTIVES = (
    "ExecStart=",
    "ExecStartPre=",
    "ExecStartPost=",
    "ExecReload=",
    "ExecStop=",
    "ExecStopPost=",
)


def parse_unit_execs(unit_text: str, *, unit_name: str | None = None) -> list[str]:
    # §C-14: collect every Exec* directive's first path token, not
    # just ExecStart. systemctl cat (which is used by collect_systemd
    # below) already de-references drop-in .conf overrides, so we
    # see the effective unit text. systemd-analyze cat-config exists
    # but does the same de-reference for unit-style configs; we
    # stick with `systemctl cat` because it's available on every
    # systemd 245+ box and doesn't require a separate package.
    paths: list[str] = []
    for line in unit_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for prefix in EXEC_DIRECTIVES:
            if stripped.startswith(prefix):
                first = command_first_path(
                    stripped.split("=", 1)[1],
                    source=f"{unit_name}:{prefix.rstrip('=')}" if unit_name else None,
                )
                if first:
                    paths.append(first)
                break
    return unique(paths)


def parse_environment_files(unit_text: str) -> list[str]:
    paths: list[str] = []
    for line in unit_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.startswith("EnvironmentFile="):
            continue
        value = stripped.split("=", 1)[1]
        for item in split_systemd_list(value):
            if item.startswith("/"):
                paths.append(item)
    return unique(paths)


def absolute_paths_from_file(path: str) -> list[str]:
    # §C-12: don't regex-scan native ELF binaries — they're full of
    # incidental byte sequences that look like absolute paths but are
    # actually code/data, and the regex match cost on a multi-MB
    # binary is wasted work. Cheap check: read first 4 bytes; if they
    # are the ELF magic, return empty. Also skip very large files
    # (>1 MiB) — no shell wrapper or config file should be that big.
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return []
    if head[:4] == b"\x7fELF":
        return []
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    if size > 1024 * 1024:
        return []
    try:
        data = Path(path).read_text(errors="ignore")
    except OSError:
        return []
    found: list[str] = []
    for match in ABS_PATH_RE.finditer(data):
        candidate = match.group(0).rstrip(".,;:)\"'")
        if candidate.startswith(("/usr/", "/bin/", "/sbin/", "/lib/")):
            found.append(candidate)
    return unique(found)


def unique(items: Iterable[str]) -> list[str]:
    seen: OrderedDict[str, None] = OrderedDict()
    for item in items:
        if item and item not in seen:
            seen[item] = None
    return list(seen)


def package_files(package: str) -> list[str]:
    # §C-11: `--` guards against a package name shaped like a dpkg
    # option (--admindir=/tmp/evil, etc.).
    text = run(["dpkg-query", "--listfiles", "--", package])
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("/"):
            out.append(line)
    return unique(out)


def package_files_batch(packages: list[str]) -> dict[str, list[str]]:
    """§C-15: single batched `dpkg-query --listfiles` for many packages.

    dpkg-query separates per-package output with a blank line on
    multi-arg input and emits stanzas in the same order packages
    were passed on the argv. We rely on that ordering — see the
    behaviour test in the brief.
    """
    packages = [p for p in packages if p]
    if not packages:
        return {}
    if len(packages) == 1:
        return {packages[0]: package_files(packages[0])}
    text = run(["dpkg-query", "--listfiles", "--", *packages])
    out: dict[str, list[str]] = {p: [] for p in packages}
    if not text:
        return out
    stanzas = text.split("\n\n")
    # Be defensive: if dpkg-query produces fewer stanzas than
    # packages (older versions, missing packages, etc.), fall back
    # to per-package calls for the unmatched suffix.
    if len(stanzas) < len(packages):
        for pkg in packages:
            out[pkg] = package_files(pkg)
        return out
    for pkg, stanza in zip(packages, stanzas):
        files: list[str] = []
        for line in stanza.splitlines():
            line = line.strip()
            if line.startswith("/"):
                files.append(line)
        out[pkg] = unique(files)
    return out


def package_versions_batch(packages: list[str]) -> dict[str, str]:
    """§C-15: single batched `dpkg-query -W` for many packages.

    `-W -f='${Package} ${Version}\\n'` returns one line per
    package; order is alphabetical, not input order, so we
    parse into a dict keyed by package name.
    """
    packages = [p for p in packages if p]
    if not packages:
        return {}
    text = run(["dpkg-query", "-W", "-f=${Package} ${Version}\n", "--", *packages])
    out: dict[str, str] = {p: "" for p in packages}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[0] in out:
            out[parts[0]] = parts[1].strip()
    return out


def package_conffiles(package: str) -> list[str]:
    info_path = Path("/var/lib/dpkg/info") / f"{package}.conffiles"
    try:
        text = info_path.read_text()
    except OSError:
        return []
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("/"):
            out.append(line)
    return unique(out)


def package_version(package: str) -> str:
    # §C-11: `--` keeps an attacker-controlled package name from
    # being interpreted as a dpkg-query flag.
    return run(["dpkg-query", "-W", "-f=${Version}", "--", package]).strip()


def package_for_path(path: str) -> str | None:
    # §C-11: path comes from ExecStart inference (manual --include
    # too); `--` keeps a hostile path from being parsed as flags.
    text = run(["dpkg-query", "-S", "--", path])
    if not text:
        return None
    first = text.splitlines()[0]
    if ": " in first:
        pkg = first.rsplit(": ", 1)[0].strip()
    elif ":" in first:
        pkg = first.split(":", 1)[0].strip()
    else:
        return None
    return pkg or None


def apparmor_profile_path(unit_name: str | None, exec_paths: list[str]) -> str | None:
    """§C-16: locate an AppArmor profile that may describe this unit.

    Ubuntu's naming convention for /etc/apparmor.d/ is the slashes-
    replaced-with-dots form of the binary path, e.g.
        /usr/sbin/nginx  ->  /etc/apparmor.d/usr.sbin.nginx
    We try every ExecStart-derived path. The unit name itself
    (e.g. nginx.service) is also tried with the .service suffix
    stripped, in case the profile is named by unit rather than
    binary. Returns the first existing file path or None.
    """
    candidates: list[str] = []
    for path in exec_paths:
        if path.startswith("/"):
            stem = path.lstrip("/").replace("/", ".")
            candidates.append(f"/etc/apparmor.d/{stem}")
    if unit_name:
        bare = unit_name[:-8] if unit_name.endswith(".service") else unit_name
        candidates.append(f"/etc/apparmor.d/{bare}")
    for c in unique(candidates):
        if os.path.isfile(c):
            return c
    return None


# AppArmor rule line shapes we care about. This is intentionally
# a best-effort regex parse, NOT a real AppArmor parser. Ambiguous
# globs default to read-only classification. A future hardening
# effort can pull in the libapparmor Python bindings.
_AA_RULE_RE = re.compile(
    r"^\s*(?P<deny>deny\s+)?(?P<owner>owner\s+)?(?P<path>/[^\s,]+)\s+(?P<perms>[a-zA-Z]+)\s*,",
)


def apparmor_paths_for_unit(unit_name: str | None, exec_paths: list[str]) -> dict[str, set[str]]:
    """§C-16: parse an AppArmor profile and return path classifications.

    Returns a dict with keys 'read_paths', 'write_paths', 'deny_paths'.
    Each value is a set of stripped path globs (the leading
    /etc/apparmor.d glob syntax is preserved as-is — the caller can
    decide whether to ground them against the filesystem).

    Best-effort: profile files use a small grammar (path + perm
    letters + comma) plus include directives, deny rules, owner
    qualifiers, and a flock of macros under /etc/apparmor.d/abstractions
    that we do NOT follow. Missing profile / unreadable file ->
    empty sets (silent).
    """
    result: dict[str, set[str]] = {"read_paths": set(), "write_paths": set(), "deny_paths": set()}
    profile = apparmor_profile_path(unit_name, exec_paths)
    if not profile:
        return result
    try:
        text = Path(profile).read_text(errors="ignore")
    except OSError:
        return result
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _AA_RULE_RE.match(raw)
        if not match:
            continue
        path = match.group("path")
        perms = match.group("perms").lower()
        if match.group("deny"):
            result["deny_paths"].add(path)
            continue
        # Ambiguous (e.g. perms not strictly one of r/w/k/m): treat
        # as read-only to stay conservative.
        if "w" in perms or "a" in perms or "c" in perms:
            result["write_paths"].add(path)
        else:
            result["read_paths"].add(path)
    return result


def real_if_leaf_symlink(path: str) -> tuple[str, str | None]:
    if os.path.islink(path):
        target = os.path.realpath(path)
        return target, f"{path} is a symlink leaf; sealing target {target}"
    return path, None


def path_exists(path: str) -> bool:
    return os.path.exists(path) or os.path.islink(path)


def is_executable_file(path: str) -> bool:
    try:
        st = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and bool(st.st_mode & 0o111)


def is_directory(path: str) -> bool:
    try:
        return os.path.isdir(path)
    except OSError:
        return False


def has_prefix(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == p.rstrip("/") or path.startswith(p) for p in prefixes)


def should_skip_seal_path(path: str) -> str | None:
    if not path.startswith("/"):
        return "not absolute"
    # §C-18: the daemon's profile grammar tokenises seal lines via
    # strtok_r on whitespace (see compartment-bpf.c::load_conf).
    # A path containing ' ' or '\t' cannot survive a round-trip
    # through that grammar — it would be split into multiple tokens
    # and either silently truncated or rejected. Filter at the
    # generator and warn loudly; the operator must rename the path
    # or add it manually via a quoted include in a future grammar
    # extension.
    if " " in path or "\t" in path:
        return "path contains whitespace (daemon strtok_r grammar cannot represent it)"
    if path.rstrip("/") in BROAD_SEAL_PATHS:
        return "too broad for a draft seal"
    if has_prefix(path, VIRTUAL_PREFIXES):
        return "virtual filesystem path"
    if has_prefix(path, MUTABLE_PREFIXES):
        return "mutable runtime path"
    if len(path.encode("utf-8")) > MAX_SEAL_PATH_BYTES:
        return f"path exceeds daemon line cap ({MAX_SEAL_PATH_BYTES} bytes)"
    if not path_exists(path):
        return "path does not exist on this host"
    return None


def package_config_candidate(path: str) -> bool:
    if not path_exists(path):
        return False
    if not is_directory(path):
        return True
    base = os.path.basename(path.rstrip("/"))
    if base.endswith(".d"):
        return True
    if base in {"cron.hourly", "cron.daily", "cron.weekly", "cron.monthly"}:
        return True
    return False


def add_seal(draft: Draft, path: str, reason: str, source: str) -> None:
    skip = should_skip_seal_path(path)
    if skip:
        draft.skipped.append(f"{path} ({reason}, {source}): {skip}")
        # §C-18: surface whitespace-skipped paths on stderr in
        # addition to the header note, so a piped-to-file render
        # doesn't bury the warning.
        if "whitespace" in skip:
            sys.stderr.write(f"profile-draft: WARNING: skipping {path}: {skip}\n")
        return
    resolved, note = real_if_leaf_symlink(path)
    if note:
        draft.warnings.append(note)
    skip = should_skip_seal_path(resolved)
    if skip:
        draft.skipped.append(f"{path} -> {resolved} ({reason}, {source}): {skip}")
        if "whitespace" in skip:
            sys.stderr.write(f"profile-draft: WARNING: skipping {path} -> {resolved}: {skip}\n")
        return
    if resolved not in draft.seals:
        # §C-13: flags come from draft.default_flags so a single
        # --flags arg threads through the whole candidate set.
        draft.seals[resolved] = Candidate(resolved, reason, source, flags=draft.default_flags)


def add_writable(draft: Draft, path: str, reason: str, source: str) -> None:
    if not path or not path.startswith("/"):
        return
    if path not in draft.writable:
        draft.writable[path] = Candidate(path, reason, source)


def collect_systemd(draft: Draft) -> dict[str, str]:
    if not draft.unit:
        return {}

    props = [
        "ExecStart",
        "FragmentPath",
        "DropInPaths",
        "StateDirectory",
        "LogsDirectory",
        "CacheDirectory",
        "RuntimeDirectory",
        "ConfigurationDirectory",
        "ReadWritePaths",
        "PIDFile",
    ]
    # §C-11: `--` before draft.unit prevents a unit name shaped like
    # a systemctl flag (--root=/tmp/evil, etc.) from being interpreted.
    show = run(["systemctl", "show", "--no-pager"] + [f"--property={x}" for x in props] + ["--", draft.unit])
    values = parse_key_values(show)

    unit_text = run(["systemctl", "cat", "--no-pager", "--", draft.unit])
    if not values and not unit_text:
        draft.warnings.append(f"could not read systemd metadata for {draft.unit}")

    execs = parse_execstart(values.get("ExecStart", ""))
    execs.extend(parse_unit_execs(unit_text, unit_name=draft.unit))
    draft.exec_starts = unique(execs)

    for path in draft.exec_starts:
        add_seal(draft, path, "systemd ExecStart binary", f"unit {draft.unit}")
        for embedded in absolute_paths_from_file(path):
            if has_prefix(embedded, EXEC_PREFIXES) and is_executable_file(embedded):
                add_seal(draft, embedded, "executable referenced by ExecStart script", path)

    for key in ("FragmentPath", "DropInPaths"):
        for path in split_systemd_list(values.get(key, "")):
            add_seal(draft, path, f"systemd {key}", f"unit {draft.unit}")

    for path in parse_environment_files(unit_text):
        add_seal(draft, path, "systemd EnvironmentFile", f"unit {draft.unit}")

    for key, base in STATE_DIR_PROPERTIES.items():
        for item in split_systemd_list(values.get(key, "")):
            path = item if item.startswith("/") else f"{base}/{item}"
            add_writable(draft, path, f"systemd {key}", f"unit {draft.unit}")

    for item in split_systemd_list(values.get("ReadWritePaths", "")):
        add_writable(draft, item, "systemd ReadWritePaths", f"unit {draft.unit}")

    pid_file = values.get("PIDFile", "")
    if pid_file.startswith("/"):
        add_writable(draft, pid_file, "systemd PIDFile", f"unit {draft.unit}")

    for item in split_systemd_list(values.get("ConfigurationDirectory", "")):
        path = item if item.startswith("/") else f"/etc/{item}"
        add_seal(draft, path, "systemd ConfigurationDirectory", f"unit {draft.unit}")

    return values


def collect_packages(draft: Draft, include_executables: bool) -> None:
    if not draft.packages:
        return
    # §C-15: one dpkg-query fork for the whole package set, not one
    # fork per package. The previous shape forked 2*N times (version
    # + listfiles); the new shape forks twice total.
    versions = package_versions_batch(draft.packages)
    files_by_pkg = package_files_batch(draft.packages)
    for package in draft.packages:
        version = versions.get(package, "") or package_version(package)
        if version:
            draft.versions[package] = version
        else:
            draft.warnings.append(f"could not read dpkg version for package {package}")

        files = files_by_pkg.get(package, [])
        conffiles = package_conffiles(package)
        if not files and not conffiles:
            draft.warnings.append(f"could not read dpkg file list for package {package}")

        for path in conffiles:
            add_seal(draft, path, "dpkg conffile", f"package {package}")

        for path in files:
            if has_prefix(path, MUTABLE_PREFIXES):
                if is_directory(path):
                    add_writable(draft, path, "package mutable directory", f"package {package}")
                continue
            if has_prefix(path, CONFIG_PREFIXES):
                if package_config_candidate(path):
                    add_seal(draft, path, "package config/control path", f"package {package}")
                continue
            if include_executables and has_prefix(path, EXEC_PREFIXES) and is_executable_file(path):
                add_seal(draft, path, "package executable", f"package {package}")


def collect_apparmor(draft: Draft) -> None:
    """§C-16: pull AppArmor-classified paths in as a third metadata source.

    write_paths and deny_paths are advisory annotations only — they
    appear in the rendered header so the operator sees what AppArmor
    already considers writable/denied for this unit. read_paths that
    survive should_skip_seal_path become additional seal candidates,
    since AppArmor treats them as read-only static and so do we.
    """
    classifications = apparmor_paths_for_unit(draft.unit, draft.exec_starts)
    if not any(classifications.values()):
        return
    profile = apparmor_profile_path(draft.unit, draft.exec_starts)
    if profile:
        draft.warnings.append(f"AppArmor profile parsed (best-effort): {profile}")
    for path in sorted(classifications["read_paths"]):
        # Glob globs through unchanged; if AppArmor used wildcards
        # (most do), should_skip_seal_path will reject them via
        # 'path does not exist on this host', which is the right
        # outcome — operator must materialise the explicit list.
        add_seal(draft, path, "AppArmor read-only path", f"AppArmor {profile}")
    for path in sorted(classifications["write_paths"]):
        add_writable(draft, path, "AppArmor write path", f"AppArmor {profile}")
    for path in sorted(classifications["deny_paths"]):
        draft.warnings.append(f"AppArmor deny rule (informational): {path}")


def infer_packages(draft: Draft) -> None:
    packages = list(draft.packages)
    for path in draft.exec_starts:
        pkg = package_for_path(path)
        if pkg and pkg not in packages:
            packages.append(pkg)
            draft.warnings.append(f"inferred package {pkg} from {path}")
    draft.packages = packages


def render(draft: Draft) -> str:
    lines: list[str] = []
    title = draft.name
    if draft.unit:
        title = f"{title} ({draft.unit})"

    lines.extend(
        [
            f"# Profile: {title}",
            "#",
            "# Status          : DRAFT - review and VM-test before use",
            "# Generated by    : tools/profile-draft.py",
        ]
    )

    if draft.unit:
        lines.append(f"# Systemd unit    : {draft.unit}")
    if draft.exec_starts:
        lines.append("# ExecStart paths :")
        for path in draft.exec_starts:
            lines.append(f"#   {path}")
    if draft.packages:
        lines.append("# Packages        :")
        for package in draft.packages:
            version = draft.versions.get(package, "unknown version")
            lines.append(f"#   {package} ({version})")
    if draft.liveness:
        lines.extend(["#", "# Liveness check:", f"#   {draft.liveness}"])
    elif draft.unit:
        lines.extend(["#", "# Liveness check:", f"#   systemctl is-active --quiet {draft.unit}"])

    pos_target = positive_control_target(draft)
    if pos_target:
        lines.extend(
            [
                "#",
                "# Positive-control candidate (VM only):",
                f"#   {pos_target}",
            ]
        )

    if draft.writable:
        lines.extend(["#", "# Runtime state / writable paths (NOT sealed):"])
        for candidate in draft.writable.values():
            lines.append(f"#   {candidate.path}  ({candidate.reason}; {candidate.source})")

    if draft.warnings:
        lines.extend(["#", "# Generator notes:"])
        for warning in unique(draft.warnings):
            lines.append(f"#   {warning}")

    if draft.skipped:
        lines.extend(["#", "# Skipped candidates:"])
        for skipped in unique(draft.skipped):
            lines.append(f"#   {skipped}")

    lines.extend(
        [
            "#",
            "# Validate before use:",
            "#   ./compartment-bpf --dry-run <this-file>",
            "#   sudo bash tests/profile-smoke.sh  # for shipped profiles",
            "#",
        ]
    )

    if not draft.seals:
        lines.append("# No seal candidates found. Add seal lines manually after review.")
        lines.append("")
        return "\n".join(lines)

    current_reason = None
    for candidate in draft.seals.values():
        if candidate.reason != current_reason:
            lines.extend(["", f"# {candidate.reason}"])
            current_reason = candidate.reason
        # §C-13: per-candidate flags. Default 'full' preserves the
        # historical rendering exactly.
        lines.append(f"seal {candidate.path:<48} {candidate.flags}")

    lines.append("")
    return "\n".join(lines)


def positive_control_target(draft: Draft) -> str | None:
    preferred_words = ("config", "conffile", "EnvironmentFile", "ConfigurationDirectory")
    for candidate in draft.seals.values():
        if is_directory(candidate.path):
            continue
        if any(word in candidate.reason for word in preferred_words):
            return candidate.path
    return None


def build_draft(args: argparse.Namespace) -> Draft:
    name = args.name
    if not name:
        if args.unit:
            name = args.unit[:-8] if args.unit.endswith(".service") else args.unit
        elif args.package:
            name = args.package[0]
        else:
            name = "draft"

    draft = Draft(
        name=name,
        unit=args.unit,
        packages=list(args.package or []),
        liveness=args.liveness,
        default_flags=args.flags,
    )

    # §C-9: --systemd-only / --package-only are mutually exclusive
    # (enforced by argparse). Default behaviour (neither set) is
    # both sources, same as before.
    if not args.package_only:
        collect_systemd(draft)
        # §C-16: AppArmor is a third metadata source, gated by the
        # same --package-only switch (it's logically systemd-side
        # since it keys off the unit + ExecStart paths).
        collect_apparmor(draft)
    if args.infer_package and not args.systemd_only:
        infer_packages(draft)
    if not args.systemd_only:
        collect_packages(draft, include_executables=args.seal_package_executables)

    for path in args.include:
        add_seal(draft, path, "manual include", "command line")
    for path in args.writable:
        add_writable(draft, path, "manual writable path", "command line")
    for path in args.exclude:
        resolved = os.path.realpath(path) if path_exists(path) else path
        draft.seals.pop(resolved, None)
        draft.seals.pop(path, None)
        draft.warnings.append(f"excluded {path} by command line")

    return draft


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Draft a compartment-bpf seal profile from systemd and dpkg metadata.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  tools/profile-draft.py --unit ssh.service --output profiles/sshd.draft.conf\n"
            "  tools/profile-draft.py --unit chrony.service --package chrony --seal-package-executables\n"
            "  tools/profile-draft.py --package nginx --name nginx --liveness 'systemctl is-active --quiet nginx'\n\n"
            "The output is a draft. Always run --dry-run and VM validation before use."
        ),
    )
    parser.add_argument("--unit", help="systemd unit to inspect, for example ssh.service")
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        help="Debian package to inspect; may be repeated",
    )
    parser.add_argument(
        "--no-infer-package",
        dest="infer_package",
        action="store_false",
        help="do not infer package from ExecStart path",
    )
    parser.set_defaults(infer_package=True)
    parser.add_argument("--name", help="profile name for the generated header")
    parser.add_argument("--liveness", help="liveness check command to record in the header")
    parser.add_argument(
        "--seal-package-executables",
        action="store_true",
        help="also seal executable files from inspected packages",
    )
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        help="extra absolute path to seal; may be repeated",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="remove a generated seal path; may be repeated",
    )
    parser.add_argument(
        "--writable",
        action="append",
        default=[],
        help="record an intentionally writable path in the header; may be repeated",
    )
    parser.add_argument("-o", "--output", help="write profile to this file instead of stdout")
    parser.add_argument(
        "--flags",
        default="full",
        help=(
            "comma-separated flag set rendered for each seal line "
            "(default: full). Example: --flags no-write,no-unlink,no-chmod "
            "to reproduce the shells-allowlist profile."
        ),
    )

    # §C-9: --systemd-only and --package-only choose between metadata
    # sources. Default (neither): both. Mutually exclusive.
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument(
        "--systemd-only",
        action="store_true",
        help="skip dpkg-query metadata; rely on systemd unit + AppArmor only",
    )
    source_group.add_argument(
        "--package-only",
        action="store_true",
        help="skip systemd / AppArmor metadata; rely on dpkg-query only",
    )

    args = parser.parse_args(argv)
    if not args.unit and not args.package:
        parser.error("provide --unit, --package, or both")
    for v in (args.unit, args.name, args.liveness, args.flags, *args.package, *args.include, *args.exclude, *args.writable):
        if v and ("\n" in v or "\r" in v):
            parser.error("argument value contains a newline; rendered header would inject directives")
    # §C-13: shallow sanity-check the flags string. The daemon does
    # its own grammar check; here we just refuse obvious mistakes.
    if any(c in args.flags for c in " \t"):
        parser.error("--flags must be comma-separated without whitespace")
    return args


def _atomic_write(dest: Path, text: str) -> None:
    """§C-10: atomic, symlink-refusing write of `text` to `dest`.

    Writes to a tempfile next to the destination with O_NOFOLLOW|
    O_CREAT|O_EXCL, then os.replace into place. Refuses to chase a
    symlink at the destination, so an attacker who pre-creates
    `<dest>` as a symlink to /etc/shadow cannot use this tool as a
    write primitive. The tempfile is cleaned up in the failure path.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Fail-closed if the destination already exists as a symlink:
    # os.replace would replace the symlink itself (not follow it),
    # but operator intent is almost always "write a file here", not
    # "atomically swap a symlink for a file". Refusing prevents the
    # tool from being used to silently break a hostile-or-stale
    # symlink the operator didn't intend to clobber.
    try:
        st = os.lstat(str(dest))
    except OSError:
        st = None
    if st is not None and stat.S_ISLNK(st.st_mode):
        raise RuntimeError(
            f"profile-draft: refusing to overwrite {dest}: destination is a symlink"
        )
    tmp = dest.parent / f"{dest.name}.tmp.{os.getpid()}"
    fd = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(str(tmp), flags, 0o644)
        os.write(fd, text.encode("utf-8"))
        os.close(fd)
        fd = None
        os.replace(str(tmp), str(dest))
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    draft = build_draft(args)
    text = render(draft)

    if args.output:
        _atomic_write(Path(args.output), text)
    else:
        sys.stdout.write(text)
    if not draft.seals:
        sys.stderr.write(
            f"profile-draft: no seal candidates for {draft.name}; "
            "review --unit/--package args or pass --include\n"
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
