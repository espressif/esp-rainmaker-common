#!/usr/bin/env python3
"""Fail if a component's packaged files changed without a version bump.

For every component declared in .github/workflows/upload_components.yml
this compares the files under the component against the target branch. If
any changed but the `version:` in its idf_component.yml was not bumped, a
new version would never reach the registry (the action skips
already-published versions) -- so fail CI here, loudly, instead of
shipping a silent no-op. The root component is scoped to its own files:
the sub-component directories and repo infrastructure are excluded.

A sub-component ships inside rmaker_common and needs a root bump too,
unless the root manifest's `files.exclude` drops it. Then it bumps alone.

Opt-out: include the token "[skip-version-bump]" in any commit message in
the merge request's range to mark the change as intentional (e.g. a docs
or badge tweak you don't want to publish as a release). The check then
reports what it found and passes.

The component list and name resolution are shared with
validate_components.py so both jobs agree on what a "component" is.
"""
import os
import sys
from pathlib import Path

from validate_components import (
    find_action_step,
    git,
    parse_components,
    read_version,
    root_scope,
    version_bumped,
)

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/upload_components.yml"
# Branch to compare against; origin/master for the default branch pipelines.
BASE = os.environ.get("VERSION_BUMP_BASE", "origin/master")
SKIP_TOKEN = "[skip-version-bump]"


def excluded_paths(manifest):
    """Paths that the root manifest's `files.exclude` drops from its package."""
    return {
        p.resolve()
        for pattern in (manifest.get("files") or {}).get("exclude") or []
        for p in ROOT.glob(pattern)
    }


def main():
    import yaml

    if not WORKFLOW.is_file():
        sys.exit(f"Workflow not found: {WORKFLOW}")
    step = find_action_step(yaml.safe_load(WORKFLOW.read_text()))
    if step is None:
        sys.exit(f"No upload-components-ci-action step found in {WORKFLOW}")
    components = parse_components((step.get("with") or {}).get("components") or "")

    # Best-effort refresh of the base ref; ignore failures so the check can
    # also be run locally offline against an already-fetched ref.
    branch = BASE.split("/", 1)[-1]
    git("fetch", "--quiet", "origin", branch)
    base = git("merge-base", BASE, "HEAD").stdout.strip() or BASE

    # The opt-out token may live in any commit introduced on this branch.
    commit_msgs = git("log", "--format=%B", f"{base}..HEAD").stdout
    opted_out = SKIP_TOKEN.lower() in commit_msgs.lower()

    excluded = excluded_paths(yaml.safe_load((ROOT / "idf_component.yml").read_text()))

    violations = []
    root = None
    bundled_changed = []
    for name, path, _entry in components:
        full = (ROOT / path).resolve()
        is_root = full == ROOT
        scope = root_scope(components) if is_root else [path]
        changed = git(
            "diff", "--name-only", f"{base}..HEAD", "--", *scope
        ).stdout.splitlines()
        optional = full in excluded or full / "idf_component.yml" in excluded
        if not is_root and not optional:
            bundled_changed += changed
        bumped = version_bumped(base, full)
        cur_ver = read_version((full / "idf_component.yml").read_text())
        entry = (name or full.name, path, cur_ver, changed, bumped)
        if is_root:
            root = entry
        elif changed and not bumped:
            violations.append(entry[:4])

    # rmaker_common ships its bundled sub-components, so their changes need a root bump too.
    if root is not None:
        label, path, cur_ver, changed, bumped = root
        if (changed or bundled_changed) and not bumped:
            violations.insert(0, (label, path, cur_ver, changed + bundled_changed))

    if not violations:
        print("OK: every changed component has a version bump (or none changed).")
        return

    print("Components changed without a version bump:")
    for label, path, ver, files in violations:
        print(f"  - {label} ({path}): still at {ver}")
        for f in files:
            print(f"      {f}")

    if opted_out:
        print(
            f"\n{SKIP_TOKEN} found in the branch's commit messages -- "
            f"treating the change as intentional, passing."
        )
        return

    print(
        f"\nBump 'version' in each component's idf_component.yml, or add "
        f"{SKIP_TOKEN} to a commit message if this change is intentional and "
        f"should not be published as a new version."
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
