from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path


ALLOWED_NORMALIZED_FILES = ("latest.parquet", "latest_manifest.json")
SNAPSHOT_GLOB = "urls-*.parquet"
BRANCH_GUARD_FILES = {
    "vercel.json": '{\n  "$schema": "https://openapi.vercel.sh/vercel.json",\n  "ignoreCommand": "exit 0"\n}\n',
    "frontend/vercel.json": '{\n  "$schema": "https://openapi.vercel.sh/vercel.json",\n  "ignoreCommand": "exit 0"\n}\n',
}


def run(command: list[str], *, cwd: Path) -> None:
    subprocess.run(command, cwd=str(cwd), check=True)


def remote_branch_exists(repo_root: Path, branch: str) -> bool:
    result = subprocess.run(
        ["git", "ls-remote", "--exit-code", "--heads", "origin", branch],
        cwd=str(repo_root),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def ensure_normalized_dir(repo_root: Path) -> Path:
    normalized_dir = repo_root / "data" / "normalized"
    normalized_dir.mkdir(parents=True, exist_ok=True)
    return normalized_dir


def prune_snapshot_history(normalized_dir: Path, keep: int) -> list[Path]:
    snapshots = sorted(normalized_dir.glob(SNAPSHOT_GLOB))
    for stale_path in snapshots[:-keep]:
        stale_path.unlink(missing_ok=True)
    return sorted(normalized_dir.glob(SNAPSHOT_GLOB))


def clear_normalized_dir(normalized_dir: Path) -> None:
    for pattern in (*ALLOWED_NORMALIZED_FILES, SNAPSHOT_GLOB):
        for path in normalized_dir.glob(pattern):
            path.unlink(missing_ok=True)


def clear_worktree(worktree_root: Path) -> None:
    for path in worktree_root.iterdir():
        if path.name == ".git":
            continue
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()


def merge_missing_snapshots(source_dir: Path, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    for snapshot_path in sorted(source_dir.glob(SNAPSHOT_GLOB)):
        target_path = target_dir / snapshot_path.name
        if not target_path.exists():
            shutil.copy2(snapshot_path, target_path)


def copy_normalized_history(source_dir: Path, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    clear_normalized_dir(target_dir)

    for filename in ALLOWED_NORMALIZED_FILES:
        source_path = source_dir / filename
        if source_path.exists():
            shutil.copy2(source_path, target_dir / filename)

    for snapshot_path in sorted(source_dir.glob(SNAPSHOT_GLOB)):
        shutil.copy2(snapshot_path, target_dir / snapshot_path.name)


def write_branch_guard_files(worktree_root: Path) -> None:
    for relative_path, content in BRANCH_GUARD_FILES.items():
        target_path = worktree_root / relative_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(content, encoding="utf-8")


@contextmanager
def orphan_worktree(repo_root: Path, branch: str):
    """Empty worktree on a throwaway orphan branch, for single-commit publishing."""
    work_branch = f"{branch}-publish-tmp"
    with tempfile.TemporaryDirectory(prefix=f"{branch}-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        run(["git", "worktree", "add", "--force", "--detach", str(temp_dir)], cwd=repo_root)
        try:
            subprocess.run(
                ["git", "branch", "-D", work_branch],
                cwd=str(repo_root),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            run(["git", "checkout", "--orphan", work_branch], cwd=temp_dir)
            run(["git", "rm", "-rf", "--ignore-unmatch", "."], cwd=temp_dir)
            clear_worktree(temp_dir)
            yield temp_dir
        finally:
            run(["git", "worktree", "remove", "--force", str(temp_dir)], cwd=repo_root)
            subprocess.run(
                ["git", "branch", "-D", work_branch],
                cwd=str(repo_root),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )


@contextmanager
def worktree_checkout(repo_root: Path, branch: str):
    with tempfile.TemporaryDirectory(prefix=f"{branch}-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        has_remote = remote_branch_exists(repo_root, branch)
        if has_remote:
            run(["git", "worktree", "add", "--force", str(temp_dir), f"origin/{branch}"], cwd=repo_root)
            run(["git", "checkout", "-B", branch, f"origin/{branch}"], cwd=temp_dir)
        else:
            run(["git", "worktree", "add", "--force", "--detach", str(temp_dir)], cwd=repo_root)
            run(["git", "checkout", "--orphan", branch], cwd=temp_dir)
            run(["git", "rm", "-rf", "--ignore-unmatch", "."], cwd=temp_dir)
            clear_worktree(temp_dir)
        try:
            yield temp_dir
        finally:
            run(["git", "worktree", "remove", "--force", str(temp_dir)], cwd=repo_root)


def hydrate(repo_root: Path, branch: str) -> int:
    if not remote_branch_exists(repo_root, branch):
        print(f"Remote branch '{branch}' does not exist; skipping hydrate.")
        return 0

    target_dir = ensure_normalized_dir(repo_root)
    with worktree_checkout(repo_root, branch) as worktree_root:
        source_dir = worktree_root / "data" / "normalized"
        if not source_dir.exists():
            print(f"Remote branch '{branch}' has no normalized history; skipping hydrate.")
            return 0
        copy_normalized_history(source_dir, target_dir)
    print(f"Hydrated normalized history from '{branch}'.")
    return 0


def publish(repo_root: Path, branch: str, keep: int, commit_message: str) -> int:
    normalized_dir = ensure_normalized_dir(repo_root)

    # Union the branch's existing snapshots into the local history so a publish
    # from a fresh checkout never erases previously accumulated snapshots.
    if remote_branch_exists(repo_root, branch):
        with worktree_checkout(repo_root, branch) as worktree_root:
            source_dir = worktree_root / "data" / "normalized"
            if source_dir.exists():
                merge_missing_snapshots(source_dir, normalized_dir)

    snapshot_paths = prune_snapshot_history(normalized_dir, keep)
    if not snapshot_paths and not any((normalized_dir / name).exists() for name in ALLOWED_NORMALIZED_FILES):
        print("No normalized history found to publish.")
        return 0

    # Publish as a single orphan commit and force-push: the branch is derived
    # data, and keeping history would accumulate stale snapshot blobs forever.
    with orphan_worktree(repo_root, branch) as worktree_root:
        target_dir = worktree_root / "data" / "normalized"
        copy_normalized_history(normalized_dir, target_dir)
        prune_snapshot_history(target_dir, keep)
        write_branch_guard_files(worktree_root)

        run(["git", "add", "-A"], cwd=worktree_root)
        result = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=str(worktree_root), check=False)
        if result.returncode == 0:
            print(f"No {branch} changes to publish.")
            return 0

        run(["git", "commit", "-m", commit_message], cwd=worktree_root)
        run(["git", "push", "--force", "origin", f"HEAD:refs/heads/{branch}"], cwd=worktree_root)
    print(f"Published normalized history to '{branch}' as a single commit.")
    return 0


def assert_promoted_bundle(model_dir: Path) -> int:
    required = (
        "model_bundle.joblib",
        "metadata.json",
        "training_summary.json",
        "leaderboard.json",
    )
    missing = [name for name in required if not (model_dir / name).exists()]
    if missing:
        raise SystemExit(f"Incomplete promoted bundle in {model_dir}: missing {', '.join(missing)}")
    print(f"Promoted bundle in '{model_dir}' is complete.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Hydrate and publish normalized snapshot history to a dedicated git branch.")
    parser.add_argument("--repo-root", default=".", help="Repository root containing the git checkout.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    hydrate_parser = subparsers.add_parser("hydrate", help="Hydrate data/normalized from the dedicated history branch.")
    hydrate_parser.add_argument("--branch", default="model-data")

    publish_parser = subparsers.add_parser("publish", help="Publish data/normalized into the dedicated history branch.")
    publish_parser.add_argument("--branch", default="model-data")
    publish_parser.add_argument("--keep", type=int, default=14)
    publish_parser.add_argument("--commit-message", required=True)

    assert_parser = subparsers.add_parser("assert-promoted", help="Fail if the promoted model bundle is incomplete.")
    assert_parser.add_argument("--model-dir", default="data/models/promoted")

    args = parser.parse_args()
    repo_root = Path(args.repo_root).expanduser().resolve()
    os.chdir(repo_root)

    if args.command == "hydrate":
        return hydrate(repo_root, args.branch)
    if args.command == "publish":
        return publish(repo_root, args.branch, args.keep, args.commit_message)
    if args.command == "assert-promoted":
        return assert_promoted_bundle((repo_root / args.model_dir).resolve())
    raise SystemExit(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
