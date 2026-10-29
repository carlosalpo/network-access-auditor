"""Reproduce execution evidence in a NEW directory; never alter the checkout."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def snapshot(repo):
    return {p.relative_to(repo).as_posix(): sha(p) for p in sorted(repo.rglob('*'))
            if p.is_file() and '.git' not in p.relative_to(repo).parts}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', type=Path, required=True)
    ap.add_argument('--destination', type=Path, required=True)
    args = ap.parse_args()
    repo = args.repo.resolve()
    dest = args.destination.resolve()
    dest.mkdir(parents=True, exist_ok=False)
    for name in ['logs', 'sources', 'runtime']:
        (dest / name).mkdir()
    before = snapshot(repo)
    def git(*cmd):
        return subprocess.check_output(['git', '-C', str(repo), *cmd], text=True).strip()
    commit = git('rev-parse', 'HEAD')
    assert commit == 'bf76b4bf12d0c08422ed98ca05e024d9557f737b'
    assert not git('status', '--porcelain')
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
               PATH=str(repo / '.venv/bin') + os.pathsep + os.environ['PATH'],
               TMPDIR=str(dest / 'runtime'))
    execution = []
    def run(label, command):
        start = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = subprocess.run(command, cwd=repo, env=env, capture_output=True)
        (dest / 'logs' / (label + '.stdout.log')).write_bytes(result.stdout)
        (dest / 'logs' / (label + '.stderr.log')).write_bytes(result.stderr)
        execution.append(dict(label=label, started_at_utc=start, exit_code=result.returncode))
        assert result.returncode == 0, label
        return result.stdout.decode()
    version = run('version', ['.venv/bin/naa', '--version']).strip()
    python = run('python', ['.venv/bin/python', '--version']).strip()
    run('pytest', ['.venv/bin/python', '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
                   '--basetemp', str(dest / 'runtime/pytest')])
    run('examples', ['.venv/bin/python', 'scripts/check_examples.py', '--output', str(dest / 'outputs')])
    for p in sorted((repo / 'examples').glob('*.json')):
        shutil.copyfile(p, dest / 'sources' / p.name)
    after = snapshot(repo)
    assert before == after, 'Repository bytes changed'
    assert not git('status', '--porcelain')
    record = dict(commit=commit, version=version, python=python,
                  captured_date='2026-10-29', timezone='America/Tegucigalpa',
                  executions=execution, repository_files_unchanged=True,
                  git_status_before='', git_status_after='',
                  tracked_source_sha256={p: before[p] for p in git('ls-files').splitlines()})
    (dest / 'logs/run.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k:record[k] for k in ['commit','version','python','repository_files_unchanged']}))

if __name__ == '__main__':
    main()
