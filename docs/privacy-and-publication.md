# Privacy and Publication

The private development repository may contain history that is unsuitable for
publication even after its current tree is clean. Do not rewrite it in place and
assume caches or existing clones have been erased.

## Release Privacy Checklist

1. Export any deployment-specific behavior into an ignored private profile.
2. Run the tree privacy scan with the private denylist.
3. Regenerate and check CLI references, man pages, and completions.
4. Build wheel and sdist in an isolated directory.
5. Scan both archives and inspect their file lists.
6. Create a new public export from tracked files only.
7. Scan the clean export's entire Git history.
8. Verify neutral Git author identity and absence of remotes before publishing.
9. Obtain owner approval for organization, trademark, license, and fixture use.

```bash
python privacy_check.py --root .
python privacy_check.py --root . dist/*.whl dist/*.tar.gz
python create_public_export.py ../netops-platform-public
python ../netops-platform-public/privacy_check.py --root ../netops-platform-public --git-history
```

Use `NETOPS_PRIVACY_DENYLIST_FILE` for a private newline-separated identifier
list. Never commit the real denylist. `.privacy-denylist.example` documents the
format.

The scanner checks text surfaces and paths for denied identifiers, personal
absolute paths, RFC 1918 addresses, private keys, common cloud-token forms, and
literal secret assignments. Release CI additionally checks generated
references, archives, WebUI assets, and synthetic address conventions. Public
repository CI scans the complete independent Git history; private development
CI does not scan its intentionally retained legacy history.

## Public Export

`create_public_export.py` copies tracked files, excludes known private runtime
artifacts, runs privacy checks, initializes a new `main` branch, and creates one
baseline commit using a neutral maintainer identity. It does not modify the
private repository, copy its `.git` directory, or configure a remote.

The exported set is force-staged only after it is bounded and privacy-scanned.
This preserves source-tracked generated assets even when a broad ignore rule
would otherwise hide them in the newly initialized repository.

Untracked files are excluded by default. `--include-untracked` exists only for a
deliberate pre-commit rehearsal; inspect its output and never use it as a reason
to skip staging/reviewing the private source tree.
