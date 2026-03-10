# Push cveResponderAI to GitHub

The repository is already initialized with `main` and an initial commit. To create the **public** repo and push:

## Option A — GitHub CLI (recommended)

```bash
cd /path/to/cveanalyzer   # or cveResponderAI folder

# One-time login (browser or token)
gh auth login

# Create public repo and push (repo name: cveResponderAI)
gh repo create cveResponderAI --public --source=. --remote=origin \
  --description "Local AI for CVE triage, MITRE ATT&CK mapping, and IR planning (Ollama + NVD + CISA KEV)" \
  --push
```

If `origin` already exists:

```bash
git remote remove origin
gh repo create cveResponderAI --public --source=. --remote=origin --push
```

## Option B — GitHub website

1. Create a new **public** repository named `cveResponderAI` (no README/license — already in project).
2. Then:

```bash
cd /path/to/cveanalyzer
git remote add origin https://github.com/emr4h/cveResponderAI.git
git branch -M main
git push -u origin main
```

Replace `emr4h` if your GitHub username is different; update `README.md` and `LICENSE` accordingly.

## Large file note

`data/mitre-attack.json` (~46 MB) is included. GitHub allows files up to 100 MB. If push fails or is slow, consider [Git LFS](https://git-lfs.com/) or documenting a download step instead.
