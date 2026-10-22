# GitHub Submission Guide

The external GitHub repository and assigned partner's PR need your GitHub account and course assignment details. This guide prepares the exact workflow, but it does not invent repository or partner-review links.

## Easiest workflow using the PR-ready ZIP (PowerShell)

The `SecureNotes-OWASP-PR-Ready.zip` bundle already contains a local Git history: `main` is the untouched vulnerable starter and `security-fixes` contains the completed fixes. This preserves the lab requirement that the pull request show a clean diff.

1. Create an empty **public** GitHub repository named `securenotes-w13` (do not add a README/license from GitHub).
2. Extract the ZIP, open PowerShell in its `SecureNotes-STUDENT` folder, and run:

```powershell
git status
git branch
git remote add origin https://github.com/YOUR-USERNAME/securenotes-w13.git
git push -u origin main
git push -u origin security-fixes
python -m pip install -r requirements.txt
python tests\smoke_test.py
```

3. On GitHub, open **Compare & pull request** with base `main` and compare `security-fixes`. Use the PR description below.

## Alternate workflow if you are not using the PR-ready ZIP

Keep both ZIP files from the assignment in a known folder. Extract the **original** `OWASP_PEER_CODE (1).zip` and the fixed project ZIP to separate folders. Then:

1. Create an empty **public** GitHub repository named `securenotes-w13` (do not add a README/license from GitHub).
2. In PowerShell, change directory into the original extracted `SecureNotes-STUDENT` folder and make the starter commit:

```powershell
git init
git branch -M main
git add .
git commit -m "Starter: SecureNotes (vulnerable)"
git remote add origin https://github.com/YOUR-USERNAME/securenotes-w13.git
git push -u origin main
git switch -c security-fixes
```

3. Copy the fixed project's updated files into that original repository folder, replacing `app\main.py`, `FINDINGS.md`, and `README.md`, and adding `.env.example`, `GITHUB_SUBMISSION_GUIDE.md`, `PEER_REVIEW_SHEET.md`, and `tests\smoke_test.py`. Keep `.git` from the original repository. Do not copy `venv` or a `.env` file.
4. From that same folder, run the tests and commit/push the fixes:

```powershell
python -m pip install -r requirements.txt
python tests\smoke_test.py
git add .
git commit -m "Fix OWASP Top 10 issues (A01, A02, A04, A05, A07, A10)"
git push -u origin security-fixes
```

5. On GitHub, open **Compare & pull request** with base `main` and compare `security-fixes`. Use this PR description:

```text
This PR fixes the six planted OWASP Top 10 (2025) risks in SecureNotes:
- A01 Broken Access Control: notes are scoped to the authenticated owner.
- A02 Security Misconfiguration: configured CORS/secret; no stack traces in API responses.
- A04 Cryptographic Failures: salted PBKDF2 password hashes.
- A05 Injection: parameterized login query.
- A07 Authentication Failures: signed, expiring bearer tokens and generic login errors.
- A10 Mishandling of Exceptional Conditions: admin permission checks fail closed.

Validation: python tests/smoke_test.py
```

Replace the validation line with the actual result shown on your machine.

## Three constructive comment examples for the partner PR

Only use comments that genuinely match the code in your assigned partner's diff.

- **Strength:** "Could we keep this parameterized query? It keeps user input separate from SQL syntax and prevents this injection path."
- **Must-fix:** "Could we include the authenticated user's ID in this note lookup? As written, a caller may be able to request another user's note by changing the ID (A01)."
- **Suggestion:** "Could we add a test for a tampered or expired bearer token here? That would help prove invalid tokens fail closed (A07)."

Then click **Review changes** and choose **Approve** only if the fixes and tests are satisfactory; otherwise choose **Request changes**. Review the actual PR before deciding. Save your own PR URL and the reviewed PR URL for LMS submission.
