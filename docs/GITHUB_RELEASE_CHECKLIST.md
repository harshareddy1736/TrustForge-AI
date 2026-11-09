# GitHub release checklist

## Prepare local source

- [ ] Extract the release ZIP.
- [ ] Run the Python test suite.
- [ ] Run `mvn clean verify` with Java 25.
- [ ] Run frontend tests and `npm run build`.
- [ ] Start all three services and complete one live repository scan.
- [ ] Download and inspect the SBOM and Markdown report.
- [ ] Capture a dashboard screenshot and short demo video.
- [ ] Review `.gitignore`; do not commit `.env`, tokens, H2 database, `.venv`, `node_modules`, Maven `target`, or build outputs.

## Publish

```bash
git init
git add .
git status
git commit -m "Release TrustForge AI v1.1.0"
git branch -M main
git remote add origin https://github.com/<your-username>/TrustForge-AI.git
git push -u origin main
```

Replace the placeholder URL with the repository you created. If the project already has a Git remote, inspect it with `git remote -v` before adding another.

## Verify after push

- [ ] GitHub Actions shows all three CI jobs passing.
- [ ] README renders the architecture and run instructions correctly.
- [ ] Add screenshot/video links that point to files actually committed to the repository.
- [ ] Add project topics and a concise repository description.
- [ ] Pin the repository on your GitHub profile.
- [ ] Add an appropriate license only after choosing the license terms you want.
