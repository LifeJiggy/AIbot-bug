# 📦 Publishing AIbot-bug

Follow these steps to push your project to GitHub and PyPI.

## 1. Push to GitHub

Assuming you have a repository created on GitHub:

```bash
# Initialize git if not already
git init

# Add files
git add .

# Commit
git commit -m "Beast Mode 4.0: Robotic Evolution & PyPI Readiness"

# Link to GitHub (replace with your repo URL)
git remote add origin https://github.com/yourusername/AIbot-bug.git

# Push
git branch -M main
git push -u origin main
```

---

## 2. Publish to PyPI

You will need a PyPI account and the `twine` and `build` packages.

### Install build tools:
```bash
pip install --upgrade build twine
```

### Build the package:
```bash
python -m build
```

### Upload to PyPI:
```bash
# Upload to TestPyPI first (Optional but recommended)
python -m twine upload --repository testpypi dist/*

# Upload to real PyPI
python -m twine upload dist/*
```

---

## 3. Post-Publish Verification
Once uploaded, anyone can install your tool with:
```bash
pip install aibot-bug
```
And run it with:
```bash
aibot-bug
```
