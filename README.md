# 🔐 CI Threat Modeler

Automated **SBOM → Vulnerability Scan → Threat Model** pipeline as a **GitHub Action**.

---

## 🚀 Features
- Generate SBOM using [Syft](https://github.com/anchore/syft)
- Scan SBOM with [Trivy](https://github.com/aquasecurity/trivy)
- Map CVEs → CWEs → STRIDE threat categories
- Produce `threat_model.json`
- Upload threat model as an artifact in CI/CD

---

## 📦 Usage

In your repo:

```yaml
name: Threat Modeling
on: [push, pull_request]

jobs:
  threat-model:
    runs-on: ubuntu-latest
    steps:
      - name: Use CI Threat Modeler
        uses: harshsoni-harsh/ci-threat-modeler@v1
        with:
          path: .
