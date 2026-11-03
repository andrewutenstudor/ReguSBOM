# ReguBOM — Open-Source EU Cyber Resilience Act (CRA) & ENISA SBOM Regulatory Gateway

[![ReguBOM CE CI](https://github.com/andrewutenstudor/ReguSBOM/actions/workflows/ci.yml/badge.svg)](https://github.com/andrewutenstudor/ReguSBOM/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Compliance](https://img.shields.io/badge/Compliance-CRA_Art._13_%7C_ENISA_2026-blue.svg)](#)
[![Formats](https://img.shields.io/badge/Formats-CycloneDX_1.7_%7C_SPDX_3.0.1-green.svg)](#)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB.svg?logo=python&logoColor=white)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Air-Gap Ready](https://img.shields.io/badge/Air--Gap-Zero--Telemetry-success)](#-zero-telemetry--air-gap-guarantee)

> **ReguBOM Community Edition (CE)** is a production-ready, open-source regulatory gateway for validating, inspecting, and certifying Software Bill of Materials (SBOMs) against the **EU Cyber Resilience Act (Regulation EU 2024/2847 - CRA)**, the **ENISA Technical Advisory on SBOM (October 2026)**, and **BSI TR-03183-2 v2.1.0**.

---

## ⚡ 30-Second Quickstart

Spin up the self-hosted ReguBOM Community Edition stack (FastAPI Backend + React Web UI + SQLite) with Docker Compose:

```bash
# Clone the repository
git clone https://github.com/andrewutenstudor/ReguSBOM.git
cd ReguSBOM

# Launch Community Edition stack
docker compose -f docker-compose.ce.yml up -d
```

- 🌐 **Web UI**: Open [http://localhost:5173](http://localhost:5173) in your browser.
- 📡 **REST API & Swagger Docs**: Access [http://localhost:8000/docs](http://localhost:8000/docs).

To stop the containers:
```bash
docker compose -f docker-compose.ce.yml down
```

---

## 💻 Headless CLI Usage

ReguBOM ships with an independent, headless regulatory CLI (`regubom_cli.py`) engineered for CI/CD gates, air-gapped terminal auditing, and pre-commit checks.

### 1. Direct Local / Air-Gapped Scan (No API Server Needed)
```bash
python backend/cli/regubom_cli.py backend/sample_ce_sbom.json
```

### 2. Subcommand Syntax with Remote/Local API Gateway
```bash
python backend/cli/regubom_cli.py scan test-sbom.json --api-url http://localhost:8000
```

### 3. Machine-Readable JSON Output for CI/CD Pipeline Gates
```bash
python backend/cli/regubom_cli.py scan release_sbom.json --output json > audit_report.json
```

### 4. Enforce Strict Zero-Warning Verification
```bash
python backend/cli/regubom_cli.py scan release_sbom.json --fail-on-warnings
```

#### Exit Codes
| Exit Code | Regulatory Meaning |
|:---------:|:-------------------|
| `0` | **PASS** or conditional **WARNING** (audit passed mandatory requirements) |
| `1` | **FAIL** (non-compliant; rejected under CRA Art. 13 / ENISA standards) |
| `2` | **WARNING** (when `--fail-on-warnings` is specified) |

---

## 📋 12-Point ENISA October 2026 & BSI TR-03183-2 Audit Checklist

Every ingested SBOM is evaluated by our local deterministic audit engine across 12 mandatory regulatory criteria:

| # | Regulatory Check | Legal & Technical Reference | Description |
|---|:---|:---|:---|
| **1** | **Standard & Format** | CRA Art. 13 / Annex II | Validates CycloneDX (v1.4, v1.5, v1.6, v1.7 ECMA-424) or SPDX (v2.3, v3.0.1) against local bundled schemas. |
| **2** | **Document Timestamp** | ENISA Table 1 / RFC 3339 | Strict ISO-8601 UTC timestamp check certifying the build/release instant. |
| **3** | **Author & Creator Contact** | ENISA Table 1 / RFC 5322 | Validates that author identities contain an RFC-compliant email or institutional URI. |
| **4** | **Tooling Identification** | ENISA Table 1 / BSI TR-03183 | Complete name and version metadata for SBOM generation tools. |
| **5** | **Lifecycle Phase** | ENISA Table 1 | Verifies lifecycle state designation (`design`, `source`, `build`, `analysed`, `deployed`, `runtime`). |
| **6** | **Cryptographic Attestation** | CRA Annex II / in-toto | Audits Cosign, in-toto attestations, or embedded cryptographic signatures. |
| **7** | **Primary Subject Definition** | ENISA Table 2 | Identifies the top-level root product entity with name, version, and type. |
| **8** | **Component Inventory** | ENISA Table 4 / CISA 2026 | Enforces unique names, versions, and standard package identifiers (PURL / CPE). |
| **9** | **Cryptographic Hash Imprints** | CRA Art. 13 / BSI TR-03183 | Requires SHA-256 or SHA-512 cryptographic digests for all component artifacts. |
| **10** | **SPDX License Compliance** | CRA Annex II / SPDX 3.25+ | Verifies normalized SPDX license expressions and flags non-standard free-text entries. |
| **11** | **Dependency Graph Delta** | ENISA Table 6 / NIS2 Art. 21 | Verifies directed dependency relationships, flagging orphan nodes and circular dependencies. |
| **12** | **Supplier Provenance** | ENISA Table 5 (1st vs 3rd Party) | Enforces strict manufacturer identification with bifurcated rules for proprietary vs OSS. |

---

## 🛡️ Zero-Telemetry & Air-Gap Guarantee

ReguBOM is designed from the ground up for strict national security, defense, and air-gapped critical infrastructure environments:

- **Local Schema Compilation**: CycloneDX (1.4–1.7) and SPDX (2.3–3.0.1) JSON schemas are bundled directly on disk in `backend/app/schemas/`. Schema compilation via `fastjsonschema` runs exclusively offline with zero outbound HTTP requests.
- **Frontend Isolation**: No Google Fonts, external CDNs, or third-party telemetry scripts. All UI icons, fonts, and assets are bundled locally in the compiled web build.
- **Hermetic Execution**: Backend validation and reporting operate with zero egress connectivity.

---

## 🏛️ Community Edition (CE) vs Enterprise Edition (EE)

ReguBOM follows an **Open-Core** architecture. The core regulatory validator is 100% open-source and free under Apache 2.0.

| Capability | Community Edition (CE) *(Open Source)* | Enterprise Edition (EE) *(Commercial)* |
|:---|:---:|:---:|
| **License** | **Apache 2.0** | **Commercial Enterprise** |
| **Deployment Mode** | Standalone Docker / Headless CLI | Helm / Kubernetes (RKE2, OpenShift) / Compose |
| **Database** | Embedded SQLite / Local Engine | PostgreSQL 16 Cluster + TimescaleDB |
| **ENISA 12-Point Checklist** | ✅ Included | ✅ Included |
| **Offline Schema Engine** | ✅ Included | ✅ Included |
| **Headless CLI Scanner** | ✅ Included | ✅ Included |
| **Product & Release Asset Catalog** | ❌ | ✅ Included |
| **SBOM Differential & Drift Engine** | ❌ | ✅ Included |
| **Role-Based Access Control (RBAC)** | ❌ | ✅ Included (Admin, Operator, Auditor) |
| **SSO & Identity Federation** | ❌ | ✅ Active Directory / LDAP / Keycloak OIDC |
| **Multi-Factor Authentication (MFA)** | ❌ | ✅ RFC 6238 TOTP (Google/MS Authenticator) |
| **Product-Scoped CI/CD API Keys** | ❌ | ✅ Included |
| **Air-Gap Cryptographic Licensing** | ❌ | ✅ Ed25519 Hardware/Air-Gap Signed Claims |
| **Enterprise SLA & Support** | Community GitHub Discussions | Dedicated 24/7 Support & Regulatory SLAs |

> 📖 *For enterprise deployments, compliance advisory, or on-premise air-gapped licensing, please contact the enterprise team or visit our enterprise documentation.*

---

## 🚀 Local Development Setup

### Backend (Python 3.12+)
```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run the FastAPI server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend (Node 20+)
```bash
cd frontend
npm install --legacy-peer-deps

# Start Vite dev server in Community mode
VITE_REGUBOM_EDITION=community npm run dev
```

---

## 🧪 Testing

Run backend tests and linting:
```bash
# Linting
flake8 backend/app backend/cli --max-line-length=120

# Run headless CLI audit test
python backend/cli/regubom_cli.py scan backend/sample_ce_sbom.json
```

---

## 📄 License & Attributions

- **ReguBOM Community Edition** is licensed under the [Apache License 2.0](LICENSE).
- Integrates the foundational `modulo_SBOM` validator authored by the Italian National Cybersecurity Agency (**ACN** — *Agenzia per la Cybersicurezza Nazionale*), licensed under **EUPL v1.2**.
