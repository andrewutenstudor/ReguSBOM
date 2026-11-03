# ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway Helm Chart

Enterprise-grade Helm chart for deploying **ReguBOM** in air-gapped sovereign Kubernetes, OpenShift, and RKE2 clusters.

Compliant with:
- **ENISA Technical Advisory on SBOM (October 2026)**
- **BSI TR-03183-2 v2.1.0 & CISA 2026 Minimum Elements**
- **EU Cyber Resilience Act (CRA Art. 13 & Annex II)**
- **OpenShift restricted-v2 SCC & Hardened CIS Benchmarks** (UID 10001 non-root)

---

## 1. Architectural Highlights

```mermaid
flowchart TD
    Ingress["Kubernetes Ingress (TLS Secret)"] -->|/api/*| BackendSvc["Backend ClusterIP :8000"]
    Ingress -->|/*| FrontendSvc["Frontend ClusterIP :80"]
    FrontendSvc --> FrontendPods["Frontend Pods (React 18 / Nginx :8080)<br/>UID: 10001"]
    BackendSvc --> BackendPods["Backend Pod (FastAPI 3.12 / ENISA Engine)<br/>UID: 10001"]
    BackendPods -->|Internal / External| Postgres[("PostgreSQL 16 StatefulSet / Managed RDS")]
    BackendPods --> PersistentStorage[("Persistent PVC 20Gi<br/>Uploads, Reports, License")]
```

---

## 2. Key Parameter Reference

| Parameter | Type | Default | Description |
|:---|:---|:---|:---|
| `global.airgapped` | boolean | `true` | When true, disables all external HTTP/image fetch attempts and enforces offline sovereignty. |
| `imageRegistry` | string | `""` | Global registry domain/prefix override prepended to all pod images (e.g. `harbor.corp:8443/regubom`). |
| `backend.image.repository` | string | `"regubom-backend"` | Backend container image repository. |
| `backend.image.tag` | string | `"v2.0.0"` | Backend container image tag. |
| `backend.replicaCount` | int | `1` | Number of backend replicas. |
| `frontend.image.repository` | string | `"regubom-frontend"` | Frontend container image repository. |
| `frontend.image.tag` | string | `"v2.0.0"` | Frontend container image tag. |
| `frontend.replicaCount` | int | `2` | Stateless frontend replicas. |
| `postgresql.enabled` | boolean | `true` | Deploy internal PostgreSQL 16 StatefulSet with PVC. |
| `postgresql.externalDatabase.url` | string | `""` | External connection string (when `postgresql.enabled: false`). |
| `securityContext.runAsUser` | int | `10001` | Non-root pod UID for strict OpenShift / RKE2 compliance. |
| `securityContext.runAsNonRoot`| boolean | `true` | Prevents root execution. |
| `ingress.enabled` | boolean | `true` | Enable Kubernetes Ingress resource. |
| `ingress.className` | string | `"nginx"` | Ingress controller class name. |
| `ingress.tls` | list | `[{secretName: "regubom-tls-cert", hosts: ["regubom.internal"]}]` | TLS secrets with **zero external cert-manager dependency**. |

---

## 3. Installation Scenarios

### Scenario A: Fully Air-Gapped Sovereign Deployment (Internal PostgreSQL)

1. Load and retag container images using `load_offline.sh`:
   ```bash
   ./load_offline.sh -r harbor.internal.corp:8443 -p regubom --push
   ```
2. Create your pre-issued corporate TLS secret:
   ```bash
   kubectl create namespace regubom
   kubectl create secret tls regubom-tls-cert \
     --cert=corp-ca-bundle.crt \
     --key=corp-private.key \
     -n regubom
   ```
3. Install ReguBOM using the generated values override:
   ```bash
   helm install regubom ./helm/regubom \
     -f regubom-airgap-values.yaml \
     -n regubom
   ```

### Scenario B: External Managed PostgreSQL (RDS, Crunchy, CloudNativePG)

Create a custom `values-external-db.yaml`:
```yaml
global:
  airgapped: true

imageRegistry: "harbor.internal.corp:8443/regubom"

postgresql:
  enabled: false
  externalDatabase:
    url: "postgresql://regubom_user:StrongPassword@pg-cluster.internal.corp:5432/regubom_db"

ingress:
  hosts:
    - host: "sbom.corporate.internal"
      paths:
        - path: /api
          pathType: Prefix
          service: backend
        - path: /
          pathType: Prefix
          service: frontend
  tls:
    - secretName: "corporate-wildcard-tls"
      hosts:
        - "sbom.corporate.internal"
```

Deploy:
```bash
helm install regubom ./helm/regubom -f values-external-db.yaml -n regubom
```

---

## 4. Security & Compliance Checklist

- [x] **Non-Root Execution**: Runs under UID `10001` and GID `10001`.
- [x] **Capabilities Dropped**: `ALL` Linux capabilities dropped.
- [x] **No Cert-Manager Coupling**: Ingress supports pre-provisioned enterprise PKI certificates directly.
- [x] **Immutable Storage**: Mounts dedicated PVC for reports and uploaded SBOM archives.
- [x] **Zero Telemetry**: All external network egress and analytics disabled.
