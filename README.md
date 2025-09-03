# az_vuln_cli

A command-line tool for Azure container vulnerability scanning and analysis. Scans container images from Azure Container Registry (ACR) and Azure Kubernetes Service (AKS) using Trivy, then generates comprehensive vulnerability reports.

## Prerequisites

- **Python 3.x**
- **Azure CLI**
- **Trivy**
- **kubectl**  

> Windows: Use WSL (Windows Subsystem for Linux)

## Quickstart

### 1. Setup

```bash
git clone <repository-url>
cd az_vuln_cli
./setup.sh
```

### 2. Configure

Copy `environments.yaml.example` to `environments.yaml` and update with your Azure resources:

```bash
cp environments.yaml.example environments.yaml
# Edit environments.yaml with your subscriptions, registries, and clusters
```

### 3. Authenticate

```bash
./az_vuln_cli.py auth
```

### 4. Generate Inventories

```bash
./az_vuln_cli.py inventory all
```

### 5. Scan Everything

```bash
./az_vuln_cli.py scan all
```

## Key Output File

- `reports/vulnerability_comparison_analysis.xlsx` - Complete analysis workbook  
Read the *FAQ and help* sheet on how to interpret the analysis.
