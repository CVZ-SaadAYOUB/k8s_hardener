# K8sHardener User Manual

## 1. Introduction

K8sHardener is a command-line utility designed to help you enhance the security posture of your Kubernetes clusters. It provides a suite of tools for auditing, hardening, and managing various security aspects, from Role-Based Access Control (RBAC) and Pod Security to Istio service mesh configuration, intrusion detection with Falco, and container image security.

This utility is interactive, guiding you through different modules and actions with clear prompts. It also supports specific commands for MicroK8s environments where applicable.

## 2. Prerequisites

Before using K8sHardener, ensure you have the following:

* **Python 3.6+ and Pip:** The utility is written in Python.
* **Kubernetes Cluster Access:**
    * `kubectl` (or `microk8s.kubectl` for MicroK8s) configured to access your target cluster.
    * Appropriate permissions in the cluster to perform the actions offered by the utility (e.g., list pods, modify RBAC, install Helm charts).
* **Python Dependencies:** Install the required packages using the `requirements.txt` file:
    ```bash
    pip install -r requirements.txt
    ```
    The `requirements.txt` should contain at least:
    ```
    kubernetes
    pyyaml
    pyfiglet
    rich
    questionary
    ```
* **External Tools (for specific modules):**
    * **Helm:** Required for Falco installation (`ids_monitor/falco_installer.py`). The script can attempt to install Helm if not found.
    * **Trivy:** Required for image scanning (`scanners/image_scanner.py`) and SBOM generation (`scanners/supply_chain_auditor.py`).
    * **Cosign:** Required for image signature verification (`scanners/supply_chain_auditor.py`).
    * **curl & bash:** Required if you opt for the automatic Helm installation.

## 3. Installation & Setup (Making it a CLI Command)

To use K8sHardener as a convenient CLI command (e.g., `k8s-hardener`):

1.  **Ensure `main.py` is Executable and Has a Shebang:**
    * Add `#!/usr/bin/env python3` as the very first line of `k8s_hardener/main.py`.
    * Make it executable: `chmod +x k8s_hardener/main.py`.

2.  **Create a Wrapper Script (Recommended):**
    * Create a file, for example, at `/usr/local/bin/k8s-hardener` (requires sudo) or `~/.local/bin/k8s-hardener` (if `~/.local/bin` is in your PATH).
    * Add the following content, **replacing `/path/to/your/k8s_hardener/main.py` with the actual absolute path**:
        ```bash
        #!/bin/bash
        # Wrapper script for K8sHardener
        MAIN_SCRIPT_PATH="/path/to/your/k8s_hardener/main.py"
        "$MAIN_SCRIPT_PATH" "$@"
        ```
    * Make the wrapper script executable: `sudo chmod +x /usr/local/bin/k8s-hardener`.

3.  **Test:**
    Open a new terminal or run `hash -r` (for bash/zsh) and type `k8s-hardener`.

## 4. General Usage

Launch the utility by running the `main.py` script directly (`python3 k8s_hardener/main.py`) or using the CLI command you set up (e.g., `k8s-hardener`).

Upon launch, you will see an ASCII banner and be prompted to set up an output directory. This directory will be used to save any generated files, reports, or backup configurations.

You will then be presented with the main menu. Navigate using the arrow keys or by typing the number corresponding to your choice and pressing Enter.

**Command-Line Arguments:**
The utility accepts the following command-line arguments:
* `--dry-run`: Perform a dry run for applicable actions (e.g., RBAC hardening). The utility will show what changes would be made without actually applying them.
* `--namespace <namespace_name>` or `-n <namespace_name>`: Specify a namespace for operations that are namespace-specific (e.g., Falco alert watcher).
* `--since <duration>` or `-s <duration>`: Show logs since a relative duration for the alert watcher (e.g., `5m`, `1h`, `10s`).

## 5. Modules Overview

### 5.1. General Kubernetes Hardening

This module focuses on core Kubernetes security configurations.

* **RBAC Management (`utils/rbac_hardener.py`)**
    * **Audit RBAC:** Scans Role-Based Access Control (RBAC) configurations (Roles, ClusterRoles, RoleBindings, ClusterRoleBindings) for overly permissive rules, risky subjects (like `system:masters` or default service accounts), and other potential misconfigurations. You can choose to exclude findings related to known system components.
    * **Harden RBAC:** After an audit, this option interactively guides you through remediating identified RBAC issues. It can propose changes like removing risky subjects or modifying RoleRefs and generate YAML for you to apply (with a dry-run option).
    * **Generate RBAC:** Interactively helps you create new, fine-grained RBAC Roles, ClusterRoles, RoleBindings, or ClusterRoleBindings.

* **Pod Security Checker (`utils/pod_security_checker.py`)**
    * Scans running pods for common security misconfigurations, including:
        * Privileged containers
        * Usage of host network, PID, or IPC namespaces
        * Containers allowing privilege escalation
        * Containers not running as non-root users or explicitly running as UID 0
        * Dangerous Linux capabilities
        * Non-read-only root filesystems
        * Mounting of sensitive host paths
        * Use of any HostPath volumes
        * Unnecessary automounting of service account tokens
        * Exposure of secrets as environment variables
        * Missing liveness/readiness probes
        * Use of host ports
        * Missing recommended pod-level securityContext settings (e.g., `runAsNonRoot`, `seccompProfile`).
    * Provides a severity-colored report (Critical, High, Medium, Low, Info).
    * Allows saving the report in TXT or CSV format.
    * Can prompt to delete pods identified with HIGH severity issues.

* **Network Policy Generator (`utils/network_policy_generator.py`)**
    * Interactively helps you create Kubernetes NetworkPolicy resources to control traffic flow between pods.
    * You can define:
        * The pods the policy applies to (via `podSelector`).
        * Policy types (Ingress for incoming traffic, Egress for outgoing).
        * Rules specifying allowed peers (other pods via `podSelector`, namespaces via `namespaceSelector`, or IP ranges via `ipBlock`) and ports/protocols.
    * Generates YAML for the policy, which can be saved to a file and/or applied to the cluster.

### 5.2. Istio and Zero Trust

This module provides tools for managing Istio service mesh installations and security policies. It adapts to MicroK8s for Istio installation.

* **Istio Installation Manager (`istio_manager/istio_installer.py`)**
    * **Check Istio Installation Status:** Verifies if Istio (specifically `istiod`) is running.
    * **Download Istio (Generic K8s):** Downloads the `istioctl` binary and Istio manifests for generic Kubernetes distributions.
    * **Install/Upgrade Istio:** Installs or upgrades Istio. For MicroK8s, it uses `microk8s enable istio`. For generic K8s, it uses `istioctl`.
    * **Enable Sidecar Injection for Namespace(s):** Labels specified namespaces for automatic Istio sidecar proxy injection.
    * **Uninstall Istio:** Removes Istio from the cluster.

* **mTLS Enforcement Manager (`istio_manager/mtls_enforcer.py`)**
    * **Get Current Mesh-Wide mTLS Mode:** Checks the `PeerAuthentication` policy in the `istio-system` namespace to determine the current mesh-wide mutual TLS mode.
    * **Enforce STRICT mTLS (Mesh-wide):** Applies a `PeerAuthentication` policy to enforce STRICT mTLS across the mesh.
    * **Set PERMISSIVE mTLS (Mesh-wide):** Sets the mesh-wide mTLS mode to PERMISSIVE.
    * **Disable/UNSET Mesh-wide mTLS Policy:** Sets the mesh-wide `PeerAuthentication` mode to UNSET, effectively reverting to Istio's default (usually PERMISSIVE) or allowing inheritance from more specific policies.

* **Istio Policy Checker (`istio_manager/policy_checker.py`)**
    * Audits Istio `AuthorizationPolicy` resources for overly permissive rules (e.g., ALLOW policies with no rules, rules allowing all sources/paths/methods).
    * Checks Istio `PeerAuthentication` policies for mTLS modes other than STRICT (e.g., PERMISSIVE, DISABLE) or port-level overrides that might weaken security.
    * Highlights policies in sensitive namespaces (e.g., `istio-system`, `kube-system`).

### 5.3. Intrusion Detection

Tools for setting up and monitoring runtime intrusion detection systems.

* **Falco Installer (`ids_monitor/falco_installer.py`)**
    * Installs Falco, a cloud-native runtime security tool, into your Kubernetes cluster using its official Helm chart.
    * If Helm is not detected, it offers to attempt an automatic installation of Helm using its official script.
    * Prompts for Falco configuration options like namespace, driver kind (eBPF, kernel module), audit log integration, JSON output, and log level.

* **Alert Watcher (`ids_monitor/alert_watcher.py`)**
    * Streams and displays Falco alerts in real-time from Falco pods running in your cluster.
    * If multiple Falco pods are found, it allows you to select which one to stream logs from.
    * Supports fetching logs since a relative duration (e.g., `5m`, `1h`) using the `--since` argument.
    * Alerts are color-coded by priority.

### 5.4. Image & Supply Chain

Focuses on the security of container images and the software supply chain.

* **Image Scanner (`scanners/image_scanner.py`)**
    * Scans container images for known vulnerabilities using **Trivy**.
    * Allows selecting images from currently running pods in the cluster or by manually entering image names (e.g., `nginx:latest`).
    * Displays results in tables, categorized by severity (Critical, High, Medium, Low), including Vulnerability ID, Package, Version, and Fix Version.
    * Also reports misconfigurations and secrets found by Trivy.

* **Supply Chain Auditor (`scanners/supply_chain_auditor.py`)**
    * Audits container images for supply chain security aspects:
        * **SBOM Generation:** Uses **Trivy** to generate a Software Bill of Materials (SBOM) for an image in CycloneDX format. It can display a summary and the full SBOM content.
        * **Image Signature Verification:** Uses **Cosign** to verify the signature of container images. It can try with experimental keyless features if initial verification fails.
    * Allows selecting images from running pods or manual entry.
    * SBOMs are saved to an output directory (configurable, defaults to a temporary location or the main output directory if run via `main.py`).

* **Deployment YAML Checker (`scanners/deployment_yaml_checker.py`)**
    * Scans a directory containing Kubernetes YAML files (specifically looking for `Deployment` kinds) for common security misconfigurations *before* they are applied to the cluster.
    * Checks include:
        * Privileged containers (`securityContext.privileged: true`)
        * Host namespaces (`hostPID`, `hostIPC`, `hostNetwork`)
        * Running as root (`securityContext.runAsNonRoot: false` or `runAsUser: 0`)
        * Allowing privilege escalation (`securityContext.allowPrivilegeEscalation: true`)
        * Non-read-only root filesystems
        * Missing CPU/Memory limits and requests
        * Use of `:latest` image tags
        * Risky container capabilities (e.g., `SYS_ADMIN`) or not dropping all default capabilities.
        * Automatic mounting of service account tokens (`automountServiceAccountToken: true`).
    * Reports findings per deployment.

### 5.5. Configuration Backups

* **Configuration Backuper (`backups/configuration_backuper.py`)**
    * Fetches and saves the configuration (as YAML files) of common Kubernetes resources from your cluster.
    * Resources backed up include: Namespaces, ClusterRoles, ClusterRoleBindings, Deployments, StatefulSets, DaemonSets, Services, ConfigMaps, Secrets, Roles, RoleBindings, ServiceAccounts, Ingresses, NetworkPolicies, PersistentVolumeClaims, CronJobs, and Jobs.
    * System namespaces (like `kube-system`, `istio-system`) are skipped by default for namespaced resources.
    * Secrets are backed up, so handle the output directory with care.
    * YAML files are cleaned of runtime/managed fields to be suitable for re-application or auditing.
    * Organizes backups into directories by namespace (for namespaced resources) or a `cluster_scoped` directory.

## 6. Troubleshooting & Notes

* **Permissions:** Ensure the user/service account running K8sHardener has sufficient permissions in the Kubernetes cluster to perform the selected actions. For example, listing secrets requires `get/list` on secrets, and installing Helm charts requires permissions to create various resources.
* **External Tools:** Make sure Trivy, Cosign, and Helm are installed and in your system's PATH if you intend to use the modules that rely on them. The Falco installer can attempt to install Helm.
* **MicroK8s:** When using with MicroK8s, ensure `microk8s.kubectl` is accessible or your kubeconfig is correctly set up. The Istio installer specifically uses MicroK8s commands.
* **Output Directory:** All generated files (reports, YAMLs, backups) will be saved to the output directory specified at the start of the utility.
* **Interactive Prompts:** Pay close attention to the interactive prompts, especially those confirming critical actions like deleting pods or applying RBAC changes.
* **Dry Run:** Utilize the `--dry-run` option for features like RBAC hardening to preview changes before applying them.

---
For further assistance or to report issues, please refer to the project's source or contact the maintainer.

