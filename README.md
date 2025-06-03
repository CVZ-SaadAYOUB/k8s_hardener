# K8sHardener Utility

K8sHardener is a command-line utility designed to help you enhance the security posture of your Kubernetes clusters. It provides an interactive suite of tools for auditing, hardening, and managing various security aspects, from Role-Based Access Control (RBAC) and Pod Security to Istio service mesh configuration, intrusion detection with Falco, and container image security.

## Prerequisites

Before using K8sHardener, ensure you have the following installed and configured:

1.  **Git:** To clone this repository.
2.  **Python 3.6+ and Pip:** The utility is written in Python.
3.  **Kubernetes Cluster Access:**
    * `kubectl` (or `microk8s.kubectl` for MicroK8s environments) configured to access your target Kubernetes cluster.
    * Appropriate permissions within the cluster to perform the actions offered by the utility (e.g., list pods, modify RBAC, install Helm charts).
4.  **External Tools (for specific modules):**
    * **Helm:** Required for Falco installation. The script can attempt an automatic installation if Helm is not found.
    * **Trivy:** Required for image scanning and SBOM generation.
    * **Cosign:** Required for image signature verification.
    * **curl & bash:** Required if you opt for the automatic Helm installation.

## Setup and Installation

Follow these steps to set up and run K8sHardener:

1.  **Clone the Repository:**
    Open your terminal and clone the repository using SSH (ensure your SSH key is added to GitHub):
    ```bash 
    git clone git@github.com:CVZ-SaadAYOUB/k8s_hardener.git
    cd k8s_hardener
    ```

2.  **Install Dependencies:**
    Navigate into the cloned directory (which should be your `k8s_hardener` project root) and install the required Python packages from `requirements.txt`:
    ```bash
    pip3 install -r requirements.txt
    ```

3.  **Make it a CLI Command (Recommended):**
    To run `k8s-hardener` as a command from anywhere in your terminal:

    * **Ensure `main.py` is executable and has the correct shebang:**
        The first line of `main.py` should be `#!/usr/bin/env python3`. Make the script executable:
        ```bash
        chmod +x main.py
        ```

    * **Create a wrapper script:**
        Create a new file, for example, at `/usr/local/bin/k8s-hardener` (this usually requires `sudo` privileges). If you don't have sudo access or prefer a user-local installation, you can use a directory like `~/.local/bin` (ensure this directory is in your system's `PATH`).

        Content for the wrapper script (e.g., `/usr/local/bin/k8s-hardener`)
      
    * **Make the wrapper script executable:**
        ```bash
        sudo chmod +x /usr/local/bin/k8s-hardener
        ```
        (Adjust the path if you used `~/.local/bin` or another location).

## Running K8sHardener

Once set up as a CLI command, you can run the utility from any terminal location:
```bash
k8s-hardener
