#!/usr/bin/env python3
"""
Falco Installer for Kubernetes
Installs Falco into a Kubernetes cluster using Helm.
Includes an option to attempt Helm installation if not found.
"""
import sys
import argparse
import subprocess
import os
import json # Added for parsing helm repo list
from typing import List, Dict, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Confirm # Confirm is better for Yes/No
import questionary # For more complex prompts if needed, and for consistency

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    # This import is for the table in the status check
    from rich.table import Table
    K8S_CLIENT_LOADED = True
except ImportError:
    K8S_CLIENT_LOADED = False

console = Console()

HELM_RELEASE_NAME = "falco"
FALCO_HELM_REPO_NAME = "falcosecurity"
FALCO_HELM_REPO_URL = "https://falcosecurity.github.io/charts"
FALCO_CHART_NAME = f"{FALCO_HELM_REPO_NAME}/falco"
HELM_INSTALL_SCRIPT_URL = "https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3"
HELM_INSTALL_SCRIPT_NAME = "get_helm.sh"

# --- Helper Functions ---

def _command_exists(command: str) -> bool:
    """Checks if a command exists on the system."""
    try:
        if command == 'helm':
            args = ['version']
        else:
            args = ['--version']
        
        subprocess.run([command] + args, capture_output=True, text=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def _install_helm_via_script() -> bool:
    """Attempts to install Helm using its official shell script."""
    console.print(Panel(
        Text.from_markup(
            "Attempting to install Helm using the official `get.helm.sh` script.\n"
            f"This script will be downloaded from: {HELM_INSTALL_SCRIPT_URL}\n"
            "[bold yellow]Note:[/bold yellow] This installation method is primarily for Linux/macOS.\n"
            "The script might ask for `sudo` password to place Helm in a system directory (e.g., /usr/local/bin)."
        ),
        title="[cyan]Automatic Helm Installation[/cyan]",
        border_style="cyan"
    ))

    if not _command_exists("curl"):
        console.print("[bold red]Error: `curl` is required to download the Helm installation script but it's not found.[/bold red]")
        console.print("Please install `curl` or install Helm manually: https://helm.sh/docs/intro/install/")
        return False
    if not _command_exists("bash"):
        console.print("[bold red]Error: `bash` is required to run the Helm installation script but it's not found.[/bold red]")
        console.print("Please install `bash` or install Helm manually: https://helm.sh/docs/intro/install/")
        return False

    try:
        console.print(f"Downloading Helm installation script to ./{HELM_INSTALL_SCRIPT_NAME}...")
        subprocess.run(
            ['curl', '-fsSL', '-o', HELM_INSTALL_SCRIPT_NAME, HELM_INSTALL_SCRIPT_URL],
            check=True
        )
        console.print("Download complete.")

        console.print(f"Making {HELM_INSTALL_SCRIPT_NAME} executable...")
        subprocess.run(['chmod', '+x', HELM_INSTALL_SCRIPT_NAME], check=True)

        console.print(f"Running ./{HELM_INSTALL_SCRIPT_NAME} to install Helm...")
        console.print("[italic]You might be prompted for your sudo password if the script needs to write to protected directories.[/italic]")
        
        install_process = subprocess.run([f'./{HELM_INSTALL_SCRIPT_NAME}'], check=False)
        
        if install_process.returncode != 0:
            console.print(f"[bold red]Helm installation script finished with an error (code {install_process.returncode}).[/bold red]")
            console.print("Please check any output above or try installing Helm manually.")
            return False
        
        console.print("[green]Helm installation script executed.[/green]")
        console.print("Verifying Helm installation...")
        
        if _command_exists("helm"):
            result = subprocess.run(['helm', 'version'], capture_output=True, text=True)
            console.print(f"[green]Helm successfully installed and verified: {result.stdout.strip()}[/green]")
            return True
        else:
            console.print("[bold red]Helm command still not found after installation attempt.[/bold red]")
            console.print("This might be due to PATH issues or the installation script not completing as expected for your environment.")
            console.print("You might need to open a new terminal session or update your PATH.")
            return False

    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error during Helm installation process:[/bold red]\n{e.stderr or e.stdout or str(e)}")
        return False
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred during Helm installation: {e}[/bold red]")
        return False
    finally:
        if os.path.exists(HELM_INSTALL_SCRIPT_NAME):
            try:
                os.remove(HELM_INSTALL_SCRIPT_NAME)
                console.print(f"Cleaned up ./{HELM_INSTALL_SCRIPT_NAME}.")
            except OSError as e:
                console.print(f"[yellow]Warning: Could not remove ./{HELM_INSTALL_SCRIPT_NAME}: {e}[/yellow]")

def _prompt_and_install_helm() -> bool:
    """Asks the user if they want to install Helm and attempts installation if yes."""
    console.print(Panel(
        Text.from_markup(
            "[bold yellow]Helm CLI not found.[/bold yellow]\n"
            "Helm is required to install Falco using this script."
        ),
        title="[bold yellow]Dependency Missing[/bold yellow]",
        border_style="yellow"
    ))

    install_choice = questionary.confirm(
        "Do you want to attempt to install Helm automatically using the official script (get.helm.sh)?",
        default=True
    ).ask()

    if install_choice:
        return _install_helm_via_script()
    else:
        console.print("User declined automatic Helm installation.")
        console.print("Please install Helm manually: https://helm.sh/docs/intro/install/")
        return False

def _check_helm_installed() -> bool:
    """Checks if Helm CLI is installed and available. Offers to install if not found."""
    try:
        result = subprocess.run(['helm', 'version'], capture_output=True, text=True, check=True)
        console.print(f"[green]Helm found: {result.stdout.strip()}[/green]")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return _prompt_and_install_helm()


def _add_update_falco_repo() -> bool:
    """Adds the Falco Helm repository and updates it."""
    try:
        console.print(f"Checking for Helm repository '{FALCO_HELM_REPO_NAME}'...")
        if not _command_exists("helm"):
             console.print("[red]Cannot manage Helm repositories because Helm command is not available.[/red]")
             return False

        repo_list_result = subprocess.run(['helm', 'repo', 'list', '-o', 'json'], capture_output=True, text=True, check=True)
        repo_list = json.loads(repo_list_result.stdout)
        repo_exists = any(repo['name'] == FALCO_HELM_REPO_NAME and repo['url'] == FALCO_HELM_REPO_URL for repo in repo_list)

        if not repo_exists:
            console.print(f"Adding Falco Helm repository '{FALCO_HELM_REPO_NAME}' from {FALCO_HELM_REPO_URL}...")
            subprocess.run(
                ['helm', 'repo', 'add', FALCO_HELM_REPO_NAME, FALCO_HELM_REPO_URL],
                check=True, capture_output=True
            )
            console.print("[green]Falco repository added successfully.[/green]")
        else:
            console.print(f"Falco repository '{FALCO_HELM_REPO_NAME}' already configured.")

        console.print("Updating Helm repositories...")
        subprocess.run(['helm', 'repo', 'update'], check=True, capture_output=True)
        console.print("[green]Helm repositories updated.[/green]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error managing Falco Helm repository:[/bold red]\n{e.stderr or e.stdout}")
        return False
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error parsing Helm repository list: {e}[/bold red]")
        return False


def _get_installation_options() -> Dict[str, any]:
    """Asks the user for Falco installation options."""
    options = {}
    console.print("\n--- Falco Installation Configuration ---", style="bold blue")

    options["namespace"] = questionary.text(
        "Enter the namespace for Falco installation (will be created if it doesn't exist):",
        default="falco"
    ).ask()
    if not options["namespace"]:
        console.print("[red]Namespace cannot be empty. Exiting.[/red]")
        sys.exit(1)

    console.print("\nFalco Driver Configuration:")
    options["driver_kind"] = questionary.select(
        "Select Falco driver kind (eBPF is recommended for modern kernels):",
        choices=[
            {"name": "eBPF probe (modern kernels, default)", "value": "ebpf"},
            {"name": "Kernel module (legacy)", "value": "module"},
            {"name": "Userspace instrumentation (modern_ebpf, specific environments)", "value": "modern_ebpf"}
        ]
    ).ask()

    console.print("\nFalco Event Sources:")
    options["audit_log_enabled"] = questionary.confirm(
        "Enable Kubernetes Audit Log as an event source? (Requires separate audit log setup)",
        default=False
    ).ask()

    console.print("\nFalco Alerting:")
    options["json_output"] = questionary.confirm(
        "Enable JSON output for Falco logs? (Recommended for easier parsing by alert watchers)",
        default=True
    ).ask()

    options["log_level"] = questionary.select(
        "Set Falco log level:",
        choices=["critical", "error", "warning", "notice", "info", "debug"],
        default="info"
    ).ask()
    
    console.print("\nFalco Resource Configuration:")
    options["set_resources"] = questionary.confirm(
        "Set custom resource requests and limits for Falco? (Recommended for resource-constrained environments)",
        default=True
    ).ask()

    if options.get("set_resources"):
        console.print(Text("Enter values in Kubernetes format (e.g., CPU: '100m', Memory: '256Mi').", style="dim"))
        options["cpu_request"] = questionary.text("Enter CPU request:", default="100m").ask()
        options["mem_request"] = questionary.text("Enter Memory request:", default="256Mi").ask()
        options["cpu_limit"] = questionary.text("Enter CPU limit:", default="500m").ask()
        options["mem_limit"] = questionary.text("Enter Memory limit:", default="512Mi").ask()

    console.print(Panel(
        Text.from_markup(
            "For advanced configuration, including custom rules, you may need to provide a custom values.yaml file to Helm.\n"
            "Refer to the official Falco Helm chart documentation for all available options."
        ),
        title="[dim]Advanced Configuration Note[/dim]",
        border_style="dim"
    ))

    return options

def _check_falco_pods_status(namespace: str, release_name: str):
    """Checks the status of Falco pods after installation attempt."""
    if not K8S_CLIENT_LOADED:
        console.print("[yellow]Kubernetes client library not found. Cannot check pod status.[/yellow]")
        return

    try:
        try:
            config.load_kube_config()
        except config.ConfigException:
            pass

        v1 = client.CoreV1Api()
        console.print(f"\nChecking status of Falco pods in namespace '{namespace}' (release: '{release_name}')...")
        label_selector = f"app.kubernetes.io/name=falco,app.kubernetes.io/instance={release_name}"
        pods = v1.list_namespaced_pod(namespace, label_selector=label_selector, timeout_seconds=10)

        if not pods.items:
            console.print(f"[yellow]No Falco pods found with label '{label_selector}' in namespace '{namespace}'. It might take a few moments for them to appear.[/yellow]")
            return

        table = Table(title=f"Falco Pod Status ({namespace})")
        table.add_column("Pod Name", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Restarts", style="yellow")
        table.add_column("Node", style="magenta")

        for pod in pods.items:
            status = pod.status.phase
            restarts = sum(cs.restart_count for cs in pod.status.container_statuses) if pod.status.container_statuses else 0
            node_name = pod.spec.node_name if pod.spec else "N/A"
            status_style = "green" if status in ["Running", "Succeeded"] else "bold red"
            table.add_row(pod.metadata.name, Text(status, style=status_style), str(restarts), node_name)
        console.print(table)
        console.print("Use 'kubectl get pods -n falco' and 'kubectl logs -n falco -l app.kubernetes.io/name=falco' for more details.")

    except ApiException as e:
        console.print(f"[bold red]Error checking Falco pod status: {e.reason} (Status: {e.status})[/bold red]")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred while checking pod status: {e}[/bold red]")


# --- Main Execution ---
def run_falco_installer():
    """Main function to drive Falco installation."""
    console.rule("[bold green]Kubernetes Falco Installer[/bold green]", style="green")

    if not _check_helm_installed():
        return

    if not _add_update_falco_repo():
        console.print("[red]Failed to set up Falco Helm repository. Cannot proceed with Falco installation.[/red]")
        return

    install_options = _get_installation_options()
    namespace = install_options["namespace"]

    helm_cmd = [
        'helm', 'upgrade', '--install', HELM_RELEASE_NAME, FALCO_CHART_NAME,
        '--namespace', namespace,
        '--create-namespace' 
    ]

    helm_cmd.extend(['--set', f'driver.kind={install_options["driver_kind"]}'])
    if install_options["driver_kind"] == "modern_ebpf":
        helm_cmd.extend(['--set', 'driver.loader.modernEbpf.enabled=true'])

    helm_cmd.extend(['--set', f'auditLog.enabled={str(install_options["audit_log_enabled"]).lower()}'])
    
    # FIXED: Use the correct key `json_output` instead of `jsonOutput`
    helm_cmd.extend(['--set', f'falco.json_output={str(install_options["json_output"]).lower()}'])
    
    helm_cmd.extend(['--set', f'falco.logLevel={install_options["log_level"]}'])
    
    if install_options.get("set_resources"):
        if install_options.get("cpu_request"):
            helm_cmd.extend(['--set', f'falco.resources.requests.cpu={install_options["cpu_request"]}'])
        if install_options.get("mem_request"):
            helm_cmd.extend(['--set', f'falco.resources.requests.memory={install_options["mem_request"]}'])
        if install_options.get("cpu_limit"):
            helm_cmd.extend(['--set', f'falco.resources.limits.cpu={install_options["cpu_limit"]}'])
        if install_options.get("mem_limit"):
            helm_cmd.extend(['--set', f'falco.resources.limits.memory={install_options["mem_limit"]}'])

    console.print("\n[bold]Prepared Helm command:[/bold]")
    console.print(f"  {' '.join(helm_cmd)}")

    confirm_helm_install = questionary.confirm("\nProceed with Falco installation using the command above?", default=True).ask()
    if confirm_helm_install is None:
        console.print("Falco installation aborted by user.")
        return
    if not confirm_helm_install:
        console.print("Falco installation aborted by user.")
        return

    console.print(f"\nInstalling Falco '{HELM_RELEASE_NAME}' into namespace '{namespace}'...")
    try:
        process = subprocess.run(helm_cmd, capture_output=True, text=True, check=False) 

        if process.returncode == 0:
            console.print(Panel(
                Text.from_markup(f"[green]Falco '{HELM_RELEASE_NAME}' installation/upgrade initiated successfully![/green]\n"
                                 f"{process.stdout.strip()}"),
                title="[green]Helm Output[/green]", border_style="green"
            ))
            if process.stderr:
                 console.print(Panel(Text(process.stderr.strip(), style="yellow"), title="[yellow]Helm Stderr (Warnings/Info)[/yellow]", border_style="yellow"))
            _check_falco_pods_status(namespace, HELM_RELEASE_NAME)
        else:
            console.print(Panel(
                Text.from_markup(f"[bold red]Falco installation failed. Return code: {process.returncode}[/bold red]\n"
                                 f"Stdout:\n{process.stdout.strip()}\n\n"
                                 f"Stderr:\n{process.stderr.strip()}"),
                title="[bold red]Helm Error[/bold red]", border_style="red"
            ))
            return
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred during Helm execution: {e}[/bold red]")
        return

    console.print("\n[bold green]Falco installation process complete.[/bold green]")
    console.print("It may take a few minutes for all Falco components to be fully operational.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Install Falco on Kubernetes using Helm.")
    args = parser.parse_args()

    try:
        run_falco_installer()
    except (KeyboardInterrupt, EOFError):
        console.print("\n\n[yellow]Falco installation process aborted by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]An unhandled error occurred: {e}[/bold red]")
        sys.exit(1)
