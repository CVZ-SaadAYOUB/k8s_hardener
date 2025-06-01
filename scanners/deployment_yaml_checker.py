#!/usr/bin/env python3
"""
Kubernetes Deployment YAML Checker
Scans a directory for Kubernetes deployment YAML files and checks for common security concerns.
"""
import os
import yaml
from typing import List, Dict, Any, Optional, Tuple # Retained Optional and Tuple though not explicitly used in visible changes for future-proofing

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
import questionary
import sys # Retained for sys.exit in standalone mode

console = Console()

# --- Security Check Definitions ---

def check_privileged(container: Dict[str, Any], path_prefix: str) -> List[str]:
    """Checks for privileged containers."""
    findings = []
    if container.get('securityContext', {}).get('privileged') is True:
        findings.append(f"{path_prefix}.securityContext.privileged: Container is running as privileged.")
    return findings

def check_host_namespaces(spec: Dict[str, Any], path_prefix: str) -> List[str]:
    """Checks for hostPID, hostIPC, hostNetwork."""
    findings = []
    if spec.get('hostPID') is True:
        findings.append(f"{path_prefix}.hostPID: Pod is using host PID namespace.")
    if spec.get('hostIPC') is True:
        findings.append(f"{path_prefix}.hostIPC: Pod is using host IPC namespace.")
    if spec.get('hostNetwork') is True:
        findings.append(f"{path_prefix}.hostNetwork: Pod is using host network.")
    return findings

def check_run_as_non_root(container: Dict[str, Any], path_prefix: str) -> List[str]:
    """Checks for runAsNonRoot."""
    findings = []
    sc = container.get('securityContext', {})
    if sc.get('runAsNonRoot') is not True: # Checks for False or not present
        findings.append(f"{path_prefix}.securityContext.runAsNonRoot: Container is not configured to run as non-root (should be true).")
    # Also check runAsUser explicitly if runAsNonRoot is not set or false
    if sc.get('runAsNonRoot') is not True and sc.get('runAsUser') == 0:
        findings.append(f"{path_prefix}.securityContext.runAsUser: Container is explicitly running as root (UID 0).")

    return findings

def check_allow_privilege_escalation(container: Dict[str, Any], path_prefix: str) -> List[str]:
    """Checks for allowPrivilegeEscalation."""
    findings = []
    sc = container.get('securityContext', {})
    if sc.get('allowPrivilegeEscalation') is True: # Explicitly true is bad. Default is true if not set, but policy should enforce false.
        findings.append(f"{path_prefix}.securityContext.allowPrivilegeEscalation: Container allows privilege escalation.")
    elif 'allowPrivilegeEscalation' not in sc:
         findings.append(f"{path_prefix}.securityContext.allowPrivilegeEscalation: Not set (defaults to true). Recommend setting to false.")
    return findings


def check_readonly_root_filesystem(container: Dict[str, Any], path_prefix: str) -> List[str]:
    """Checks for readOnlyRootFilesystem."""
    findings = []
    sc = container.get('securityContext', {})
    if sc.get('readOnlyRootFilesystem') is not True:
        findings.append(f"{path_prefix}.securityContext.readOnlyRootFilesystem: Root filesystem is not read-only (should be true).")
    return findings

def check_resource_limits_requests(container: Dict[str, Any], path_prefix: str) -> List[str]:
    """Checks for CPU/Memory limits and requests."""
    findings = []
    resources = container.get('resources', {})
    if not resources.get('limits', {}).get('cpu'):
        findings.append(f"{path_prefix}.resources.limits.cpu: CPU limit not set.")
    if not resources.get('limits', {}).get('memory'):
        findings.append(f"{path_prefix}.resources.limits.memory: Memory limit not set.")
    if not resources.get('requests', {}).get('cpu'):
        findings.append(f"{path_prefix}.resources.requests.cpu: CPU request not set.")
    if not resources.get('requests', {}).get('memory'):
        findings.append(f"{path_prefix}.resources.requests.memory: Memory request not set.")
    return findings

def check_latest_tag(container: Dict[str, Any], path_prefix: str) -> List[str]:
    """Checks for ':latest' image tag."""
    findings = []
    image_name = container.get('image', '')
    if ':' not in image_name or image_name.endswith(':latest'):
        findings.append(f"{path_prefix}.image: Image '{image_name}' uses 'latest' tag or no tag (implicitly latest).")
    return findings

def check_capabilities(container: Dict[str, Any], path_prefix: str) -> List[str]:
    """Checks container capabilities."""
    findings = []
    sc = container.get('securityContext', {})
    capabilities = sc.get('capabilities', {})
    if 'drop' not in capabilities or "ALL" not in capabilities.get('drop', []):
        findings.append(f"{path_prefix}.securityContext.capabilities.drop: Consider dropping 'ALL' capabilities and adding only required ones in 'add'.")
    if capabilities.get('add'):
        common_risky_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"] # Add more as needed
        added_caps = capabilities.get('add', [])
        risky_added = [cap for cap in added_caps if cap in common_risky_caps]
        if risky_added:
            findings.append(f"{path_prefix}.securityContext.capabilities.add: Contains potentially risky capabilities: {', '.join(risky_added)}.")
    return findings

def check_automount_service_account_token(pod_spec: Dict[str, Any], path_prefix: str) -> List[str]:
    """Checks automountServiceAccountToken for the Pod spec."""
    findings = []
    # True is the default if not set.
    if 'automountServiceAccountToken' not in pod_spec or pod_spec.get('automountServiceAccountToken') is True:
        findings.append(f"{path_prefix}.automountServiceAccountToken: Is 'true' or not set (default is true). Consider setting to 'false' if service account token is not needed by the pod, or use a specific service account.")
    return findings


CONTAINER_CHECKS = [
    check_privileged,
    check_run_as_non_root,
    check_allow_privilege_escalation,
    check_readonly_root_filesystem,
    check_resource_limits_requests,
    check_latest_tag,
    check_capabilities,
]

POD_SPEC_CHECKS = [
    check_host_namespaces,
    check_automount_service_account_token,
]

# --- YAML Processing ---

def scan_yaml_file(file_path: str) -> Dict[str, List[str]]:
    """Scans a single YAML file for deployments and their security issues."""
    findings_per_deployment: Dict[str, List[str]] = {}
    try:
        with open(file_path, 'r') as f:
            docs = list(yaml.safe_load_all(f)) # Use safe_load_all for multi-document YAMLs
        
        for doc_index, doc in enumerate(docs):
            if not doc or not isinstance(doc, dict): # Skip empty or non-dict documents
                continue

            if doc.get('kind') == 'Deployment':
                deployment_name = doc.get('metadata', {}).get('name', f"UnnamedDeployment_Doc{doc_index}")
                current_findings: List[str] = []
                
                pod_template_spec = doc.get('spec', {}).get('template', {}).get('spec', {})
                if not pod_template_spec:
                    current_findings.append("Deployment does not have a valid .spec.template.spec section.")
                    findings_per_deployment[deployment_name] = current_findings
                    continue

                # Pod-level checks
                pod_path_prefix = f"Deployment '{deployment_name}'.spec.template.spec"
                for check_func in POD_SPEC_CHECKS:
                    current_findings.extend(check_func(pod_template_spec, pod_path_prefix))


                # Container-level checks
                containers = pod_template_spec.get('containers', [])
                for i, container in enumerate(containers):
                    container_name = container.get('name', f"container_{i}")
                    path_prefix = f"Deployment '{deployment_name}'.spec.template.spec.containers['{container_name}']"
                    for check_func in CONTAINER_CHECKS:
                        current_findings.extend(check_func(container, path_prefix))
                
                init_containers = pod_template_spec.get('initContainers', [])
                for i, init_container in enumerate(init_containers):
                    container_name = init_container.get('name', f"initContainer_{i}")
                    path_prefix = f"Deployment '{deployment_name}'.spec.template.spec.initContainers['{container_name}']"
                    for check_func in CONTAINER_CHECKS: # Apply same checks to init containers
                        current_findings.extend(check_func(init_container, path_prefix))

                if current_findings:
                    findings_per_deployment[deployment_name] = current_findings
            
            # Could add checks for other kinds like StatefulSet, DaemonSet similarly

    except yaml.YAMLError as e:
        console.print(Text(f"Error parsing YAML file {file_path}: {e}", style="bold red"))
        findings_per_deployment[f"YAML_Parse_Error_{os.path.basename(file_path)}"] = [str(e)]
    except Exception as e:
        console.print(Text(f"Unexpected error processing file {file_path}: {e}", style="bold red"))
        findings_per_deployment[f"Processing_Error_{os.path.basename(file_path)}"] = [str(e)]
        
    return findings_per_deployment

# --- Reporting ---

def display_findings(file_path: str, findings_per_deployment: Dict[str, List[str]]):
    """Displays findings for a single file."""
    base_name = os.path.basename(file_path)
    if not findings_per_deployment:
        console.print(Panel(f"[green]No significant security concerns found in deployments within '{base_name}'.[/green]", title=f"Scan Results: {base_name}", border_style="green"))
        return

    console.print(Panel(f"[yellow]Security Review for Deployments in '{base_name}':[/yellow]", title=f"Scan Results: {base_name}", border_style="yellow"))
    
    for deployment_name, issues in findings_per_deployment.items():
        if not issues: 
            console.print(f"\n[green]No issues found for Deployment: [bold]{deployment_name}[/bold][/green]")
            continue

        table = Table(title=f"Deployment: [bold blue]{deployment_name}[/bold blue]")
        table.add_column("Concern Path / Details", style="dim", overflow="fold")
        table.add_column("Recommendation / Finding", style="red")

        for issue in issues:
            parts = issue.split(":", 1)
            path = parts[0]
            finding_text = parts[1].strip() if len(parts) > 1 else "Details missing"
            table.add_row(path, finding_text)
        console.print(table)

# --- Main Execution ---

def run():
    # Removed argparse logic
    # parser = argparse.ArgumentParser(
    #     description="Scan Kubernetes Deployment YAML files in a directory for security concerns.",
    #     prog="deployment_yaml_checker.py"
    # )
    # parser.add_argument(
    #     "directory",
    #     type=str,
    #     help="Directory containing Kubernetes YAML files to scan."
    # )
    # args = parser.parse_args()

    console.print(Text("\n--- Starting Kubernetes Deployment YAML Checker ---", style="bold green"))

    # Prompt user for the directory
    target_directory = questionary.text(
        "Enter the directory containing Kubernetes YAML files to scan:",
        validate=lambda path: True if os.path.isdir(path) else "Path is not a valid directory or does not exist."
    ).ask()

    if not target_directory:
        console.print(Text("No directory provided. Exiting.", style="yellow"))
        # If called from main.py, sys.exit() might be too abrupt.
        # Consider returning or raising an error for main.py to handle.
        # For now, exiting if no directory is given.
        sys.exit(0) 
        return # Added return to be safe, though sys.exit should halt.

    # Use the prompted directory instead of args.directory
    if not os.path.isdir(target_directory): # Double check, though questionary validate should handle this
        console.print(Text(f"Error: Directory '{target_directory}' not found or is not a directory.", style="bold red"))
        sys.exit(1) # Exit if not a valid directory after prompt

    yaml_files_found = False
    for root, _, files in os.walk(target_directory):
        for file in files:
            if file.endswith((".yaml", ".yml")):
                yaml_files_found = True
                file_path = os.path.join(root, file)
                console.print(f"\nScanning file: [cyan]{file_path}[/cyan]...")
                findings = scan_yaml_file(file_path)
                display_findings(file_path, findings)
    
    if not yaml_files_found:
        console.print(Text(f"No YAML files (.yaml or .yml) found in directory '{target_directory}'.", style="yellow"))

    console.print(Text("\nDeployment YAML checking finished.", style="bold green"))

if __name__ == "__main__":
    # import sys # sys is already imported at the top
    try:
        run()
    except (KeyboardInterrupt, EOFError):
        console.print(Text("\nScan aborted by user.", style="yellow"))
        sys.exit(0)
    except Exception as e:
        import traceback
        console.print(Text(f"[bold red]Critical error during execution:[/bold red]", style="red"))
        console.print(traceback.format_exc()) 
        sys.exit(1)