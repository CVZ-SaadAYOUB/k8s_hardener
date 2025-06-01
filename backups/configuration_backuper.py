#!/usr/bin/env python3
"""
Kubernetes Configuration Backuper
Fetches and saves common Kubernetes resource configurations as YAML files.
"""

import os
import sys
import yaml
import argparse
from typing import Dict, List, Any, Optional, Tuple

from rich.console import Console
from rich.text import Text
from rich.panel import Panel # <--- ADD THIS LINE
import questionary

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    # This will be handled in the run function

console = Console()

# Define system namespaces to skip by default
SYSTEM_NAMESPACE_PREFIXES = ['kube-', 'kubernetes-', 'istio-', 'calico-', 'falco-', 'gatekeeper-']

# Define resources to back up
# Format: (kind, api_group_method_name, list_method_name, is_namespaced)
# api_group_method_name refers to the attribute name in 'client' (e.g., CoreV1Api, AppsV1Api)
RESOURCES_TO_BACKUP: List[Tuple[str, str, str, bool]] = [
    # Cluster-scoped
    ("Namespace", "CoreV1Api", "list_namespace", False),
    ("ClusterRole", "RbacAuthorizationV1Api", "list_cluster_role", False),
    ("ClusterRoleBinding", "RbacAuthorizationV1Api", "list_cluster_role_binding", False),
    # Namespaced
    ("Deployment", "AppsV1Api", "list_deployment_for_all_namespaces", True), # Fetches across all then filters
    ("StatefulSet", "AppsV1Api", "list_stateful_set_for_all_namespaces", True),
    ("DaemonSet", "AppsV1Api", "list_daemon_set_for_all_namespaces", True),
    ("Service", "CoreV1Api", "list_service_for_all_namespaces", True),
    ("ConfigMap", "CoreV1Api", "list_config_map_for_all_namespaces", True),
    ("Secret", "CoreV1Api", "list_secret_for_all_namespaces", True),
    ("Role", "RbacAuthorizationV1Api", "list_role_for_all_namespaces", True),
    ("RoleBinding", "RbacAuthorizationV1Api", "list_role_binding_for_all_namespaces", True),
    ("ServiceAccount", "CoreV1Api", "list_service_account_for_all_namespaces", True),
    ("Ingress", "NetworkingV1Api", "list_ingress_for_all_namespaces", True),
    ("NetworkPolicy", "NetworkingV1Api", "list_network_policy_for_all_namespaces", True),
    ("PersistentVolumeClaim", "CoreV1Api", "list_persistent_volume_claim_for_all_namespaces", True),
    ("CronJob", "BatchV1Api", "list_cron_job_for_all_namespaces", True),
    ("Job", "BatchV1Api", "list_job_for_all_namespaces", True),
]

def _init_kube_clients() -> Optional[Dict[str, Any]]:
    """Initializes and returns a dictionary of Kubernetes API clients."""
    if not K8S_AVAILABLE:
        console.print("[bold red]Kubernetes Python client library is not installed. Please install it: pip install kubernetes[/bold red]")
        return None
    try:
        try:
            config.load_incluster_config()
            console.print("[info]Using in-cluster Kubernetes configuration.[/info]")
        except config.ConfigException:
            config.load_kube_config()
            console.print("[info]Using local kubeconfig file.[/info]")
        
        return {
            "CoreV1Api": client.CoreV1Api(),
            "AppsV1Api": client.AppsV1Api(),
            "RbacAuthorizationV1Api": client.RbacAuthorizationV1Api(),
            "NetworkingV1Api": client.NetworkingV1Api(),
            "BatchV1Api": client.BatchV1Api(),
            # Add other APIs as needed for more resources
        }
    except config.ConfigException as e:
        console.print(f"[bold red]Could not configure Kubernetes client: {e}[/bold red]")
        console.print("Ensure a valid kubeconfig or in-cluster role with appropriate permissions.")
        return None
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred initializing Kubernetes clients: {e}[/bold red]")
        return None

def _clean_resource_dict(resource_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Removes runtime and managed fields from a resource dictionary."""
    cleaned_dict = resource_dict.copy() # Work on a copy

    # Remove top-level status
    if "status" in cleaned_dict:
        del cleaned_dict["status"]

    # Clean metadata
    if "metadata" in cleaned_dict and isinstance(cleaned_dict["metadata"], dict):
        metadata = cleaned_dict["metadata"]
        fields_to_remove = [
            "uid", "selfLink", "resourceVersion", "creationTimestamp",
            "deletionTimestamp", "deletionGracePeriodSeconds", "generation",
            "managedFields", "annotations" # Often contains kubectl last-applied or controller info
        ]
        # Selectively keep some annotations if needed, but for backup, often good to remove all
        # For example, to keep specific user annotations:
        # kept_annotations = {}
        # if "annotations" in metadata:
        # for k, v in metadata["annotations"].items():
        # if not k.startswith("kubectl.kubernetes.io/") and not k.startswith("deployment.kubernetes.io/"):
        # kept_annotations[k] = v
        # metadata["annotations"] = kept_annotations
        # if not metadata["annotations"]:
        # del metadata["annotations"]

        for field in fields_to_remove:
            if field in metadata:
                del metadata[field]
    return cleaned_dict

def _save_resource_to_yaml(resource: Any, base_dir: str, kind: str, is_namespaced: bool):
    """Saves a single Kubernetes resource object to a YAML file."""
    resource_dict = client.ApiClient().sanitize_for_serialization(resource)
    cleaned_dict = _clean_resource_dict(resource_dict)

    name = resource.metadata.name
    namespace = resource.metadata.namespace if is_namespaced and hasattr(resource.metadata, 'namespace') else None

    if is_namespaced:
        if not namespace: # Should not happen if API returns correct objects
            console.print(f"[yellow]Warning: Skipping namespaced resource '{kind}/{name}' as it lacks namespace info.[/yellow]")
            return
        # Skip system namespaces
        if any(namespace.startswith(prefix) for prefix in SYSTEM_NAMESPACE_PREFIXES):
            console.print(f"[dim]Skipping resource '{kind}/{name}' in system namespace '{namespace}'[/dim]")
            return
        
        resource_path_parts = [base_dir, namespace, kind]
    else: # Cluster-scoped
        resource_path_parts = [base_dir, "cluster_scoped", kind]

    resource_dir = os.path.join(*resource_path_parts)
    os.makedirs(resource_dir, exist_ok=True)

    file_path = os.path.join(resource_dir, f"{name}.yaml")

    try:
        with open(file_path, 'w') as f:
            yaml.dump(cleaned_dict, f, sort_keys=False, indent=2)
        console.print(f"  Backed up: [cyan]{kind}/{ (namespace + '/') if namespace else ''}{name}[/cyan] to [green]{file_path}[/green]")
        if kind == "Secret":
            console.print(f"    [bold yellow]Warning: Secret '{name}' in namespace '{namespace}' backed up. Contents are sensitive.[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]Error saving {kind} '{name}' to {file_path}: {e}[/bold red]")


def run(cli_args=None):
    """Main function to perform configuration backup."""
    console.print(Panel(Text.from_markup("[bold u]Kubernetes Configuration Backuper[/bold u]"), style="bold green", expand=False))

    if not K8S_AVAILABLE:
        console.print("[bold red]Exiting: Kubernetes Python client is required but not installed.[/bold red]")
        return

    backup_base_dir = None
    if cli_args and hasattr(cli_args, 'output_dir') and cli_args.output_dir:
        backup_base_dir = cli_args.output_dir
        console.print(f"[info]Using output directory from main program: {backup_base_dir}[/info]")
    else:
        default_dir = os.path.join(os.getcwd(), "k8s_config_backup")
        backup_base_dir = questionary.text(
            "Enter the base directory to save Kubernetes configurations:",
            default=default_dir
        ).ask()
        if not backup_base_dir:
            console.print("[yellow]No backup directory specified. Exiting.[/yellow]")
            return

    try:
        if not os.path.exists(backup_base_dir):
            os.makedirs(backup_base_dir, exist_ok=True)
            console.print(f"Backup directory created: [blue]{backup_base_dir}[/blue]")
        else:
            console.print(f"Using existing backup directory: [blue]{backup_base_dir}[/blue]")
    except Exception as e:
        console.print(f"[bold red]Error with backup directory '{backup_base_dir}': {e}[/bold red]")
        return

    api_clients = _init_kube_clients()
    if not api_clients:
        console.print("[bold red]Failed to initialize Kubernetes API clients. Cannot proceed with backup.[/bold red]")
        return

    console.print("\n[bold]Starting Kubernetes configuration backup process...[/bold]")

    for kind, api_client_name, list_method_name, is_namespaced in RESOURCES_TO_BACKUP:
        console.rule(f"[bold blue]Backing up {kind}s[/bold blue]")
        
        api_client_instance = api_clients.get(api_client_name)
        if not api_client_instance:
            console.print(f"[bold red]  Error: API client '{api_client_name}' not available. Skipping {kind}s.[/bold red]")
            continue
        
        list_method = getattr(api_client_instance, list_method_name, None)
        if not list_method:
            console.print(f"[bold red]  Error: List method '{list_method_name}' not found on '{api_client_name}'. Skipping {kind}s.[/bold red]")
            continue

        try:
            # For methods like list_xxx_for_all_namespaces, no specific namespace arg is needed here.
            # For truly cluster-scoped that don't have "for_all_namespaces" in their list method:
            if is_namespaced: # Methods like list_deployment_for_all_namespaces handle this
                 ret = list_method()
            else: # Cluster-scoped like list_namespace, list_cluster_role
                 ret = list_method()


            if not ret.items:
                console.print(f"  No {kind}s found.")
                continue
            
            console.print(f"  Found {len(ret.items)} {kind}(s).")
            for item in ret.items:
                _save_resource_to_yaml(item, backup_base_dir, kind, is_namespaced)

        except ApiException as e:
            console.print(f"[bold red]  API Error listing {kind}s: {e.status} - {e.reason}[/bold red]")
            if e.body:
                try:
                    error_body = yaml.safe_load(e.body) # Or json.loads(e.body)
                    console.print(f"  Error details: {error_body.get('message', e.body[:200])}") # Print first 200 chars of body if message not found
                except:
                    console.print(f"  Error details (raw): {e.body[:200]}")


        except Exception as e:
            console.print(f"[bold red]  Unexpected error listing {kind}s: {e}[/bold red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")


    console.print(Panel("[bold green]Kubernetes configuration backup process finished.[/bold green]", expand=False))

if __name__ == "__main__":
    # Standalone execution will prompt for directory or use default if this script's own args are not set
    parser = argparse.ArgumentParser(description="Backup Kubernetes configurations.")
    parser.add_argument(
        "--output-dir",
        help="Base directory to save backups. If not provided, will prompt or use default 'k8s_config_backup'."
    )
    # Add other specific args for standalone if needed in future

    args = parser.parse_args()
    
    # When run standalone, cli_args passed to run() will be the parsed args from here.
    # This allows --output-dir to work for standalone execution.
    # If --output-dir is not given, `args.output_dir` will be None, and `run` will prompt.
    try:
        run(cli_args=args) 
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Backup process aborted by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]A critical error occurred: {e}[/bold red]")
        import traceback
        console.print(traceback.format_exc())
        sys.exit(1)