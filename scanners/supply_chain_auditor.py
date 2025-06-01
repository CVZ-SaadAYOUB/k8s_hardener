#!/usr/bin/env python3
"""
Kubernetes Supply Chain Auditor
Audits container images for supply chain security aspects like SBOMs and signatures.
"""
import sys
import argparse
import subprocess
import json
import os
from typing import Dict, List, Any, Optional
import logging
import tempfile

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.syntax import Syntax
import questionary

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    from kubernetes.config import ConfigException # Ensure this is imported if used directly
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    logging.warning("Kubernetes library not found. Cluster-related features will be disabled.")

console = Console()

# --- External Tool Checks ---

def _check_tool_installed(tool_name: str, install_url: str) -> bool:
    """Checks if a given command-line tool is available in the PATH."""
    try:
        subprocess.run([tool_name, '--version'], check=True, capture_output=True, text=True)
        logging.info(f"{tool_name} is installed.")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        console.print(Panel(
            Text.from_markup(
                f"[bold red]Error: '{tool_name}' command not found or failed to run.[/bold red]\n"
                f"This tool is required for some audit functions.\n"
                f"Please install {tool_name}: {install_url}"
            ),
            title="[bold red]Tool Not Found[/bold red]",
            border_style="red"
        ))
        return False

# --- Kubernetes Client Setup (Optional) ---
def _get_k8s_api_client() -> Optional[client.CoreV1Api]:
    """Load Kubernetes configuration and return a CoreV1Api client if available."""
    if not K8S_AVAILABLE:
        return None
    try:
        config.load_incluster_config()
        logging.info("Using in-cluster Kubernetes configuration.")
    except ConfigException:
        try:
            config.load_kube_config()
            logging.info("Using kubeconfig file configuration.")
        except ConfigException:
            logging.warning("Could not configure Kubernetes client (no in-cluster or kubeconfig).")
            return None
    try:
        return client.CoreV1Api()
    except Exception as e:
        logging.error(f"Error initializing Kubernetes CoreV1Api client: {e}")
        return None

# --- Image Source Selection ---

def _get_images_from_cluster(api: client.CoreV1Api, namespace: Optional[str] = None) -> List[str]:
    """Fetches a list of unique image names from running pods, optionally filtered by namespace."""
    images = set()
    ns_message = f"in namespace '{namespace}'" if namespace else "across all namespaces"
    console.print(Text(f"\nFetching images from running pods {ns_message}...", style="blue"))
    try:
        if namespace:
            pods = api.list_namespaced_pod(namespace, watch=False, timeout_seconds=10).items
        else:
            pods = api.list_pod_for_all_namespaces(watch=False, timeout_seconds=10).items

        for pod in pods:
            for container in pod.spec.containers:
                images.add(container.image)
            if pod.spec.init_containers:
                for init_container in pod.spec.init_containers:
                    images.add(init_container.image)
            if hasattr(pod.spec, 'ephemeral_containers') and pod.spec.ephemeral_containers:
                for ephemeral_container in pod.spec.ephemeral_containers:
                    images.add(ephemeral_container.image)
        
        logging.info(f"Found {len(images)} unique images in cluster pods {ns_message}.")
        return sorted(list(images))
    except ApiException as e:
        console.print(Text(f"Error listing pods: {e.reason} (Status: {e.status})", style="red"))
        logging.error(f"Error listing pods: {e}")
    except Exception as e: 
        console.print(Text(f"An unexpected error occurred fetching images: {e}", style="red"))
        logging.error(f"Unexpected error fetching images: {e}")
    return []


def _select_images_to_audit(k8s_api: Optional[client.CoreV1Api], requested_namespace: Optional[str]) -> List[str]:
    """Prompts user to select images to audit."""
    choices = ["Manually enter image name(s)"]
    if k8s_api:
        choices.insert(0, "Select from running pods in the cluster")
    choices.append("Cancel")

    source_choice = questionary.select(
        "Select image source for auditing:",
        choices=choices
    ).ask()

    if source_choice == "Cancel" or source_choice is None:
        return []

    if source_choice == "Select from running pods in the cluster" and k8s_api:
        namespace_to_scan = requested_namespace
        if not namespace_to_scan and K8S_AVAILABLE: # K8S_AVAILABLE check here is redundant if k8s_api is present but good for clarity
            try:
                namespaces_items = k8s_api.list_namespace().items
                namespaces = [ns.metadata.name for ns in namespaces_items]
                if not namespaces:
                    console.print(Text("No namespaces found in the cluster.", style="yellow"))
                else:
                    scan_all_ns = questionary.confirm("Scan all namespaces?", default=True).ask()
                    if not scan_all_ns: # User wants to select a specific namespace
                        # Add "All" option to allow user to revert to scanning all after choosing not to
                        ns_choices = ["All"] + sorted(namespaces)
                        selected_ns_choice = questionary.select("Select namespace:", choices=ns_choices).ask()
                        if selected_ns_choice == "All": 
                            namespace_to_scan = None # Scan all namespaces
                        elif not selected_ns_choice: # User cancelled namespace selection
                            return [] 
                        else:
                            namespace_to_scan = selected_ns_choice
            except ApiException as e:
                console.print(Text(f"Could not list namespaces: {e.reason}", style="red"))
            except Exception as e:
                console.print(Text(f"An unexpected error occurred fetching namespaces: {e}", style="red"))

        cluster_images = _get_images_from_cluster(k8s_api, namespace_to_scan)
        if not cluster_images:
            console.print(Text("No images found in the cluster or failed to connect.", style="yellow"))
            if questionary.confirm("Do you want to enter image names manually instead?").ask():
                return _manual_image_entry()
            return []
        
        selected_images = questionary.checkbox(
            "Select images to audit (space to select, enter to confirm):",
            choices=cluster_images
        ).ask()
        return selected_images if selected_images else []

    elif source_choice == "Manually enter image name(s)":
        return _manual_image_entry()
    return []

def _manual_image_entry() -> List[str]:
    """Handles manual entry of image names."""
    console.print(Text("\nEnter image names one by one (leave empty to finish):", style="blue"))
    manual_images = []
    while True:
        image_name = questionary.text("Image name (e.g., alpine:latest, gcr.io/my-project/my-image:v1):").ask()
        if not image_name:
            break
        manual_images.append(image_name.strip())
    return manual_images

# --- SBOM Generation ---

def _generate_sbom_with_trivy(image_name: str, output_dir: str, sbom_format: str = "cyclonedx") -> Optional[str]:
    """Generates SBOM for an image using Trivy and returns the path to the SBOM file."""
    if not _check_tool_installed("trivy", "https://github.com/aquasecurity/trivy#installation"):
        return None

    console.print(f"\nGenerating SBOM ({sbom_format}) for [bold blue]{image_name}[/bold blue]...")
    
    safe_image_name = image_name.replace('/', '_').replace(':', '_')
    sbom_filename = f"sbom_{safe_image_name}.{sbom_format}.json"
    sbom_filepath = os.path.join(output_dir, sbom_filename)

    command = [
        'trivy', 'image',
        '--format', sbom_format,
        '--output', sbom_filepath,
        '--quiet', 
        image_name
    ]
    try:
        process = subprocess.run(command, check=True, capture_output=True, text=True)
        if process.returncode == 0: # Technically, check=True means this will always be 0 unless an exception is raised
            console.print(f"SBOM generated successfully: [cyan]{sbom_filepath}[/cyan]")
            return sbom_filepath
        # else block is largely unreachable if check=True is effective
        # else:
        #     logging.error(f"Trivy SBOM generation for {image_name} failed. Exit code: {process.returncode}")
        #     console.print(f"[bold red]Trivy SBOM generation failed for {image_name}:[/bold red]")
        #     if process.stdout: console.print(f"Stdout:\n{process.stdout}")
        #     if process.stderr: console.print(f"Stderr:\n{process.stderr}")
        #     return None
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error running Trivy for SBOM generation on {image_name}:[/bold red]\n{e.stderr or e.stdout}")
        logging.error(f"Trivy subprocess error for {image_name}: {e}")
        return None
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred during SBOM generation for {image_name}:[/bold red] {e}")
        logging.error(f"Unexpected error during SBOM generation for {image_name}: {e}")
        return None

def _display_sbom_summary(sbom_filepath: str):
    """Displays a summary of the generated SBOM."""
    try:
        with open(sbom_filepath, 'r') as f:
            sbom_data = json.load(f)
        
        components = sbom_data.get('components', [])
        metadata_component = sbom_data.get('metadata', {}).get('component', {}) # Corrected to metadata.component
        image_id = metadata_component.get('name', os.path.basename(sbom_filepath)) # Fallback for image_id
        bom_format = sbom_data.get('bomFormat', 'Unknown').lower()

        console.print(Panel(
            f"[bold]SBOM Summary for:[/bold] {image_id}\n"
            f"[bold]Format:[/bold] {bom_format.capitalize()}\n"
            f"[bold]Total Components:[/bold] {len(components)}\n"
            f"[bold]SBOM File:[/bold] [cyan]{sbom_filepath}[/cyan]",
            title="[green]SBOM Details[/green]",
            expand=False
        ))

        if components and questionary.confirm("Display first few components from SBOM?", default=False).ask():
            table = Table(title=f"Top Components from SBOM ({os.path.basename(sbom_filepath)})")
            table.add_column("Name", style="cyan")
            table.add_column("Version", style="magenta")
            table.add_column("Type", style="yellow")
            table.add_column("BOM-Ref", style="dim", overflow="fold")

            for comp in components[:10]: 
                table.add_row(
                    comp.get('name', 'N/A'),
                    comp.get('version', 'N/A'),
                    comp.get('type', 'N/A'),
                    comp.get('bom-ref', 'N/A')
                )
            console.print(table)
        
        if questionary.confirm("View full SBOM content?", default=False).ask():
            with open(sbom_filepath, 'r') as f_content:
                content = f_content.read()
            console.print(Syntax(content, "json", theme="native", line_numbers=True))

    except json.JSONDecodeError:
        console.print(f"[red]Error: Could not parse SBOM file {sbom_filepath}. Not valid JSON.[/red]")
    except FileNotFoundError:
        console.print(f"[red]Error: SBOM file {sbom_filepath} not found.[/red]")
    except Exception as e:
        console.print(f"[red]Error displaying SBOM summary: {e}[/red]")

# --- Image Signature Verification ---

def _check_image_signature_with_cosign(image_name: str) -> None:
    """Checks image signature using Cosign."""
    if not _check_tool_installed("cosign", "https://docs.sigstore.dev/cosign/installation/"): # Corrected URL
        return

    console.print(f"\nVerifying signature for [bold blue]{image_name}[/bold blue] with Cosign...")
    env = os.environ.copy()

    try:
        process = subprocess.run(['cosign', 'verify', image_name], capture_output=True, text=True, env=env, timeout=60) # Increased timeout
        
        if process.returncode == 0:
            console.print(Panel(
                Text.from_markup(f"[green]Signature VERIFIED for {image_name}![/green]\n\n"
                f"[bold]Cosign Output:[/bold]\n{process.stdout.strip()}\n\n"
                f"[italic]Stderr (if any):[/italic]\n{process.stderr.strip()}"),
                title="[green]Cosign Verification Success[/green]",
                border_style="green"
            ))
        else:
            console.print(Panel(
                Text.from_markup(f"[yellow]Signature verification FAILED or no signatures found for {image_name}.[/yellow]\n"
                f"Return code: {process.returncode}\n\n"
                f"[bold]Cosign Stderr:[/bold]\n{process.stderr.strip() or '(empty)'}\n\n"
                f"[italic]Stdout (if any):[/italic]\n{process.stdout.strip() or '(empty)'}"),
                title="[yellow]Cosign Verification Failed/No Signature[/yellow]",
                border_style="yellow"
            ))
            if "no matching signatures" in process.stderr.lower() or \
               "could not get valid tlog entry" in process.stderr.lower() or \
               "experimental" in process.stderr.lower(): # Broader check for experimental hint
                 if questionary.confirm("Verification failed. Try again with experimental keyless features (COSIGN_EXPERIMENTAL=1)?", default=False).ask():
                    env_exp = env.copy()
                    env_exp["COSIGN_EXPERIMENTAL"] = "1"
                    console.print("Retrying with COSIGN_EXPERIMENTAL=1...")
                    process_exp = subprocess.run(['cosign', 'verify', image_name], capture_output=True, text=True, env=env_exp, timeout=60)
                    if process_exp.returncode == 0:
                        console.print(Panel(
                            Text.from_markup(f"[green]Signature VERIFIED for {image_name} with COSIGN_EXPERIMENTAL=1![/green]\n\n"
                            f"[bold]Cosign Output:[/bold]\n{process_exp.stdout.strip()}\n\n"
                            f"[italic]Stderr (if any):[/italic]\n{process_exp.stderr.strip()}"),
                            title="[green]Cosign Verification Success (Experimental)[/green]",
                            border_style="green"
                        ))
                    else:
                        console.print(Panel(
                            Text.from_markup(f"[yellow]Signature verification FAILED (experimental) for {image_name}.[/yellow]\n"
                            f"Return code: {process_exp.returncode}\n\n"
                            f"[bold]Cosign Stderr:[/bold]\n{process_exp.stderr.strip() or '(empty)'}\n\n"
                            f"[italic]Stdout (if any):[/italic]\n{process_exp.stdout.strip() or '(empty)'}"),
                            title="[yellow]Cosign Verification Failed (Experimental)[/yellow]",
                            border_style="yellow"
                        ))
    except subprocess.TimeoutExpired:
        console.print(f"[red]Cosign verification for {image_name} timed out.[/red]")
    except FileNotFoundError: 
        console.print("[red]Cosign command not found (should have been checked).[/red]")
    except Exception as e:
        console.print(f"[red]An unexpected error occurred during Cosign verification for {image_name}:[/red] {e}")

# --- Main Execution ---

def run(cli_args=None): # Accept arguments from main.py
    local_args = None
    if cli_args: # Called from main.py
        args = cli_args
    else: # Standalone execution
        parser = argparse.ArgumentParser(
            description="Audit container images for supply chain security (SBOMs, signatures).",
            prog="supply_chain_auditor.py"
        )
        parser.add_argument(
            "--image",
            type=str,
            help="Specify a single image name to audit directly. Skips interactive selection."
        )
        parser.add_argument(
            "--namespace",
            "-n",
            type=str,
            help="Kubernetes namespace to filter images from (if selecting from cluster)."
        )
        parser.add_argument(
            "--sbom-dir", # This will be used if output_dir is not provided via cli_args
            type=str,
            default=os.path.join(tempfile.gettempdir(), "k8s_hardener_sboms"),
            help="Directory to store generated SBOM files (used if not called from main_menu with output_dir)."
        )
        parser.add_argument(
            "--skip-sbom",
            action="store_true",
            help="Skip SBOM generation and analysis."
        )
        parser.add_argument(
            "--skip-signature-check",
            action="store_true",
            help="Skip image signature verification."
        )
        args = parser.parse_args()
        local_args = args # Keep a reference to locally parsed args if needed

    console.print(Panel(Text.from_markup("[bold u]Supply Chain Auditor[/bold u]"), style="bold green", expand=False))

    # Determine the effective SBOM directory
    # Prioritize output_dir from main.py's args if available and not skipping SBOMs
    effective_sbom_dir = getattr(args, 'output_dir', None) if not getattr(args, 'skip_sbom', False) else None
    
    if not effective_sbom_dir and not getattr(args, 'skip_sbom', False) : # If output_dir wasn't passed or if it's a standalone run
        effective_sbom_dir = getattr(args, 'sbom_dir', os.path.join(tempfile.gettempdir(), "k8s_hardener_sboms"))

    # Create SBOM output directory if it doesn't exist and SBOMs are not skipped
    if effective_sbom_dir and not getattr(args, 'skip_sbom', False) : # Check if effective_sbom_dir is set
        if not os.path.exists(effective_sbom_dir):
            try:
                os.makedirs(effective_sbom_dir, exist_ok=True)
                console.print(f"SBOMs will be saved to: [cyan]{effective_sbom_dir}[/cyan]")
            except OSError as e:
                console.print(f"[red]Error creating SBOM directory {effective_sbom_dir}: {e}. Using default temp dir for SBOMs.[/red]")
                effective_sbom_dir = tempfile.gettempdir() 
        else:
             console.print(f"SBOMs will be saved to: [cyan]{effective_sbom_dir}[/cyan]")


    k8s_api_client: Optional[client.CoreV1Api] = None
    # Use getattr to safely access attributes that might not be on cli_args
    arg_image = getattr(args, 'image', None)
    arg_namespace = getattr(args, 'namespace', None)

    if K8S_AVAILABLE and (not arg_image or arg_namespace):
        k8s_api_client = _get_k8s_api_client()
        if not k8s_api_client and not arg_image:
             console.print("[yellow]Warning: Kubernetes client not available. Cluster image selection is disabled.[/yellow]")

    images_to_audit: List[str] = []
    if arg_image:
        images_to_audit = [arg_image]
        console.print(f"Auditing image specified via CLI: [cyan]{arg_image}[/cyan]")
    else:
        images_to_audit = _select_images_to_audit(k8s_api_client, arg_namespace)

    if not images_to_audit:
        console.print(Text("\nNo images selected or specified for auditing. Returning to menu.", style="yellow"))
        return # Changed from sys.exit(0)

    console.print(f"\nSelected {len(images_to_audit)} image(s) for audit: [yellow]{', '.join(images_to_audit)}[/yellow]")

    # Safely get skip_sbom and skip_signature_check flags
    skip_sbom_flag = getattr(args, 'skip_sbom', False)
    skip_signature_check_flag = getattr(args, 'skip_signature_check', False)

    for image in images_to_audit:
        console.rule(f"[bold]Auditing: {image}[/bold]", style="blue")

        if not skip_sbom_flag:
            if questionary.confirm(f"Generate SBOM for '{image}'?", default=True).ask():
                if not effective_sbom_dir: # Should not happen if skip_sbom is false, but a safeguard
                    console.print("[red]SBOM output directory not set. Skipping SBOM generation.[/red]")
                else:
                    sbom_file = _generate_sbom_with_trivy(image, effective_sbom_dir)
                    if sbom_file:
                        _display_sbom_summary(sbom_file)
            else:
                console.print(f"Skipping SBOM generation for {image}.")
        else:
            console.print("SBOM generation skipped via command-line argument or settings.")

        if not skip_signature_check_flag:
            if questionary.confirm(f"Check signature for '{image}' with Cosign?", default=True).ask():
                _check_image_signature_with_cosign(image)
            else:
                console.print(f"Skipping signature check for {image}.")
        else:
            console.print("Signature check skipped via command-line argument or settings.")
        
        console.print("") 

    console.print(Panel("[bold green]Supply chain audit finished.[/bold green]", expand=False))

if __name__ == "__main__":
    try:
        run() # cli_args will be None, so internal argparse runs
    except (KeyboardInterrupt, EOFError): 
        console.print(Text("\nAudit aborted by user.", style="yellow"))
        sys.exit(0) # sys.exit is fine for standalone execution
    except Exception as e:
        logging.error(f"A critical error occurred in supply_chain_auditor: {e}", exc_info=True)
        console.print(Panel(Text.from_markup(f"[bold red]Critical Unhandled Error:[/bold red]\n{e}"), title="[bold red] Auditor Error [/bold red]"))
        sys.exit(1) # sys.exit is fine for standalone execution