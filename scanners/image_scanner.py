#!/usr/bin/env python3
"""
Kubernetes Image Scanner
Scans container images for vulnerabilities using Trivy.
Allows selecting images from running pods or specifying manually.
"""
import sys
import argparse
import subprocess
import json # To parse Trivy's JSON output
from typing import Dict, List, Any, Optional

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

from rich.console import Console
from rich.table import Table
from rich.text import Text
import questionary

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.config import ConfigException

console = Console()

# --- External Tool Check ---

def _check_trivy_installed() -> bool:
    """Checks if the Trivy binary is available in the PATH."""
    try:
        subprocess.run(['trivy', '--version'], check=True, capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        console.print(Text("\n[bold red]Error:[/bold red] Trivy command not found or failed to run.", style="bold red"))
        console.print(Text("Please install Trivy: https://github.com/aquasecurity/trivy#installation", style="yellow"))
        return False

# --- Kubernetes Client Setup ---
# Reusing helper pattern
def _get_k8s_api_clients() -> Optional[client.CoreV1Api]:
    """Load Kubernetes configuration and return a CoreV1Api client."""
    try:
        config.load_incluster_config()
        logging.info("Using in-cluster Kubernetes configuration.")
    except ConfigException:
        try:
            config.load_kube_config()
            logging.info("Using kubeconfig file configuration.")
        except ConfigException:
            logging.error("Could not configure Kubernetes client. Make sure you are inside a cluster or have a valid kubeconfig.")
            console.print(Text(
                 "Could not configure Kubernetes client. Ensure a valid kubeconfig or in-cluster env.",
                 style="bold red"
            ))
            return None # Return None if client cannot be configured

    try:
        return client.CoreV1Api()
    except Exception as e:
        logging.error(f"Error initializing Kubernetes CoreV1Api client: {e}")
        console.print(Text(f"Error initializing Kubernetes CoreV1Api client: {e}", style="bold red"))
        return None


# --- Image Source Selection ---

def _get_images_from_cluster(api: Optional[client.CoreV1Api]) -> List[str]:
    """Fetches a list of unique image names from running pods."""
    if not api:
        console.print(Text("Skipping cluster image fetch: Kubernetes API not connected.", style="yellow"))
        return []

    console.print(Text("\nFetching images from running pods...", style="blue"))
    images = set()
    try:
        # List pods across all namespaces
        pods = api.list_pod_for_all_namespaces(watch=False).items
        for pod in pods:
            for container in pod.spec.containers:
                images.add(container.image)
            if pod.spec.init_containers:
                for init_container in pod.spec.init_containers:
                     images.add(init_container.image)
            if pod.spec.ephemeral_containers:
                 for ephemeral_container in pod.spec.ephemeral_containers:
                     images.add(ephemeral_container.image)


        logging.info(f"Found {len(images)} unique images in cluster pods.")
        return sorted(list(images))

    except ApiException as e:
        console.print(Text(f"Error listing pods to get images: {e}", style="red"))
        logging.error(f"Error listing pods: {e}")
        return []
    except Exception as e:
        console.print(Text(f"An unexpected error occurred fetching images: {e}", style="red"))
        logging.error(f"Unexpected error fetching images: {e}")
        return []


def _select_images_to_scan(api: Optional[client.CoreV1Api]) -> List[str]:
    """Prompts user to select images to scan, from cluster or manually."""
    images_to_scan: List[str] = []

    source_choice = questionary.select(
        "Select image source:",
        choices=[
            "Select from running pods in the cluster",
            "Manually enter image name(s)",
            "Cancel"
        ]
    ).ask()

    if source_choice == "Cancel":
        return []

    if source_choice == "Select from running pods in the cluster":
        cluster_images = _get_images_from_cluster(api)
        if not cluster_images:
            console.print(Text("No images found in the cluster or failed to connect.", style="yellow"))
            # Fallback to manual entry? Or let user try manual? Let user choose.
            fallback_to_manual = questionary.confirm("Do you want to enter image names manually instead?").ask()
            if fallback_to_manual:
                 return _select_images_to_scan(api) # Recursively call for manual entry
            else:
                 return [] # User chose not to enter manually


        selected_images = questionary.checkbox(
            "Select images to scan (use spacebar, Enter to confirm):",
            choices=cluster_images
        ).ask()
        return selected_images if selected_images else []

    elif source_choice == "Manually enter image name(s)":
        console.print(Text("\nEnter image names one by one (leave empty to finish):", style="blue"))
        manual_images = []
        while True:
            image_name = questionary.text("Image name (e.g., nginx:latest, ubuntu):").ask()
            if not image_name:
                break
            manual_images.append(image_name.strip())
        return manual_images if manual_images else []

    return [] # Should not be reached

# --- Trivy Scanning ---

def _run_trivy_scan(image_name: str) -> Optional[Dict[str, Any]]:
    """Runs Trivy scan on an image and returns parsed JSON output."""
    if not _check_trivy_installed():
        return None # Should be caught before calling, but defensive check

    console.print(Text(f"\nRunning Trivy scan for image: [bold blue]{image_name}[/bold blue]...", style="blue"))

    try:
        # Run trivy image scan, outputting JSON
        result = subprocess.run(
            ['trivy', 'image', '--format', 'json', image_name],
            check=True, # Raise CalledProcessError on non-zero exit (unless it's a known Trivy exit code for vulnerabilities found)
            capture_output=True,
            text=True # Decode stdout/stderr as text
        )

        # Trivy can return non-zero even if scan was successful but vulnerabilities were found (exit codes 1 or 2).
        # We should check the exit code but primarily rely on parsing the JSON.
        if result.returncode != 0 and result.returncode not in [1, 2]: # 0: no vulns, 1: vulns found, 2: scan failed
             logging.error(f"Trivy scan failed for {image_name} with exit code {result.returncode}")
             console.print(Text(f"[bold red]Trivy scan failed for {image_name}:[/bold red] Exit Code {result.returncode}\n{result.stderr}", style="bold red"))
             return None

        # Attempt to parse JSON output
        try:
            scan_output = json.loads(result.stdout)
            return scan_output
        except json.JSONDecodeError:
            logging.error(f"Failed to parse Trivy JSON output for {image_name}")
            console.print(Text(f"[bold red]Failed to parse Trivy JSON output for {image_name}:[/bold red]\n{result.stdout}\n{result.stderr}", style="bold red"))
            return None

    except FileNotFoundError:
        # This case should be caught by _check_trivy_installed, but included for robustness
        console.print(Text("[bold red]Error:[/bold red] Trivy command not found during scan execution.", style="bold red"))
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during Trivy scan for {image_name}: {e}")
        console.print(Text(f"[bold red]An unexpected error occurred during scan for {image_name}:[/bold red] {e}", style="bold red"))
        return None


# --- Reporting ---

def _display_scan_results(image_name: str, scan_data: Optional[Dict[str, Any]]) -> None:
    """Displays formatted scan results from parsed Trivy output."""
    console.print(Text(f"\n--- Scan Results for [bold blue]{image_name}[/bold blue] ---", style="bold green"))

    if scan_data is None:
        console.print(Text("Could not retrieve or parse scan results.", style="red"))
        return

    if not scan_data.get('Results'):
        console.print(Text("No security issues found (or results format unexpected).", style="green"))
        return

    # Iterate through each result object (filesystem, packages, etc.)
    for result_obj in scan_data['Results']:
        target = result_obj.get('Target', 'Unknown Target')
        vulnerabilities = result_obj.get('Vulnerabilities')
        misconfigurations = result_obj.get('Misconfigurations')
        secrets = result_obj.get('Secrets')

        if vulnerabilities:
            console.print(Text(f"\n[bold]Vulnerabilities found in {target}:[/bold]", style="magenta"))
            vuln_table = Table(title=f"Vulnerabilities ({target})")
            vuln_table.add_column("Vulnerability ID", style="bold")
            vuln_table.add_column("Severity", style="bold")
            vuln_table.add_column("Package", style="bold")
            vuln_table.add_column("Version")
            vuln_table.add_column("Fix Version")
            vuln_table.add_column("Title")

            # Sort vulnerabilities by severity (Critical > High > Medium > Low)
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
            sorted_vulns = sorted(vulnerabilities, key=lambda x: severity_order.get(x.get('Severity', 'UNKNOWN').upper(), 4))


            for vuln in sorted_vulns:
                severity = vuln.get('Severity', 'Unknown').upper()
                severity_style = "bold red" if severity == "CRITICAL" else "bold magenta" if severity == "HIGH" else "bold yellow" if severity == "MEDIUM" else "green" if severity == "LOW" else "white"

                vuln_table.add_row(
                    Text(vuln.get('VulnerabilityID', 'N/A'), style="cyan"),
                    Text(severity, style=severity_style),
                    vuln.get('PkgName', 'N/A'),
                    vuln.get('InstalledVersion', 'N/A'),
                    vuln.get('FixedVersion', 'None'),
                    Text(vuln.get('Title', 'N/A'), style="dim"),
                     # Could add more details like Description, PrimaryURL if needed
                )
            console.print(vuln_table)

        if misconfigurations:
             console.print(Text(f"\n[bold]Misconfigurations found in {target}:[/bold]", style="magenta"))
             mco_table = Table(title=f"Misconfigurations ({target})")
             mco_table.add_column("ID", style="bold")
             mco_table.add_column("Severity", style="bold")
             mco_table.add_column("Type")
             mco_table.add_column("Message")
             mco_table.add_column("Resolution")

             # Sort misconfigurations by severity
             severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
             sorted_mcos = sorted(misconfigurations, key=lambda x: severity_order.get(x.get('Severity', 'UNKNOWN').upper(), 4))


             for mco in sorted_mcos:
                 severity = mco.get('Severity', 'Unknown').upper()
                 severity_style = "bold red" if severity == "CRITICAL" else "bold magenta" if severity == "HIGH" else "bold yellow" if severity == "MEDIUM" else "green" if severity == "LOW" else "white"
                 mco_table.add_row(
                      mco.get('ID', 'N/A'),
                      Text(severity, style=severity_style),
                      mco.get('Type', 'N/A'),
                      mco.get('Message', 'N/A'),
                      mco.get('Resolution', 'N/A'),
                 )
             console.print(mco_table)


        if secrets:
             console.print(Text(f"\n[bold]Secrets found in {target}:[/bold]", style="magenta"))
             secrets_table = Table(title=f"Secrets ({target})")
             secrets_table.add_column("Category", style="bold")
             secrets_table.add_column("Severity", style="bold")
             secrets_table.add_column("Title")
             secrets_table.add_column("Match")

             # Sort secrets by severity
             severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4} # Secrets can also have severities
             sorted_secrets = sorted(secrets, key=lambda x: severity_order.get(x.get('Severity', 'UNKNOWN').upper(), 4))

             for secret in sorted_secrets:
                 severity = secret.get('Severity', 'Unknown').upper()
                 severity_style = "bold red" if severity == "CRITICAL" else "bold magenta" if severity == "HIGH" else "bold yellow" if severity == "MEDIUM" else "green" if severity == "LOW" else "white"
                 secrets_table.add_row(
                     secret.get('Category', 'N/A'),
                     Text(severity, style=severity_style),
                     secret.get('Title', 'N/A'),
                     secret.get('Match', 'N/A'),
                 )
             console.print(secrets_table)


        if not vulnerabilities and not misconfigurations and not secrets:
             console.print(Text(f"No vulnerabilities, misconfigurations, or secrets found in {target}.", style="green"))


    console.print(Text("\n--- End of Scan Results ---", style="bold green"))


# --- Main Execution Function ---

def run():
    """
    Entry point function called by main.py or when the script is run directly.
    Interactively scans container images using Trivy.
    """
    parser = argparse.ArgumentParser(
        description="Scan container images for vulnerabilities using Trivy.",
        prog="image_scanner.py"
    )
    # Could add args like --image <name>, --selector <label=value> later
    args = parser.parse_args()

    console.print(Text("\n--- Starting Image Scan ---", style="bold green")) # <--- This is the correct header

    if not _check_trivy_installed():
        # The check function already prints error message
        return # Exit if Trivy is not installed

    # Get K8s API client to potentially list cluster images
    k8s_client = _get_k8s_api_clients()
    if not k8s_client:
         console.print(Text("Warning: Could not connect to Kubernetes API. Will only be able to scan manually entered images.", style="yellow"))
         # k8s_client remains None, _select_images_to_scan will handle this

    images_to_scan = _select_images_to_scan(k8s_client)

    if not images_to_scan:
        console.print(Text("\nNo images selected for scanning. Exiting.", style="yellow"))
        return

    all_scan_results: Dict[str, Optional[Dict[str, Any]]] = {}

    for image in images_to_scan:
        scan_data = _run_trivy_scan(image)
        all_scan_results[image] = scan_data
        # Display results immediately after each scan
        _display_scan_results(image, scan_data)

    # Could add options here to save aggregated results or generate a report


    console.print(Text("\nImage scanning finished.", style="bold green"))


# --- Standalone Execution ---

if __name__ == "__main__":
    run()