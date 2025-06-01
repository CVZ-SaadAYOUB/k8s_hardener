#!/usr/bin/env python3
"""
Falco Alert Watcher for Kubernetes
Streams and displays Falco alerts from Falco pods in a Kubernetes cluster.
"""
import sys
import argparse
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict # <<< Make sure this line is present and includes Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
import questionary

try:
    from kubernetes import client, config, watch
    from kubernetes.client.rest import ApiException
    K8S_CLIENT_LOADED = True
except ImportError:
    K8S_CLIENT_LOADED = False
    # This script heavily relies on the Kubernetes client.
    # A proper error will be raised in main if it's not available.

console = Console()

# --- Kubernetes API Interaction ---

def _get_k8s_api_client() -> Optional[client.CoreV1Api]:
    """Loads Kubernetes configuration and returns a CoreV1Api client."""
    if not K8S_CLIENT_LOADED:
        console.print("[bold red]Kubernetes Python client is not installed. Please install it: pip install kubernetes[/bold red]")
        return None
    try:
        # Try loading in-cluster config first, then kube_config
        try:
            config.load_incluster_config()
            console.print("[info]Using in-cluster Kubernetes configuration.[/info]")
        except config.ConfigException:
            config.load_kube_config()
            console.print("[info]Using local kubeconfig file.[/info]")
        return client.CoreV1Api()
    except config.ConfigException as e:
        console.print(f"[bold red]Could not configure Kubernetes client: {e}[/bold red]")
        console.print("Ensure you have a valid kubeconfig file or are running within a cluster.")
        return None
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred while initializing Kubernetes client: {e}[/bold red]")
        return None


def _find_falco_pods(api: client.CoreV1Api, namespace: str) -> List[client.V1Pod]:
    """Finds Falco pods in the specified namespace."""
    pods_found = []
    try:
        # Common labels for Falco pods installed via Helm chart
        label_selector = "app.kubernetes.io/name=falco"
        pod_list = api.list_namespaced_pod(namespace, label_selector=label_selector, timeout_seconds=10)
        pods_found = [pod for pod in pod_list.items if pod.status.phase == "Running"]
        if not pods_found: # Try another common label if the first one fails
            label_selector_alt = "app=falco" # Older or different Falco chart versions
            pod_list_alt = api.list_namespaced_pod(namespace, label_selector=label_selector_alt, timeout_seconds=10)
            pods_found = [pod for pod in pod_list_alt.items if pod.status.phase == "Running"]

    except ApiException as e:
        console.print(f"[bold red]Error listing Falco pods in namespace '{namespace}': {e.reason} (Status: {e.status})[/bold red]")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred finding Falco pods: {e}[/bold red]")
    return pods_found

# --- Alert Processing and Display ---

PRIORITY_COLORS = {
    "emergency": "bold white on red",
    "alert": "bold red",
    "critical": "red",
    "error": "bright_red",
    "warning": "yellow",
    "notice": "cyan",
    "informational": "blue",
    "debug": "dim"
}

def _parse_falco_log_entry(log_line: str) -> Optional[Dict]:
    """Parses a Falco log line (expected to be JSON)."""
    try:
        alert = json.loads(log_line)
        # Ensure essential fields are present to consider it a Falco alert
        if "output" in alert and "priority" in alert and "rule" in alert and "time" in alert:
            return alert
    except json.JSONDecodeError:
        # Not a JSON line, or not a Falco alert; could be other Falco container logs
        logging.debug(f"Non-JSON or non-alert log line: {log_line[:100]}...")
    return None

def _format_alert_for_display(alert: Dict) -> Panel:
    """Formats a parsed Falco alert into a Rich Panel."""
    priority = alert.get("priority", "unknown").lower()
    color = PRIORITY_COLORS.get(priority, "white")

    timestamp_str = alert.get("time", "")
    try:
        # Falco timestamps are often like "2023-05-15T10:20:30.123456789Z"
        dt_obj = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        formatted_time = dt_obj.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
    except ValueError:
        formatted_time = timestamp_str # Fallback to raw string

    title_text = Text.from_markup(f"[{color}]Priority: {priority.upper()}[/{color}] | Rule: {alert.get('rule', 'N/A')}")

    content = Text()
    content.append(f"Time: {formatted_time}\n", style="dim")
    content.append(f"Output: {alert.get('output', 'N/A')}\n", style="default")

    fields = alert.get("output_fields", {})
    if fields and isinstance(fields, dict): # Ensure fields is a dictionary
        content.append("Fields:\n", style="bold")
        for key, value in fields.items():
            if value is not None: # Don't print NoneType values
                 content.append(f"  - {key}: {value}\n", style="dim")

    return Panel(content, title=title_text, border_style=color, expand=False)

# --- Main Execution ---

MAX_ALERTS_DISPLAYED = 20 # Keep this many alerts in the live view
displayed_alerts_panels: List[Panel] = []

def update_live_display(live: Live) -> None:
    """Generates the content for the live display."""
    render_group = displayed_alerts_panels # Directly use the list of panels
    live.update(Panel(render_group, title="[bold cyan]Falco Alerts Stream[/bold cyan]", border_style="cyan"))

def run_alert_watcher(args):
    """Main function to watch and display Falco alerts."""
    if not K8S_CLIENT_LOADED:
        console.print("[bold red]Cannot start alert watcher: Kubernetes Python client is not installed.[/bold red]")
        console.print("Please run: pip install kubernetes")
        sys.exit(1)

    k8s_api = _get_k8s_api_client()
    if not k8s_api:
        sys.exit(1)

    falco_namespace = args.namespace
    if not falco_namespace:
        falco_namespace = questionary.text(
            "Enter the namespace where Falco is running:",
            default="falco"
        ).ask()
        if not falco_namespace:
            console.print("[red]Namespace cannot be empty. Exiting.[/red]")
            return

    console.print(f"Searching for running Falco pods in namespace '{falco_namespace}'...")
    falco_pods = _find_falco_pods(k8s_api, falco_namespace)

    if not falco_pods:
        console.print(f"[yellow]No running Falco pods found in namespace '{falco_namespace}'.[/yellow]")
        console.print("Ensure Falco is installed and running correctly.")
        return

    selected_pod_name: Optional[str] = None
    if len(falco_pods) == 1:
        selected_pod_name = falco_pods[0].metadata.name
        console.print(f"Found one Falco pod: [cyan]{selected_pod_name}[/cyan]")
    else:
        pod_choices = [pod.metadata.name for pod in falco_pods]
        selected_pod_name = questionary.select(
            "Multiple Falco pods found. Select one to stream logs from:",
            choices=pod_choices
        ).ask()
        if not selected_pod_name:
            console.print("No pod selected. Exiting.")
            return
    
    console.print(f"Attempting to stream logs from Falco pod: [cyan]{selected_pod_name}[/cyan] in namespace [cyan]{falco_namespace}[/cyan]")
    
    since_seconds_val = None
    if args.since:
        try:
            # Parse Helm-like duration string e.g., "5m", "1h", "10s"
            if args.since.endswith('s'):
                since_seconds_val = int(args.since[:-1])
            elif args.since.endswith('m'):
                since_seconds_val = int(args.since[:-1]) * 60
            elif args.since.endswith('h'):
                since_seconds_val = int(args.since[:-1]) * 3600
            else:
                since_seconds_val = int(args.since) # Assume seconds if no suffix
            console.print(f"Fetching logs from the last {args.since} ({since_seconds_val} seconds).")
        except ValueError:
            console.print(f"[yellow]Invalid --since format '{args.since}'. Ignoring.[/yellow]")


    console.print("\n[bold]Watching for Falco alerts... Press Ctrl+C to stop.[/bold]")

    try:
        w = watch.Watch()
        stream_kwargs = {
            "name": selected_pod_name,
            "namespace": falco_namespace,
            "container": "falco",  # Falco container name within the pod
            "follow": True,
            "_preload_content": False, # Important for streaming
            "timestamps": True # Include timestamps in logs from K8s
        }
        if since_seconds_val is not None:
            stream_kwargs["since_seconds"] = since_seconds_val

        with Live(console=console, refresh_per_second=4, transient=True) as live_display:
            update_live_display(live_display) # Initial empty display
            
            for raw_line in w.stream(k8s_api.read_namespaced_pod_log, **stream_kwargs):
                decoded_line = raw_line.decode('utf-8').strip()
                
                # Kubernetes log lines often have a timestamp prefix, try to strip it for JSON parsing
                # e.g., "2023-05-19T12:34:56.789012345Z {\"output\": ...}"
                json_start_index = decoded_line.find('{')
                if json_start_index != -1:
                    potential_json = decoded_line[json_start_index:]
                    alert = _parse_falco_log_entry(potential_json)
                    if alert:
                        alert_panel = _format_alert_for_display(alert)
                        displayed_alerts_panels.insert(0, alert_panel) # Add to the top
                        if len(displayed_alerts_panels) > MAX_ALERTS_DISPLAYED:
                            displayed_alerts_panels.pop() # Remove oldest
                        update_live_display(live_display)
                else:
                    logging.debug(f"Skipping non-JSON line fragment: {decoded_line[:100]}")

    except ApiException as e:
        if e.status == 404: # Pod not found
            console.print(f"[bold red]Error: Falco pod '{selected_pod_name}' not found in namespace '{falco_namespace}'. It might have been deleted.[/bold red]")
        else:
            console.print(f"[bold red]Kubernetes API Error while streaming logs: {e.reason} (Status: {e.status})[/bold red]")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred while streaming logs: {e}[/bold red]")
    finally:
        w.stop()
        console.print("\nAlert watcher stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Watch Falco alerts from Kubernetes pod logs.")
    parser.add_argument(
        "--namespace", "-n",
        type=str,
        help="Namespace where Falco is running (e.g., falco). Will prompt if not provided."
    )
    parser.add_argument(
        "--since", "-s",
        type=str,
        help="Show logs since a relative duration (e.g., 5m, 1h, 10s). If not specified, streams live logs only."
    )
    args = parser.parse_args()

    try:
        run_alert_watcher(args)
    except (KeyboardInterrupt, EOFError):
        console.print("\n\n[yellow]Alert watcher terminated by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]An unhandled error occurred in alert_watcher: {e}[/bold red]")
        # import traceback
        # console.print(traceback.format_exc()) # For debugging
        sys.exit(1)