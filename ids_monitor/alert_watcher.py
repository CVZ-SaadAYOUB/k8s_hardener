#!/usr/bin/env python3
"""
Falco Alert Watcher for Kubernetes
Streams and displays Falco alerts from Falco pods in an interactive, scrollable view.
"""
import sys
import argparse
import json
import time
import logging
import os
import threading
from datetime import datetime
from typing import Optional, List, Dict

# This script now requires the 'readchar' library.
# Please install it using: pip install readchar
try:
    import readchar
except ImportError:
    print("Error: 'readchar' library not found. Please run 'pip install readchar' to install it.")
    sys.exit(1)

from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text
import questionary

try:
    from kubernetes import client, config, watch
    from kubernetes.client.rest import ApiException
    K8S_CLIENT_LOADED = True
except ImportError:
    K8S_CLIENT_LOADED = False

# --- Global State Variables ---
console = Console()
logging.basicConfig(level=logging.WARNING, format='%(levelname)s:%(message)s')

all_alerts: List[Text] = []
alert_lock = threading.Lock()
scroll_position = 0
is_paused = False  # New state variable for pausing the live feed
exit_event = threading.Event()

# --- Kubernetes API Interaction ---

def _get_k8s_api_client() -> Optional[client.CoreV1Api]:
    """Loads Kubernetes configuration and returns a CoreV1Api client."""
    if not K8S_CLIENT_LOADED:
        console.print("[bold red]Kubernetes Python client is not installed. Please install it: pip install kubernetes[/bold red]")
        return None
    try:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        # Suppress info messages unless debugging
        # console.print("[info]Using local kubeconfig file.[/info]")
        return client.CoreV1Api()
    except config.ConfigException as e:
        console.print(f"[bold red]Could not configure Kubernetes client: {e}[/bold red]")
        return None
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred while initializing Kubernetes client: {e}[/bold red]")
        return None


def _find_falco_pods(api: client.CoreV1Api, namespace: str) -> List[client.V1Pod]:
    """Finds Falco pods in the specified namespace."""
    pods_found = []
    try:
        label_selector = "app.kubernetes.io/name=falco"
        pod_list = api.list_namespaced_pod(namespace, label_selector=label_selector, timeout_seconds=10)
        pods_found = [pod for pod in pod_list.items if pod.status.phase == "Running"]
        if not pods_found:
            label_selector_alt = "app=falco"
            pod_list_alt = api.list_namespaced_pod(namespace, label_selector=label_selector_alt, timeout_seconds=10)
            pods_found = [pod for pod in pod_list_alt.items if pod.status.phase == "Running"]
    except ApiException as e:
        console.print(f"[bold red]Error listing Falco pods in namespace '{namespace}': {e.reason} (Status: {e.status})[/bold red]")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred finding Falco pods: {e}[/bold red]")
    return pods_found


# --- Alert Formatting ---

PRIORITY_COLORS = {
    "emergency": "bold white on dark_red",
    "alert": "bold red",
    "critical": "bold red",
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
        if "output" in alert and "priority" in alert and "rule" in alert:
            return alert
    except json.JSONDecodeError:
        logging.debug(f"Non-JSON line: {log_line[:100]}...")
    return None

def _format_alert_for_display(alert: Dict) -> Text:
    """Formats a parsed Falco alert into a Rich Text object."""
    priority = alert.get("priority", "unknown").lower()
    color = PRIORITY_COLORS.get(priority, "white")
    timestamp_str = alert.get("time", "")
    try:
        dt_obj = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        formatted_time = dt_obj.strftime("%Y-%m-%d %H:%M:%S") + " UTC"
    except ValueError:
        formatted_time = timestamp_str

    alert_text = Text()
    alert_text.append(f"Priority: {priority.upper()} | Rule: {alert.get('rule', 'N/A')}\n", style=color)
    alert_text.append(f"Time: {formatted_time}\n", style="dim")
    
    output_fields = alert.get("output_fields", {})
    if output_fields and isinstance(output_fields, dict):
        alert_text.append("Details:\n", style="bold")
        for key, value in output_fields.items():
            if value is None: continue
            field_name = f"  - {key}: "
            field_value = str(value)
            
            style = "cyan"
            value_style = "default"
            if key == "k8s.pod.name": value_style = "bold white on blue"
            elif key == "fd.cip": value_style = "bold white on red"
            
            alert_text.append(field_name, style=style)
            alert_text.append(field_value + "\n", style=value_style)
    else:
        alert_text.append("Output: " + alert.get('output', 'N/A'))
    
    return alert_text

# --- Log Streaming Thread ---

def stream_k8s_logs(k8s_api: client.CoreV1Api, pod_name: str, namespace: str, since: Optional[int]):
    """Runs in a background thread to fetch logs and add them to the global list."""
    global scroll_position
    w = watch.Watch()
    stream_kwargs = {
        "name": pod_name,
        "namespace": namespace,
        "container": "falco",
        "follow": True,
        "_preload_content": False,
        "timestamps": True
    }
    if since:
        stream_kwargs["since_seconds"] = since

    try:
        for raw_line in w.stream(k8s_api.read_namespaced_pod_log, **stream_kwargs):
            if exit_event.is_set():
                break
            
            decoded_line = raw_line.strip()
            if not decoded_line: continue

            json_start_index = decoded_line.find('{')
            if json_start_index != -1:
                potential_json = decoded_line[json_start_index:]
                alert = _parse_falco_log_entry(potential_json)
                if alert:
                    alert_text = _format_alert_for_display(alert)
                    with alert_lock:
                        all_alerts.insert(0, alert_text)
                        # If not paused, jump to the top to show the new alert
                        if not is_paused:
                            scroll_position = 0
    except ApiException as e:
        console.print(f"\n[bold red]Log stream stopped due to API error: {e.reason}[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]Log stream stopped due to unexpected error: {e}[/bold red]")
    finally:
        w.stop()
        exit_event.set()

# --- Display and Input Handling ---

def redraw_display():
    """Clears the screen and redraws the alerts based on the current scroll position."""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # UPDATED: Header now shows mode and new controls
    mode_text = "[bold green]LIVE[/]" if not is_paused else "[bold yellow]PAUSED[/]"
    controls_text = "UP/DOWN: Scroll | SPACE: Pause/Resume | R: Refresh to Top | Q: Quit"
    header_text = f"{mode_text} | {controls_text}"

    header = Panel(
        Text(header_text, justify="center"),
        title="[bold cyan]Falco Alerts Stream[/bold cyan]",
        border_style="cyan"
    )
    console.print(header)
    
    with alert_lock:
        if not all_alerts:
            console.print(Text("\n  Waiting for first Falco alert...\n", justify="center", style="dim"))
            return

        terminal_height = console.height
        alerts_to_show = terminal_height - 7

        start_index = scroll_position
        end_index = start_index + alerts_to_show
        visible_alerts = all_alerts[start_index:end_index]

        for i, alert_text in enumerate(visible_alerts):
            console.print(alert_text)
            console.print("******************************", style="dim")
        
        console.print(f"\nShowing alerts {start_index + 1}-{min(end_index, len(all_alerts))} of {len(all_alerts)}", style="bold yellow")

def keyboard_listener():
    """Listens for keyboard input in a separate thread."""
    global scroll_position, is_paused
    while not exit_event.is_set():
        key = readchar.readkey()
        
        if key == readchar.key.UP:
            is_paused = True  # Pause on scroll
            with alert_lock:
                if scroll_position > 0:
                    scroll_position -= 1
        elif key == readchar.key.DOWN:
            is_paused = True  # Pause on scroll
            with alert_lock:
                if scroll_position < len(all_alerts) - 1:
                    scroll_position += 1
        elif key == ' ': # Spacebar
            is_paused = not is_paused
        elif key.lower() == 'r': # Refresh
            is_paused = False
            scroll_position = 0
        elif key.lower() == 'q':
            exit_event.set()


# --- Main Watcher Logic ---

def run_alert_watcher(args):
    """Main function to set up threads and run the interactive watcher."""
    if not K8S_CLIENT_LOADED:
        console.print("[bold red]Kubernetes client not installed.[/bold red]")
        return
    
    k8s_api = _get_k8s_api_client()
    if not k8s_api: return

    falco_namespace = args.namespace or questionary.text("Enter Falco namespace:", default="falco").ask()
    if not falco_namespace: return
    
    pods = _find_falco_pods(k8s_api, falco_namespace)
    if not pods:
        console.print(f"[yellow]No running Falco pods found in '{falco_namespace}'.[/yellow]")
        return

    selected_pod_name = pods[0].metadata.name
    if len(pods) > 1:
        selected_pod_name = questionary.select("Multiple Falco pods found, select one:", choices=[p.metadata.name for p in pods]).ask()
    if not selected_pod_name: return
    
    console.print(f"Streaming logs from [cyan]{selected_pod_name}[/cyan] in namespace [cyan]{falco_namespace}[/cyan].")
    
    since_seconds = None
    if args.since:
        try:
            if args.since.endswith('s'): since_seconds = int(args.since[:-1])
            elif args.since.endswith('m'): since_seconds = int(args.since[:-1]) * 60
            elif args.since.endswith('h'): since_seconds = int(args.since[:-1]) * 3600
        except ValueError:
            console.print(f"[yellow]Invalid --since format '{args.since}'.[/yellow]")

    log_thread = threading.Thread(
        target=stream_k8s_logs,
        args=(k8s_api, selected_pod_name, falco_namespace, since_seconds),
        daemon=True
    )
    log_thread.start()

    input_thread = threading.Thread(target=keyboard_listener, daemon=True)
    input_thread.start()

    try:
        while not exit_event.is_set():
            redraw_display()
            time.sleep(0.1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
    finally:
        exit_event.set()
        os.system('cls' if os.name == 'nt' else 'clear')
        console.print("\nAlert watcher stopped.")

# --- Entry Point ---

def main():
    parser = argparse.ArgumentParser(description="Watch Falco alerts from Kubernetes pod logs.")
    parser.add_argument("--namespace", "-n", type=str, help="Namespace where Falco is running.")
    parser.add_argument("--since", "-s", type=str, help="Show logs since a relative duration (e.g., 5m, 1h).")
    args = parser.parse_args()
    run_alert_watcher(args)

if __name__ == "__main__":
    main()
