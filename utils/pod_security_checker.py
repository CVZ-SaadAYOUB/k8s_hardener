#!/usr/bin/env python3
"""
Kubernetes Pod Security Checker
Scans pods for common and advanced security misconfigurations and reports severity-colored findings.
Provides options to save the report and manage risky pods.
"""
import sys
import argparse
import csv # Import csv module
from datetime import datetime # Import datetime for timestamps
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.config import ConfigException
from rich.console import Console
from rich.text import Text
import questionary # Import questionary

console = Console()

# Severity levels
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# Styles for Rich
STYLE_HIGH = "bold red"
STYLE_MEDIUM = "bold yellow"
STYLE_LOW = "blue"
STYLE_INFO = "cyan"

# Common safe capabilities to suggest clarity
COMMON_SAFE_CAPS = ["NET_BIND_SERVICE", "KILL", "CHOWN"]
# Host paths considered sensitive
SENSITIVE_HOST_PATHS = ["/", "/var/run/docker.sock", "/dev", "/sys"]
# System namespaces to skip
SYSTEM_NAMESPACE_PREFIXES = ['kube-', 'kubernetes-']

# --- Kubernetes Client Setup ---
def get_k8s_client() -> client.CoreV1Api:
    """Load Kubernetes configuration and return a CoreV1Api client."""
    try:
        config.load_kube_config()
        console.print(Text("Loaded kubeconfig.", style="green"))
    except ConfigException:
        try:
            config.load_incluster_config()
            console.print(Text("Loaded in-cluster config.", style="green"))
        except ConfigException:
            console.print(Text(
                "Could not configure Kubernetes client. Ensure a valid kubeconfig or in-cluster env.",
                style="bold red"
            ))
            # In the context of the main script, we might not want to sys.exit
            # but rather return None or raise an exception.
            # For standalone execution and simplicity here, we'll exit.
            sys.exit(1)
    return client.CoreV1Api()

# --- Security Checks ---
# (These functions are the same as before, they just return the raw findings)

def check_privileged_containers(pod) -> list:
    issues = []
    containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
    for c in containers:
        sc = c.security_context
        if sc and getattr(sc, 'privileged', False):
            issues.append((SEVERITY_HIGH,
                f"Container '{c.name}' is privileged."))
    return issues


def check_host_network(pod) -> list:
    return [(SEVERITY_HIGH, "Pod uses hostNetwork: true.")] if pod.spec.host_network else []


def check_host_pid_ipc(pod) -> list:
    issues = []
    if pod.spec.host_pid:
        issues.append((SEVERITY_HIGH, "Pod uses hostPID: true."))
    if pod.spec.host_ipc:
        issues.append((SEVERITY_HIGH, "Pod uses hostIPC: true."))
    return issues


def check_privilege_escalation(pod) -> list:
    issues = []
    p_sc = pod.spec.security_context
    containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
    for c in containers:
        sc = c.security_context
        # Default for allowPrivilegeEscalation is true for privileged containers or when runAsUser is 0
        # We check explicitly if set to true, or if None and not explicitly runAsNonRoot
        ape = getattr(sc, 'allow_privilege_escalation', None)
        # Check effective runAsNonRoot - container level overrides pod level
        run_non_root_effective = getattr(sc, 'run_as_non_root', getattr(p_sc, 'run_as_non_root', False))
        run_as_user_effective = getattr(sc, 'run_as_user', getattr(p_sc, 'run_as_user', None))

        if ape is True:
             issues.append((SEVERITY_MEDIUM,
                f"Container '{c.name}' allows privilege escalation."))
        # If ape is not explicitly set (is None) and running as root (UID 0) or not explicitly non-root, it defaults to true
        elif ape is None:
             is_running_as_root = (run_as_user_effective is None or run_as_user_effective == 0) and not run_non_root_effective
             # Check if the effective user is root AND the container is not privileged (where ape is always true)
             # A non-privileged root container without ape=false is MEDIUM risk
             if is_running_as_root and not getattr(sc, 'privileged', False):
                  issues.append((SEVERITY_MEDIUM,
                     f"Container '{c.name}': allowPrivilegeEscalation not set, defaults to true when running as root and not privileged."))


    return issues


def check_run_as_non_root(pod) -> list:
    issues = []
    p_sc = pod.spec.security_context
    containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
    for c in containers:
        sc = c.security_context
        run_non_root_effective = getattr(sc, 'run_as_non_root', getattr(p_sc, 'run_as_non_root', False))
        run_as_user_effective = getattr(sc, 'run_as_user', getattr(p_sc, 'run_as_user', None))

        if not run_non_root_effective and (run_as_user_effective is None or run_as_user_effective == 0):
            # Check specifically for UID 0 if runAsNonRoot is false or unset
            if run_as_user_effective == 0 or (run_as_user_effective is None and not run_non_root_effective):
                 issues.append((SEVERITY_MEDIUM,
                    f"Container '{c.name}' not configured to run as non-root (effective UID potentially 0)."))
    return issues


def check_capabilities(pod) -> list:
    issues = []
    containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
    dangerous_capabilities = [
        "SYS_ADMIN", "NET_ADMIN", "DAC_OVERRIDE", "NET_RAW", "AUDIT_CONTROL",
        "AUDIT_WRITE", "BPF", "CHECKPOINT_RESTORE", "DAC_READ_SEARCH",
        "FOWNER", "FSETID", "KILL", "LINUX_IMMUTABLE", "MAC_ADMIN",
        "MAC_OVERRIDE", "MKNOD", "SETFCAP", "SETGID", "SETPCAP", "SETUID",
        "SYSLOG", "SYS_CHROOT", "SYS_MODULE", "SYS_NICE", "SYS_PACCT",
        "SYS_PTRACE", "SYS_RAWIO", "SYS_RESOURCE", "SYS_TIME", "SYS_TTY_CONFIG",
        "WAKE_ALARM"
    ]
    for c in containers:
        sc = c.security_context
        caps = getattr(sc, 'capabilities', None)
        if caps:
            added = caps.add or []
            dropped = caps.drop or []
            for cap in added:
                if cap in dangerous_capabilities:
                    issues.append((SEVERITY_HIGH,
                        f"Container '{c.name}' adds dangerous capability '{cap}'."))
            if 'ALL' not in dropped:
                issues.append((SEVERITY_LOW,
                    f"Container '{c.name}' does not drop ALL capabilities."))
            else: # ALL is dropped, check if common safe ones are explicitly dropped for clarity
                for cap in COMMON_SAFE_CAPS:
                    if cap not in dropped:
                        issues.append((SEVERITY_INFO,
                            f"Container '{c.name}' drops ALL but could explicitly drop '{cap}' for clarity."))
        else:
            issues.append((SEVERITY_LOW,
                f"Container '{c.name}' uses default capabilities (consider dropping ALL)."))
    return issues


def check_read_only_fs(pod) -> list:
    issues = []
    containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
    for c in containers:
        sc = c.security_context
        if not getattr(sc, 'read_only_root_filesystem', False):
            issues.append((SEVERITY_LOW,
                f"Container '{c.name}' missing readOnlyRootFilesystem."))
    return issues


def check_volume_mounts(pod) -> list:
    # This checks for *sensitive* host paths specifically
    issues = []
    for vol in pod.spec.volumes or []:
        hp = getattr(vol, 'host_path', None)
        if hp:
            path = hp.path
            if any(path.startswith(s) for s in SENSITIVE_HOST_PATHS):
                issues.append((SEVERITY_HIGH,
                    f"Pod mounts sensitive host path '{path}' via volume '{vol.name}'."))
    return issues


def check_host_path_volumes_any(pod) -> list:
    # This checks for *any* HostPath volume, which is a broader check
    issues = []
    for vol in pod.spec.volumes or []:
        if getattr(vol, 'host_path', None):
            # Avoid duplicating HIGH severity from check_volume_mounts
            is_sensitive = any(vol.host_path.path.startswith(s) for s in SENSITIVE_HOST_PATHS)
            if not is_sensitive:
                 issues.append((SEVERITY_MEDIUM,
                    f"Pod defines HostPath volume '{vol.name}' -> {vol.host_path.path} (not a known sensitive path, but review recommended)."))
    return issues


def check_subpath_volume_mounts(pod) -> list:
    issues = []
    containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
    for c in containers:
        for vm in c.volume_mounts or []:
            if vm.sub_path:
                issues.append((SEVERITY_LOW,
                    f"Container '{c.name}' uses subPath '{vm.sub_path}' on volume mount '{vm.name}'. Review potential escape risks."))
    return issues


def check_run_as_user_zero(pod) -> list:
    # Explicitly checks if UID is 0 (root)
    issues = []
    p_sc = pod.spec.security_context
    p_run_user = getattr(p_sc, 'run_as_user', None)
    if p_run_user == 0:
        issues.append((SEVERITY_HIGH, "Pod securityContext runAsUser is 0 (root)."))
    containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
    for c in containers:
        sc = c.security_context
        c_run_user = getattr(sc, 'run_as_user', None)
        # Container setting overrides Pod setting if both are present
        effective_run_user = c_run_user if c_run_user is not None else p_run_user
        if effective_run_user == 0:
            issues.append((SEVERITY_HIGH,
                f"Container '{c.name}' effectively runs as root (UID 0)."))
    return issues


def check_run_as_group_fs_group(pod) -> list:
    # Recommendations for group IDs
    issues = []
    sc = pod.spec.security_context
    if not getattr(sc, 'run_as_group', None):
        issues.append((SEVERITY_INFO, "Pod missing recommended runAsGroup setting."))
    if not getattr(sc, 'fs_group', None):
        issues.append((SEVERITY_INFO, "Pod missing recommended fsGroup setting."))
    # Check container-specific runAsGroup if Pod-level is missing
    containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
    for c in containers:
        c_sc = c.security_context
        if not getattr(c_sc, 'run_as_group', None) and not getattr(sc, 'run_as_group', None):
             issues.append((SEVERITY_INFO,
                f"Container '{c.name}' missing recommended runAsGroup setting (and no Pod-level default)."))
    return issues


def check_automount_service_account_token(pod) -> list:
    # Check if the SA token is automounted unnecessarily
    issues = []
    # Defaults to True if not explicitly set
    token = getattr(pod.spec, 'automount_service_account_token', True)
    if token is True:
        issues.append((SEVERITY_MEDIUM,
            "Pod automountServiceAccountToken is enabled (consider disabling if not needed)."))
    return issues


def check_secret_env_vars(pod) -> list:
    # Check for secrets exposed as environment variables
    issues = []
    containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
    for c in containers:
        for env in c.env or []:
            if env.value_from and getattr(env.value_from, 'secret_key_ref', None):
                issues.append((SEVERITY_MEDIUM,
                    f"Container '{c.name}' uses secret '{env.value_from.secret_key_ref.name}' as ENV var (consider mounting as file)."))
    return issues


def check_missing_probes(pod) -> list:
    # Check for missing health probes
    issues = []
    containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
    for c in containers:
        if not c.liveness_probe:
            issues.append((SEVERITY_LOW,
                f"Container '{c.name}' missing livenessProbe (risk of undetected failures)."))
        if not c.readiness_probe:
            issues.append((SEVERITY_LOW,
                f"Container '{c.name}' missing readinessProbe (risk of sending traffic to unready instances)."))
        # Optional: Check for startupProbe if it's a slow-starting app
        # if not c.startup_probe:
        #      issues.append((SEVERITY_INFO,
        #         f"Container '{c.name}' missing startupProbe for slow initialization."))
    return issues


def check_host_ports(pod) -> list:
    # Check for containers binding directly to host ports
    issues = []
    containers = (pod.spec.containers or []) + (pod.spec.init_containers or [])
    for c in containers:
        for p in c.ports or []:
            if p.host_port:
                issues.append((SEVERITY_HIGH,
                    f"Container '{c.name}' uses hostPort {p.host_port} (bypasses Service abstraction)."))
    return issues


def check_security_context_recommended_defaults(pod) -> list:
    # Check for key recommended settings at the Pod level
    issues = []
    sc = pod.spec.security_context
    if sc is None:
         issues.append((SEVERITY_LOW, "Pod missing entire securityContext block (no Pod-level defaults)."))
         # Don't check individual recommended settings if the block is missing
         return issues

    rec = []
    # Check runAsNonRoot default
    if getattr(sc, 'run_as_non_root', None) is not True: # Explicitly checking if NOT True
        # Only recommend if runAsUser is 0 or None at Pod level
        if getattr(sc, 'run_as_user', None) is None or getattr(sc, 'run_as_user', None) == 0:
             rec.append('runAsNonRoot: true') # Suggest enabling it

    # Check seccompProfile default (RuntimeDefault or Localhost)
    if not getattr(sc, 'seccomp_profile', None):
        rec.append('seccompProfile') # Suggest adding it

    # Check apparmor Profile annotation (Pod level)
    annotations = pod.metadata.annotations or {}
    has_apparmor_pod = annotations.get('container.apparmor.security.beta.kubernetes.io/pod', None) is not None
    if not has_apparmor_pod:
        rec.append('AppArmor profile annotation')

    for r in rec:
        issues.append((SEVERITY_INFO,
            f"Pod securityContext missing recommended setting or annotation: '{r}'."))
    return issues

# Aggregate all checks - ORDER MATTERS FOR SEVERITY (HIGH first for reporting)
CHECKS = [
    # HIGH severity checks
    check_privileged_containers,
    check_host_network,
    check_host_pid_ipc,
    check_run_as_user_zero,        # Explicitly checks UID 0
    check_volume_mounts,           # Sensitive host paths
    check_host_ports,              # Host ports

    # MEDIUM severity checks
    check_privilege_escalation,    # Defaults or explicit true
    check_run_as_non_root,         # Not explicitly non-root (potential UID 0 via inheritance/default)
    check_host_path_volumes_any,   # Any HostPath volume
    check_automount_service_account_token,
    check_secret_env_vars,

    # LOW severity checks
    check_capabilities,            # Dropping ALL vs default caps
    check_read_only_fs,
    check_subpath_volume_mounts,
    check_missing_probes,

    # INFO severity checks (Recommendations)
    check_run_as_group_fs_group,
    check_security_context_recommended_defaults,
]


def scan_pod(pod) -> list:
    """Runs all security checks against a single Pod."""
    findings = []
    for fn in CHECKS:
        findings.extend(fn(pod))

    # Sort findings by severity (High to Info)
    severity_order = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2, SEVERITY_INFO: 3}
    findings.sort(key=lambda item: severity_order.get(item[0], 99))

    return findings


def scan_namespace(api: client.CoreV1Api, namespace: str) -> dict:
    """Scans all pods in a given namespace for security issues."""
    console.print(Text(f"\nScanning namespace: {namespace}", style="bold blue"))
    try:
        pods = api.list_namespaced_pod(namespace).items
    except ApiException as e:
        console.print(Text(f"Error listing pods in {namespace}: {e}", style="bold red"))
        return {}

    if not pods:
        console.print(Text(f"No pods found in namespace {namespace}.", style="yellow"))
        return {}

    results = {}
    with console.status(f"[blue]Scanning {len(pods)} pods in {namespace}...") as status:
        for i, pod in enumerate(pods):
            status.update(f"[blue]Scanning pod {i+1}/{len(pods)}: {pod.metadata.name}")
            findings = scan_pod(pod)
            if findings:
                results[f"{pod.metadata.namespace}/{pod.metadata.name}"] = findings
    return results


def scan_all_namespaces(api: client.CoreV1Api) -> dict:
    """Scans all pods across all namespaces for security issues."""
    console.print(Text("\nScanning all namespaces...", style="bold blue"))
    try:
        nss = [ns.metadata.name for ns in api.list_namespace().items]
    except ApiException as e:
        console.print(Text(f"Error listing namespaces: {e}", style="bold red"))
        return {}

    if not nss:
         console.print(Text("No namespaces found in the cluster.", style="yellow"))
         return {}

    all_res = {}
    scanned_namespaces = 0
    for ns in nss:
        if any(ns.startswith(pref) for pref in SYSTEM_NAMESPACE_PREFIXES):
            console.print(Text(f"Skipping system namespace: {ns}", style="yellow"))
            continue
        scanned_namespaces += 1
        all_res.update(scan_namespace(api, ns))

    if scanned_namespaces == 0:
         console.print(Text("No user namespaces found to scan after skipping system namespaces.", style="yellow"))

    return all_res


def style_for(severity: str) -> str:
    """Returns the Rich style string for a given severity level."""
    return {
        SEVERITY_HIGH: STYLE_HIGH,
        SEVERITY_MEDIUM: STYLE_MEDIUM,
        SEVERITY_LOW: STYLE_LOW,
        SEVERITY_INFO: STYLE_INFO
    }.get(severity, "")


def report(results: dict) -> None:
    """Generates and prints a security report based on findings."""
    console.print(Text("\n--- Pod Security Scan Report ---", style="bold green"))

    if not results:
        console.print(Text("No security issues found.", style="green"))
        return

    # Sort results alphabetically by pod name for consistent output
    sorted_pod_names = sorted(results.keys())

    for pod_name in sorted_pod_names:
        findings = results[pod_name]
        console.print(Text(f"\nPod: {pod_name}", style="bold cyan"))
        # Findings are already sorted by severity from scan_pod
        for severity, message in findings:
            style = style_for(severity)
            console.print(f"  [[{style}]{severity}[/{style}]] {message}")

    console.print(Text("\n--- End of Report ---", style="bold green"))

# --- Reporting and Action Functions ---

def save_report_txt(filename: str, results: dict) -> None:
    """Saves the report to a plain text file."""
    try:
        with open(filename, 'w') as f:
            f.write("--- Kubernetes Pod Security Scan Report ---\n")
            if not results:
                f.write("No security issues found.\n")
            else:
                for pod_name, findings in sorted(results.items()):
                    f.write(f"\nPod: {pod_name}\n")
                    for severity, message in findings:
                        f.write(f"  [{severity}] {message}\n")
            f.write("\n--- End of Report ---\n")
        console.print(Text(f"Report saved to {filename}", style="green"))
    except IOError as e:
        console.print(Text(f"Error saving report to {filename}: {e}", style="bold red"))

def save_report_csv(filename: str, results: dict) -> None:
    """Saves the report to a CSV file."""
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Namespace", "Pod Name", "Severity", "Message"])
            if results:
                for pod_name, findings in sorted(results.items()):
                    namespace, name = pod_name.split('/', 1)
                    for severity, message in findings:
                        writer.writerow([namespace, name, severity, message])
        console.print(Text(f"Report saved to {filename}", style="green"))
    except IOError as e:
        console.print(Text(f"Error saving report to {filename}: {e}", style="bold red"))

def ask_to_save_report(results: dict) -> None:
    """Asks the user if they want to save the report and handles saving."""
    if not results:
        # No findings to save
        return

    save_option = questionary.confirm("Do you want to save the report to a file?").ask()

    if save_option:
        file_format = questionary.select(
            "Choose a file format:",
            choices=['txt', 'csv']
        ).ask()

        if file_format:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"k8s-pod-security-report_{timestamp}.{file_format}"
            filename = questionary.text(
                "Enter filename:",
                default=default_filename
            ).ask()

            if filename:
                if file_format == 'txt':
                    save_report_txt(filename, results)
                elif file_format == 'csv':
                    save_report_csv(filename, results)

def ask_and_delete_risky_pods(api: client.CoreV1Api, results: dict) -> None:
    """Identifies risky pods, asks the user, and attempts deletion."""
    risky_pods = []
    for pod_name, findings in results.items():
        if any(sev == SEVERITY_HIGH for sev, msg in findings):
            risky_pods.append(pod_name)

    if not risky_pods:
        console.print(Text("\nNo pods identified with HIGH severity issues recommended for deletion.", style="green"))
        return

    console.print(Text("\n--- Risky Pods Identified (HIGH Severity Findings) ---", style="bold yellow"))
    for pod_name in risky_pods:
        console.print(f"- {pod_name}")
    console.print(Text("---------------------------------------------------", style="bold yellow"))


    confirm_delete_list = questionary.confirm(
        "Do you want to attempt to delete the listed risky pods?"
    ).ask()

    if confirm_delete_list:
        console.print(Text("\nAttempting to delete risky pods...", style="bold red"))
        for pod_name in risky_pods:
            namespace, name = pod_name.split('/', 1)
            confirm_delete_pod = questionary.confirm(f"Confirm deletion of pod: {pod_name}?").ask()

            if confirm_delete_pod:
                try:
                    # Use DeleteOptions to prevent immediate foreground deletion issues in some setups
                    api.delete_namespaced_pod(name, namespace, body=client.V1DeleteOptions())
                    console.print(Text(f"Successfully sent delete request for pod: {pod_name}", style="green"))
                except ApiException as e:
                    console.print(Text(f"Error deleting pod {pod_name}: {e.status} - {e.reason}", style="bold red"))
                except Exception as e:
                    console.print(Text(f"An unexpected error occurred deleting pod {pod_name}: {e}", style="bold red"))
            else:
                console.print(Text(f"Skipping deletion of pod: {pod_name}", style="yellow"))
        console.print(Text("\nDeletion attempts finished.", style="bold red"))
    else:
        console.print(Text("\nPod deletion cancelled.", style="yellow"))


# --- Main Execution Function ---

def run():
    """
    Entry point function called by main.py or when the script is run directly.
    Handles argument parsing, scanning, reporting, saving, and deletion prompts.
    """
    parser = argparse.ArgumentParser(
        description="Scan Kubernetes pods for security misconfigurations.",
        prog="pod_security_checker.py" # Set prog name explicitly
    )
    parser.add_argument(
        "-n", "--namespace", help="Namespace to scan (defaults to all user namespaces)."
    )
    # Use parse_args() when run directly, as main.py likely passes clean args
    # If main.py passes unknown args, switch back to parse_known_args()
    args = parser.parse_args()


    api_client = get_k8s_client()

    if api_client: # Proceed only if client initialization was successful
        if args.namespace:
            scan_results = scan_namespace(api_client, args.namespace)
        else:
            scan_results = scan_all_namespaces(api_client)

        report(scan_results)

        # Ask about saving the report
        ask_to_save_report(scan_results)

        # Ask about deleting risky pods
        ask_and_delete_risky_pods(api_client, scan_results)


# --- Standalone Execution ---

if __name__ == "__main__":
    # If the script is run directly, call the run() function
    run()