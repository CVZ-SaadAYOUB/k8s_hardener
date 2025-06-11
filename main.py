#!/usr/bin/env python3
# ASCII banner generation
from pyfiglet import Figlet

# Rich library for colored and styled CLI output
from rich.console import Console

# Import all hardening modules from subfolders
from utils import (
    rbac_hardener,
    rbac_auditor, # Added import for the auditor
    # kubelet_security_checker, # Removed
    pod_security_checker,
    network_policy_generator,
)
# Secret Encryption Checker placeholder removed

from istio_manager import (
    policy_checker
)
from istio_manager.istio_installer import IstioInstaller
from istio_manager.mtls_enforcer import MtlsEnforcer

from ids_monitor import (
    falco_installer,
    # snort_deployer, # Removed
    alert_watcher
)
from scanners import (
    image_scanner,
    supply_chain_auditor,
    deployment_yaml_checker,
)
from backups import (
    configuration_backuper
)

# Menu navigation library
import questionary
import sys
import argparse
import os # Added for os.makedirs and os.path.exists
from datetime import datetime # Added for timestamping output files

# Global console instance for rich printing
console = Console()

# Show ASCII banner at launch
def show_banner():
    figlet = Figlet(font='slant')
    banner = figlet.renderText('K8sHardener')
    console.print(f"[bold red]{banner}[/bold red]")
    console.print("[red]Made with <3 by CvZ[/red]")
    console.print("[red]Kubernetes Security Automation Suite[/red]\n")

# Function to prompt for and set up the output directory
def prompt_for_output_directory() -> str:
    console.print("[bold blue]Setup Output Directory[/bold blue]")
    default_output_dir = os.path.join(os.getcwd(), "k8s_hardener_output")
    
    output_dir_path = questionary.text(
        "Enter the directory path where all generated files will be saved:",
        default=default_output_dir
    ).ask()

    if not output_dir_path:
        output_dir_path = default_output_dir
        console.print(f"[yellow]No path entered. Using default: {output_dir_path}[/yellow]")

    try:
        if not os.path.exists(output_dir_path):
            os.makedirs(output_dir_path, exist_ok=True)
            console.print(f"[green]Output directory created: {output_dir_path}[/green]")
        else:
            console.print(f"[green]Using existing output directory: {output_dir_path}[/green]")
        return output_dir_path
    except Exception as e:
        console.print(f"[bold red]Error creating/accessing output directory '{output_dir_path}': {e}[/bold red]")
        console.print(f"[yellow]Falling back to current working directory for outputs.[/yellow]")
        return os.getcwd()


# Top-level main menu
def main_menu():
    return questionary.select(
        "Main Modules - Choose a category:",
        choices=[
            "1. General Kubernetes Hardening",
            "2. Istio and Zero Trust",
            "3. Intrusion Detection",
            "4. Image & Supply Chain",
            "5. Configuration Backups",
            "Exit"
        ]).ask()

# Submenu for general Kubernetes utilities
def utils_menu():
    return questionary.select(
        "Utils Module - Choose a function:",
        choices=[
            "RBAC Management",
            "Pod Security Checker",
            "Network Policy Generator",
            "⬅ Back to Main Menu"
        ]).ask()

# ADDED: Submenu for RBAC operations to meet the new requirement
def rbac_management_menu():
    return questionary.select(
        "RBAC Management - Choose an action:",
        choices=[
            "Audit RBAC",
            "Harden RBAC",
            "Generate RBAC",
            "⬅ Back to General Kubernetes Hardening"
        ]).ask()

# Submenu for Istio management
def istio_menu():
    return questionary.select(
        "Istio and Zero Trust - Choose a function:",
        choices=[
            "Istio Installation Manager",
            "mTLS Enforcement Manager",
            "Istio Policy Checker (coming soon)",
            "⬅ Back to Main Menu"
        ]).ask()

# Submenu for Istio Installation tasks
def istio_installation_menu():
    return questionary.select(
        "Istio Installation Manager - Choose an action:",
        choices=[
            "Check Istio Installation Status",
            "Download Istio (Generic K8s)",
            "Install/Upgrade Istio",
            "Enable Sidecar Injection for Namespace(s)",
            "Uninstall Istio",
            "⬅ Back to Istio and Zero Trust Menu"
        ]).ask()

# Submenu for mTLS Enforcement tasks
def mtls_enforcement_menu():
    return questionary.select(
        "mTLS Enforcement Manager - Choose an action:",
        choices=[
            "Get Current Mesh-Wide mTLS Mode",
            "Enforce STRICT mTLS (Mesh-wide)",
            "Set PERMISSIVE mTLS (Mesh-wide)",
            "Disable/UNSET Mesh-wide mTLS Policy",
            "⬅ Back to Istio and Zero Trust Menu"
        ]).ask()

# Submenu for intrusion detection utilities
def ids_menu():
    return questionary.select(
        "IDS Monitor - Choose a function:",
        choices=[
            "Falco Installer",
            # "Snort Deployer", # Removed
            "Alert Watcher",
            "⬅ Back to Main Menu"
        ]).ask()

# Submenu for image & pipeline security
def scanners_menu():
    return questionary.select(
        "Scanners - Choose a function:",
        choices=[
            "Image Scanner ",
            "Supply Chain Auditor (coming soon)",
            "Deployment YAML Checker",
            "⬅ Back to Main Menu"
        ]).ask()

# Submenu for configuration backup tools
def backups_menu():
    return questionary.select(
        "Backups - Choose a function:",
        choices=[
            "Configuration Backuper",
            "⬅ Back to Main Menu"
        ]).ask()

# Handles routing of the selected menu item to the proper function
def route_menu(args): # args will now have args.output_dir
    # Tool instantiation moved into the menu logic where needed
    istio_installation_tool = IstioInstaller()
    mtls_enforcement_tool = MtlsEnforcer()

    console.print(f"[info]Using output directory: {args.output_dir}[/info]")


    while True:
        choice = main_menu()

        if choice is None:
            console.print("\n[red]Exiting... Stay secure![/red]")
            sys.exit()

        # === General Kubernetes Hardening Utilities ===
        if choice.startswith("1"):
            while True:
                sub = utils_menu()
                if sub is None: break

                if sub == "RBAC Management":
                    # FIXED: This block now handles the new RBAC sub-menu.
                    while True:
                        rbac_action = rbac_management_menu()
                        if rbac_action is None or rbac_action.startswith("⬅"):
                            break

                        if rbac_action.startswith("Audit RBAC"):
                            console.print("▶ Running RBAC Auditor (Read-only)...")
                            auditor = rbac_auditor.RBACAuditor()
                            if not auditor.core_api or not auditor.rbac_api:
                                console.print("[bold red]Failed to connect to Kubernetes API. Aborting audit.[/bold red]")
                                continue
                            
                            exclude_system = questionary.confirm(
                                "Exclude findings related to known system components (e.g., Calico, CoreDNS)?",
                                default=True
                            ).ask()
                            if exclude_system is None: continue

                            findings = auditor.audit_rbac()
                            auditor.print_audit_findings(findings, exclude_system=exclude_system)

                        elif rbac_action.startswith("Harden RBAC"):
                            console.print("▶ Initializing RBAC Hardener (Audit & Fix)...")
                            hardener = rbac_hardener.RBACHardener(
                                namespace_filter=args.namespace,
                                output_file=os.path.join(args.output_dir, f"rbac_hardening_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml")
                            )
                            hardener.run()
                        
                        elif rbac_action.startswith("Generate RBAC"):
                            console.print("[bold yellow]This feature is not yet implemented.[/bold yellow]")
                            console.print("The current tool can audit and modify existing roles, but not generate new ones from scratch.")
                        
                elif sub.startswith("Pod Security Checker"):
                    console.print("▶ Running Pod Security Checker...")
                    pod_security_checker.run() 
                elif sub.startswith("Network Policy Generator"):
                    console.print("▶ Running Network Policy Generator...")
                    network_policy_generator.run() 
                elif sub == "⬅ Back to Main Menu":
                    break
        # === Istio Zero Trust Management ===
        elif choice.startswith("2"):
            while True:
                istio_choice = istio_menu()
                if istio_choice is None: break

                if istio_choice == "Istio Installation Manager":
                    while True:
                        install_action = istio_installation_menu()
                        if install_action is None: break

                        if install_action == "Check Istio Installation Status":
                            console.print("▶ Checking Istio Installation Status...")
                            installed = istio_installation_tool.is_istio_installed()
                            if installed:
                                console.print("[green]Istio appears to be installed.[/green]")
                            else:
                                console.print("[yellow]Istio does not appear to be installed or istiod is not found.[/yellow]")
                        elif install_action == "Download Istio (Generic K8s)":
                            console.print("▶ Downloading Istio (for Generic K8s)...")
                            istio_installation_tool.download_istio() 
                        elif install_action == "Install/Upgrade Istio":
                            console.print("▶ Installing/Upgrading Istio...")
                            confirm_install = questionary.confirm("Proceed with Istio installation/upgrade?", default=True).ask()
                            if confirm_install is None: continue
                            if confirm_install:
                                istio_installation_tool.install_istio(confirm=False)
                            else:
                                console.print("[yellow]Istio installation cancelled.[/yellow]")
                        elif install_action == "Enable Sidecar Injection for Namespace(s)":
                            console.print("▶ Enabling Sidecar Injection...")
                            ns_input = questionary.text("Enter comma-separated namespaces:").ask()
                            if ns_input is None: continue
                            if ns_input:
                                namespaces = [ns.strip() for ns in ns_input.split(',')]
                                istio_installation_tool.enable_sidecar_injection(namespaces)
                            else:
                                console.print("[yellow]No namespaces provided.[/yellow]")
                        elif install_action == "Uninstall Istio":
                            console.print("▶ Uninstalling Istio...")
                            confirm_uninstall = questionary.confirm("Proceed with Istio uninstallation?", default=True).ask()
                            if confirm_uninstall is None: continue
                            if confirm_uninstall:
                                istio_installation_tool.uninstall_istio(confirm=False)
                            else:
                                console.print("[yellow]Istio uninstallation cancelled.[/yellow]")
                        elif install_action == "⬅ Back to Istio and Zero Trust Menu":
                            break
                elif istio_choice == "mTLS Enforcement Manager":
                    while True:
                        mtls_action = mtls_enforcement_menu()
                        if mtls_action is None: break

                        if mtls_action == "Get Current Mesh-Wide mTLS Mode":
                            console.print("▶ Getting Current Mesh-Wide mTLS Mode...")
                            mode = mtls_enforcement_tool.get_current_mesh_wide_mtls_mode()
                            if mode:
                                console.print(f"[blue]Current Mesh-Wide mTLS Mode: {mode}[/blue]")
                            else:
                                console.print("[red]Could not determine mTLS mode.[/red]")
                        elif mtls_action == "Enforce STRICT mTLS (Mesh-wide)":
                            console.print("▶ Enforcing STRICT mTLS (Mesh-wide)...")
                            mtls_enforcement_tool.enforce_strict_mtls(confirm=True)
                        elif mtls_action == "Set PERMISSIVE mTLS (Mesh-wide)":
                            console.print("▶ Setting PERMISSIVE mTLS (Mesh-wide)...")
                            mtls_enforcement_tool.allow_permissive_mtls(confirm=True)
                        elif mtls_action == "Disable/UNSET Mesh-wide mTLS Policy":
                            console.print("▶ Disabling/UNSETTING Mesh-wide mTLS Policy...")
                            mtls_enforcement_tool.disable_mesh_wide_mtls_enforcement(confirm=True)
                        elif mtls_action == "⬅ Back to Istio and Zero Trust Menu":
                            break
                elif istio_choice == "Istio Policy Checker":
                    console.print("▶ Checking Istio Policies...")
                    policy_checker.run()
                elif istio_choice == "⬅ Back to Main Menu":
                    break
        # === Intrusion Detection Tools ===
        elif choice.startswith("3"):
            while True:
                sub = ids_menu()
                if sub is None: break

                if sub == "Falco Installer":
                    console.print("▶ Installing Falco...")
                    falco_installer.run_falco_installer()
                # elif sub == "Snort Deployer": # Removed
                #     console.print("▶ Deploying Snort...")
                #     try:
                #         snort_deployer.run()
                #     except AttributeError:
                #         console.print("[yellow]Snort Deployer module or run() function not found/implemented.[/yellow]")
                elif sub == "Alert Watcher":
                    console.print("▶ Starting Alert Watcher...")
                    alert_watcher.run_alert_watcher(args)
                elif sub == "⬅ Back to Main Menu":
                    break
        # === Container Image & Supply Chain ===
        elif choice.startswith("4"):
            while True:
                sub = scanners_menu()
                if sub is None: break

                if sub == "Image Scanner":
                    console.print("▶ Running Image Scanner...")
                    image_scanner.run()
                elif sub == "Supply Chain Auditor":
                    console.print("▶ Running Supply Chain Auditor...")
                    supply_chain_auditor.run() 
                elif sub == "Deployment YAML Checker":
                    console.print("▶ Running Deployment YAML Checker...")
                    deployment_yaml_checker.run() 
                elif sub == "⬅ Back to Main Menu":
                    break
        # === Backup Section ===
        elif choice.startswith("5"):
            while True:
                sub = backups_menu()
                if sub is None: break

                if sub == "Configuration Backuper":
                    console.print("▶ Running Configuration Backuper...")
                    try:
                        configuration_backuper.run() 
                    except AttributeError:
                        console.print("[yellow]Configuration Backuper module or run() function not found/implemented.[/yellow]")
                elif sub == "⬅ Back to Main Menu":
                    break
        # === Exit Program ===
        elif choice.startswith("Exit"):
            console.print("\n[red]Exiting... Stay secure![/red]")
            sys.exit()

# Entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kubernetes Security Automation Suite.")
    parser.add_argument('--dry-run', action='store_true', help='Perform a dry run for applicable actions (e.g., RBAC hardening).')
    parser.add_argument('--namespace', '-n', dest='namespace', help='Namespace for specific operations (e.g., Falco alert watcher)')
    parser.add_argument('--since', '-s', dest='since', help='Relative duration for logs (e.g., 5m, 1h for alert watcher)')

    args = parser.parse_args()

    try:
        show_banner()
        args.output_dir = prompt_for_output_directory()
        
        route_menu(args)
    except (KeyboardInterrupt, EOFError):
        console.print("\n[bold yellow]Operation cancelled by user. Exiting... Stay secure![/bold yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected critical error occurred in K8sHardener: {e}[/bold red]")
        import traceback
        traceback.print_exc() 
        sys.exit(1)
