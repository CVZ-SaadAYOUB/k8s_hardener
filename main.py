# ASCII banner generation
from pyfiglet import Figlet

# Rich library for colored and styled CLI output
from rich.console import Console

# Import all hardening modules from subfolders
from utils import (
    rbac_hardener,
    secret_encryption_checker,
    kubelet_security_checker,
    pod_security_checker,
    network_policy_generator,
)
from istio_manager import (
    istio_installer,
    mtls_enforcer,
    policy_checker
)
from ids_monitor import (
    falco_installer,
    snort_deployer,
    alert_watcher
)
from scanners import (
    image_scanner,
    supply_chain_auditor
)
from backups import (
    configuration_backuper
)

# Menu navigation library
import questionary
import sys
import argparse # Import argparse for main script

# Global console instance for rich printing
console = Console()

# Show ASCII banner at launch
def show_banner():
    figlet = Figlet(font='slant')
    banner = figlet.renderText('K8sHardener')
    console.print(f"[bold red]{banner}[/bold red]")
    console.print("[red]Made with <3 by CvZ[/red]")
    console.print("[red]Kubernetes Security Automation Suite[/red]\n")

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
            "RBAC Management", # Changed to group RBAC functions
            "Pod Security Checker",
            "Network Policy Generator",
            "Kubelet Security Checker",
            "Secret Encryption Checker",
            "⬅ Back to Main Menu"
        ]).ask()

# New submenu for RBAC operations
def rbac_management_menu():
    return questionary.select(
        "RBAC Management - Choose an action:",
        choices=[
            "Audit RBAC",
            "Harden RBAC",
            "Generate RBAC",
            "⬅ Back to General Kubernetes Hardening"
        ]).ask()


# Submenu for Istio management tools
def istio_menu():
    return questionary.select(
        "Istio Manager - Choose a function:",
        choices=[
            "Istio Installer",
            "mTLS Enforcer",
            "Policy Checker",
            "⬅ Back to Main Menu"
        ]).ask()

# Submenu for intrusion detection utilities
def ids_menu():
    return questionary.select(
        "IDS Monitor - Choose a function:",
        choices=[
            "Falco Installer",
            "Snort Deployer",
            "Alert Watcher",
            "⬅ Back to Main Menu"
        ]).ask()

# Submenu for image & pipeline security
def scanners_menu():
    return questionary.select(
        "Scanners - Choose a function:",
        choices=[
            "Image Scanner",
            "Supply Chain Auditor",
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
def route_menu(args): # Pass args to route_menu
    # Instantiate the RBAC Hardener once
    rbac_tool = rbac_hardener.RBACHardener()

    while True:
        choice = main_menu()

        # === General Kubernetes Hardening Utilities ===
        if choice.startswith("1"):
            while True:
                sub = utils_menu()
                if sub == "RBAC Management": # Handle the new RBAC group
                    while True:
                        rbac_action = rbac_management_menu()
                        if rbac_action == "Audit RBAC":
                            console.print("▶ Running RBAC Audit...")
                            # Pass the exclude_system flag from main args if available
                            audit_findings = rbac_tool.audit_rbac()
                            if audit_findings: # Only print if there are findings (or errors)
                                # Need to get the exclude_system choice globally or here
                                # Let's prompt for exclude_system before running audit/harden from menu
                                exclude_system_for_rbac = questionary.confirm(
                                    "Exclude findings related to known system components from audit output?"
                                ).ask()
                                rbac_tool.print_audit_findings(audit_findings, exclude_system=exclude_system_for_rbac)

                        elif rbac_action == "Harden RBAC":
                             console.print("▶ Running RBAC Hardener...")
                             # Hardening depends on audit findings first
                             audit_findings = rbac_tool.audit_rbac() # Re-run audit or get from previous step? Re-running is simpler for now.
                             if audit_findings and not (len(audit_findings) == 1 and "error" in audit_findings[0] and audit_findings[0].get("severity") == "Error"):
                                 exclude_system_for_rbac = questionary.confirm(
                                    "Exclude findings related to known system components from hardening?"
                                ).ask()
                                 proposed_changes = rbac_tool.interactive_hardening(audit_findings, exclude_system=exclude_system_for_rbac)
                                 if proposed_changes:
                                     hardening_yaml = rbac_tool.generate_hardening_yaml(proposed_changes)
                                     if hardening_yaml: # Check if YAML was actually generated
                                         # Pass --dry-run from main args if present
                                         rbac_tool.apply_hardening_changes(hardening_yaml, dry_run=args.dry_run)
                                 else:
                                     console.print("[blue]No changes proposed during interactive hardening.[/blue]")
                             elif audit_findings and len(audit_findings) == 1 and "error" in audit_findings[0]:
                                 console.print("[bold red]Cannot proceed with hardening due to audit errors.[/bold red]")


                        elif rbac_action == "Generate RBAC":
                             console.print("▶ Running RBAC Generator...")
                             # Call the new generator method
                             rbac_tool.generate_rbac_interactive()

                        elif rbac_action == "⬅ Back to General Kubernetes Hardening":
                            break # Back to Utils menu

                elif sub.startswith("Pod"):
                    console.print("▶ Running Pod Security Checker...")
                    pod_security_checker.run()
                elif sub.startswith("Network"):
                    console.print("▶ Running Network Policy Generator...")
                    network_policy_generator.run()
                elif sub.startswith("Kubelet"):
                    console.print("▶ Running Kubelet Security Checker...")
                    kubelet_security_checker.run()
                elif sub.startswith("Secret"):
                    console.print("▶ Running Secret Encryption Checker...")
                    secret_encryption_checker.run()
                elif sub == "⬅ Back to Main Menu":
                    break # Back to Main menu

        # === Istio Zero Trust Management ===
        elif choice.startswith("2"):
            while True:
                sub = istio_menu()
                if sub == "Istio Installer":
                    console.print("▶ Installing Istio...")
                    istio_installer.run()
                elif sub == "mTLS Enforcer":
                    console.print("▶ Enforcing mTLS...")
                    mtls_enforcer.run()
                elif sub == "Policy Checker":
                    console.print("▶ Checking Istio Policies...")
                    policy_checker.run()
                elif sub == "⬅ Back to Main Menu":
                    break

        # === Intrusion Detection Tools ===
        elif choice.startswith("3"):
            while True:
                sub = ids_menu()
                if sub == "Falco Installer":
                    console.print("▶ Installing Falco...")
                    falco_installer.run()
                elif sub == "Snort Deployer":
                    console.print("▶ Deploying Snort...")
                    snort_deployer.run()
                elif sub == "Alert Watcher":
                    console.print("▶ Starting Alert Watcher...")
                    alert_watcher.run()
                elif sub == "⬅ Back to Main Menu":
                    break

        # === Container Image & Supply Chain ===
        elif choice.startswith("4"):
            while True:
                sub = scanners_menu()
                if sub == "Image Scanner":
                    console.print("▶ Running Image Scanner...")
                    image_scanner.run()
                elif sub == "Supply Chain Auditor":
                    console.print("▶ Running Supply Chain Auditor...")
                    supply_chain_auditor.run()
                elif sub == "⬅ Back to Main Menu":
                    break

        # === Backup Section ===
        elif choice.startswith("5"):
            while True:
                sub = backups_menu()
                if sub == "Configuration Backuper":
                    console.print("▶ Running Configuration Backuper...")
                    configuration_backuper.run()
                elif sub == "⬅ Back to Main Menu":
                    break

        # === Exit Program ===
        elif choice.startswith("Exit"):
            console.print("\n[red]Exiting... Stay secure![/red]")
            sys.exit()

# Entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kubernetes Security Automation Suite.")
    # Add the --dry-run argument to the main script as well
    parser.add_argument('--dry-run', action='store_true', help='Perform a dry run for applicable actions (e.g., hardening).')
    # Add other potential global arguments here if needed

    args = parser.parse_args()

    show_banner()
    route_menu(args) # Pass args to the route_menu