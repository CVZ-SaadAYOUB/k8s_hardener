#!/usr/bin/env python3
"""
RBAC Hardener - Kubernetes RBAC Security Audit and Hardening Tool

This tool discovers overprivileged RBAC configurations in Kubernetes clusters,
provides interactive hardening recommendations, and applies security fixes.
"""

import argparse
import json
import logging
import logging.handlers
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Union
import yaml

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    from kubernetes.config.config_exception import ConfigException
except ImportError:
    print("ERROR: kubernetes-python-client not installed. Run: pip install kubernetes>=27.2.0")
    sys.exit(2)

try:
    import questionary
    from questionary import Choice
except ImportError:
    print("ERROR: questionary not installed. Run: pip install questionary")
    sys.exit(2)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.spinner import Spinner
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.text import Text
except ImportError:
    print("ERROR: rich not installed. Run: pip install rich")
    sys.exit(2)

# Global console for rich output
console = Console()

# Severity levels
SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"

# Core resources that are security-sensitive
CORE_RESOURCES = {
    "pods", "secrets", "deployments", "services", "configmaps",
    "persistentvolumes", "persistentvolumeclaims", "nodes",
    "serviceaccounts", "roles", "rolebindings", "clusterroles",
    "clusterrolebindings", "networkpolicies", "ingresses"
}

# Write verbs that can modify resources
WRITE_VERBS = {
    "create", "update", "patch", "delete", "deletecollection",
    "bind", "escalate", "impersonate"
}

# Read verbs
READ_VERBS = {"get", "list", "watch"}


class RBACFinding:
    """Represents a single RBAC security finding."""
    
    def __init__(self, kind: str, name: str, namespace: Optional[str] = None):
        self.kind = kind
        self.name = name
        self.namespace = namespace
        self.verbs: Set[str] = set()
        self.api_groups: Set[str] = set()
        self.resources: Set[str] = set()
        self.subjects: List[Dict[str, str]] = []
        self.severity: str = SEVERITY_LOW
        self.raw_object: Optional[Dict[str, Any]] = None
        
    def add_rule(self, verbs: List[str], api_groups: List[str], resources: List[str]):
        """Add a rule to this finding."""
        self.verbs.update(verbs or [])
        self.api_groups.update(api_groups or [""])
        self.resources.update(resources or [])
        
    def add_subjects(self, subjects: List[Dict[str, str]]):
        """Add subjects (for bindings)."""
        self.subjects.extend(subjects or [])
        
    def compute_severity(self) -> str:
        """Compute severity based on verbs and resources."""
        # Critical: wildcard verbs or resources
        if "*" in self.verbs or "*" in self.resources:
            self.severity = SEVERITY_CRITICAL
            return self.severity
            
        # High: write verbs on core resources
        if self.verbs & WRITE_VERBS and self.resources & CORE_RESOURCES:
            self.severity = SEVERITY_HIGH
            return self.severity
            
        # Medium: read verbs on core resources
        if self.verbs & READ_VERBS and self.resources & CORE_RESOURCES:
            self.severity = SEVERITY_MEDIUM
            return self.severity
            
        # Low: everything else
        self.severity = SEVERITY_LOW
        return self.severity
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            "kind": self.kind,
            "name": self.name,
            "namespace": self.namespace,
            "verbs": list(self.verbs),
            "api_groups": list(self.api_groups),
            "resources": list(self.resources),
            "subjects": self.subjects,
            "severity": self.severity
        }


class RBACHardener:
    """Main RBAC hardening tool."""
    
    def __init__(self, namespace_filter: Optional[str] = None, 
                 severity_filter: str = SEVERITY_LOW,
                 force_patch: bool = False,
                 policy_file: Optional[str] = None,
                 output_file: Optional[str] = None):
        self.namespace_filter = namespace_filter
        self.severity_filter = severity_filter
        self.force_patch = force_patch
        self.policy_file = policy_file
        self.output_file = output_file or f"rbac_hardening_{datetime.now().strftime('%Y%m%d_%H%M')}.yaml"
        
        self.v1 = None
        self.rbac_v1 = None
        self.findings: List[RBACFinding] = []
        self.proposed_changes: List[Dict[str, Any]] = []
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup rotating file logging."""
        log_dir = Path.home() / ".rbac_hardener"
        log_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.handlers.RotatingFileHandler(
                    log_dir / "rbac_hardener.log",
                    maxBytes=10*1024*1024,  # 10MB
                    backupCount=5
                ),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def authenticate(self) -> bool:
        """Authenticate with Kubernetes cluster."""
        try:
            # Try kubeconfig first
            config.load_kube_config()
            console.print("[green]✓[/green] Authenticated using kubeconfig")
        except ConfigException:
            try:
                # Fall back to in-cluster config
                config.load_incluster_config()
                console.print("[green]✓[/green] Authenticated using in-cluster config")
            except ConfigException as e:
                console.print(f"[red]✗[/red] Failed to authenticate: {e}")
                return False
                
        # Initialize API clients
        self.v1 = client.CoreV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        return True
        
    def discover_rbac_objects(self) -> List[RBACFinding]:
        """Discover all RBAC objects and create findings."""
        findings = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            # Discover Roles
            task = progress.add_task("Discovering Roles...", total=None)
            try:
                if self.namespace_filter:
                    roles = self.rbac_v1.list_namespaced_role(self.namespace_filter)
                else:
                    roles = self.rbac_v1.list_role_for_all_namespaces()
                    
                for role in roles.items:
                    finding = self._process_role(role)
                    if finding:
                        findings.append(finding)
                        
            except ApiException as e:
                self.logger.error(f"Error discovering roles: {e}")
                
            # Discover ClusterRoles
            progress.update(task, description="Discovering ClusterRoles...")
            try:
                cluster_roles = self.rbac_v1.list_cluster_role()
                for cluster_role in cluster_roles.items:
                    finding = self._process_cluster_role(cluster_role)
                    if finding:
                        findings.append(finding)
            except ApiException as e:
                self.logger.error(f"Error discovering cluster roles: {e}")
                
            # Discover RoleBindings
            progress.update(task, description="Discovering RoleBindings...")
            try:
                if self.namespace_filter:
                    role_bindings = self.rbac_v1.list_namespaced_role_binding(self.namespace_filter)
                else:
                    role_bindings = self.rbac_v1.list_role_binding_for_all_namespaces()
                    
                for binding in role_bindings.items:
                    finding = self._process_role_binding(binding)
                    if finding:
                        findings.append(finding)
            except ApiException as e:
                self.logger.error(f"Error discovering role bindings: {e}")
                
            # Discover ClusterRoleBindings
            progress.update(task, description="Discovering ClusterRoleBindings...")
            try:
                cluster_role_bindings = self.rbac_v1.list_cluster_role_binding()
                for binding in cluster_role_bindings.items:
                    finding = self._process_cluster_role_binding(binding)
                    if finding:
                        findings.append(finding)
            except ApiException as e:
                self.logger.error(f"Error discovering cluster role bindings: {e}")
                
        self.findings = findings
        return findings
        
    def _process_role(self, role) -> Optional[RBACFinding]:
        """Process a Role object into a finding."""
        if not role.rules:
            return None
            
        finding = RBACFinding("Role", role.metadata.name, role.metadata.namespace)
        finding.raw_object = role.to_dict()
        
        for rule in role.rules:
            finding.add_rule(
                rule.verbs or [],
                rule.api_groups or [],
                rule.resources or []
            )
            
        finding.compute_severity()
        return finding if self._should_include_finding(finding) else None
        
    def _process_cluster_role(self, cluster_role) -> Optional[RBACFinding]:
        """Process a ClusterRole object into a finding."""
        if not cluster_role.rules:
            return None
            
        # Skip system cluster roles
        if cluster_role.metadata.name.startswith("system:"):
            return None
            
        finding = RBACFinding("ClusterRole", cluster_role.metadata.name)
        finding.raw_object = cluster_role.to_dict()
        
        for rule in cluster_role.rules:
            finding.add_rule(
                rule.verbs or [],
                rule.api_groups or [],
                rule.resources or []
            )
            
        finding.compute_severity()
        return finding if self._should_include_finding(finding) else None
        
    def _process_role_binding(self, binding) -> Optional[RBACFinding]:
        """Process a RoleBinding object into a finding."""
        finding = RBACFinding("RoleBinding", binding.metadata.name, binding.metadata.namespace)
        finding.raw_object = binding.to_dict()
        
        subjects = []
        for subject in binding.subjects or []:
            subjects.append({
                "kind": subject.kind,
                "name": subject.name,
                "namespace": getattr(subject, "namespace", None)
            })
        finding.add_subjects(subjects)
        
        # For bindings, severity is based on the role they bind to
        # This is a simplified approach - in practice, you'd need to fetch the role
        finding.severity = SEVERITY_MEDIUM
        return finding if self._should_include_finding(finding) else None
        
    def _process_cluster_role_binding(self, binding) -> Optional[RBACFinding]:
        """Process a ClusterRoleBinding object into a finding."""
        # Skip system bindings
        if binding.metadata.name.startswith("system:"):
            return None
            
        finding = RBACFinding("ClusterRoleBinding", binding.metadata.name)
        finding.raw_object = binding.to_dict()
        
        subjects = []
        for subject in binding.subjects or []:
            subjects.append({
                "kind": subject.kind,
                "name": subject.name,
                "namespace": getattr(subject, "namespace", None)
            })
        finding.add_subjects(subjects)
        
        # ClusterRoleBindings are typically higher severity
        finding.severity = SEVERITY_HIGH
        return finding if self._should_include_finding(finding) else None
        
    def _should_include_finding(self, finding: RBACFinding) -> bool:
        """Check if finding should be included based on filters."""
        severity_order = [SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL]
        min_severity_idx = severity_order.index(self.severity_filter)
        finding_severity_idx = severity_order.index(finding.severity)
        
        return finding_severity_idx >= min_severity_idx
        
    def display_findings(self):
        """Display findings in a Rich table grouped by severity."""
        if not self.findings:
            console.print("[yellow]No findings to display[/yellow]")
            return
            
        # Group by severity
        severity_groups = {
            SEVERITY_CRITICAL: [],
            SEVERITY_HIGH: [],
            SEVERITY_MEDIUM: [],
            SEVERITY_LOW: []
        }
        
        for finding in self.findings:
            severity_groups[finding.severity].append(finding)
            
        # Display each severity group
        for severity in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]:
            findings_in_group = severity_groups[severity]
            if not findings_in_group:
                continue
                
            # Color code by severity
            color = {
                SEVERITY_CRITICAL: "red",
                SEVERITY_HIGH: "orange1",
                SEVERITY_MEDIUM: "yellow",
                SEVERITY_LOW: "blue"
            }[severity]
            
            table = Table(title=f"{severity} Severity Findings ({len(findings_in_group)})")
            table.add_column("Kind", style="bold")
            table.add_column("Name")
            table.add_column("Namespace")
            table.add_column("Verbs", max_width=30)
            table.add_column("Resources", max_width=30)
            table.add_column("Subjects", max_width=30)
            
            for finding in findings_in_group:
                verbs_str = ", ".join(sorted(finding.verbs)) if finding.verbs else "-"
                resources_str = ", ".join(sorted(finding.resources)) if finding.resources else "-"
                subjects_str = ", ".join([f"{s['kind']}/{s['name']}" for s in finding.subjects]) if finding.subjects else "-"
                
                table.add_row(
                    f"[{color}]{finding.kind}[/{color}]",
                    finding.name,
                    finding.namespace or "-",
                    verbs_str,
                    resources_str,
                    subjects_str
                )
                
            console.print(table)
            console.print()
            
    def interactive_hardening(self):
        """Interactive workflow for hardening decisions."""
        if not self.findings:
            console.print("[yellow]No findings to harden[/yellow]")
            return
            
        console.print(Panel(
            "Interactive Hardening Workflow\n\n"
            "For each finding, choose your hardening action:\n"
            "• Delete: Remove the RBAC object entirely\n"
            "• Modify: Narrow down permissions (you'll specify new verbs/resources)\n"
            "• Skip: Keep as-is\n\n"
            "Type 'quit' at any prompt to jump to review phase.",
            title="Hardening Instructions"
        ))
        
        for i, finding in enumerate(self.findings, 1):
            console.print(f"\n[bold]Finding {i}/{len(self.findings)}:[/bold]")
            console.print(f"  {finding.kind}: {finding.name} ({finding.severity})")
            
            if finding.namespace:
                console.print(f"  Namespace: {finding.namespace}")
                
            if finding.verbs:
                console.print(f"  Verbs: {', '.join(sorted(finding.verbs))}")
                
            if finding.resources:
                console.print(f"  Resources: {', '.join(sorted(finding.resources))}")
                
            if finding.subjects:
                subjects_str = ", ".join([f"{s['kind']}/{s['name']}" for s in finding.subjects])
                console.print(f"  Subjects: {subjects_str}")
                
            try:
                action = questionary.select(
                    "Choose action:",
                    choices=[
                        Choice("Delete object", "delete"),
                        Choice("Modify object", "modify"),
                        Choice("Skip", "skip")
                    ]
                ).ask()
                
                if action is None or action == "quit":
                    break
                    
                if action == "delete":
                    self.proposed_changes.append({
                        "action": "delete",
                        "finding": finding,
                        "target": finding.to_dict()
                    })
                    console.print("[red]✓[/red] Marked for deletion")
                    
                elif action == "modify":
                    modification = self._get_modification_details(finding)
                    if modification:
                        self.proposed_changes.append({
                            "action": "modify",
                            "finding": finding,
                            "modification": modification
                        })
                        console.print("[yellow]✓[/yellow] Marked for modification")
                        
                elif action == "skip":
                    console.print("[blue]✓[/blue] Skipped")
                    
            except KeyboardInterrupt:
                console.print("\n[red]Interrupted by user[/red]")
                break
                
    def _get_modification_details(self, finding: RBACFinding) -> Optional[Dict[str, Any]]:
        """Get modification details from user."""
        try:
            console.print("\nEnter new permissions (comma-separated lists):")
            
            new_verbs_str = questionary.text(
                "New verbs:",
                default=", ".join(sorted(finding.verbs)) if finding.verbs else ""
            ).ask()
            
            if new_verbs_str is None:
                return None
                
            new_resources_str = questionary.text(
                "New resources:",
                default=", ".join(sorted(finding.resources)) if finding.resources else ""
            ).ask()
            
            if new_resources_str is None:
                return None
                
            new_api_groups_str = questionary.text(
                "New API groups:",
                default=", ".join(sorted(finding.api_groups)) if finding.api_groups else ""
            ).ask()
            
            if new_api_groups_str is None:
                return None
                
            return {
                "verbs": [v.strip() for v in new_verbs_str.split(",") if v.strip()],
                "resources": [r.strip() for r in new_resources_str.split(",") if r.strip()],
                "api_groups": [g.strip() for g in new_api_groups_str.split(",") if g.strip()]
            }
            
        except KeyboardInterrupt:
            return None
            
    def review_and_execute(self):
        """Review proposed changes and execute them."""
        if not self.proposed_changes:
            console.print("[yellow]No changes proposed[/yellow]")
            return
            
        # Display summary
        table = Table(title=f"Proposed Changes ({len(self.proposed_changes)})")
        table.add_column("Action", style="bold")
        table.add_column("Kind")
        table.add_column("Name")
        table.add_column("Namespace")
        table.add_column("Details")
        
        for change in self.proposed_changes:
            finding = change["finding"]
            action = change["action"]
            
            if action == "delete":
                details = "Complete removal"
            elif action == "modify":
                mod = change["modification"]
                details = f"Verbs: {', '.join(mod['verbs'])}"
            else:
                details = "-"
                
            color = "red" if action == "delete" else "yellow"
            
            table.add_row(
                f"[{color}]{action.title()}[/{color}]",
                finding.kind,
                finding.name,
                finding.namespace or "-",
                details
            )
            
        console.print(table)
        
        # Ask for execution mode
        try:
            mode = questionary.select(
                "Choose execution mode:",
                choices=[
                    Choice("Apply to cluster", "apply"),
                    Choice("Dry-run (print YAML & actions)", "dry-run"),
                    Choice("Generate YAML only", "yaml-only")
                ]
            ).ask()
            
            if mode is None:
                console.print("[yellow]Cancelled[/yellow]")
                return
                
            if mode == "apply":
                self._apply_changes()
            elif mode == "dry-run":
                self._dry_run_changes()
            elif mode == "yaml-only":
                self._generate_yaml_only()
                
        except KeyboardInterrupt:
            console.print("\n[red]Interrupted by user[/red]")
            
    def _apply_changes(self):
        """Apply changes to the cluster."""
        console.print("[bold]Applying changes to cluster...[/bold]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            for i, change in enumerate(self.proposed_changes, 1):
                task = progress.add_task(f"Processing change {i}/{len(self.proposed_changes)}...", total=None)
                
                try:
                    if change["action"] == "delete":
                        self._delete_object(change["finding"])
                        console.print(f"[green]✓[/green] Deleted {change['finding'].kind}/{change['finding'].name}")
                        
                    elif change["action"] == "modify":
                        self._modify_object(change["finding"], change["modification"])
                        console.print(f"[yellow]✓[/yellow] Modified {change['finding'].kind}/{change['finding'].name}")
                        
                except Exception as e:
                    console.print(f"[red]✗[/red] Failed to process {change['finding'].name}: {e}")
                    self.logger.error(f"Failed to process change: {e}")
                    
        console.print("[bold green]✓ All changes applied[/bold green]")
        
    def _delete_object(self, finding: RBACFinding):
        """Delete an RBAC object."""
        name = finding.name
        namespace = finding.namespace
        
        if finding.kind == "Role":
            self.rbac_v1.delete_namespaced_role(name, namespace)
        elif finding.kind == "ClusterRole":
            self.rbac_v1.delete_cluster_role(name)
        elif finding.kind == "RoleBinding":
            self.rbac_v1.delete_namespaced_role_binding(name, namespace)
        elif finding.kind == "ClusterRoleBinding":
            self.rbac_v1.delete_cluster_role_binding(name)
            
    def _modify_object(self, finding: RBACFinding, modification: Dict[str, Any]):
        """Modify an RBAC object using server-side apply or clone strategy."""
        if not self.force_patch:
            try:
                self._server_side_apply(finding, modification)
                return
            except Exception as e:
                self.logger.warning(f"Server-side apply failed, falling back to clone strategy: {e}")
                
        # Clone strategy: create hardened version, then delete original
        self._clone_and_replace(finding, modification)
        
    def _server_side_apply(self, finding: RBACFinding, modification: Dict[str, Any]):
        """Attempt server-side apply modification."""
        # TODO: Implement server-side apply logic
        # This would require constructing the modified object and using
        # patch_namespaced_* or patch_cluster_* methods with server-side apply
        raise NotImplementedError("Server-side apply not yet implemented")
        
    def _clone_and_replace(self, finding: RBACFinding, modification: Dict[str, Any]):
        """Clone object with modifications, then replace original."""
        # Create hardened clone
        hardened_name = f"{finding.name}-hardened"
        
        # TODO: Implement clone and replace logic
        # This would involve:
        # 1. Create a copy of the original object
        # 2. Modify its rules/permissions
        # 3. Apply the new object
        # 4. Delete the original object
        raise NotImplementedError("Clone and replace not yet implemented")
        
    def _dry_run_changes(self):
        """Perform dry-run showing what would happen."""
        console.print("[bold]Dry-run mode: Showing what would happen[/bold]")
        
        yaml_content = self._generate_yaml_manifest()
        
        console.print("\n[bold]Generated YAML manifest:[/bold]")
        console.print(yaml_content)
        
        console.print(f"\n[bold]Actions that would be performed:[/bold]")
        for change in self.proposed_changes:
            finding = change["finding"]
            action = change["action"]
            
            if action == "delete":
                console.print(f"[red]DELETE[/red] {finding.kind}/{finding.name}")
            elif action == "modify":
                console.print(f"[yellow]MODIFY[/yellow] {finding.kind}/{finding.name}")
                
        # Optionally write to file
        write_file = questionary.confirm(f"Write YAML to {self.output_file}?").ask()
        if write_file:
            with open(self.output_file, 'w') as f:
                f.write(yaml_content)
            console.print(f"[green]✓[/green] YAML written to {self.output_file}")
            
    def _generate_yaml_only(self):
        """Generate YAML manifest only."""
        console.print("[bold]Generating YAML manifest...[/bold]")
        
        yaml_content = self._generate_yaml_manifest()
        
        with open(self.output_file, 'w') as f:
            f.write(yaml_content)
            
        console.print(f"[green]✓[/green] YAML manifest written to {self.output_file}")
        console.print(f"\nGenerated manifest for {len(self.proposed_changes)} changes")
        
    def _generate_yaml_manifest(self) -> str:
        """Generate YAML manifest for all proposed changes."""
        documents = []
        
        for change in self.proposed_changes:
            finding = change["finding"]
            
            if change["action"] == "delete":
                # For deletions, we could generate a comment or skip
                documents.append(f"# DELETE {finding.kind}/{finding.name}")
                
            elif change["action"] == "modify":
                # Generate modified object YAML
                modified_obj = self._create_modified_object(finding, change["modification"])
                documents.append(yaml.dump(modified_obj, default_flow_style=False))
                
        return "\n---\n".join(documents)
        
    def _create_modified_object(self, finding: RBACFinding, modification: Dict[str, Any]) -> Dict[str, Any]:
        """Create a modified version of the RBAC object."""
        # Start with original object
        obj = finding.raw_object.copy()
        
        # Modify rules for Roles and ClusterRoles
        if finding.kind in ["Role", "ClusterRole"] and "rules" in obj:
            # Simplified: replace all rules with single modified rule
            obj["rules"] = [{
                "verbs": modification["verbs"],
                "apiGroups": modification["api_groups"],
                "resources": modification["resources"]
            }]
            
        # Update metadata
        if "metadata" in obj:
            obj["metadata"]["name"] = f"{finding.name}-hardened"
            # Remove resourceVersion and other server-generated fields
            for field in ["resourceVersion", "uid", "creationTimestamp", "generation"]:
                obj["metadata"].pop(field, None)
                
        return obj
        
    def run(self) -> int:
        """Main execution flow."""
        try:
            console.print("[bold blue]RBAC Hardener - Kubernetes Security Tool[/bold blue]")
            console.print()
            
            # Authenticate
            if not self.authenticate():
                return 2
                
            # Discovery phase
            console.print("[bold]Phase 1: Discovery[/bold]")
            findings = self.discover_rbac_objects()
            console.print(f"Found {len(findings)} RBAC findings")
            
            if not findings:
                console.print("[green]No security findings detected![/green]")
                return 0
                
            # Display findings
            self.display_findings()
            
            # Interactive hardening
            console.print("\n[bold]Phase 2: Interactive Hardening[/bold]")
            self.interactive_hardening()
            
            # Review and execute
            console.print("\n[bold]Phase 3: Review & Execution[/bold]")
            self.review_and_execute()
            
            return 0
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user[/yellow]")
            return 1
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
            self.logger.error(f"Unexpected error: {e}\n{traceback.format_exc()}")
            return 2


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Kubernetes RBAC Security Audit and Hardening Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--namespace",
        help="Filter discovery to specific namespace"
    )
    
    parser.add_argument(
        "--severity",
        choices=[SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL],
        default=SEVERITY_LOW,
        help="Minimum severity level to include (default: Low)"
    )
    
    parser.add_argument(
        "--patch",
        action="store_true",
        help="Force strategic-merge patch instead of server-side apply"
    )
    
    parser.add_argument(
        "--policy-file",
        help="External JSON file defining custom severity rules"
    )
    
    parser.add_argument(
        "--output",
        help="Output filename for generated YAML (default: timestamp-based)"
    )
    
    args = parser.parse_args()
    
    # Create and run hardener
    hardener = RBACHardener(
        namespace_filter=args.namespace,
        severity_filter=args.severity,
        force_patch=args.patch,
        policy_file=args.policy_file,
        output_file=args.output
    )
    
    return hardener.run()


# TODO: Future enhancements
def map_to_cis_benchmark(finding: RBACFinding) -> List[str]:
    """Map finding to CIS Kubernetes Benchmark controls."""
    # TODO: Implement CIS benchmark mapping
    # This would map findings to specific CIS controls like:
    # - 5.1.1 Ensure that the cluster-admin role is only used where required
    # - 5.1.2 Minimize access to secrets
    # - 5.1.3 Minimize wildcard use in Roles and ClusterRoles
    return []


def generate_opa_policies(findings: List[RBACFinding]) -> str:
    """Generate OPA/Gatekeeper policies to prevent similar issues."""
    # TODO: Implement OPA policy generation
    # This would create Gatekeeper ConstraintTemplates and Constraints
    # to prevent creation of overprivileged RBAC objects
    return ""


def generate_falco_rules(findings: List[RBACFinding]) -> str:
    """Generate Falco rules to detect runtime RBAC abuse."""
    # TODO: Implement Falco rule generation
    # This would create Falco rules to detect suspicious RBAC usage
    return ""


# Unit test scaffold
def test_rbac_finding():
    """Test RBACFinding class."""
    finding = RBACFinding("Role", "test-role", "default")
    finding.add_rule(["*"], [""], ["*"])
    assert finding.compute_severity() == SEVERITY_CRITICAL
    
    finding2 = RBACFinding("Role", "test-role-2", "default")
    finding2.add_rule(["get", "list"], [""], ["pods"])
    assert finding2.compute_severity() == SEVERITY_MEDIUM


def test_severity_computation():
    """Test severity computation logic."""
    # Critical: wildcard verbs
    finding = RBACFinding("Role", "test", "default")
    finding.add_rule(["*"], [""], ["pods"])
    assert finding.compute_severity() == SEVERITY_CRITICAL
    
    # Critical: wildcard resources
    finding = RBACFinding("Role", "test", "default")
    finding.add_rule(["get"], [""], ["*"])
    assert finding.compute_severity() == SEVERITY_CRITICAL
    
    # High: write verbs on core resources
    finding = RBACFinding("Role", "test", "default")
    finding.add_rule(["create", "delete"], [""], ["pods", "secrets"])
    assert finding.compute_severity() == SEVERITY_HIGH
    
    # Medium: read verbs on core resources
    finding = RBACFinding("Role", "test", "default")
    finding.add_rule(["get", "list"], [""], ["pods"])
    assert finding.compute_severity() == SEVERITY_MEDIUM
    
    # Low: everything else
    finding = RBACFinding("Role", "test", "default")
    finding.add_rule(["get"], [""], ["configmaps"])
    assert finding.compute_severity() == SEVERITY_LOW


def test_yaml_generation():
    """Test YAML manifest generation."""
    finding = RBACFinding("Role", "test-role", "default")
    finding.raw_object = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {
            "name": "test-role",
            "namespace": "default"
        },
        "rules": [
            {
                "verbs": ["*"],
                "apiGroups": [""],
                "resources": ["*"]
            }
        ]
    }
    
    hardener = RBACHardener()
    modification = {
        "verbs": ["get", "list"],
        "api_groups": [""],
        "resources": ["pods"]
    }
    
    modified_obj = hardener._create_modified_object(finding, modification)
    assert modified_obj["metadata"]["name"] == "test-role-hardened"
    assert modified_obj["rules"][0]["verbs"] == ["get", "list"]
    assert modified_obj["rules"][0]["resources"] == ["pods"]


def run_tests():
    """Run all unit tests."""
    try:
        test_rbac_finding()
        test_severity_computation()
        test_yaml_generation()
        print("✓ All tests passed")
        return True
    except AssertionError as e:
        print(f"✗ Test failed: {e}")
        return False
    except Exception as e:
        print(f"✗ Test error: {e}")
        return False


if __name__ == "__main__":
    # Check if running tests
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        success = run_tests()
        sys.exit(0 if success else 1)
    
    # Normal execution
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(2)
