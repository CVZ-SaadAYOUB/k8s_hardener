# k8s_hardener/utils/rbac_hardener.py

import os
import logging
import argparse
import sys
import yaml # Import for generating YAML
import subprocess # For running kubectl
from collections import defaultdict # To count findings by severity
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.config import ConfigException # Import ConfigException from kubernetes.config
from rich.console import Console # For color output
from rich.table import Table # For potentially nicer output later
from rich.text import Text # For colored text

import questionary # Import questionary for interactive generation
from datetime import datetime # Import datetime for timestamp in filename
from typing import Dict, List, Any, Optional # Import typing hints


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rich Console for colored output
console = Console()

# Severity levels and colors
SEVERITY_COLORS = {
    "Critical": "bold red",
    "High": "bold magenta", # Using magenta for High to differentiate from Critical red
    "Medium": "bold yellow",
    "Low": "green",
    "Warning": "cyan",
    "Info": "blue",
    "Error": "bold red", # Add color for errors
}

# Define the order of severities for sorting and display (most severe first)
SEVERITY_ORDER = list(SEVERITY_COLORS.keys())[:-1] # Exclude 'Error' from standard order


# --- Dangerous Permission Checks ---
# Define patterns for dangerous permissions based on the provided table
# Added 'base_severity' to each pattern
DANGEROUS_PERMISSIONS = {
    "Full Access": {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"], "base_severity": "Critical"},
    "Modify RBAC": {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles", "rolebindings", "clusterroles", "clusterrolebindings"], "verbs": ["create", "update", "patch", "delete"], "base_severity": "Critical"},
    "Create Pods": {"apiGroups": [""], "resources": ["pods"], "verbs": ["create"], "base_severity": "Medium"}, # Base Medium, escalated by subjects
    "Create Privileged Pods": {"apiGroups": [""], "resources": ["pods/privileged"], "verbs": ["create"], "base_severity": "Critical"},
    "Exec into Pods": {"apiGroups": [""], "resources": ["pods/exec", "pods/attach"], "verbs": ["create"], "base_severity": "High"},
    "Access Secrets": {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch"]},
    "Access Sensitive ConfigMaps": {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "list", "watch"], "base_severity": "Medium"}, # Base Medium, escalated in sensitive namespaces
    "Direct Etcd Access": {"apiGroups": ["*"], "resources": ["etcdassignments", "etcdrequests"], "verbs": ["*"], "base_severity": "Critical"},
    "Access Node Resources": {"apiGroups": [""], "resources": ["nodes", "nodes/proxy", "nodes/stats", "nodes/log"], "verbs": ["get", "list"], "base_severity": "Medium"},
}


# --- Risky Subject Checks ---
# Added 'severity_escalation' to each risky subject pattern
RISKY_SUBJECTS = {
    "system:masters Group": {"kind": "Group", "name": "system:masters", "severity_escalation": "Critical"},
    "Default ServiceAccount": {"kind": "ServiceAccount", "name": "default", "severity_escalation": "Medium"}, # Base Medium, escalated by binding scope/permissions
    "Authenticated Users Wildcard": {"kind": "Group", "name": "system:authenticated", "severity_escalation": "High"},
    "Unauthenticated Users Wildcard": {"kind": "Group", "name": "system:unauthenticated", "severity_escalation": "Critical"},
}


# --- Known System Components (for filtering) ---
# Findings related to these names/namespaces might be necessary for cluster operation
SYSTEM_COMPONENTS = [
    "system:", # Prefix for many system components
    "microk8s-", # Prefix for MicroK8s specific components
    "calico-", # Calico CNI
    "coredns", # DNS
    "kube-system", # Namespace
    "kube-public", # Namespace
    "kube-node-lease", # Namespace
    "kube-proxy", # Namespace
    "kubernetes-dashboard", # Dashboard (if installed)
    "storage-provisioner", # Default storage
    "hostpath-provisioner", # MicroK8s hostpath
]


# --- RBAC Generator Functions (Integrated) ---

# Helper function moved outside the class to be used by __init__ and potentially other modules
# Also checks for client config connection status
def _get_k8s_api_clients() -> tuple[Optional[client.CoreV1Api], Optional[client.RbacAuthorizationV1Api]]:
    """Load Kubernetes configuration and return API clients."""
    core_api = None
    rbac_api = None
    try:
        # Try in-cluster config first
        config.load_incluster_config()
        logging.info("Using in-cluster Kubernetes configuration.")
    except ConfigException:
        # Fallback to kubeconfig file
        try:
            config.load_kube_config()
            logging.info("Using kubeconfig file configuration.")
        except ConfigException:
            logging.error("Could not configure Kubernetes client. Make sure you are inside a cluster or have a valid kubeconfig.")
            console.print(Text(
                 "Could not configure Kubernetes client. Ensure a valid kubeconfig or in-cluster env.",
                 style="bold red"
            ))
            return None, None # Return None clients if connection fails

    # If config loaded, initialize clients
    try:
        core_api = client.CoreV1Api()
        rbac_api = client.RbacAuthorizationV1Api()
        logging.info("Kubernetes API clients initialized.")
    except Exception as e:
         logging.error(f"Error initializing Kubernetes API clients: {e}")
         console.print(Text(f"Error initializing Kubernetes API clients: {e}", style="bold red"))
         return None, None

    return core_api, rbac_api


# Helper function for generator, depends on a working client
def _get_namespaces(api: Optional[client.CoreV1Api]) -> List[str]:
    """Fetches a list of all namespaces if API is available."""
    if not api:
        console.print(Text("Cannot fetch namespaces: Kubernetes API not connected.", style="yellow"))
        return []
    try:
        namespaces = api.list_namespace().items
        return sorted([ns.metadata.name for ns in namespaces])
    except ApiException as e:
        console.print(Text(f"Error listing namespaces: {e}", style="red"))
        return []
    except Exception as e:
        console.print(Text(f"An unexpected error occurred listing namespaces: {e}", style="red"))
        return []

# RBAC Rule Generation - Standalone function, doesn't strictly need class instance
def prompt_policy_rule() -> Optional[Dict[str, Any]]:
    """Prompts user to define a single PolicyRule."""
    console.print(Text("\n--- New Policy Rule ---", style="bold blue"))
    rule: Dict[str, Any] = {}

    # API Groups
    api_groups_options = ["", "apps", "rbac.authorization.k8s.io", "networking.k8s.io", "storage.k8s.io", "batch", "extensions", "apiextensions.k8s.io", "admissionregistration.k8s.io", "autoscaling", "policy", "scheduling.k8s.io", "node.k8s.io", "discovery.k8s.io", "flowcontrol.apiserver.k8s.io", "custom (specify comma-separated)", "* (all)"]
    selected_api_groups_choices = questionary.checkbox(
        "Select API Groups (use spacebar to select, Enter to confirm):",
        choices=api_groups_options
    ).ask()

    if not selected_api_groups_choices:
        console.print(Text("No API Groups selected. This rule will be skipped.", style="yellow"))
        return None

    final_api_groups = []
    if "* (all)" in selected_api_groups_choices:
        final_api_groups = ["*"] # '*' is the specific value for all
    else:
        for group in selected_api_groups_choices:
            if group == "custom (specify comma-separated)":
                custom_groups_str = questionary.text("Enter custom API Groups (comma-separated):").ask()
                if custom_groups_str:
                    final_api_groups.extend([g.strip() for g in custom_groups_str.split(',') if g.strip()])
            elif group: # Handle empty string for core API group
                final_api_groups.append(group)
    rule['apiGroups'] = sorted(list(set(final_api_groups))) # Remove duplicates and sort

    # Resources
    resources_options = ["pods", "deployments", "services", "configmaps", "secrets", "namespaces", "nodes", "bindings", "endpoints", "events", "limitranges", "persistentvolumeclaims", "persistentvolumes", "pods/log", "pods/exec", "deployments/scale", "statefulsets", "replicasets", "daemonsets", "roles", "rolebindings", "clusterroles", "clusterrolebindings", "ingresses", "networkpolicies", "storageclasses", "volumeattachments", "* (all)", "custom (specify comma-separated)"]
    selected_resources_choices = questionary.checkbox(
        "Select Resources (use spacebar to select, Enter to confirm):",
        choices=resources_options
    ).ask()

    if not selected_resources_choices:
        console.print(Text("No Resources selected. This rule will be skipped.", style="yellow"))
        return None

    final_resources = []
    if "* (all)" in selected_resources_choices:
        final_resources = ["*"]
    else:
        for resource in selected_resources_choices:
            if resource == "custom (specify comma-separated)":
                custom_resources_str = questionary.text("Enter custom Resources (comma-separated):").ask()
                if custom_resources_str:
                    final_resources.extend([r.strip() for r in custom_resources_str.split(',') if r.strip()])
            elif resource:
                 final_resources.append(resource)
    rule['resources'] = sorted(list(set(final_resources))) # Remove duplicates and sort

    # Verbs
    verbs_options = ["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "* (all)"]
    selected_verbs_choices = questionary.checkbox(
        "Select Verbs (use spacebar to select, Enter to confirm):",
        choices=verbs_options
    ).ask()

    if not selected_verbs_choices:
        console.print(Text("No Verbs selected. This rule will be skipped.", style="yellow"))
        return None

    final_verbs = []
    if "* (all)" in selected_verbs_choices:
        final_verbs = ["*"]
    else:
        final_verbs = sorted(list(set([v.strip() for v in selected_verbs_choices if v.strip()]))) # Remove duplicates and sort
    rule['verbs'] = final_verbs


    # Resource Names (Optional)
    add_resource_names = questionary.confirm("Restrict this rule to specific resource names?").ask()
    if add_resource_names:
        resource_names = []
        console.print(Text("\nEnter specific resource names (e.g., 'my-configmap', 'my-secret-76p9q') (leave empty to finish):", style="bold blue"))
        while True:
            name = questionary.text("Enter resource name:").ask()
            if not name:
                break
            resource_names.append(name.strip())
        if resource_names:
            rule['resourceNames'] = sorted(list(set(resource_names)))

    # Rule must have at least one of apiGroups, resources, verbs
    # In this interactive flow, we already check if selections are empty.
    # A rule with just resourceNames is invalid without resources/verbs.
    if not rule.get('apiGroups') or not rule.get('resources') or not rule.get('verbs'):
         console.print(Text("Rule definition is incomplete (missing apiGroups, resources, or verbs). Skipping.", style="yellow"))
         return None

    return rule

# Subject Generation - Takes the core_api client as argument
def prompt_subject(api: Optional[client.CoreV1Api]) -> Optional[Dict[str, Any]]:
    """Prompts user to define a single Subject."""
    console.print(Text("\n--- New Subject ---", style="bold blue"))
    subject_type = questionary.select(
        "Select Subject Type:",
        choices=['User', 'Group', 'ServiceAccount']
    ).ask()

    if not subject_type:
        console.print(Text("Subject Type not selected. Skipping this subject.", style="yellow"))
        return None

    name = questionary.text(f"Enter {subject_type} name (e.g., 'alice', 'my-group', 'default'):").ask()
    if not name:
        console.print(Text(f"{subject_type} name cannot be empty. Skipping this subject.", style="yellow"))
        return None

    subject: Dict[str, Any] = {
        "kind": subject_type,
        "name": name.strip()
    }

    if subject_type == 'ServiceAccount':
         # Pass the API client to get_namespaces
         namespaces = _get_namespaces(api)
         if not namespaces and api: # Check if API client exists but we still got no namespaces
             console.print(Text("Could not fetch namespaces. Cannot set ServiceAccount namespace.", style="red"))
             # Decide how to handle - maybe allow user to type? For now, skip subject
             return None # Cannot define SA without namespace list

         sa_namespace = questionary.select(
             "Select ServiceAccount namespace:",
             choices=namespaces if namespaces else ["default"] # Offer default if API call failed or not connected
         ).ask()
         if not sa_namespace:
             console.print(Text("ServiceAccount namespace cannot be empty. Skipping this subject.", style="yellow"))
             return None
         subject['namespace'] = sa_namespace

    # apiGroup is required for User and Group subjects in the API object
    if subject_type in ["User", "Group"]:
         subject["apiGroup"] = "rbac.authorization.k8s.io"


    return subject

# Display and Save YAML - Can be methods or standalone
def display_rbac_yaml(resource: Dict[str, Any]) -> str:
    """Displays the generated RBAC resource YAML and returns the string."""
    resource_type = resource['kind']
    console.print(Text(f"\n--- Generated {resource_type} YAML ---", style="bold green"))
    yaml_output = yaml.dump(resource, default_flow_style=False, sort_keys=False)
    console.print(yaml_output)
    console.print(Text("------------------------------------", style="bold green"))
    return yaml_output # Return the YAML string for saving

def save_yaml_to_file(filename: str, yaml_content: str) -> None:
    """Saves the YAML content to a specified file."""
    try:
        with open(filename, 'w') as f:
            f.write(yaml_content)
        console.print(Text(f"YAML saved to {filename}", style="green"))
    except IOError as e:
        console.print(Text(f"Error saving YAML to {filename}: {e}", style="bold red"))


class RBACHardener:
    """
    Audits Kubernetes RoleBindings and ClusterRoleBindings for potential
    security misconfigurations, suggests improvements, and can generate RBAC resources.
    """

    def __init__(self):
        """
        Initializes the Kubernetes clients.
        Loads in-cluster config or kubeconfig. Clients might be None if connection fails.
        """
        # Use the helper function to load config and get clients
        self.core_api, self.rbac_api = _get_k8s_api_clients()
        # Now self.core_api and self.rbac_api can be None

    def _is_system_finding(self, finding):
        """
        Checks if a finding is likely related to a core system component
        based on its name or namespace.
        """
        name = finding.get("name", "").lower()
        namespace = finding.get("namespace", "").lower()

        for component_prefix in SYSTEM_COMPONENTS:
            if name.startswith(component_prefix) or namespace.startswith(component_prefix):
                return True
        return False

    def _filter_findings(self, findings, severities=None, exclude_system=False, binding_types=None):
        """
        Filters a list of findings based on severity, system component status, and binding type.
        """
        filtered = []
        for find in findings:
            # Filter by severity
            find_severity = find.get("severity", "Info")
            if severities is not None:
                # Handle "Error" severity separately as it's not in SEVERITY_ORDER
                if find_severity == "Error":
                    if "Error" not in severities:
                        continue
                elif find_severity not in severities:
                    continue

            # Filter out system components if requested
            if exclude_system and self._is_system_finding(find):
                continue

            # Filter by binding type
            if binding_types is not None:
                if find.get("type") not in binding_types:
                    continue

            filtered.append(find)
        return filtered


    def _check_rule_matches(self, rule, dangerous_permission_pattern):
        """
        Checks if a single RBAC rule matches a dangerous permission pattern.
        Handles wildcards in apiGroups, resources, and verbs.
        """
        # Check apiGroups
        api_groups_match = False
        # Ensure rule.api_groups is treated as a list, handling None
        rule_api_groups = rule.api_groups if rule.api_groups is not None else []
        # Core API group is represented by ""
        if "" in dangerous_permission_pattern["apiGroups"] and not rule_api_groups:
             api_groups_match = True
        elif "*" in dangerous_permission_pattern["apiGroups"]:
            api_groups_match = True
        else:
            for group in rule_api_groups:
                if group in dangerous_permission_pattern["apiGroups"]:
                    api_groups_match = True
                    break

        # Check resources
        resources_match = False
        # Ensure rule.resources is treated as a list, handling None
        rule_resources = rule.resources if rule.resources is not None else []
        if "*" in dangerous_permission_pattern["resources"]:
            resources_match = True
        else:
            for resource in rule_resources:
                if resource in dangerous_permission_pattern["resources"]:
                    resources_match = True
                    break

        # Check verbs
        verbs_match = False
        # Ensure rule.verbs is treated as a list, handling None
        rule_verbs = rule.verbs if rule.verbs is not None else []
        if "*" in dangerous_permission_pattern["verbs"]:
            verbs_match = True
        else:
            for verb in rule_verbs:
                if verb in dangerous_permission_pattern["verbs"]:
                    verbs_match = True
                    break

        return api_groups_match and resources_match and verbs_match

    def _get_effective_severity(self, base_severity, subjects, binding_details):
        """
        Determines the effective severity based on base permission severity
        and the presence of risky subjects or context.
        Consolidates severity escalation logic.
        """
        effective_severity = base_severity
        current_severity_index = SEVERITY_ORDER.index(effective_severity)

        # Check for risky subjects and escalate severity
        for subject in subjects:
            for risky_subj_name, risky_subj_pattern in RISKY_SUBJECTS.items():
                if subject.kind == risky_subj_pattern["kind"] and subject.name == risky_subj_pattern["name"]:
                    escalation_severity = risky_subj_pattern["severity_escalation"]
                    escalation_index = SEVERITY_ORDER.index(escalation_severity)
                    # Escalate only if the risky subject's severity is higher than current effective severity
                    if escalation_index < current_severity_index:
                        effective_severity = escalation_severity
                        current_severity_index = escalation_index

        # Check for binding to system:masters group explicitly (always Critical)
        for subject in subjects:
            if subject.kind == "Group" and subject.name == "system:masters":
                return "Critical" # This overrides any other severity calculation

        # Check for binding to cluster-admin ClusterRole explicitly (always High)
        if binding_details.get("roleRef", {}).get("name") == "cluster-admin" and binding_details.get("roleRef", {}).get("kind") == "ClusterRole":
             # system:masters with cluster-admin is caught above
            return "High" # Any other subject with cluster-admin is High

        # Check for wildcard subjects explicitly (system:authenticated/unauthenticated)
        for subject in subjects:
            if subject.kind == "Group" and subject.name in ["system:authenticated", "system:unauthenticated"]:
                return "Critical" # Wildcard subjects are Critical regardless of permission


        # Specific escalations based on context (e.g., sensitive namespaces)
        if effective_severity in ["Low", "Medium", "High"]:
            if binding_details.get("namespace") in ["kube-system", "kube-public", "kube-node-lease", "kube-proxy"]: # Add more sensitive namespaces if needed
                # Escalate if in sensitive namespace, but not higher than High
                if effective_severity in ["Low", "Medium"]:
                    effective_severity = "High"


        # Check for RoleBinding referencing a ClusterRole (base Low/Medium if not escalated by permissions/subjects)
        if binding_details.get("type") == "RoleBinding" and binding_details.get("roleRef", {}).get("kind") == "ClusterRole":
            # If the calculated effective severity is lower than Medium, set it to Medium
            if SEVERITY_ORDER.index(effective_severity) > SEVERITY_ORDER.index("Medium"):
                effective_severity = "Medium"


        return effective_severity


    def _analyze_role_rules(self, rules, subjects, binding_details):
        """
        Analyzes a list of Role/ClusterRole rules for dangerous permissions
        and generates findings based on the subjects and binding context.
        """
        findings = []
        if not rules:
            # If no rules, but it's a RoleBinding referencing a ClusterRole, add the base finding
            if binding_details.get("type") == "RoleBinding" and binding_details.get("roleRef", {}).get("kind") == "ClusterRole":
                findings.append({
                    "type": binding_details["type"],
                    "name": binding_details["name"],
                    "namespace": binding_details.get("namespace", "N/A"),
                    "severity": "Low", # Base severity for this pattern if no specific dangerous permission
                    "check": "RoleBinding references a ClusterRole",
                    "details": f"RoleBinding in namespace '{binding_details.get('namespace', 'N/A')}' references ClusterRole '{binding_details['roleRef']['name']}'. Ensure the ClusterRole permissions are appropriate for this namespace context.",
                    "binding_details": binding_details
                })
            return findings # No rules, or handled the RoleBinding/ClusterRole case

        for rule in rules:
            for perm_name, perm_pattern in DANGEROUS_PERMISSIONS.items():
                if self._check_rule_matches(rule, perm_pattern):
                    # Found a dangerous permission granted by this role/clusterrole
                    # Determine severity based on subjects and context using the consolidated logic
                    effective_severity = self._get_effective_severity(
                        perm_pattern.get("base_severity", "Low"), # Use base severity from pattern
                        subjects,
                        binding_details
                    )

                    details = f"Grants '{perm_name}' permission ({rule.api_groups}/{rule.resources}/{rule.verbs})."

                    # Add details about risky subjects if they are present
                    risky_subject_details = []
                    for subject in subjects:
                         for risky_subj_name, risky_subj_pattern in RISKY_SUBJECTS.items():
                            if subject.kind == risky_subj_pattern["kind"] and subject.name == risky_subj_pattern["name"]:
                                risky_subject_details.append(f"Subject '{subject.kind}/{subject.name}'")

                    if risky_subject_details:
                         details += f" Involves risky subjects: {', '.join(risky_subject_details)}."

                    # Add details about sensitive namespace if applicable
                    if binding_details.get("namespace") in ["kube-system", "kube-public", "kube-node-lease", "kube-proxy"]:
                         details += f" Binding is in sensitive namespace '{binding_details.get('namespace', 'N/A')}'."


                    findings.append({
                        "type": binding_details["type"],
                        "name": binding_details["name"],
                        "namespace": binding_details.get("namespace", "N/A"),
                        "severity": effective_severity,
                        "check": f"Grants Dangerous Permission: {perm_name}",
                        "details": details,
                        "binding_details": binding_details # Keep full binding details for hardening
                    })

        # If no dangerous permissions were found in the rules, but it's a RoleBinding referencing a ClusterRole, add the base finding
        if binding_details.get("type") == "RoleBinding" and binding_details.get("roleRef", {}).get("kind") == "ClusterRole":
            # Check if any findings were already added from rule analysis for this binding
            # Corrected variable names binding_type and binding_name to use binding_details
            if not any(f.get("binding_details", {}).get("name") == binding_details.get("name") for f in findings):
                findings.append({
                    "type": binding_details.get("type"),
                    "name": binding_details.get("name"),
                    "namespace": binding_details.get("namespace"),
                    "severity": "Low", # Base severity for this pattern if no specific dangerous permission
                    "check": "RoleBinding references a ClusterRole",
                    "details": f"RoleBinding in namespace '{binding_details.get('namespace', 'N/A')}' references ClusterRole '{binding_details['roleRef']['name']}'. Ensure the ClusterRole permissions are appropriate for this namespace context.",
                    "binding_details": binding_details
                })


        return findings


    def _analyze_binding(self, binding, binding_type):
        """
        Fetches the referenced Role/ClusterRole and analyzes its rules.
        Returns a list of findings for this specific binding.
        Requires API clients to be initialized.
        """
        findings = []
        if not self.rbac_api or not self.core_api:
            logging.error("API clients not initialized. Skipping binding analysis.")
            return [{
                "error": "Kubernetes API not connected.",
                "severity": "Error"
            }]

        role_ref_name = binding.role_ref.name
        role_ref_kind = binding.role_ref.kind
        subjects = binding.subjects if binding.subjects else []
        binding_name = binding.metadata.name
        binding_namespace = binding.metadata.namespace if binding_type == "RoleBinding" else "N/A"

        binding_details = {
            "type": binding_type,
            "name": binding_name,
            "namespace": binding_namespace,
            "subjects": subjects,
            "roleRef": {"name": role_ref_name, "kind": role_ref_kind},
            "apiVersion": binding.api_version,
            "kind": binding.kind,
        }

        # --- Analyze Rules for Dangerous Permissions ---
        try:
            role_rules = []
            if role_ref_kind == "ClusterRole":
                cr = self.rbac_api.read_cluster_role(name=role_ref_name)
                role_rules = cr.rules if cr.rules else []

            elif role_ref_kind == "Role":
                if binding_namespace == "N/A": # Should not happen for RoleBindings, but safety check
                    logging.warning(f"RoleBinding '{binding_name}' has N/A namespace. Skipping rule analysis.")
                    findings.append({
                        "type": binding_type, "name": binding_name, "namespace": binding_namespace,
                        "severity": "Warning", "check": "Missing Namespace for RoleRef",
                        "details": "RoleBinding is missing namespace, cannot fetch Role rules.",
                        "binding_details": binding_details
                    })
                    return findings # Cannot fetch namespaced role without namespace

                role = self.rbac_api.read_namespaced_role(name=role_ref_name, namespace=binding_namespace)
                role_rules = role.rules if role.rules else []

            else:
                logging.warning(f"Unknown RoleRef kind '{role_ref_kind}' for binding '{binding_name}' in ns '{binding_namespace}'. Cannot analyze rules.")
                findings.append({
                    "type": binding_type,
                    "name": binding_name,
                    "namespace": binding_namespace,
                    "severity": "Warning",
                    "check": "Unknown RoleRef Kind",
                    "details": f"Binding references unknown RoleRef kind '{role_ref_kind}'. Cannot analyze granted permissions.",
                    "binding_details": binding_details
                })
                return findings # Cannot proceed with rule analysis

            # Analyze the rules for dangerous permissions and add findings
            findings.extend(self._analyze_role_rules(role_rules, subjects, binding_details))


        except ApiException as e:
            # Error occurred while fetching the Role/ClusterRole
            # Use binding_name, binding_type, binding_namespace from the outer scope
            logging.warning(f"Could not fetch {role_ref_kind} '{role_ref_name}' for binding '{binding_name}' in ns '{binding_namespace}': {e}")
            findings.append({
                "type": binding_type,
                "name": binding_name,
                "namespace": binding_namespace,
                "severity": "Warning",
                "check": "Unresolvable RoleRef",
                "details": f"Binding references {role_ref_kind} '{role_ref_name}' that could not be fetched. This binding might be ineffective or point to a configuration error.",
                "binding_details": binding_details
            })


        return findings


    def audit_rbac(self):
        """
        Audits RoleBindings and ClusterRoleBindings for potential risks.
        Returns a list of all findings.
        Requires API clients to be initialized.
        """
        if not self.rbac_api or not self.core_api:
            console.print("[bold red]Cannot perform audit: Kubernetes API not connected.[/bold red]")
            return [{"error": "Kubernetes API not connected.", "severity": "Error"}]

        console.print("\n[bold blue]--- Starting RBAC Audit ---[/bold blue]")
        all_findings = []

        # Audit ClusterRoleBindings
        console.print("[blue]Auditing ClusterRoleBindings...[/blue]")
        try:
            cluster_role_bindings = self.rbac_api.list_cluster_role_binding().items
            console.print(f"[blue]Found {len(cluster_role_bindings)} ClusterRoleBindings.[/blue]")
            for crb in cluster_role_bindings:
                all_findings.extend(self._analyze_binding(crb, "ClusterRoleBinding"))

        # This except block catches errors during the listing of ClusterRoleBindings
        except ApiException as e:
            console.print(f"[bold red]Error auditing ClusterRoleBindings: {e}[/bold red]")
            # Error occurred during the listing itself, no specific binding details available
            all_findings.append({
                "error": f"Error listing ClusterRoleBindings: {e}",
                "severity": "Error" # Mark as error severity
            })


        # Audit RoleBindings per namespace
        console.print("\n[blue]Auditing RoleBindings across namespaces...[/blue]")
        # This try block is for the overall namespace listing and RoleBinding audit
        try:
            namespaces = [ns.metadata.name for ns in self.core_api.list_namespace().items]
            console.print(f"[blue]Found {len(namespaces)} namespaces.[/blue]")
            for ns in namespaces:
                logging.debug(f"Auditing RoleBindings in namespace: {ns}")
                # This inner try block is for listing RoleBindings within a specific namespace
                try:
                    role_bindings = self.rbac_api.list_namespaced_role_binding(namespace=ns).items
                    for rb in role_bindings:
                         # binding_name, binding_type, binding_namespace are defined here
                        all_findings.extend(self._analyze_binding(rb, "RoleBinding"))
                # This except block catches errors during the listing of RoleBindings in a namespace
                except ApiException as e:
                    # Error occurred while listing RoleBindings in a specific namespace
                    console.print(f"[bold red]Error auditing RoleBindings in namespace {ns}: {e}[/bold red]")
                    all_findings.append({
                        "error": f"Error listing RoleBindings in namespace {ns}: {e}",
                        "severity": "Error", # Mark as error severity
                        "namespace": ns # Include namespace context
                    })

        # This except block catches errors during the listing of namespaces
        except ApiException as e:
            console.print(f"[bold red]Error auditing RoleBindings across namespaces: {e}[/bold red]")
            # Error occurred during namespace listing
            all_findings.append({
                "error": f"Error listing namespaces: {e}",
                "severity": "Error" # Mark as error severity
            })


        console.print("\n[bold blue]--- RBAC Audit Finished ---[/bold blue]")
        return all_findings

    def print_audit_findings(self, findings, exclude_system=False):
        """
        Prints a summary of audit findings by severity and allows
        the user to view detailed findings for specific severities,
        with system component findings filtered based on the exclude_system flag.
        """
        if not findings or (len(findings) == 1 and "error" in findings[0] and findings[0].get("severity") == "Error"):
             console.print("\n[bold green]🎉 RBAC Audit completed. No significant issues found or API connection failed. 🎉[/bold green]")
             # If there's a single error finding, print it and return
             if findings and "error" in findings[0]:
                 console.print(f"\n[bold red]ERROR: {findings[0]['error']}[/bold red]")
             return


        console.print("\n[bold blue]--- RBAC Audit Summary ---[/bold blue]")

        # Filter findings based on system exclusion before counting
        # Exclude the top-level API error if it exists before filtering by system
        non_api_error_findings = [f for f in findings if "error" not in f or f.get("severity") != "Error"]
        filtered_findings_system = self._filter_findings(non_api_error_findings, exclude_system=exclude_system)


        if exclude_system:
             console.print(f"[blue]Summary based on {len(filtered_findings_system)} findings after excluding system components.[/blue]")


        # Count findings by severity from the filtered list (including any errors that weren't the top-level API error)
        severity_counts = defaultdict(int)
        all_display_findings = filtered_findings_system[:] # Start with system-filtered findings

        # Add back any specific errors that occurred during namespace processing
        specific_errors = [f for f in findings if "error" in f and f.get("severity") == "Error"]
        all_display_findings.extend(specific_errors)


        for find in all_display_findings:
            severity_counts[find.get("severity", "Info")] += 1

        # Print summary table
        summary_table = Table(title="Audit Findings Summary by Severity")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", style="bold")

        # Print severities in defined order
        for severity in SEVERITY_ORDER:
            count = severity_counts.get(severity, 0)
            if count > 0:
                summary_table.add_row(Text(severity, style=SEVERITY_COLORS[severity]), str(count))

        # Add a row for errors if any
        error_count = severity_counts.get("Error", 0) # Use "Error" key
        if error_count > 0:
             summary_table.add_row(Text("Error", style="bold red"), str(error_count))


        console.print(summary_table)

        # Ask user which severities to view from the filtered list
        while True:
            console.print("\nEnter severity levels to view detailed findings (e.g., Critical,High) or 'all' or 'none':")
            user_input = console.input("[bold blue]Your choice:[/bold blue] ").strip().lower()

            if user_input == 'none':
                console.print("[blue]Skipping detailed findings view.[/blue]")
                severities_to_view = []
                break
            elif user_input == 'all':
                severities_to_view = SEVERITY_ORDER + ["Error"] # Include errors in 'all'
                break
            else:
                requested_severities = [s.strip().capitalize() for s in user_input.split(',') if s.strip()]
                # Ensure "Error" is handled correctly
                valid_severities = [s for s in requested_severities if s in SEVERITY_ORDER]
                if "Error" in requested_severities:
                    valid_severities.append("Error")


                if not valid_severities:
                    console.print("[yellow]Invalid input. Please enter comma-separated severities (Critical, High, Medium, Low, Warning, Info, Error) or 'all' or 'none'.[/yellow]")
                else:
                    severities_to_view = valid_severities
                    break

        # Print detailed findings for selected severities from the filtered list
        if severities_to_view:
            console.print("\n[bold blue]--- Detailed Audit Findings ---[/bold blue]")
            # Sort findings by severity for printing
            # Ensure the key handles findings without 'severity' gracefully (like error objects)
            severity_sort_key = lambda x: (SEVERITY_ORDER.index(x.get("severity", "Info")) if x.get("severity") in SEVERITY_ORDER else (len(SEVERITY_ORDER) if x.get("severity") != "Error" else len(SEVERITY_ORDER) + 1), x.get("name", ""))
            # Sort the findings that were included in the summary table
            sorted_display_findings = sorted(all_display_findings, key=severity_sort_key)


            for find in sorted_display_findings:
                severity = find.get("severity", "Info") if "error" not in find else "Error"
                if severity in severities_to_view:
                    if "error" in find:
                        console.print(f"\n[bold red]ERROR: {find['error']}[/bold red]")
                        # Print namespace context for errors if available
                        if find.get("namespace"):
                            console.print(f"[bold]Namespace:[/bold] {find['namespace']}")
                        console.print("-" * 40, style="blue")
                    else:
                        severity_color = SEVERITY_COLORS.get(severity, "white")
                        console.print(f"\n[bold {severity_color}]Severity:[/bold {severity_color}] {severity}")
                        console.print(f"[bold]Type:[/bold] {find['type']}")
                        console.print(f"[bold]Name:[/bold] {find['name']}")
                        console.print(f"[bold]Namespace:[/bold] {find.get('namespace', 'N/A')}")
                        console.print(f"[bold]Check:[/bold] {find['check']}")
                        console.print(f"[bold]Details:[/bold] {find['details']}")
                        console.print("-" * 40, style="blue")

    def _prompt_modify_binding(self, find):
        """
        Guides the user through modifying a binding.
        Returns a list of proposed changes (dictionaries).
        """
        proposed_changes = []
        original_binding = find.get('binding_details')

        if not original_binding:
            console.print("[bold red]Error: Cannot retrieve original binding details for modification. Skipping.[/bold red]")
            return []

        console.print(f"\n[bold blue]Modifying {find['type']} '{find['name']}' in namespace '{find.get('namespace', 'N/A')}'[/bold blue]")

        while True:
            modify_choice = console.input(
                "[bold yellow]Modification Options:[/bold yellow] "
                "([bold]s[/bold]ubjects, [bold]r[/bold]oleRef, [bold]e[/bold]xit modification): " # Added 'e' for exit
            ).lower()

            if modify_choice == 's':
                # --- Modify Subjects ---
                subjects_to_modify = original_binding.get('subjects', [])
                if not subjects_to_modify:
                    console.print("[yellow]No subjects found in this binding to modify.[/yellow]")
                    continue

                console.print("[blue]Current Subjects in this binding:[/blue]")
                for sub_idx, subject in enumerate(subjects_to_modify):
                    subj_str = f"{subject.kind}/{subject.name}"
                    if subject.namespace:
                        subj_str += f" in namespace '{subject.namespace}'"
                    console.print(f" [{sub_idx}] {subj_str}")


                subject_action = console.input("[bold yellow]Subject Action:[/bold yellow] ([bold]r[/bold]emove subjects, [bold]a[/bold]dd new subject placeholder, [bold]c[/bold]ancel): ").lower()

                if subject_action == 'r':
                    # Remove subjects
                    while True:
                        remove_input = console.input("[bold yellow]Enter indices of subjects to REMOVE (comma-separated, e.g., 0,2) or 'd' when done: [/bold yellow]").lower()
                        if remove_input == 'd':
                            break
                        try:
                            indices_to_remove = [int(idx.strip()) for idx in remove_input.split(',') if idx.strip()]
                            valid_indices = [idx for idx in indices_to_remove if 0 <= idx < len(subjects_to_modify)]

                            if not valid_indices:
                                console.print("[yellow]No valid indices entered.[/yellow]")
                                continue

                            # Create a new subjects list without the selected subjects
                            new_subjects = [s for i, s in enumerate(subjects_to_modify) if i not in valid_indices]

                            confirm_remove = console.input(f"[bold red]CRITICAL ACTION:[/bold red] Are you sure you want to REMOVE selected subjects? ([bold]yes[/bold]/no): ").lower()
                            if confirm_remove == 'yes':
                                # Generate a patch to replace the subjects list
                                patch_obj = {
                                    "apiVersion": original_binding["apiVersion"],
                                    "kind": original_binding["kind"],
                                    "metadata": {
                                        "name": original_binding["name"],
                                    },
                                    "subjects": new_subjects # Replace the entire subjects list
                                }
                                if original_binding.get("namespace"):
                                    patch_obj["metadata"]["namespace"] = original_binding["namespace"]

                                console.print(f"[green]Marking {find['type']} '{find['name']}' for modification (remove subjects).[/green]")
                                proposed_changes.append(patch_obj)
                                return proposed_changes # Return after completing a modification action
                            else:
                                console.print("[yellow]Subject removal cancelled.[/yellow]")

                        except ValueError:
                            console.print("[yellow]Invalid input. Please enter comma-separated numbers or 'd'.[/yellow]")

                elif subject_action == 'a':
                    # Add new subject placeholder
                    new_kind = console.input("[bold yellow]Enter new subject Kind (User, Group, ServiceAccount): [/bold yellow]").strip()
                    new_name = console.input(f"[bold yellow]Enter new {new_kind} Name: [/bold yellow]").strip()
                    new_namespace = None
                    if new_kind == "ServiceAccount":
                        new_namespace = console.input(f"[bold yellow]Enter new ServiceAccount Namespace (leave empty for binding namespace): [/bold yellow]").strip() or original_binding.get("namespace")

                    if not new_kind or not new_name:
                        console.print("[yellow]Kind and Name are required. Action cancelled.[/yellow]")
                        continue

                    new_subject = {"kind": new_kind, "name": new_name}
                    if new_namespace:
                        new_subject["namespace"] = new_namespace
                    if new_kind in ["User", "Group"]:
                         new_subject["apiGroup"] = "rbac.authorization.k8s.io" # apiGroup is needed for User/Group subjects


                    confirm_add = console.input(f"[bold red]CRITICAL ACTION:[/bold red] Are you sure you want to ADD subject placeholder '{new_kind}/{new_name}'? ([bold]yes[/bold]/no): ").lower()
                    if confirm_add == 'yes':
                        # Create a new subjects list with the added subject
                        updated_subjects = subjects_to_modify + [new_subject]

                        patch_obj = {
                            "apiVersion": original_binding["apiVersion"],
                            "kind": original_binding["kind"],
                            "metadata": {
                                "name": original_binding["name"],
                            },
                            "subjects": updated_subjects # Replace the entire subjects list
                        }
                        if original_binding.get("namespace"):
                            patch_obj["metadata"]["namespace"] = original_binding["namespace"]

                        console.print(f"[green]Marking {find['type']} '{find['name']}' for modification (add subject placeholder).[/green]")
                        console.print("[yellow]Remember to verify the details of the added subject in the generated YAML.[/yellow]")
                        proposed_changes.append(patch_obj)
                        return proposed_changes # Return after completing a modification action
                    else:
                        console.print("[yellow]Subject addition cancelled.[/yellow]")

                elif subject_action == 'c':
                    console.print("[yellow]Subject modification cancelled.[/yellow]")
                    continue # Go back to main modification options

                else:
                    console.print("[yellow]Invalid subject action.[/yellow]")

            elif modify_choice == 'r':
                # --- Modify RoleRef ---
                console.print(f"[blue]Current Role Reference: Kind='{original_binding['roleRef']['kind']}', Name='{original_binding['roleRef']['name']}'[/blue]")
                console.print("[yellow]Changing the role reference requires knowing the name of an existing, less privileged Role or ClusterRole.[/yellow]")

                new_role_name = console.input("[bold yellow]Enter the NAME of the new Role or ClusterRole to reference (or 'c' to cancel): [/bold yellow]").strip()

                if new_role_name.lower() == 'c':
                    console.print("[yellow]Role reference modification cancelled.[/yellow]")
                    continue # Go back to main modification options

                new_role_kind = console.input(f"[bold yellow]Enter the KIND of '{new_role_name}' (Role or ClusterRole): [/bold yellow]").strip()

                if new_role_kind not in ["Role", "ClusterRole"]:
                    console.print("[yellow]Invalid Role Kind. Must be 'Role' or 'ClusterRole'. Action cancelled.[/yellow]")
                    continue


                confirm_role_change = console.input(f"[bold red]CRITICAL ACTION:[/bold red] Are you sure you want to change roleRef to Kind='{new_role_kind}', Name='{new_role_name}'? ([bold]yes[/bold]/no): ").lower()

                if confirm_role_change == 'yes':
                    # Generate a patch to replace the roleRef
                    patch_obj = {
                        "apiVersion": original_binding["apiVersion"],
                        "kind": original_binding["kind"],
                        "metadata": {
                            "name": original_binding["name"],
                        },
                        "roleRef": { # Replace the entire roleRef object
                            "apiGroup": "rbac.authorization.k8s.io",
                            "kind": new_role_kind,
                            "name": new_role_name,
                        }
                    }
                    if original_binding.get("namespace"):
                        patch_obj["metadata"]["namespace"] = original_binding["namespace"]

                    console.print(f"[green]Marking {find['type']} '{find['name']}' for modification (change roleRef).[/green]")
                    console.print("[yellow]Ensure the referenced Role/ClusterRole exists and grants appropriate permissions.[/yellow]")
                    proposed_changes.append(patch_obj)
                    return proposed_changes # Return after completing a modification action
                else:
                    console.print("[yellow]Role reference change cancelled.[/yellow]")

            elif modify_choice == 'e': # Added exit option
                console.print("[yellow]Exiting modification for this finding.[/yellow]")
                return [] # Return empty list to indicate no changes for this finding

            else:
                console.print("[yellow]Invalid modification option.[/yellow]")

        return proposed_changes # Should be unreachable if actions return


    def interactive_hardening(self, findings, exclude_system=False):
        """
        Guides the user through interactive hardening based on audit findings.
        Generates a YAML script for proposed changes.
        Allows filtering findings before hardening based on system exclusion and binding type.
        Includes basic modification (subject removal, add subject placeholder, change roleRef).
        """
        # Hardening should target Critical, High, and Medium findings
        risky_findings = [f for f in findings if f.get("severity") in ["Critical", "High", "Medium"]]

        if not risky_findings:
            console.print("\n[bold green]No Critical, High, or Medium severity findings to address interactively.[/bold green]")
            return []

        console.print("\n[bold yellow]--- Starting Interactive Hardening ---[/bold yellow]")
        console.print("[yellow]We will go through Critical, High, and Medium findings to suggest remediation.[/yellow]")

        # Apply initial system exclusion filter if requested
        current_risky_findings = self._filter_findings(risky_findings, exclude_system=exclude_system)

        if exclude_system:
            console.print(f"[blue]Starting hardening with {len(current_risky_findings)} findings after initial system exclusion.[/blue]")


        # Offer additional filtering options
        while True:
            filter_choice = console.input("[bold yellow]Apply additional filters to findings before hardening?[/bold yellow] ([bold]t[/bold]ype, [bold]s[/bold]everity, [bold]n[/bold]one, [bold]p[/bold]roceed): ").lower()

            if filter_choice == 't':
                # Filter by binding type
                while True:
                    type_input = console.input("[bold blue]Filter by binding type? ([bold]rb[/bold] for RoleBinding, [bold]crb[/bold] for ClusterRoleBinding, [bold]all[/bold]): [/bold blue]").strip().lower()
                    if type_input == 'rb':
                        current_risky_findings = self._filter_findings(current_risky_findings, binding_types=["RoleBinding"])
                        console.print(f"[blue]Hardening will proceed with {len(current_risky_findings)} RoleBinding findings.[/blue]")
                        break
                    elif type_input == 'crb':
                        current_risky_findings = self._filter_findings(current_risky_findings, binding_types=["ClusterRoleBinding"])
                        console.print(f"[blue]Hardening will proceed with {len(current_risky_findings)} ClusterRoleBinding findings.[/blue]")
                        break
                    elif type_input == 'all':
                        # No type filter needed, use current list
                        console.print("[blue]No type filter applied.[/blue]")
                        break
                    else:
                        console.print("[yellow]Invalid input. Please enter 'rb', 'crb', or 'all'.[/yellow]")

            elif filter_choice == 's':
                # Filter by severity (allow selecting subset of Critical, High, Medium)
                while True:
                    console.print("\nEnter severity levels to include in hardening (e.g., Critical,High) or 'all':")
                    severity_input = console.input("[bold blue]Your choice (Critical, High, Medium):[/bold blue] ").strip().lower()

                    if severity_input == 'all':
                        # No severity filter needed, use current list
                        console.print("[blue]No severity filter applied.[/blue]")
                        break
                    else:
                        requested_severities = [s.strip().capitalize() for s in severity_input.split(',') if s.strip()]
                        valid_severities = [s for s in requested_severities if s in ["Critical", "High", "Medium"]]

                        if not valid_severities:
                            console.print("[yellow]Invalid input. Please enter comma-separated severities from Critical, High, Medium, or 'all'.[/yellow]")
                        else:
                            current_risky_findings = self._filter_findings(current_risky_findings, severities=valid_severities)
                            console.print(f"[blue]Hardening will proceed with {len(current_risky_findings)} findings of selected severities.[/blue]")
                            break

            elif filter_choice == 'n':
                console.print("[blue]No additional filtering applied.[/blue]")
                break # Exit filtering loop

            elif filter_choice == 'p':
                console.print("[blue]Proceeding to hardening with the current filtered list.[/blue]")
                break # Exit filtering loop and proceed

            else:
                console.print("[yellow]Invalid input. Please enter 't', 's', 'n', or 'p'.[/yellow]")
                continue # Ask again if input is invalid


        if not current_risky_findings:
            console.print("\n[bold green]No findings remaining after filtering to address interactively.[/bold green]")
            return [] # Return empty list if no findings left

        # --- Group findings by binding for unique presentation ---
        findings_by_binding = defaultdict(list)
        for find in current_risky_findings:
            # Create a unique key for each binding
            binding_key = f"{find.get('type')}/{find.get('namespace', 'N/A')}/{find.get('name')}"
            findings_by_binding[binding_key].append(find)

        # Create a list of unique binding summaries with highest severity
        unique_bindings_list = []
        for binding_key, findings_list in findings_by_binding.items():
            # Find the highest severity for this binding
            highest_severity = "Info" # Start with lowest
            for find in findings_list:
                find_severity = find.get("severity", "Info")
                if SEVERITY_ORDER.index(find_severity) < SEVERITY_ORDER.index(highest_severity):
                    highest_severity = find_severity

            # Get binding details from the first finding (they are the same for all in the group)
            binding_details = findings_list[0].get('binding_details', {})

            unique_bindings_list.append({
                "key": binding_key,
                "highest_severity": highest_severity,
                "type": binding_details.get("type"),
                "name": binding_details.get("name"),
                "namespace": binding_details.get("namespace", "N/A"),
                "findings": findings_list # Store all original findings for this binding
            })

        # Sort unique bindings by highest severity
        sorted_unique_bindings = sorted(unique_bindings_list, key=lambda x: SEVERITY_ORDER.index(x["highest_severity"]))


        # --- Present unique bindings and get user selection ---
        console.print("\n[bold blue]--- Risky Bindings Found ---[/bold blue]")
        # Store unique bindings with their presentation index for easy lookup
        unique_bindings_by_index = {idx + 1: binding_summary for idx, binding_summary in enumerate(sorted_unique_bindings)}

        for idx, binding_summary in enumerate(sorted_unique_bindings):
            severity_color = SEVERITY_COLORS.get(binding_summary['highest_severity'], 'white')
            console.print(
                f"[{idx+1}] [bold {severity_color}]Highest Severity:[/bold {severity_color}] {binding_summary['highest_severity']}, "
                f"[bold]Type:[/bold] {binding_summary['type']}, [bold]Name:[/bold] {binding_summary['name']}, "
                f"[bold]Namespace:[/bold] {binding_summary['namespace']}"
            )

        proposed_changes = []

        # Loop to allow selecting and processing multiple bindings
        while True:
            select_input = console.input(
                "\n[bold blue]Enter the number of the binding you want to work on, 'all' to process all, or 'exit' to finish hardening: [/bold blue]"
            ).strip().lower()

            if select_input == 'exit':
                console.print("[blue]Exiting hardening session.[/blue]")
                break # Exit the main hardening loop

            if select_input == 'all':
                bindings_to_process_this_round = list(unique_bindings_by_index.values())
                console.print("[blue]Processing all selected bindings.[/blue]")
            else:
                try:
                    binding_number = int(select_input)
                    if binding_number in unique_bindings_by_index:
                        bindings_to_process_this_round = [unique_bindings_by_index[binding_number]]
                        console.print(f"[blue]Processing binding {binding_number}.[/blue]")
                    else:
                        console.print("[yellow]Invalid binding number.[/yellow]")
                        continue # Ask for input again
                except ValueError:
                    console.print("[yellow]Invalid input. Please enter a number, 'all', or 'exit'.[/yellow]")
                    continue # Ask for input again


            # --- Process selected bindings for this round ---
            # Use a separate list to collect changes from this round's processing
            changes_from_this_round = []
            # Use a flag to check if the user exited modification for a finding
            # exited_modification = False # This flag is now less critical with the new flow, but keep for consistency

            # Inner loop to process the batch of selected bindings (usually just one unless 'all' was chosen)
            for i, binding_summary in enumerate(bindings_to_process_this_round):
                 # Get all original findings for this binding
                 findings_for_this_binding = binding_summary['findings']

                 console.print(f"\n[bold]Addressing Binding:[/bold] {binding_summary['type']} '{binding_summary['name']}' in namespace '{binding_summary['namespace']}'")
                 console.print(f"[bold]Highest Severity:[/bold] {binding_summary['highest_severity']}")

                 # Display all individual findings for this specific binding
                 console.print("\n[blue]Individual Findings for this Binding:[/blue]")
                 for find_idx, find in enumerate(findings_for_this_binding):
                     severity_color = SEVERITY_COLORS.get(find['severity'], 'white')
                     console.print(f" - [bold {severity_color}]Severity:[/bold {severity_color}] {find['severity']}, [bold]Check:[/bold] {find['check']}")
                     console.print(f"   [bold]Details:[/bold] {find['details']}")


                 action = console.input("[bold yellow]Suggested Action for this Binding:[/bold yellow] What would you like to do? ([bold]s[/bold]kip, [bold]d[/bold]elete binding, [bold]m[/bold]odify binding): ").lower()


                 if action == 's':
                     console.print("[yellow]Skipping this binding.[/yellow]")
                     continue # Continue to the next binding in bindings_to_process_this_round

                 elif action == 'd':
                    # Propose deletion of the binding
                    confirm_delete = console.input(f"[bold red]CRITICAL ACTION:[/bold red] Are you sure you want to DELETE the {binding_summary['type']} '{binding_summary['name']}' in namespace '{binding_summary['namespace']}'? ([bold]yes[/bold]/no): ").lower()
                    if confirm_delete == 'yes':
                        console.print(f"[green]Marking {binding_summary['type']} '{binding_summary['name']}' for deletion.[/green]")
                        # Add deletion object to changes for this round
                        if binding_summary['type'] == 'ClusterRoleBinding':
                             changes_from_this_round.append({
                                "apiVersion": "rbac.authorization.k8s.io/v1",
                                "kind": "ClusterRoleBinding",
                                "metadata": {
                                    "name": binding_summary['name']
                                },
                                "delete": True # Custom flag for our script to handle deletion
                             })
                        elif binding_summary['type'] == 'RoleBinding':
                             changes_from_this_round.append({
                                "apiVersion": "rbac.authorization.k8s.io/v1",
                                "kind": "RoleBinding",
                                "metadata": {
                                    "name": binding_summary['name'],
                                    "namespace": binding_summary['namespace']
                                },
                                "delete": True # Custom flag
                             })
                    else:
                        console.print("[yellow]Deletion cancelled.[/yellow]")

                 elif action == 'm':
                    # Call the structured modification prompt
                    # Pass the first finding from the list, as it contains the binding_details
                    # _prompt_modify_binding will return changes specifically for this binding or [] if exited
                    modification_changes = self._prompt_modify_binding(findings_for_this_binding[0])
                    if modification_changes:
                        changes_from_this_round.extend(modification_changes)
                    # If modification_changes is [], it means user exited modification for this binding
                    # The inner loop continues to the next binding in bindings_to_process_this_round.

                 else:
                     console.print("[yellow]Invalid action, skipping this binding.[/yellow]")

            # After processing all bindings in bindings_to_process_this_round:
            # Add changes from this round to the overall proposed_changes
            proposed_changes.extend(changes_from_this_round)
            # The main while True loop continues, prompting for selection again.


        return proposed_changes # Return the accumulated changes when the user exits the main loop


    def generate_hardening_yaml(self, changes):
        """
        Generates a multi-document YAML string from the proposed changes.
        """
        if not changes:
            return None

        console.print("\n[bold blue]--- Generating Hardening YAML ---[/bold blue]")
        yaml_docs = []
        for change in changes:
            # For simplicity, we'll generate delete commands or full object definitions
            # A real-world hardening script might use strategic merge patch or apply
            if change.get("delete"):
                # Generate a delete object definition
                delete_obj = {
                    "apiVersion": change["apiVersion"],
                    "kind": change["kind"],
                    "metadata": {
                        "name": change["metadata"]["name"]
                    }
                }
                if "namespace" in change["metadata"]:
                    delete_obj["metadata"]["namespace"] = change["metadata"]["namespace"]

                # Add a comment indicating this is for deletion
                yaml_docs.append(f"# --- Object to Delete ---\n{yaml.dump(delete_obj, default_flow_style=False)}")

            else:
                # Assume the change object is a full definition or patch
                # For modification, we generate the full object with the desired changes
                # kubectl apply will handle the update
                yaml_docs.append(yaml.dump(change, default_flow_style=False))

        yaml_string = "---\n".join(yaml_docs)
        console.print("[green]YAML generated. Review carefully before applying.[/green]")
        return yaml_string

    def apply_hardening_changes(self, yaml_string, dry_run=False):
        """
        Presents options to apply changes, perform a dry run, or generate a file.
        Handles saving the file if requested.
        Requires kubectl to be in the PATH.
        """
        if not yaml_string:
            console.print("[yellow]No changes proposed.[/yellow]")
            return

        console.print("\n[bold yellow]--- Proposed Hardening Actions ---[/bold yellow]")
        console.print(yaml_string)
        console.print("[bold yellow]-------------------------------[/bold yellow]")

        # Determine default action based on dry_run CLI arg
        default_action = 'dry-run' if dry_run else 'apply'

        while True:
            action_choice = console.input(
                f"[bold yellow]Choose an action:[/bold yellow] ([bold]a[/bold]pply, [bold]d[/bold]ry-run, [bold]g[/bold]enerate file, [bold]c[/bold]ancel) [default: {default_action[0]}]: "
            ).lower() or default_action[0]

            if action_choice == 'c':
                console.print("[yellow]Action cancelled by user.[/yellow]")
                return

            elif action_choice == 'g':
                # Generate file
                file_path = console.input("[bold blue]Enter file path to save YAML (leave empty for ./hardening_script.yaml): [/bold blue]").strip()
                if not file_path:
                    file_path = "hardening_script.yaml"
                    console.print(f"[blue]No path entered, saving to default: {file_path}[/blue]")

                try:
                    with open(file_path, 'w') as f:
                        f.write(yaml_string)
                    console.print(f"[bold green]Hardening YAML saved to {file_path}[/bold green]")
                except IOError as e:
                    console.print(f"[bold red]Error saving file {file_path}: {e}[/bold red]")
                return # Exit after saving

            elif action_choice in ['a', 'd']:
                # Apply or Dry Run
                is_dry_run = (action_choice == 'd')
                kubectl_args = ['kubectl', 'apply', '-f', '-']
                if is_dry_run:
                    kubectl_args.append('--dry-run=client') # Use client-side dry run for simplicity


                confirm_apply = console.input(
                    f"[bold red]CRITICAL ACTION:[/bold red] Are you sure you want to {'perform a DRY RUN' if is_dry_run else 'APPLY these changes'} to the cluster? ([bold]yes[/bold]/no): "
                ).lower()

                if confirm_apply == 'yes':
                    console.print(f"[blue]Running kubectl apply {'--dry-run=client' if is_dry_run else ''} ...[/blue]")
                    try:
                        # Use check=True to raise CalledProcessError on non-zero exit
                        process = subprocess.run(kubectl_args, input=yaml_string.encode(), capture_output=True, check=False)

                        if process.returncode != 0:
                            console.print(f"[bold red]Error applying changes:[/bold red]\n{process.stderr.decode()}")
                        else:
                            if is_dry_run:
                                console.print("[bold green]Dry Run Output:[/bold green]")
                            else:
                                console.print("[bold green]Changes applied successfully![/bold green]")
                            console.print(process.stdout.decode())

                    except FileNotFoundError:
                        console.print("[bold red]Error: kubectl command not found. Please ensure kubectl is installed and in your PATH.[/bold red]")
                    except Exception as e:
                        console.print(f"[bold red]An unexpected error occurred during application: {e}[/bold red]")


                else:
                    console.print("[yellow]Action cancelled by user.[/yellow]")

                return # Exit after applying or dry-running

            else:
                console.print("[yellow]Invalid input. Please enter 'a', 'd', 'g', or 'c'.[/yellow]")

    # --- New RBAC Generation Method ---
    def generate_rbac_interactive(self):
        """
        Runs the interactive RBAC resource generation process.
        """
        # No API client check needed here, as helper functions and apply method handle None clients

        console.print(Text("\n--- Starting RBAC Resource Generation ---", style="bold green"))

        while True: # Loop to allow generating multiple resources
            # Pass self.core_api to the interactive generation function for namespaces/suggestions
            generated_resource = self._generate_rbac_resource_interactive_prompt(self.core_api)

            if generated_resource:
                # Display YAML and capture the string output
                yaml_content = display_rbac_yaml(generated_resource)
                # Ask to save the YAML
                self._ask_to_save_yaml(generated_resource, yaml_content)
                # Ask to apply the resource - pass both clients
                self._ask_to_apply_rbac_resource(self.core_api, self.rbac_api, generated_resource)

            # Ask if user wants to generate another resource
            generate_another = questionary.confirm("Generate another RBAC resource?").ask()
            if not generate_another:
                break

        console.print(Text("\nRBAC generation finished.", style="bold green"))


    # --- Generator Helper Methods (Using class clients) ---

    def _generate_rbac_resource_interactive_prompt(self, api: Optional[client.CoreV1Api]) -> Optional[Dict[str, Any]]:
        """Interactively generates a single RBAC resource dictionary. Takes API client for lookups."""
        console.print(Text("\n--- Generate RBAC Resource ---", style="bold green"))

        resource_type = questionary.select(
            "Select RBAC Resource Type:",
            choices=['Role', 'ClusterRole', 'RoleBinding', 'ClusterRoleBinding']
        ).ask()

        if not resource_type:
            console.print(Text("No resource type selected. Aborting.", style="red"))
            return None

        name = questionary.text(f"Enter {resource_type} name:").ask()
        if not name:
            console.print(Text("Resource name cannot be empty. Aborting.", style="red"))
            return None

        namespace = None
        if resource_type in ['Role', 'RoleBinding']:
             # Use the helper function to get namespaces, passing the class's core_api client
             namespaces = _get_namespaces(api)
             if not namespaces and api: # If API was connected but no namespaces found other than default
                 console.print(Text("Could not fetch namespaces. Cannot create namespaced resource.", style="red"))
                 # Fallback or abort? Let's allow typing for flexibility
                 typed_namespace = questionary.text("Enter namespace for the Role/RoleBinding:").ask()
                 if not typed_namespace:
                     console.print(Text("Namespace cannot be empty. Aborting.", style="red"))
                     return None
                 namespace = typed_namespace.strip()
             elif not namespaces and not api: # If API was not connected at all
                  typed_namespace = questionary.text("Kubernetes API not connected. Enter namespace for the Role/RoleBinding (cannot validate):").ask()
                  if not typed_namespace:
                     console.print(Text("Namespace cannot be empty. Aborting.", style="red"))
                     return None
                  namespace = typed_namespace.strip()
             else: # API connected and namespaces found
                 namespace = questionary.select(
                     f"Select namespace for the {resource_type}:",
                     choices=namespaces
                 ).ask()
                 if not namespace:
                     console.print(Text("Namespace cannot be empty. Aborting.", style="red"))
                     return None


        resource: Dict[str, Any] = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": resource_type,
            "metadata": {
                "name": name.strip()
            }
        }
        if namespace:
            resource['metadata']['namespace'] = namespace

        # --- Define Rules for Role/ClusterRole ---
        if resource_type in ['Role', 'ClusterRole']:
            resource['rules'] = []
            console.print(Text(f"\n--- Defining Policy Rules for {resource_type} '{name}' ---", style="bold blue"))
            while True:
                rule = prompt_policy_rule() # Use the standalone prompt function
                if rule:
                    resource['rules'].append(rule)
                more_rules = questionary.confirm("Add another Policy Rule?").ask()
                if not more_rules:
                    break
            # It's valid to have a Role/ClusterRole with no rules (grants no permissions)
            # if not resource['rules']:
            #    console.print(Text(f"No Policy Rules defined for {resource_type}. It will grant no permissions.", style="yellow"))


        # --- Define Subjects and Role Ref for RoleBinding/ClusterRoleBinding ---
        elif resource_type in ['RoleBinding', 'ClusterRoleBinding']:
             resource['subjects'] = []
             console.print(Text(f"\n--- Defining Subjects for {resource_type} '{name}' ---", style="bold blue"))
             while True:
                 # Pass the class's core_api client to prompt_subject for namespace lookups
                 subject = prompt_subject(self.core_api)
                 if subject:
                     resource['subjects'].append(subject)
                 more_subjects = questionary.confirm("Add another Subject?").ask()
                 if not more_subjects:
                     break
             # It's valid to have a Binding with no subjects (binds no one)
             # if not resource['subjects']:
             #     console.print(Text(f"No Subjects defined for {resource_type}. It will bind no one.", style="yellow"))


             # RoleRef
             console.print(Text(f"\n--- Defining Role Reference for {resource_type} '{name}' ---", style="bold blue"))
             ref_kind = 'Role' if resource_type == 'RoleBinding' else 'ClusterRole'
             # Could add logic here to fetch existing roles/clusterroles to suggest names
             ref_name = questionary.text(f"Enter the name of the {ref_kind} this {resource_type} binds to:").ask()
             if not ref_name:
                  console.print(Text(f"Role reference name cannot be empty. Skipping {resource_type} creation.", style="red"))
                  return None # Cannot create binding without referencing a role/clusterrole

             resource['roleRef'] = {
                 "apiGroup": "rbac.authorization.k8s.io",
                 "kind": ref_kind,
                 "name": ref_name.strip()
             }

        return resource

    def _ask_to_save_yaml(self, resource: Dict[str, Any], yaml_content: str) -> None:
        """Asks the user if they want to save the generated YAML and handles saving."""
        save_option = questionary.confirm("Do you want to save this YAML to a file?").ask()

        if save_option:
            resource_type = resource['kind'].lower()
            resource_name = resource['metadata']['name']
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"{resource_type}-{resource_name}-{timestamp}.yaml"

            filename = questionary.text(
                "Enter filename (default is current directory):",
                default=default_filename
            ).ask()

            if filename:
                save_yaml_to_file(filename, yaml_content) # Use the standalone save function


    def _ask_to_apply_rbac_resource(self, core_api: Optional[client.CoreV1Api], rbac_api: Optional[client.RbacAuthorizationV1Api], resource: Dict[str, Any]) -> None:
        """Asks user if they want to apply the generated RBAC resource. Takes API clients."""
        if not core_api or not rbac_api: # Check if clients are available
            console.print(Text("\nCannot apply resource: Kubernetes API not connected.", style="red"))
            return

        resource_type = resource['kind']
        name = resource['metadata']['name']
        namespace = resource['metadata'].get('namespace') # Namespace is optional for ClusterRoles/Bindings

        apply_resource = questionary.confirm(f"Do you want to apply this {resource_type} '{name}'?").ask()

        if apply_resource:
            console.print(Text(f"Applying {resource_type} '{name}'...", style="bold blue"))
            if namespace:
                console.print(Text(f"  in namespace '{namespace}'", style="blue"))

            try:
                # Note: This only handles CREATE. For update/replace, you'd need kubectl apply or replace.
                # Using client.create_namespaced_... will fail if the resource already exists (409 Conflict).
                if resource_type == 'Role':
                     rbac_api.create_namespaced_role(namespace, resource)
                elif resource_type == 'ClusterRole':
                     rbac_api.create_cluster_role(resource)
                elif resource_type == 'RoleBinding':
                     rbac_api.create_namespaced_role_binding(namespace, resource)
                elif resource_type == 'ClusterRoleBinding':
                     rbac_api.create_cluster_role_binding(resource)
                else:
                    console.print(Text(f"Unknown resource type '{resource_type}'. Cannot apply.", style="bold red"))
                    return

                console.print(Text(f"{resource_type} '{name}' applied successfully.", style="green"))

            except ApiException as e:
                console.print(Text(f"Error applying {resource_type} '{name}': {e.status} - {e.reason}", style="bold red"))
                # Check if it's a "already exists" error (status 409)
                if e.status == 409:
                     console.print(Text(f"Resource '{name}' already exists. Consider using 'kubectl apply -f <file>' or adding replace logic.", style="yellow"))
                else:
                     console.print(Text(f"Body: {e.body}", style="red"))
            except Exception as e:
                console.print(Text(f"An unexpected error occurred applying {resource_type} '{name}': {e}", style="bold red"))


# Example usage (for testing the module directly)
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kubernetes RBAC Hardener, Auditor, and Generator.")
    parser.add_argument('--audit', action='store_true', help='Run the RBAC audit.')
    parser.add_argument('--harden', action='store_true', help='Run interactive hardening after audit.')
    parser.add_argument('--generate', action='store_true', help='Run interactive RBAC resource generation.')
    parser.add_argument('--dry-run', action='store_true', help='Default to dry-run in hardening application prompt.')
    # Add other potential arguments later: --suggest (non-interactive suggestions)

    args = parser.parse_args()

    # Check if any action is requested
    if not (args.audit or args.harden or args.generate):
        console.print("[yellow]Please specify an action: --audit, --harden, or --generate.[/yellow]")
        sys.exit(1)

    hardener = RBACHardener()

    # Check if clients were initialized before proceeding with API-dependent tasks
    if not hardener.core_api or not hardener.rbac_api:
        # If clients failed, only generation is possible without live data/apply
        if not args.generate:
             console.print("[bold red]Kubernetes API connection failed. Cannot perform audit or hardening.[/bold red]")
             sys.exit(1)
        else:
             console.print("[yellow]Kubernetes API connection failed. Generation is possible, but namespace suggestions and applying resources will not work.[/yellow]")


    # Consolidate initial system exclusion prompt (only if audit/harden requested)
    exclude_system_globally = False
    if args.audit or args.harden:
        while True:
            exclude_input = console.input("[bold blue]Exclude findings related to known system components (e.g., Calico, CoreDNS) from audit output and hardening? ([bold]yes[/bold]/no): [/bold blue]").strip().lower()
            if exclude_input in ['yes', 'y']:
                exclude_system_globally = True
                break
            elif exclude_input in ['no', 'n']:
                exclude_system_globally = False
                break
            else:
                console.print("[yellow]Invalid input. Please enter 'yes' or 'no'.[/yellow]")


    # --- Execute requested actions ---
    if args.generate:
        # The generate function handles its own loop
        hardener.generate_rbac_interactive()
        # If only generate was requested, we can exit here
        if not args.audit and not args.harden:
             sys.exit(0)


    if args.audit or args.harden: # Always audit if harden is requested
        audit_findings = hardener.audit_rbac()
        # Pass the global exclusion choice to print_audit_findings
        hardener.print_audit_findings(audit_findings, exclude_system=exclude_system_globally)

        if args.harden:
            # The interactive hardening logic now uses the full list of findings
            proposed_changes = hardener.interactive_hardening(audit_findings, exclude_system=exclude_system_globally)
            if proposed_changes:
                hardening_yaml = hardener.generate_hardening_yaml(proposed_changes)
                # Pass the dry_run CLI arg value to influence the default action in apply_hardening_changes
                hardener.apply_hardening_changes(hardening_yaml, dry_run=args.dry_run)
            else:
                console.print("[blue]No changes proposed during interactive hardening.[/blue]")