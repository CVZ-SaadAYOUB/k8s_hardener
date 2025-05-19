#!/usr/bin/env python3
"""
Kubernetes RBAC Generator
Interactively generates Role, ClusterRole, RoleBinding, and ClusterRoleBinding YAML manifests.
Includes option to save the generated YAML to a file.
"""
import sys
import argparse
import yaml # Import PyYAML for generating YAML
from datetime import datetime # Import datetime for timestamp in filename
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.config import ConfigException
from rich.console import Console
from rich.text import Text
import questionary
from typing import Dict, List, Any, Optional

console = Console()

# --- Kubernetes Client Setup ---
# Used to fetch existing namespaces and potentially suggest existing Roles/ClusterRoles
def get_k8s_client() -> Optional[client.CoreV1Api]:
    """Load Kubernetes configuration and return a CoreV1Api client."""
    try:
        config.load_kube_config()
    except ConfigException:
        try:
            config.load_incluster_config()
        except ConfigException:
            console.print(Text(
                "Could not configure Kubernetes client. Ensure a valid kubeconfig or in-cluster env.",
                style="bold red"
            ))
            return None # Return None if client cannot be configured
    return client.CoreV1Api()

# --- Helper Functions ---

def get_namespaces(api: Optional[client.CoreV1Api]) -> List[str]:
    """Fetches a list of all namespaces."""
    if not api:
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

def get_rbac_api_client(api_client: client.CoreV1Api) -> client.RbacAuthorizationV1Api:
     """Returns the RBAC API client."""
     return client.RbacAuthorizationV1Api(api_client.api_client)

# (Keep get_roles and get_cluster_roles if you plan to add suggestions based on existing resources)
# For brevity in this update, I'll omit them if they aren't used in the generation logic yet,
# but feel free to add them back if you enhance the prompts to suggest existing names.
#
# def get_roles(rbac_api: client.RbacAuthorizationV1Api, namespace: str) -> List[str]:
#      # ... (code from previous response)
#      pass
#
# def get_cluster_roles(rbac_api: client.RbacAuthorizationV1Api) -> List[str]:
#      # ... (code from previous response)
#      pass


# --- RBAC Rule Generation ---

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


# --- Subject Generation ---

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
         namespaces = get_namespaces(api)
         if not namespaces and api:
              console.print(Text("Could not fetch namespaces. Cannot set ServiceAccount namespace.", style="red"))
              # Decide how to handle - maybe allow user to type? For now, skip subject
              return None # Cannot define SA without namespace list

         sa_namespace = questionary.select(
            "Select ServiceAccount namespace:",
            choices=namespaces if namespaces else ["default"]
        ).ask()
         if not sa_namespace:
              console.print(Text("ServiceAccount namespace cannot be empty. Skipping this subject.", style="yellow"))
              return None
         subject['namespace'] = sa_namespace

    return subject


# --- Resource Generation ---

def generate_rbac_resource_interactive(api: Optional[client.CoreV1Api]) -> Optional[Dict[str, Any]]:
    """Interactively generates a single RBAC resource dictionary."""
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
        namespaces = get_namespaces(api)
        if not namespaces and api:
            console.print(Text("Could not fetch namespaces. Cannot create namespaced resource.", style="red"))
            return None

        namespace = questionary.select(
            f"Select namespace for the {resource_type}:",
            choices=namespaces if namespaces else ["default"] # Offer default if API call failed
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
            rule = prompt_policy_rule()
            if rule:
                resource['rules'].append(rule)
            more_rules = questionary.confirm("Add another Policy Rule?").ask()
            if not more_rules:
                break
        # It's valid to have a Role/ClusterRole with no rules (grants no permissions)
        # if not resource['rules']:
        #     console.print(Text(f"No Policy Rules defined for {resource_type}. It will grant no permissions.", style="yellow"))


    # --- Define Subjects and Role Ref for RoleBinding/ClusterRoleBinding ---
    elif resource_type in ['RoleBinding', 'ClusterRoleBinding']:
         resource['subjects'] = []
         console.print(Text(f"\n--- Defining Subjects for {resource_type} '{name}' ---", style="bold blue"))
         while True:
             subject = prompt_subject(api)
             if subject:
                 resource['subjects'].append(subject)
             more_subjects = questionary.confirm("Add another Subject?").ask()
             if not more_subjects:
                 break
         # It's valid to have a Binding with no subjects (binds no one)
         # if not resource['subjects']:
         #      console.print(Text(f"No Subjects defined for {resource_type}. It will bind no one.", style="yellow"))


         # RoleRef
         console.print(Text(f"\n--- Defining Role Reference for {resource_type} '{name}' ---", style="bold blue"))
         ref_kind = 'Role' if resource_type == 'RoleBinding' else 'ClusterRole'
         ref_name = questionary.text(f"Enter the name of the {ref_kind} this {resource_type} binds to:").ask() # Could suggest existing ones here
         if not ref_name:
              console.print(Text(f"Role reference name cannot be empty. Skipping {resource_type} creation.", style="red"))
              return None # Cannot create binding without referencing a role/clusterrole

         resource['roleRef'] = {
             "apiGroup": "rbac.authorization.k8s.io",
             "kind": ref_kind,
             "name": ref_name.strip()
         }

    return resource

def display_rbac_yaml(resource: Dict[str, Any]) -> None:
    """Displays the generated RBAC resource YAML."""
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

def ask_to_save_yaml(resource: Dict[str, Any], yaml_content: str) -> None:
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
            save_yaml_to_file(filename, yaml_content)


def ask_to_apply_rbac_resource(api_client: Optional[client.CoreV1Api], resource: Dict[str, Any]) -> None:
    """Asks user if they want to apply the generated RBAC resource."""
    if not api_client:
        console.print(Text("\nCannot apply resource: Kubernetes client not configured.", style="red"))
        return

    resource_type = resource['kind']
    name = resource['metadata']['name']
    namespace = resource['metadata'].get('namespace') # Namespace is optional for ClusterRoles/Bindings

    apply_resource = questionary.confirm(f"Do you want to apply this {resource_type} '{name}'?").ask()

    if apply_resource:
        rbac_api = get_rbac_api_client(api_client)
        console.print(Text(f"Applying {resource_type} '{name}'...", style="bold blue"))
        if namespace:
            console.print(Text(f"  in namespace '{namespace}'", style="blue"))

        try:
            if resource_type == 'Role':
                # Use replace if exists? Or just create? Let's stick to create for simplicity
                # Consider adding a replace/patch option later if needed
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


# --- Main Execution Function ---

def run():
    """
    Entry point function called by main.py or when the script is run directly.
    Interactively generates and optionally applies RBAC resources.
    """
    parser = argparse.ArgumentParser(
        description="Interactively generate Kubernetes RBAC resources (Role, ClusterRole, Binding).",
        prog="rbac_generator.py"
    )
    # No specific arguments needed for interactive generation currently
    args = parser.parse_args()

    api_client = get_k8s_client()

    # Get Kubernetes client (optional for generation, but needed for suggestions/apply)
    if api_client is None:
        console.print(Text("Warning: Could not connect to Kubernetes API. Suggestions (namespaces, existing roles) and applying resources will not be available.", style="yellow"))
        # Allow generating without API connection, but flag it. Pass None to functions.

    while True: # Loop to allow generating multiple resources
        generated_resource = generate_rbac_resource_interactive(api_client)

        if generated_resource:
            # Display YAML and capture the string output
            yaml_content = display_rbac_yaml(generated_resource)
            # Ask to save the YAML
            ask_to_save_yaml(generated_resource, yaml_content)
            # Ask to apply the resource
            ask_to_apply_rbac_resource(api_client, generated_resource)

        # Ask if user wants to generate another resource
        generate_another = questionary.confirm("Generate another RBAC resource?").ask()
        if not generate_another:
            break

    console.print(Text("\nRBAC generation finished.", style="bold green"))


# --- Standalone Execution ---

if __name__ == "__main__":
    # If the script is run directly, call the run() function
    run()