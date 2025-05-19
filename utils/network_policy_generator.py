#!/usr/bin/env python3
"""
Kubernetes Network Policy Generator
Interactively generates NetworkPolicy YAML manifests.
Includes option to save the generated YAML to a file and apply it to the cluster.
"""
import sys
import argparse
import yaml # Import PyYAML for generating YAML
from datetime import datetime # Import datetime for timestamp in filename
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.config import ConfigException # Import ConfigException explicitly
from rich.console import Console
from rich.text import Text
import questionary
import subprocess # For running kubectl apply (alternative to client API)
from typing import Dict, List, Any, Optional

console = Console()

# --- Kubernetes Client Setup ---
# Reusing a similar pattern from rbac_hardener for consistency
def _get_k8s_api_clients() -> tuple[Optional[client.CoreV1Api], Optional[client.NetworkingV1Api]]:
    """Load Kubernetes configuration and return relevant API clients."""
    core_api = None
    networking_api = None
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
        networking_api = client.NetworkingV1Api()
        logging.info("Kubernetes CoreV1Api and NetworkingV1Api clients initialized.")
    except Exception as e:
         logging.error(f"Error initializing Kubernetes API clients: {e}")
         console.print(Text(f"Error initializing Kubernetes API clients: {e}", style="bold red"))
         return None, None

    return core_api, networking_api

# Helper function for fetching namespaces, depends on a working CoreV1Api client
def _get_namespaces(api: Optional[client.CoreV1Api]) -> List[str]:
    """Fetches a list of all namespaces if CoreV1Api is available."""
    if not api:
        console.print(Text("Cannot fetch namespaces: Kubernetes CoreV1Api not connected.", style="yellow"))
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

# --- Prompt Helpers ---

def prompt_labels(prompt_text: str) -> Dict[str, str]:
    """Prompts user for a set of key-value labels."""
    labels: Dict[str, str] = {}
    console.print(Text(f"\n--- Define {prompt_text} Labels ---", style="bold blue"))
    console.print(Text("Enter labels as key=value (leave key empty to finish):", style="blue"))

    while True:
        key = questionary.text("Label Key:").ask()
        if not key:
            break
        value = questionary.text(f"Label Value for '{key}':").ask()
        if value is not None: # Allow empty string values
            labels[key.strip()] = value.strip()
        else:
             # User cancelled value prompt, skip this key
             pass # Or break the loop if cancelling value should end label entry? Sticking to leaving key empty to finish.


    return labels

def prompt_ports() -> List[Dict[str, Any]]:
    """Prompts user for a list of network ports and protocols."""
    ports: List[Dict[str, Any]] = []
    console.print(Text("\n--- Define Ports ---", style="bold blue"))

    while True:
        add_port = questionary.confirm("Add a port?").ask()
        if not add_port:
            break

        protocol = questionary.select(
            "Select Protocol:",
            choices=['TCP', 'UDP', 'SCTP', 'any'] # 'any' is a conceptual choice for the user
        ).ask()

        if not protocol:
            console.print(Text("Protocol not selected. Skipping this port.", style="yellow"))
            continue

        # Handle 'any' protocol selection conceptually for the user prompt
        if protocol == 'any':
             port_protocol = None # Omit protocol field for any
        else:
             port_protocol = protocol.upper()

        port_number = questionary.text("Enter Port Number (leave empty for any port with selected protocol):").ask()

        port_dict: Dict[str, Any] = {}
        if port_protocol:
            port_dict['protocol'] = port_protocol

        if port_number:
            try:
                port_int = int(port_number.strip())
                port_dict['port'] = port_int
            except ValueError:
                console.print(Text("Invalid port number. Skipping this port.", style="yellow"))
                continue

        if port_dict: # Only add if at least protocol or port was specified
            ports.append(port_dict)
        else:
             console.print(Text("No valid protocol or port specified for this entry. Skipping.", style="yellow"))


    return ports if ports else []

def prompt_ip_block() -> Optional[Dict[str, Any]]:
    """Prompts user to define an ipBlock."""
    console.print(Text("\n--- Define IP Block ---", style="bold blue"))
    cidr = questionary.text("Enter CIDR (e.g., 192.168.1.0/24):").ask()

    if not cidr:
        console.print(Text("CIDR is required for ipBlock. Skipping.", style="yellow"))
        return None

    ip_block: Dict[str, Any] = {"cidr": cidr.strip()}

    add_except = questionary.confirm("Add exceptions to this CIDR?").ask()
    if add_except:
        exceptions = []
        console.print(Text("Enter CIDRs to EXCLUDE from the block (leave empty to finish):", style="blue"))
        while True:
            except_cidr = questionary.text("Exception CIDR:").ask()
            if not except_cidr:
                break
            exceptions.append(except_cidr.strip())
        if exceptions:
            ip_block['except'] = exceptions

    return ip_block

def prompt_peers(direction: str, api_client: Optional[client.CoreV1Api]) -> List[Dict[str, Any]]:
    """Prompts user to define network policy peers (from or to)."""
    peers: List[Dict[str, Any]] = []
    console.print(Text(f"\n--- Define Peers ({direction}) ---", style="bold blue"))
    console.print(Text(f"These define where traffic is allowed {direction} the selected pods.", style="blue"))

    while True:
        add_peer = questionary.confirm(f"Add a peer to allow traffic {direction}?").ask()
        if not add_peer:
            break

        peer_type = questionary.select(
            "Select Peer Type:",
            choices=['Pods (podSelector)', 'Namespaces (namespaceSelector)', 'IP Blocks (ipBlock)']
        ).ask()

        if not peer_type:
            console.print(Text("Peer type not selected. Skipping this peer.", style="yellow"))
            continue

        if peer_type == 'Pods (podSelector)':
            console.print(Text("\nSpecify which pods traffic is allowed from/to.", style="blue"))
            # An empty podSelector {} matches all pods in the policy's namespace
            match_all_pods_in_ns = questionary.confirm("Allow traffic from/to ALL pods in the policy's namespace?").ask()
            if match_all_pods_in_ns:
                peers.append({"podSelector": {}})
            else:
                # Prompt for labels for a specific podSelector
                pod_labels = prompt_labels("Pod Selector")
                if pod_labels:
                    peers.append({"podSelector": {"matchLabels": pod_labels}})
                elif pod_labels == {}:
                     # User entered no labels but didn't choose "match all"
                     console.print(Text("No pod labels specified. Skipping this peer.", style="yellow"))
                # Note: We are not handling matchExpressions here for simplicity


        elif peer_type == 'Namespaces (namespaceSelector)':
            console.print(Text("\nSpecify which namespaces traffic is allowed from/to.", style="blue"))
            # An empty namespaceSelector {} matches all namespaces
            match_all_namespaces = questionary.confirm("Allow traffic from/to ALL namespaces?").ask()
            if match_all_namespaces:
                 peers.append({"namespaceSelector": {}})
            else:
                 # Prompt for labels for a specific namespaceSelector
                 namespace_labels = prompt_labels("Namespace Selector")
                 if namespace_labels:
                     peers.append({"namespaceSelector": {"matchLabels": namespace_labels}})
                 elif namespace_labels == {}:
                      # User entered no labels but didn't choose "match all"
                      console.print(Text("No namespace labels specified. Skipping this peer.", style="yellow"))
                 # Note: We are not handling matchExpressions here for simplicity

            # Optional: Combine podSelector and namespaceSelector
            combine_with_pod_selector = questionary.confirm("Restrict this namespace selection to specific pods *within* those namespaces?").ask()
            if combine_with_pod_selector:
                pod_labels_within_ns = prompt_labels("Pods within Selected Namespaces")
                if pod_labels_within_ns:
                    # Find the last added peer (which should be the namespaceSelector) and add podSelector to it
                    if peers and "namespaceSelector" in peers[-1]:
                        peers[-1]["podSelector"] = {"matchLabels": pod_labels_within_ns}
                    else:
                        console.print(Text("Could not add podSelector to namespaceSelector. Check previous selections.", style="yellow"))
                elif pod_labels_within_ns == {}:
                     console.print(Text("No pod labels within namespace specified. Not applying pod restriction.", style="yellow"))


        elif peer_type == 'IP Blocks (ipBlock)':
            ip_block = prompt_ip_block()
            if ip_block:
                peers.append({"ipBlock": ip_block})

        # Add separator for clarity in output
        if add_peer and peers:
            console.print(Text("---", style="dim")) # Separator

    return peers if peers else []

def prompt_rules(direction: str, api_client: Optional[client.CoreV1Api]) -> List[Dict[str, Any]]:
    """Prompts user to define a list of network policy rules (ingress or egress)."""
    rules: List[Dict[str, Any]] = []
    console.print(Text(f"\n--- Define {direction} Rules ---", style="bold green"))

    while True:
        add_rule = questionary.confirm(f"Add an {direction} rule?").ask()
        if not add_rule:
            break

        rule: Dict[str, Any] = {}

        # Peers (from or to)
        peer_list = prompt_peers(direction, api_client)
        if peer_list:
             rule[direction.lower()] = peer_list # 'from' or 'to' key

        # Ports
        port_list = prompt_ports()
        if port_list:
            rule['ports'] = port_list

        # A rule must have at least one of 'ports' or ('from'/'to')
        # A rule with empty 'from' or 'to' and empty 'ports' is not useful
        # If the user added peers OR ports, consider the rule valid
        if rule.get(direction.lower()) or rule.get('ports'):
            rules.append(rule)
            console.print(Text(f"{direction} rule added.", style="green"))
        else:
            console.print(Text(f"Skipping {direction} rule: No peers or ports defined.", style="yellow"))

        console.print(Text("--- End of Rule ---", style="dim"))

    return rules if rules else []


# --- Network Policy Generation ---

def generate_network_policy_interactive(api_client: Optional[client.CoreV1Api]) -> Optional[Dict[str, Any]]:
    """Interactively generates a single NetworkPolicy dictionary."""
    console.print(Text("\n--- Generate NetworkPolicy ---", style="bold green"))

    name = questionary.text("Enter NetworkPolicy name:").ask()
    if not name:
        console.print(Text("Policy name cannot be empty. Aborting.", style="red"))
        return None

    # Namespace
    namespace = None
    namespaces = _get_namespaces(api_client)
    if not namespaces and api_client: # If API was connected but no namespaces found other than default
        console.print(Text("Could not fetch namespaces. Cannot create namespaced resource.", style="red"))
        # Fallback or abort? Let's allow typing for flexibility
        typed_namespace = questionary.text("Enter namespace for the NetworkPolicy:").ask()
        if not typed_namespace:
            console.print(Text("Namespace cannot be empty. Aborting.", style="red"))
            return None
        namespace = typed_namespace.strip()
    elif not namespaces and not api_client: # If API was not connected at all
         typed_namespace = questionary.text("Kubernetes API not connected. Enter namespace for the NetworkPolicy (cannot validate):").ask()
         if not typed_namespace:
            console.print(Text("Namespace cannot be empty. Aborting.", style="red"))
            return None
         namespace = typed_namespace.strip()
    else: # API connected and namespaces found
        namespace = questionary.select(
            "Select namespace for the NetworkPolicy:",
            choices=namespaces
        ).ask()
        if not namespace:
            console.print(Text("Namespace cannot be empty. Aborting.", style="red"))
            return None


    # Pod Selector (required)
    console.print(Text("\n--- Define Pod Selector ---", style="bold blue"))
    console.print(Text("This selects the pods the NetworkPolicy applies to.", style="blue"))
    console.print(Text("An empty podSelector {} means the policy applies to ALL pods in the namespace.", style="blue"))
    select_all_pods = questionary.confirm("Apply policy to ALL pods in the namespace?").ask()

    pod_selector: Dict[str, Dict[str, str]] = {}
    if not select_all_pods:
        pod_labels = prompt_labels("Pods to select")
        if not pod_labels:
            console.print(Text("No pod labels specified. Applying policy to ALL pods in the namespace.", style="yellow"))
            # Explicitly use {} if no labels were entered, matching the 'select all' behavior
            pod_selector = {}
        else:
             pod_selector = {"matchLabels": pod_labels}
    else:
        # User explicitly selected "all pods"
        pod_selector = {} # Empty selector means all pods in the namespace

    policy: Dict[str, Any] = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": name.strip(),
            "namespace": namespace
        },
        "spec": {
            "podSelector": pod_selector, # Add the defined pod selector
            "policyTypes": [] # Initialize policy types list
        }
    }

    # Policy Types (Ingress/Egress)
    console.print(Text("\n--- Select Policy Types ---", style="bold blue"))
    policy_types_choices = questionary.checkbox(
        "Select Policy Types:",
        choices=['Ingress', 'Egress']
    ).ask()

    if not policy_types_choices:
        console.print(Text("No policy types selected. The policy will effectively do nothing.", style="yellow"))
    else:
        policy['spec']['policyTypes'] = policy_types_choices

        # Define Ingress Rules
        if 'Ingress' in policy_types_choices:
            ingress_rules = prompt_rules("Ingress", api_client) # Pass api_client
            if ingress_rules:
                policy['spec']['ingress'] = ingress_rules
            # Note: An empty ingress list means *no* ingress is allowed (denies all ingress)

        # Define Egress Rules
        if 'Egress' in policy_types_choices:
            egress_rules = prompt_rules("Egress", api_client) # Pass api_client
            if egress_rules:
                policy['spec']['egress'] = egress_rules
            # Note: An empty egress list means *no* egress is allowed (denies all egress)


    # If no policy types, ingress, or egress are defined, the policy is likely useless
    if not policy['spec']['policyTypes'] and 'ingress' not in policy['spec'] and 'egress' not in policy['spec']:
        console.print(Text("Generated policy has no policy types or rules defined. It won't enforce anything.", style="yellow"))


    return policy

def display_policy_yaml(policy: Dict[str, Any]) -> str:
    """Displays the generated NetworkPolicy YAML and returns the string."""
    console.print(Text(f"\n--- Generated NetworkPolicy YAML: {policy['metadata']['name']} ---", style="bold green"))
    yaml_output = yaml.dump(policy, default_flow_style=False, sort_keys=False)
    console.print(yaml_output)
    console.print(Text("-----------------------------------------------------", style="bold green"))
    return yaml_output

def save_policy_yaml(filename: str, yaml_content: str) -> None:
    """Saves the YAML content to a specified file."""
    try:
        with open(filename, 'w') as f:
            f.write(yaml_content)
        console.print(Text(f"NetworkPolicy YAML saved to {filename}", style="green"))
    except IOError as e:
        console.print(Text(f"Error saving YAML to {filename}: {e}", style="bold red"))

def ask_to_save_policy(policy: Dict[str, Any], yaml_content: str) -> None:
    """Asks the user if they want to save the generated YAML and handles saving."""
    save_option = questionary.confirm("Do you want to save this YAML to a file?").ask()

    if save_option:
        policy_name = policy['metadata']['name']
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"networkpolicy-{policy_name}-{timestamp}.yaml"

        filename = questionary.text(
            "Enter filename (default is current directory):",
            default=default_filename
        ).ask()

        if filename:
            save_policy_yaml(filename, yaml_content)

def ask_to_apply_policy(api_clients: tuple[Optional[client.CoreV1Api], Optional[client.NetworkingV1Api]], policy: Dict[str, Any]) -> None:
    """Asks user if they want to apply the generated NetworkPolicy."""
    core_api, networking_api = api_clients

    # Choose application method: client API (create only) or kubectl apply (create/update)
    apply_method = questionary.select(
         "How do you want to apply the policy?",
         choices=["Use 'kubectl apply -f -' (Recommended for create/update)", "Use Kubernetes client API (Creates new policy)", "Don't apply"]
    ).ask()

    if apply_method == "Don't apply":
        console.print(Text("Skipping application.", style="yellow"))
        return

    policy_name = policy['metadata']['name']
    namespace = policy['metadata']['namespace']


    if apply_method == "Use Kubernetes client API (Creates new policy)":
        if not networking_api:
            console.print(Text("\nCannot apply policy: Kubernetes NetworkingV1Api not connected.", style="red"))
            return

        console.print(Text(f"Applying NetworkPolicy '{policy_name}' in namespace '{namespace}' using client API...", style="bold blue"))

        try:
             # Note: This uses create, which will fail if the policy already exists
            networking_api.create_namespaced_network_policy(namespace, policy)
            console.print(Text(f"NetworkPolicy '{policy_name}' applied successfully.", style="green"))

        except ApiException as e:
            console.print(Text(f"Error applying NetworkPolicy '{policy_name}': {e.status} - {e.reason}", style="bold red"))
            if e.status == 409:
                 console.print(Text(f"NetworkPolicy '{policy_name}' already exists. Use 'kubectl apply' to update.", style="yellow"))
            else:
                 console.print(Text(f"Body: {e.body}", style="red"))
        except Exception as e:
            console.print(Text(f"An unexpected error occurred applying NetworkPolicy '{policy_name}': {e}", style="bold red"))

    elif apply_method == "Use 'kubectl apply -f -' (Recommended for create/update)":
         # Convert policy dict back to YAML string for kubectl
         yaml_content = yaml.dump(policy, default_flow_style=False, sort_keys=False)

         console.print(Text(f"Applying NetworkPolicy '{policy_name}' in namespace '{namespace}' using kubectl apply...", style="bold blue"))

         try:
             # Use subprocess to run kubectl apply
             process = subprocess.run(
                 ['kubectl', 'apply', '-n', namespace, '-f', '-'],
                 input=yaml_content.encode('utf-8'), # Pass YAML via stdin
                 capture_output=True,
                 check=False # Don't raise exception for non-zero exit
             )

             if process.returncode != 0:
                 console.print(Text(f"Error applying NetworkPolicy '{policy_name}' with kubectl:", style="bold red"))
                 console.print(process.stderr.decode('utf-8'))
             else:
                 console.print(Text(f"NetworkPolicy '{policy_name}' applied successfully.", style="green"))
                 console.print(process.stdout.decode('utf-8'))

         except FileNotFoundError:
             console.print(Text("Error: kubectl command not found. Please ensure kubectl is installed and in your PATH.", style="bold red"))
         except Exception as e:
             console.print(Text(f"An unexpected error occurred during kubectl apply: {e}", style="bold red"))


# --- Main Execution Function ---

def run():
    """
    Entry point function called by main.py or when the script is run directly.
    Interactively generates and optionally applies NetworkPolicy resources.
    """
    # No specific arguments needed for interactive generation currently
    parser = argparse.ArgumentParser(
        description="Interactively generate Kubernetes NetworkPolicy manifests.",
        prog="network_policy_generator.py"
    )
    args = parser.parse_args()

    # Get Kubernetes clients - only proceed if we can connect
    api_clients = _get_k8s_api_clients() # (core_api, networking_api)
    core_api, networking_api = api_clients # Unpack

    # We can generate YAML without an API connection, but suggestions (namespaces) and apply won't work.
    if not core_api or not networking_api:
         console.print(Text("Warning: Could not connect to Kubernetes API. Namespace suggestions and applying resources will not be available.", style="yellow"))
         # Pass None clients down, prompts will handle it.


    while True: # Loop to allow generating multiple resources
        # Pass the core_api client to the generation function for namespace lookups
        generated_policy = generate_network_policy_interactive(core_api)

        if generated_policy:
            # Display YAML and capture the string output
            yaml_content = display_policy_yaml(generated_policy)
            # Ask to save the YAML
            ask_to_save_policy(generated_policy, yaml_content)
            # Ask to apply the policy - pass both clients
            ask_to_apply_policy(api_clients, generated_policy)


        # Ask if user wants to generate another resource
        generate_another = questionary.confirm("Generate another NetworkPolicy?").ask()
        if not generate_another:
            break

    console.print(Text("\nNetworkPolicy generation finished.", style="bold green"))


# --- Standalone Execution ---

if __name__ == "__main__":
    # If the script is run directly, call the run() function
    run()