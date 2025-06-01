# k8s_hardener/istio_manager/policy_checker.py

import subprocess
import logging
import yaml # Using PyYAML for parsing Kubernetes YAML output
import textwrap

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PolicyChecker:
    """
    Checks Istio AuthorizationPolicy and PeerAuthentication resources in a
    Kubernetes cluster for potential security misconfigurations.
    Supports both generic K8s and MicroK8s environments.
    """

    def __init__(self):
        """
        Initializes the PolicyChecker. Detects the Kubernetes environment to use
        the correct kubectl command.
        """
        self._environment = self._detect_environment()
        self.kubectl_cmd = self._get_kubectl_command()
        # Define namespaces considered sensitive
        self.sensitive_namespaces = ["istio-system", "kube-system", "kube-public"]


    def _run_command(self, command, shell=False, capture_output=True, text=True, check=False, **kwargs):
        """
        Runs a shell command and returns the output.

        Args:
            command (list or str): The command to run.
            shell (bool): Whether to execute the command through the shell.
            capture_output (bool): Whether to capture stdout and stderr.
            text (bool): Decode stdout/stderr as text.
            check (bool): Raise CalledProcessError if the command returns a non-zero exit code.
            **kwargs: Additional arguments for subprocess.run.

        Returns:
            subprocess.CompletedProcess: The result of the command execution.
                                         Includes returncode, stdout, stderr.
        """
        try:
            command_str = ' '.join(command) if isinstance(command, list) else command
            # Log command at debug level to keep output clean unless troubleshooting
            logging.debug(f"Running command: {command_str}")

            result = subprocess.run(
                command,
                capture_output=capture_output,
                text=text,
                shell=shell,
                check=check,
                **kwargs
            )

            if result.returncode != 0:
                # Log stderr on failure
                logging.error(f"Command failed with exit code {result.returncode}:\n{result.stderr.strip()}")
            elif capture_output and result.stdout:
                 # Log stdout for successful commands if capturing and it's not empty at debug level
                 logging.debug(f"Command successful:\n{result.stdout.strip()}")
            elif capture_output:
                 # Log success even if stdout is empty
                 logging.debug("Command successful (no stdout).")

            return result

        except FileNotFoundError:
            # Handle case where the command itself is not found (e.g., kubectl not installed)
            cmd_name = command[0] if isinstance(command, list) else command.split(' ')[0]
            logging.error(f"Error: Command '{cmd_name}' not found. Make sure it's in your PATH.")
            # Return a dummy CompletedProcess with a non-zero exit code
            return subprocess.CompletedProcess(command, 1, stdout='', stderr=f"Command not found: {cmd_name}")
        except Exception as e:
            # Catch any other unexpected exceptions during command execution
            logging.error(f"An unexpected error occurred while running command '{command_str}': {e}")
            return subprocess.CompletedProcess(command, 1, stdout='', stderr=str(e))


    def _detect_environment(self):
        """
        Detects the Kubernetes environment (Generic or MicroK8s).
        Checks for the presence of the 'microk8s.enable' command.

        Returns:
            str: 'MicroK8s' or 'Generic'.
        """
        # Use 'which' to check if the command exists in the PATH
        result = self._run_command(["which", "microk8s.enable"], capture_output=True, check=False)
        if result.returncode == 0:
            return 'MicroK8s'
        else:
            return 'Generic'

    def _get_kubectl_command(self):
        """
        Returns the appropriate kubectl command prefix based on environment.

        Returns:
            str: 'kubectl' or 'microk8s.kubectl'.
        """
        if self._environment == 'MicroK8s':
            # MicroK8s uses 'microk8s.kubectl'
            return 'microk8s.kubectl'
        else:
            # Generic K8s uses 'kubectl'
            return 'kubectl'

    def _get_policies_yaml(self, policy_kind, namespace=None):
        """
        Fetches Istio policies of a given kind in YAML format.

        Args:
            policy_kind (str): The kind of policy to fetch (e.g., 'authorizationpolicies', 'peerauthentication').
            namespace (str, optional): The namespace to check. If None, checks all namespaces.

        Returns:
            list or None: A list of policy dictionaries if successful, None otherwise.
        """
        logging.info(f"Fetching {policy_kind} in namespace: {namespace if namespace else 'all namespaces'}...")
        print(f"\nFetching {policy_kind} in namespace: {namespace if namespace else 'all namespaces'}...")

        command = [self.kubectl_cmd, "get", policy_kind]
        if namespace:
            command.extend(["-n", namespace])
        else:
            command.append("--all-namespaces")

        command.extend(["-o", "yaml"]) # Request output in YAML format

        result = self._run_command(command, capture_output=True, check=False)

        if result.returncode != 0:
            print(f"Failed to fetch {policy_kind}. Check logs above.")
            return None # Indicate failure

        if not result.stdout.strip():
             print(f"No {policy_kind} found.")
             return [] # Return empty list if no policies are found but command succeeded

        try:
            # kubectl get -o yaml for multiple resources returns a List object
            yaml_output = yaml.safe_load(result.stdout)
            if not yaml_output or 'items' not in yaml_output:
                 print(f"No {policy_kind} found or unexpected kubectl output format.")
                 return [] # Handle empty or unexpected output

            return yaml_output.get('items', []) # Return the list of policy dictionaries

        except yaml.YAMLError as e:
            logging.error(f"Error parsing YAML output for {policy_kind}: {e}")
            print(f"Error parsing {policy_kind} YAML output. Check logs.")
            return None # Indicate parsing failure
        except Exception as e:
            logging.error(f"An unexpected error occurred while processing {policy_kind}: {e}")
            print(f"An unexpected error occurred while processing {policy_kind}. Check logs.")
            return None # Indicate unexpected error


    def check_authorization_policies(self, namespace=None):
        """
        Checks AuthorizationPolicy resources for potential security concerns.

        Args:
            namespace (str, optional): The namespace to check. If None, checks all namespaces.

        Returns:
            bool: True if the check completed (regardless of findings), False if fetching failed.
        """
        logging.info("Checking Authorization Policies...")
        print("\n--- Checking Authorization Policies ---")

        authz_policies = self._get_policies_yaml("authorizationpolicies", namespace)

        if authz_policies is None:
            return False # Failed to fetch policies

        if not authz_policies:
            print("No Authorization Policies found.")
            return True # No policies to check

        # Iterate through each AuthorizationPolicy found
        for policy in authz_policies:
            metadata = policy.get('metadata', {})
            spec = policy.get('spec', {})
            policy_name = metadata.get('name', 'N/A')
            policy_namespace = metadata.get('namespace', 'N/A')
            policy_action = spec.get('action', 'ALLOW') # Default action is ALLOW

            print(f"\nPolicy: {policy_namespace}/{policy_name}, Action: {policy_action}")

            # Check if the policy is in a sensitive namespace
            if policy_namespace in self.sensitive_namespaces:
                print(f"  [INFO] This policy is in a sensitive namespace: {policy_namespace}")
                logging.info(f"Authz policy {policy_namespace}/{policy_name} is in a sensitive namespace.")

            # Check for overly permissive 'ALLOW' policies
            if policy_action.upper() == 'ALLOW':
                # Check if the policy has no rules (which typically means allow all)
                if not spec.get('rules'):
                    print("  [CRITICAL] ALLOW policy with NO rules! This policy allows ALL traffic to selected workloads.")
                    logging.critical(f"Authz policy {policy_namespace}/{policy_name} is an ALLOW policy with no rules, allowing all traffic.")
                else:
                    # Analyze rules for broad permissions
                    for rule_index, rule in enumerate(spec.get('rules', [])):
                        print(f"  Rule {rule_index}:")
                        sources = rule.get('from', [])
                        destinations = rule.get('to', [])
                        conditions = rule.get('when', [])

                        # Check for broad sources
                        if not sources:
                             print("    [CRITICAL] Rule has no 'from' field. This means it applies to ALL sources.")
                             logging.critical(f"Authz policy {policy_namespace}/{policy_name}, Rule {rule_index} has no 'from', applying to all sources.")
                        else:
                            for from_rule in sources:
                                principals = from_rule.get('source', {}).get('principals', [])
                                namespaces = from_rule.get('source', {}).get('namespaces', [])
                                ip_blocks = from_rule.get('source', {}).get('ipBlocks', [])

                                if "*" in principals:
                                    print("    [CONCERN] Rule allows traffic from ANY principal ('*').")
                                    logging.warning(f"Authz policy {policy_namespace}/{policy_name}, Rule {rule_index} allows any principal.")
                                if "*" in namespaces:
                                    print("    [CONCERN] Rule allows traffic from ANY namespace ('*').")
                                    logging.warning(f"Authz policy {policy_namespace}/{policy_name}, Rule {rule_index} allows any namespace.")
                                if ip_blocks and any(ip in ["0.0.0.0/0", "::/0"] for ip in ip_blocks):
                                    print("    [CRITICAL] Rule allows traffic from ANY IP address (0.0.0.0/0 or ::/0).")
                                    logging.critical(f"Authz policy {policy_namespace}/{policy_name}, Rule {rule_index} allows any IP address.")


                        # Check for broad destinations (e.g., all paths, all methods)
                        if not destinations:
                             print("    [CONCERN] Rule has no 'to' field. This means it applies to ALL destinations.")
                             logging.warning(f"Authz policy {policy_namespace}/{policy_name}, Rule {rule_index} has no 'to', applying to all destinations.")
                        else:
                            for to_rule in destinations:
                                paths = to_rule.get('operation', {}).get('paths', [])
                                methods = to_rule.get('operation', {}).get('methods', [])

                                if paths and "*" in paths:
                                    print("    [CONCERN] Rule applies to ALL paths ('*').")
                                    logging.warning(f"Authz policy {policy_namespace}/{policy_name}, Rule {rule_index} applies to all paths.")
                                if methods and "*" in methods:
                                     print("    [CONCERN] Rule applies to ALL HTTP methods ('*').")
                                     logging.warning(f"Authz policy {policy_namespace}/{policy_name}, Rule {rule_index} applies to all methods.")

                        # Check for conditions that might weaken security (less common, more complex to analyze generically)
                        if conditions:
                             print("    [INFO] Rule has 'when' conditions. Review these manually for security implications.")
                             logging.info(f"Authz policy {policy_namespace}/{policy_name}, Rule {rule_index} has 'when' conditions.")


            # Check for restrictive 'DENY' policies (generally good, but note their existence)
            elif policy_action.upper() == 'DENY':
                print("  [INFO] This is a DENY policy. These generally enhance security.")
                logging.info(f"Authz policy {policy_namespace}/{policy_name} is a DENY policy.")
                # You could add checks here for DENY policies that might be too narrow,
                # but for hardening, focusing on overly permissive ALLOWs is primary.

            # Check for custom actions (less common)
            else:
                print(f"  [INFO] This policy uses a custom action: {policy_action}. Review manually.")
                logging.info(f"Authz policy {policy_namespace}/{policy_name} uses a custom action: {policy_action}.")


        print("\n--- Authorization Policy Check Complete ---")
        return True # Check completed


    def check_peer_authentication_policies(self, namespace=None):
        """
        Checks PeerAuthentication resources for mTLS configuration security.

        Args:
            namespace (str, optional): The namespace to check. If None, checks all namespaces.

        Returns:
            bool: True if the check completed (regardless of findings), False if fetching failed.
        """
        logging.info("Checking Peer Authentication Policies...")
        print("\n--- Checking Peer Authentication Policies ---")

        peer_auth_policies = self._get_policies_yaml("peerauthentication", namespace)

        if peer_auth_policies is None:
            return False # Failed to fetch policies

        if not peer_auth_policies:
            print("No Peer Authentication Policies found.")
            # Note: The mesh-wide default is usually PERMISSIVE even if no policy exists
            print("Note: In the absence of a mesh-wide policy, the default mTLS mode is typically PERMISSIVE.")
            logging.info("No Peer Authentication Policies found. Default mesh-wide is usually PERMISSIVE.")
            return True # No policies to check

        # Iterate through each PeerAuthentication policy
        for policy in peer_auth_policies:
            metadata = policy.get('metadata', {})
            spec = policy.get('spec', {})
            policy_name = metadata.get('name', 'N/A')
            policy_namespace = metadata.get('namespace', 'N/A')
            mtls_mode = spec.get('mtls', {}).get('mode', 'UNSET') # Default mode is UNSET if not specified

            # Determine the scope of the policy
            selector = spec.get('selector')
            scope = "Workload-specific" if selector else ("Namespace-wide" if policy_namespace != self.sensitive_namespaces[0] else "Mesh-wide (in istio-system)")


            print(f"\nPolicy: {policy_namespace}/{policy_name}, Scope: {scope}, mTLS Mode: {mtls_mode}")

            # Check if the policy explicitly sets a mode other than STRICT
            if mtls_mode.upper() == 'PERMISSIVE':
                print(f"  [CONCERN] Policy explicitly set to PERMISSIVE mode.")
                print("            This allows both plaintext and mTLS traffic to selected workloads.")
                logging.warning(f"PeerAuth policy {policy_namespace}/{policy_name} is PERMISSIVE.")
            elif mtls_mode.upper() == 'DISABLE':
                 print(f"  [CRITICAL] Policy explicitly set to DISABLE mode!")
                 print("             This disables mTLS for selected workloads.")
                 logging.critical(f"PeerAuth policy {policy_namespace}/{policy_name} is DISABLED.")
            elif mtls_mode.upper() == 'UNSET':
                 print(f"  [INFO] Policy explicitly set to UNSET mode.")
                 print("         This means the mode is inherited from a higher level (e.g., mesh-wide default).")
                 logging.info(f"PeerAuth policy {policy_namespace}/{policy_name} is UNSET.")
            elif mtls_mode.upper() == 'STRICT':
                 print(f"  [INFO] Policy explicitly set to STRICT mode. Good for security.")
                 logging.info(f"PeerAuth policy {policy_namespace}/{policy_name} is STRICT.")
            else:
                 print(f"  [INFO] Policy has an unexpected mTLS mode: {mtls_mode}. Review manually.")
                 logging.warning(f"PeerAuth policy {policy_namespace}/{policy_name} has unexpected mode: {mtls_mode}.")


            # Check for port-level mTLS overrides (can weaken security for specific ports)
            port_level_mtls = spec.get('portLevelMtls')
            if port_level_mtls:
                print(f"  [CONCERN] Policy has port-level mTLS overrides: {port_level_mtls}.")
                print("            Review these to ensure sensitive ports are not set to PERMISSIVE or DISABLE.")
                logging.warning(f"PeerAuth policy {policy_namespace}/{policy_name} has port-level overrides.")

        print("\n--- Peer Authentication Policy Check Complete ---")
        return True # Check completed


    def check_all_policies(self, namespace=None):
        """
        Performs a comprehensive check of all relevant Istio security policies.

        Args:
            namespace (str, optional): The namespace to check. If None, checks all namespaces.
        """
        logging.info(f"Starting comprehensive policy check for namespace: {namespace if namespace else 'all namespaces'}")
        print(f"\nStarting comprehensive policy check for namespace: {namespace if namespace else 'all namespaces'}")

        authz_success = self.check_authorization_policies(namespace)
        peer_auth_success = self.check_peer_authentication_policies(namespace)

        if not authz_success or not peer_auth_success:
            print("\nPolicy checks could not be fully completed due to errors fetching policies.")
            logging.error("Policy checks could not be fully completed.")
        else:
            print("\n--- Comprehensive Policy Check Finished ---")
            logging.info("Comprehensive Policy Check Finished.")


# Example Usage: Interactive Policy Checking
if __name__ == '__main__':
    print("--- Kubernetes Hardener - Istio Policy Checker Interactive ---")

    checker = PolicyChecker() # Initialize the checker

    # Check if Istio is likely installed before proceeding
    # This reuses detection logic from the IstioInstaller example,
    # but ideally, you'd have a shared utility or rely on the main CLI app
    # to ensure Istio exists before calling this module.
    # For this standalone example, a basic check is included.
    print("Checking if Istio is installed (requires 'istio-system' namespace)...")
    istio_namespace_check_cmd = [checker.kubectl_cmd, "get", "namespace", "istio-system", "--ignore-not-found"]
    istio_check_result = checker._run_command(istio_namespace_check_cmd, capture_output=True, check=False)

    if istio_check_result.returncode != 0 or not istio_check_result.stdout.strip():
        print("\nIstio does not appear to be installed (namespace 'istio-system' not found).")
        print("Cannot check Istio policies without a running Istio control plane.")
        print("Please install Istio first.")
        logging.error("Istio not found. Aborting policy check.")
    else:
        # Istio seems to be installed, proceed with interactive checks
        print("Istio system namespace found. Proceeding with policy checks.")

        while True:
            print("\nSelect an option:")
            print("  1. Check policies in ALL namespaces")
            print("  2. Check policies in a SPECIFIC namespace")
            print("  0. Exit")

            choice = input("Enter your choice: ").strip()

            if choice == '0':
                print("Exiting Policy Checker.")
                break
            elif choice == '1':
                checker.check_all_policies()
            elif choice == '2':
                target_namespace = input("Enter the namespace name: ").strip()
                if target_namespace:
                    checker.check_all_policies(namespace=target_namespace)
                else:
                    print("Namespace name cannot be empty.")
            else:
                print("Invalid choice. Please try again.")

            # Optional: Add a small delay before the next iteration
            # time.sleep(1)


    print("\n--- Istio Policy Checker Finished ---")
    logging.info("Istio Policy Checker script finished.")