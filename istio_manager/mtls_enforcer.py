# k8s_hardener/istio_manager/mtls_enforcer.py

import subprocess
import logging
import time
import os
import textwrap
import json # Import json for parsing kubectl output

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class MtlsEnforcer:
    """
    Manages Mesh-wide Mutual TLS (mTLS) enforcement in Istio using PeerAuthentication policies.
    Supports both generic K8s and MicroK8s environments. Includes environment detection
    and command execution helpers.
    """

    def __init__(self):
        """
        Initializes the MtlsEnforcer. Detects the Kubernetes environment to use
        the correct kubectl command.
        """
        self._environment = self._detect_environment()
        self.kubectl_cmd = self._get_kubectl_command()
        # Assuming Istio control plane is installed in istio-system namespace.
        # This is the standard namespace for Istio system components and mesh-wide policies.
        self.istio_namespace = "istio-system"


    def _run_command(self, command, shell=False, capture_output=True, text=True, check=False, input_data=None, **kwargs):
        """
        Runs a shell command and returns the output.

        Args:
            command (list or str): The command to run.
            shell (bool): Whether to execute the command through the shell.
            capture_output (bool): Whether to capture stdout and stderr.
            text (bool): Decode stdout/stderr as text.
            check (bool): Raise CalledProcessError if the command returns a non-zero exit code.
            input_data (str): Standard input to send to the command.
            **kwargs: Additional arguments for subprocess.run.

        Returns:
            subprocess.CompletedProcess: The result of the command execution.
                                         Includes returncode, stdout, stderr.
        """
        try:
            command_str = ' '.join(command) if isinstance(command, list) else command
            logging.info(f"Running command: {command_str}")
            if input_data:
                # Log the command input, useful for debugging YAML application
                logging.debug(f"Command input:\n{input_data}")

            result = subprocess.run(
                command,
                capture_output=capture_output,
                text=text,
                shell=shell,
                check=check,
                input=input_data, # Pass input_data to stdin
                **kwargs
            )

            if result.returncode != 0:
                # Log stderr on failure
                logging.error(f"Command failed with exit code {result.returncode}:\n{result.stderr.strip()}")
            elif capture_output and result.stdout:
                 # Log stdout for successful commands if capturing and it's not empty
                 logging.info(f"Command successful:\n{result.stdout.strip()}")
            elif capture_output:
                 # Log success even if stdout is empty
                 logging.info("Command successful (no stdout).")

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
        logging.info("Detecting Kubernetes environment...")
        # Use 'which' to check if the command exists in the PATH
        result = self._run_command(["which", "microk8s.enable"], capture_output=True, check=False)
        if result.returncode == 0:
            logging.info("MicroK8s environment detected.")
            return 'MicroK8s'
        else:
            logging.info("Generic Kubernetes environment detected.")
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

    def _get_peerauthentication_yaml(self, mode):
        """
        Generates the YAML string for a mesh-wide PeerAuthentication policy.
        This policy is applied in the Istio system namespace (istio-system)
        without a workload selector, making it apply to all workloads in the mesh.

        Args:
            mode (str): The mTLS mode ('STRICT', 'PERMISSIVE', 'UNSET').

        Returns:
            str or None: The YAML string if mode is valid, None otherwise.
        """
        # Validate the provided mode
        valid_modes = ['STRICT', 'PERMISSIVE', 'UNSET']
        if mode.upper() not in valid_modes:
            logging.error(f"Invalid mTLS mode specified: {mode}. Must be one of {valid_modes}.")
            print(f"Error: Invalid mTLS mode '{mode}'. Must be one of {valid_modes}.")
            return None

        # Define the YAML template for the PeerAuthentication policy
        yaml_template = textwrap.dedent(f"""
        apiVersion: security.istio.io/v1
        kind: PeerAuthentication
        metadata:
          name: default # The name 'default' is commonly used for mesh-wide policies
          namespace: {self.istio_namespace} # Apply in the Istio system namespace for mesh-wide effect
        spec:
          mtls:
            mode: {mode.upper()} # Set the desired mTLS mode
        """)
        return yaml_template

    def set_mtls_mode(self, mode, confirm=True):
        """
        Sets the mesh-wide mTLS mode by applying a PeerAuthentication policy.
        Includes user confirmation before applying the policy.

        Args:
            mode (str): The desired mTLS mode ('STRICT', 'PERMISSIVE', 'UNSET').
            confirm (bool): If True, prompts the user for confirmation before applying the policy.

        Returns:
            bool: True if the policy was applied successfully (or skipped due to
                  user declining), False otherwise.
        """
        # Get the YAML manifest for the specified mode
        policy_yaml = self._get_peerauthentication_yaml(mode)
        if policy_yaml is None:
            # _get_peerauthentication_yaml already logs and prints the error
            return False

        action_desc = f"set mesh-wide mTLS mode to {mode.upper()}"
        logging.info(f"Attempting to {action_desc}.")
        print(f"\nAttempting to {action_desc} by applying a PeerAuthentication policy in the '{self.istio_namespace}' namespace.")

        # Prompt for user confirmation if required
        if confirm:
            print("\n--- IMPORTANT ---")
            print("Applying this policy will affect how all services in the mesh accept connections.")
            print(f"Desired mode: {mode.upper()}")
            if mode.upper() == 'STRICT':
                print("  - STRICT: Only accepts connections encrypted with mutual TLS.")
                print("            This can break applications if clients are not configured for mTLS.")
            elif mode.upper() == 'PERMISSIVE':
                print("  - PERMISSIVE: Accepts both mutual TLS and plaintext connections.")
                print("                This is often used during migration.")
            elif mode.upper() == 'UNSET':
                 print("  - UNSET: Inherits mode from parent (typically defaults to PERMISSIVE mesh-wide).")
                 print("           Removes explicit mesh-wide enforcement set by a 'default' policy.")
            print("--- IMPORTANT ---")

            user_input = input("Are you sure you want to apply this mTLS policy? (yes/no): ").lower()
            if user_input != 'yes':
                print(f"{action_desc} cancelled by the user.")
                logging.info(f"{action_desc} cancelled by user.")
                return False # Indicate that action was cancelled

        # Command to apply the YAML piped from stdin
        # Using '-n istio-system' ensures the policy is applied in the correct namespace
        apply_command = [self.kubectl_cmd, "apply", "-n", self.istio_namespace, "-f", "-"]

        print(f"Applying PeerAuthentication policy...")
        # Execute the kubectl apply command, piping the YAML as input
        result = self._run_command(apply_command, input_data=policy_yaml, capture_output=True, check=False)

        if result.returncode == 0:
            logging.info(f"Mesh-wide mTLS mode set to {mode.upper()} successfully.")
            print(f"\nMesh-wide mTLS mode set to {mode.upper()} successfully.")
            print("It may take some time for the policy to be propagated to all sidecars.")
            return True
        else:
            logging.error(f"Failed to set mesh-wide mTLS mode to {mode.upper()}.")
            print(f"\nFailed to set mesh-wide mTLS mode to {mode.upper()}. Check logs above for details.")
            return False

    def enforce_strict_mtls(self, confirm=True):
        """
        Enforces strict mesh-wide mTLS by calling set_mtls_mode with 'STRICT'.

        Args:
            confirm (bool): If True, prompts the user for confirmation.

        Returns:
            bool: True if the policy was applied successfully (or skipped), False otherwise.
        """
        return self.set_mtls_mode('STRICT', confirm=confirm)

    def allow_permissive_mtls(self, confirm=True):
        """
        Sets mesh-wide mTLS to permissive mode by calling set_mtls_mode with 'PERMISSIVE'.

        Args:
            confirm (bool): If True, prompts the user for confirmation.

        Returns:
            bool: True if the policy was applied successfully (or skipped), False otherwise.
        """
        return self.set_mtls_mode('PERMISSIVE', confirm=confirm)

    def disable_mesh_wide_mtls_enforcement(self, confirm=True):
        """
        Disables explicit mesh-wide mTLS enforcement by setting mode to UNSET.
        Note: This removes the 'default' PeerAuthentication policy's explicit mode.
        The effective mode might revert to the mesh default (usually PERMISSIVE)
        if no other policies apply.

        Args:
            confirm (bool): If True, prompts the user for confirmation.

        Returns:
            bool: True if the policy was applied successfully (or skipped), False otherwise.
        """
        return self.set_mtls_mode('UNSET', confirm=confirm)

    def get_current_mesh_wide_mtls_mode(self):
        """
        Attempts to retrieve the current mesh-wide mTLS mode by inspecting the
        'default' PeerAuthentication policy in the istio-system namespace.

        Returns:
            str or None: The mTLS mode ('STRICT', 'PERMISSIVE', 'UNSET') as reported
                         by the policy, "PERMISSIVE (Default/Effective)" if no policy
                         is found or mode is unset, or None on error.
        """
        logging.info("Attempting to get current mesh-wide mTLS mode...")
        print("\nAttempting to get current mesh-wide mTLS mode...")

        # Command to get the 'default' PeerAuthentication policy in JSON format
        # --ignore-not-found prevents kubectl from returning an error if the policy doesn't exist
        get_command = [self.kubectl_cmd, "get", "peerauthentication", "default",
                       "-n", self.istio_namespace, "-o", "json", "--ignore-not-found"]
        result = self._run_command(get_command, capture_output=True, check=False)

        if result.returncode != 0 or not result.stdout.strip():
            # If the command failed or returned empty output, the policy likely doesn't exist
            logging.info("Mesh-wide 'default' PeerAuthentication policy not found.")
            print("Mesh-wide 'default' PeerAuthentication policy not found.")
            # According to Istio docs, the default mesh-wide mode when no policy exists is PERMISSIVE
            logging.info("Assuming effective mesh-wide mode is PERMISSIVE (Istio default).")
            print("Assuming effective mesh-wide mode is PERMISSIVE (Istio default).")
            return "PERMISSIVE (Default)" # Indicate it's the assumed default

        try:
            # Parse the JSON output
            policy_data = json.loads(result.stdout)
            # Navigate the JSON structure to find the mode
            mode = policy_data.get('spec', {}).get('mtls', {}).get('mode')

            if mode:
                # If mode is found and is a non-empty string
                logging.info(f"Current mesh-wide mTLS mode found in policy: {mode}")
                print(f"Current mesh-wide mTLS mode found in policy: {mode}")
                return mode
            else:
                # If policy exists but the mode field is missing or empty
                logging.warning("Mesh-wide 'default' PeerAuthentication policy found, but mTLS mode is not explicitly specified.")
                print("Mesh-wide 'default' PeerAuthentication policy found, but mTLS mode is not explicitly specified.")
                 # In this case, the effective mode is still the mesh default, which is PERMISSIVE
                logging.info("Assuming effective mesh-wide mode is PERMISSIVE.")
                print("Assuming effective mesh-wide mode is PERMISSIVE.")
                return "PERMISSIVE (Effective)" # Indicate mode is not explicitly set but is effective

        except json.JSONDecodeError:
             # Handle cases where the output is not valid JSON
             logging.error("Failed to parse kubectl output as JSON.")
             print("Error: Could not parse kubectl output. Is Istio correctly installed?")
             return None
        except Exception as e:
            # Catch any other errors during parsing or access
            logging.error(f"An unexpected error occurred while parsing policy: {e}")
            print(f"Error parsing PeerAuthentication policy: {e}")
            return None


# Example Usage: Interactive mTLS Management
if __name__ == '__main__':
    print("--- Kubernetes Hardener - mTLS Enforcer Interactive Manager ---")

    enforcer = MtlsEnforcer() # Initialize the enforcer

    # Check if Istio is likely installed before proceeding
    # This reuses detection logic from the previous IstioInstaller example,
    # but ideally, you'd have a shared utility or rely on the main CLI app
    # to ensure Istio exists before calling this module.
    # For this standalone example, a basic check is included.
    print("Checking if Istio is installed (requires 'istio-system' namespace and 'istiod' deployment)...")
    istio_installed_check_cmd = [enforcer.kubectl_cmd, "get", "deployment", "istiod", "-n", "istio-system", "--ignore-not-found"]
    istio_check_result = enforcer._run_command(istio_installed_check_cmd, capture_output=True, check=False)

    if istio_check_result.returncode != 0 or not istio_check_result.stdout.strip():
        print("\nIstio does not appear to be installed or 'istiod' deployment not found in 'istio-system'.")
        print("Cannot manage mTLS policies without a running Istio control plane.")
        print("Please install Istio first.")
        logging.error("Istio not found. Aborting mTLS management.")
    else:
        # Istio seems to be installed, proceed with interactive mTLS management
        print("Istio control plane found. Proceeding with mTLS management.")

        while True:
            # Get and display the current mTLS mode
            current_mode = enforcer.get_current_mesh_wide_mtls_mode()
            if current_mode is None:
                print("\nCould not determine current mTLS mode. Exiting.")
                break # Exit loop if mode cannot be determined

            print(f"\nCurrent Mesh-wide mTLS Mode: {current_mode}")
            print("\nOptions:")

            # Present options based on the current mode
            if 'STRICT' in current_mode:
                print("  1. Set mTLS mode to PERMISSIVE")
                print("  2. Disable mesh-wide mTLS enforcement (Set to UNSET)")
            elif 'PERMISSIVE' in current_mode:
                print("  1. Enforce STRICT mTLS")
                print("  2. Disable mesh-wide mTLS enforcement (Set to UNSET)")
            elif 'UNSET' in current_mode:
                 print("  1. Enforce STRICT mTLS")
                 print("  2. Set mTLS mode to PERMISSIVE")
            else:
                 # Should not happen if get_current_mesh_wide_mtls_mode works as expected
                 print("  1. Enforce STRICT mTLS")
                 print("  2. Set mTLS mode to PERMISSIVE")
                 print("  3. Disable mesh-wide mTLS enforcement (Set to UNSET)")


            print("  0. Exit")

            # Get user's choice
            choice = input("Enter your choice: ").strip()

            # Process the user's choice
            if choice == '0':
                print("Exiting mTLS Manager.")
                break # Exit the loop

            try:
                choice_num = int(choice)
                if 'STRICT' in current_mode:
                    if choice_num == 1:
                        enforcer.allow_permissive_mtls(confirm=True)
                    elif choice_num == 2:
                        enforcer.disable_mesh_wide_mtls_enforcement(confirm=True)
                    else:
                        print("Invalid choice. Please try again.")
                elif 'PERMISSIVE' in current_mode:
                    if choice_num == 1:
                        enforcer.enforce_strict_mtls(confirm=True)
                    elif choice_num == 2:
                        enforcer.disable_mesh_wide_mtls_enforcement(confirm=True)
                    else:
                         print("Invalid choice. Please try again.")
                elif 'UNSET' in current_mode:
                    if choice_num == 1:
                        enforcer.enforce_strict_mtls(confirm=True)
                    elif choice_num == 2:
                        enforcer.allow_permissive_mtls(confirm=True)
                    else:
                         print("Invalid choice. Please try again.")
                else:
                     # Handle the case where current_mode is neither STRICT, PERMISSIVE, nor UNSET explicitly
                     if choice_num == 1:
                         enforcer.enforce_strict_mtls(confirm=True)
                     elif choice_num == 2:
                         enforcer.allow_permissive_mtls(confirm=True)
                     elif choice_num == 3:
                          enforcer.disable_mesh_wide_mtls_enforcement(confirm=True)
                     else:
                          print("Invalid choice. Please try again.")


            except ValueError:
                print("Invalid input. Please enter a number.")

            # Optional: Add a small delay before the next iteration
            # time.sleep(1)

    print("--- mTLS Enforcer Interactive Manager Finished ---")
    logging.info("mTLS Enforcer Interactive Manager script finished.")