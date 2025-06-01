# k8s_hardener/istio_manager/istio_installer.py

import subprocess
import logging
import time
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class IstioInstaller:
    """
    Manages the installation and uninstallation of Istio and enabling sidecar
    injection in a Kubernetes cluster, supporting both generic K8s and MicroK8s,
    with user confirmation and existing installation detection.
    """

    def __init__(self, istio_version="latest", istio_install_profile="default"):
        """
        Initializes the IstioInstaller.

        Args:
            istio_version (str): The desired Istio version for generic K8s installs.
                                 Defaults to "latest". (Ignored for MicroK8s).
            istio_install_profile (str): The Istio installation profile to use for
                                         generic K8s installs. Defaults to "default".
                                         (Ignored for MicroK8s).
        """
        self.istio_version = istio_version
        self.istio_install_profile = istio_install_profile
        self._environment = self._detect_environment()
        self.kubectl_cmd = self._get_kubectl_command()
        # istioctl path is only relevant for generic K8s installs
        self.istioctl_path = "istioctl"


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
            logging.info(f"Running command: {command_str}")

            result = subprocess.run(
                command,
                capture_output=capture_output,
                text=text,
                shell=shell,
                check=check,
                **kwargs
            )

            if result.returncode != 0:
                logging.error(f"Command failed with exit code {result.returncode}:\n{result.stderr}")
            elif capture_output and result.stdout: # Only log stdout if capturing and it's not empty
                 logging.info(f"Command successful:\n{result.stdout.strip()}")
            elif capture_output:
                 logging.info("Command successful (no stdout).")


            return result

        except FileNotFoundError:
            cmd_name = command[0] if isinstance(command, list) else command.split(' ')[0]
            logging.error(f"Error: Command '{cmd_name}' not found. Make sure it's in your PATH.")
            # Create a dummy CompletedProcess for consistency
            return subprocess.CompletedProcess(command, 1, stdout='', stderr=f"Command not found: {cmd_name}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while running command '{command_str}': {e}")
            return subprocess.CompletedProcess(command, 1, stdout='', stderr=str(e))


    def _detect_environment(self):
        """
        Detects the Kubernetes environment (Generic or MicroK8s).

        Returns:
            str: 'MicroK8s' or 'Generic'.
        """
        logging.info("Detecting Kubernetes environment...")
        # Check if 'microk8s.enable' command exists
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
            return 'microk8s.kubectl'
        else:
            return 'kubectl'

    def is_istio_installed(self):
        """
        Checks if Istio is currently installed in the cluster by looking for
        the istio-system namespace and the istiod deployment.

        Returns:
            bool: True if Istio appears to be installed, False otherwise.
        """
        logging.info("Checking for existing Istio installation...")
        print("Checking for existing Istio installation...")

        # Check if istio-system namespace exists
        ns_check_command = [self.kubectl_cmd, "get", "namespace", "istio-system"]
        ns_result = self._run_command(ns_check_command, capture_output=True, check=False)

        if ns_result.returncode != 0:
            logging.info("Namespace 'istio-system' not found.")
            print("Namespace 'istio-system' not found.")
            return False

        logging.info("Namespace 'istio-system' found.")
        print("Namespace 'istio-system' found.")

        # Check if istiod deployment exists in istio-system
        # Use --ignore-not-found to prevent an error if the deployment is missing
        deploy_check_command = [self.kubectl_cmd, "get", "deployment", "istiod", "-n", "istio-system", "--ignore-not-found"]
        deploy_result = self._run_command(deploy_check_command, capture_output=True, check=False)

        if deploy_result.returncode == 0 and deploy_result.stdout.strip():
            logging.info("'istiod' deployment found in 'istio-system'. Istio appears to be installed.")
            print("'istiod' deployment found. Istio appears to be installed.")
            return True
        else:
            logging.info("'istiod' deployment not found in 'istio-system'. Istio does not appear to be fully installed.")
            print("'istiod' deployment not found. Istio does not appear to be fully installed.")
            # Namespace exists but istiod doesn't - partial install? Treat as not installed for fresh install purposes.
            return False


    def download_istio(self):
        """
        Downloads the specified version of Istio for generic K8s installs.
        Requires curl and tar to be available in the system's PATH.
        (Ignored for MicroK8s).
        """
        if self._environment == 'MicroK8s':
            logging.info("Running on MicroK8s, Istio download is handled by 'microk8s enable'. Skipping manual download.")
            print("Running on MicroK8s, Istio download is handled by 'microk8s enable'. Skipping manual download.")
            return True

        logging.info(f"Attempting to download Istio version: {self.istio_version}")
        print(f"\nAttempting to download Istio version: {self.istio_version}...")

        # Determine download URL and extraction command based on version
        if self.istio_version == "latest":
            # This curl command downloads and extracts directly
            download_command = f"curl -L https://istio.io/downloadIstio | sh -"
        else:
            # Example for a specific version - adjust URL and filename if needed
            # Assumes Linux amd64 architecture and a standard naming convention
            # You might need to add logic for other OS/architectures
            istio_tarball = f"istio-{self.istio_version}-linux-amd64.tar.gz"
            download_url = f"https://github.com/istio/istio/releases/download/{self.istio_version}/{istio_tarball}"
            download_command = f"curl -L {download_url} | tar xz"

        result = self._run_command(download_command, shell=True, capture_output=True, check=False)

        if result.returncode == 0:
            logging.info(f"Istio version {self.istio_version} downloaded and extracted successfully.")
            print(f"Istio version {self.istio_version} downloaded.")
            print(f"Istioctl binary is likely in a directory named 'istio-{self.istio_version}' (or similar) in your current location.")
            return True
        else:
            logging.error(f"Failed to download Istio version {self.istio_version}.")
            print(f"Failed to download Istio version {self.istio_version}. Check logs above.")
            return False


    def install_istio(self, custom_manifest=None, confirm=True):
        """
        Installs Istio in the Kubernetes cluster. Includes user confirmation.
        Uses environment-specific commands.

        Args:
            custom_manifest (str, optional): Path to a custom Istio manifest file
                                             for generic K8s installs. (Ignored for MicroK8s).
            confirm (bool): If True, prompts the user for confirmation before installing.

        Returns:
            bool: True if installation was successful (or skipped due to user
                  declining), False otherwise.
        """
        action_type = "enable Istio addon" if self._environment == 'MicroK8s' else "install Istio"
        logging.info(f"Attempting to {action_type}.")
        print(f"\nAttempting to {action_type} in your Kubernetes cluster ({self._environment} environment).")

        if confirm:
            user_input = input(f"Do you want to proceed with {action_type}? (yes/no): ").lower()
            if user_input != 'yes':
                print(f"{action_type} cancelled by the user.")
                logging.info(f"{action_type} cancelled by user.")
                return False # Indicate that installation did not proceed

        if self._environment == 'MicroK8s':
            # Command for MicroK8s
            # microk8s enable istio might be interactive asking about mTLS.
            # We run it without capturing output to allow user interaction.
            print("Running 'microk8s enable istio'. You might be prompted for configuration.")
            install_command = ["microk8s.enable", "istio"]
            result = self._run_command(install_command, capture_output=False, check=False)

        else:
            # Command for generic K8s using istioctl
            print(f"Running '{self.istioctl_path} install' with profile '{self.istio_install_profile}'.")
            install_command = [self.istioctl_path, "install", "-y"]

            if custom_manifest:
                logging.info(f"Using custom manifest: {custom_manifest}")
                install_command.extend(["-f", custom_manifest])
            elif self.istio_install_profile:
                logging.info(f"Using installation profile: {self.istio_install_profile}")
                install_command.extend(["--set", f"profile={self.istio_install_profile}"])

            # Add revision for generic K8s install for sidecar injection webhook
            revision = self.istio_install_profile if self.istio_install_profile != "default" else "default"
            install_command.extend([
                 # Ensure istio-system namespace is used
                 "--set", f"values.global.istioNamespace=istio-system",
                 # These autoInject/injection flags might be redundant depending on profile,
                 # but explicitly setting them doesn't hurt unless they conflict.
                 "--set", f"values.global.proxy.autoInject=enabled",
                 "--set", f"values.global.proxy.injection.enable=true",
                 "--set", f"revision={revision}" # Explicitly set revision for the webhook
            ])
            result = self._run_command(install_command, capture_output=True, check=False)

        if result.returncode == 0:
            success_msg = "Istio addon enablement initiated successfully." if self._environment == 'MicroK8s' else "Istio installation initiated successfully."
            print(f"\n{success_msg}")
            print("Please wait for pods to be ready in the 'istio-system' namespace.")
            print(f"Check status with: {self.kubectl_cmd} get pods -n istio-system")
            logging.info(success_msg)
            return True
        else:
            error_msg = "Istio addon enablement failed." if self._environment == 'MicroK8s' else "Istio installation failed."
            print(f"\n{error_msg} Check logs above for details.")
            logging.error(error_msg)
            return False


    def enable_sidecar_injection(self, namespaces):
        """
        Enables automatic Istio sidecar injection for the given namespaces
        using the environment-specific kubectl command.

        Args:
            namespaces (list): A list of namespace names to enable injection for.

        Returns:
            bool: True if labeling was successful for all namespaces, False otherwise.
        """
        if not namespaces:
            logging.warning("No namespaces provided for sidecar injection.")
            print("No namespaces provided for sidecar injection.")
            return True

        print(f"\nAttempting to enable Istio sidecar injection for namespaces: {namespaces}")
        logging.info(f"Attempting to enable Istio sidecar injection for namespaces: {namespaces}")

        success = True
        # Determine the correct injection label based on environment/installation method.
        # MicroK8s historically used 'istio-injection=enabled'.
        # Generic istioctl installs often use 'istio.io/rev=<revision>'.
        # We'll make an educated guess, but users might need to verify the exact label
        # by inspecting the istio-sidecar-injector MutatingWebhookConfiguration.
        if self._environment == 'MicroK8s':
             # Assume MicroK8s uses the simpler label
             injection_label = "istio-injection=enabled"
        else:
             # Assume generic install uses the revision label based on profile
             revision = self.istio_install_profile if self.istio_install_profile != "default" else "default"
             injection_label = f"istio.io/rev={revision}"
             # Fallback check: If the revision label fails, maybe try the old one?
             # This adds complexity, so let's stick to one per environment for simplicity.
             # A better approach might be to read the webhook config.

        print(f"Using sidecar injection label: '{injection_label}'")
        logging.info(f"Using sidecar injection label: '{injection_label}'")


        for ns in namespaces:
            print(f"Labeling namespace '{ns}'...")
            logging.info(f"Labeling namespace '{ns}'...")
            label_command = [self.kubectl_cmd, "label", "namespace", ns, injection_label, "--overwrite"]
            result = self._run_command(label_command, capture_output=True, check=False)

            if result.returncode != 0:
                print(f"Failed to label namespace '{ns}'. Check logs above.")
                logging.error(f"Failed to label namespace '{ns}' for Istio injection.")
                success = False
            else:
                print(f"Namespace '{ns}' labeled successfully.")
                logging.info(f"Namespace '{ns}' labeled successfully for Istio injection.")

        if success:
            print("\nEnabled sidecar injection for all specified namespaces.")
            print("Remember to restart pods in these namespaces for injection to take effect (e.g., `kubectl rollout restart deployment -n <namespace>`).")
            logging.info("Enabled sidecar injection for all specified namespaces.")
        else:
            print("\nFailed to enable sidecar injection for one or more namespaces.")
            logging.warning("Failed to enable sidecar injection for one or more namespaces.")

        return success

    def uninstall_istio(self, confirm=True):
        """
        Uninstalls Istio from the Kubernetes cluster. Includes user confirmation.
        Uses environment-specific commands.

        Returns:
            bool: True if uninstallation was successful (or skipped due to user
                  declining), False otherwise.
        """
        action_type = "disable Istio addon" if self._environment == 'MicroK8s' else "uninstall Istio"
        logging.info(f"Attempting to {action_type}.")
        print(f"\nAttempting to {action_type} from your Kubernetes cluster ({self._environment} environment).")


        if confirm:
            user_input = input(f"Do you want to proceed with {action_type}? (yes/no): ").lower()
            if user_input != 'yes':
                print(f"{action_type} cancelled by the user.")
                logging.info(f"{action_type} cancelled by user.")
                return False # Indicate that uninstallation did not proceed


        if self._environment == 'MicroK8s':
            # Command for MicroK8s
            print("Running 'microk8s disable istio'.")
            uninstall_command = ["microk8s.disable", "istio"]
            result = self._run_command(uninstall_command, capture_output=False, check=False)
        else:
            # Command for generic K8s using istioctl
            print(f"Running '{self.istioctl_path} uninstall --purge'.")
            # The --purge flag removes the istio-system namespace and CRDs in recent versions.
            uninstall_command = [self.istioctl_path, "uninstall", "-y", "--purge"]
            result = self._run_command(uninstall_command, capture_output=True, check=False)

        if result.returncode == 0:
            success_msg = "Istio addon disability initiated successfully." if self._environment == 'MicroK8s' else "Istio uninstallation initiated successfully."
            print(f"\n{success_msg}")
            logging.info(success_msg)
            if self._environment == 'Generic':
                 print("Note: The 'istio-system' namespace and CRDs should be removed by --purge, but verify if necessary.")
            return True
        else:
            error_msg = "Istio addon disability failed." if self._environment == 'MicroK8s' else "Istio uninstallation failed."
            print(f"\n{error_msg} Check logs above for details.")
            logging.error(error_msg)
            return False

# Example Usage (This would typically be called from main.py)
if __name__ == '__main__':
    print("--- Kubernetes Hardener - Istio Manager Example ---")

    # --- Step 1: Check for existing Istio installation ---
    installer = IstioInstaller(istio_install_profile="demo") # Initialize to detect environment first

    if installer.is_istio_installed():
        print("\nExisting Istio installation detected.")
        uninstall_choice = input("Do you want to uninstall the existing Istio installation before proceeding? (yes/no): ").lower()

        if uninstall_choice == 'yes':
            print("\nAttempting to uninstall existing Istio...")
            # Offer confirmation for uninstall as well
            if installer.uninstall_istio(confirm=True):
                print("\nExisting Istio uninstallation initiated. Please wait for cleanup.")
                # In a real scenario, you might wait for the istio-system namespace
                # and istiod deployment to be fully gone before proceeding.
                # time.sleep(60) # Example wait

                # After successful uninstall, proceed to installation
                print("\nProceeding with new Istio installation...")
                if installer.install_istio(confirm=True):
                    print("\nNew Istio installation/enablement process initiated.")

                    # --- Step 2: Enable Sidecar Injection ---
                    namespaces_to_harden = ["default", "my-app-namespace"]
                    print(f"\nAttempting to enable sidecar injection for {namespaces_to_harden}...")
                    installer.enable_sidecar_injection(namespaces_to_harden)
                else:
                     print("\nNew Istio installation skipped or failed after uninstall.")

            else:
                print("\nExisting Istio uninstallation skipped or failed. Aborting further Istio actions.")
                # If uninstall fails or is cancelled, don't proceed with install/injection

        else:
            print("\nKeeping existing Istio installation.")
            # If user chooses NOT to uninstall, you might then proceed to
            # enable injection on namespaces if that's the goal, or just stop.
            # For this example, we'll just stop here if they don't uninstall.
            print("Further Istio installation steps skipped as existing installation is kept.")
            # If your goal was just to ensure namespaces are injected, you could
            # call enable_sidecar_injection here:
            # namespaces_to_harden = ["default", "my-app-namespace"]
            # print(f"\nAttempting to enable sidecar injection for {namespaces_to_harden} using the existing Istio...")
            # installer.enable_sidecar_injection(namespaces_to_harden)


    else:
        print("\nNo existing Istio installation detected.")
        # If no Istio is found, proceed with installation
        print("Proceeding with Istio installation...")
        if installer.install_istio(confirm=True):
            print("\nIstio installation/enablement process initiated.")

            # --- Step 2: Enable Sidecar Injection ---
            namespaces_to_harden = ["default", "my-app-namespace"]
            print(f"\nAttempting to enable sidecar injection for {namespaces_to_harden}...")
            installer.enable_sidecar_injection(namespaces_to_harden)
        else:
             print("\nIstio installation skipped or failed.")


    print("\n--- Istio Manager Example Finished ---")
    logging.info("Istio Manager Example script finished.")