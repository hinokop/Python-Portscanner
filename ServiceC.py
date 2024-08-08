import paramiko  # pip install paramiko first if it's not already installed
import logging
import sys
import threading

# Logging Config for Bugs etc :)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Check service Status
def check_service_status(ssh_client, service_name):
    # Systemctl command to check status
    stdin, stdout, stderr = ssh_client.exec_command(f'systemctl is-active {service_name}')
    # Read and Decode response
    status = stdout.read().decode().strip()
    return status

def interactive_shell(channel):
    while True:
        if channel.recv_ready():
            output = channel.recv(1024).decode()
            sys.stdout.write(output)
            sys.stdout.flush()
        if channel.exit_status_ready():
            break

def create_remote_text_file(ssh_client):
    file_content = "./Shad0w was here"
    remote_file_path = "Shad0w_was_here.txt"
    ssh_client.exec_command(f'echo "{file_content}" > {remote_file_path}')
    print(f"Remote file '{remote_file_path}' created/overwritten successfully.")

def read_password_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.read().strip()

def main():
    # Your Server details go here, don't forget to change them!!
    hostname = 'SERVER IP'  # should be obvious
    port = 22  # Standard-SSH-Port
    username = 'USERNAME'  # should be obvious

    # Set default password file path
    default_password_file = 'path to your txt file with PW'  # Update this path to your actual password file

    # Ask the user for the authentication method
    auth_method = input("Do you want to use (1) Password or (2) SSH Key for authentication? Enter 1 or 2: ")

    password = None
    key_filename = None

    if auth_method == '1':
        password = read_password_from_file(default_password_file)
    elif auth_method == '2':
        key_filename = input("Enter the path to your private SSH key: ")
    else:
        logger.error("Invalid option. Please enter 1 or 2.")
        return

    # List of Services you wanna Check for! DON'T FORGET TO CHANGE!
    services = ['nginx', 'xrdp', 'OpenSSH']  # SET YOUR SERVICES HERE!

    try:
        # Create SSH-Client
        ssh = paramiko.SSHClient()
        # Setting the Host-Key-Policy with Paramiko for unknown Host-Keys
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logger.info(f'Trying Connection to {hostname}...')
        
        # Connect to Server based on the selected authentication method
        if password:
            ssh.connect(hostname, port, username, password)
        elif key_filename:
            ssh.connect(hostname, port, username, key_filename=key_filename)
        
        logger.info('Connection Success.')

        # Create the "Shad0w was here" text file in the remote directory
        create_remote_text_file(ssh)

        # Executing remote code message
        logger.info("Executing remote code...")
      
        # Check for status
        for service in services:
            status = check_service_status(ssh, service)
            logger.info(f'Service {service} is {status}')

        # Open an interactive shell session
        logger.info('Opening SSH shell...')
        channel = ssh.invoke_shell()
        print("Interactive SSH Shell opened. Type your commands below:")

        # Start the interactive session in a separate thread
        interactive_thread = threading.Thread(target=interactive_shell, args=(channel,))
        interactive_thread.start()

        # Send commands to the shell
        while True:
            command = input()
            if command.lower() in ['exit', 'quit']:
                channel.send('exit\n')
                break
            channel.send(command + '\n')

        # Wait for the interactive shell thread to finish
        interactive_thread.join()

        # Close Connection
        ssh.close()
        logger.info('Connection closed.')

    except Exception as e:
        logger.error(f'An Error has occurred: {e}')

if __name__ == '__main__':
    main()
