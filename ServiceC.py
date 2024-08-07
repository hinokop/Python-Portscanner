import paramiko # pip install paramiko first if its not already installed
import logging

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

def main():
    # Your Server details go here, dont forget to change them!!
    hostname = 'your_server_ip'  # should be obv.
    port = 22  # Standard-SSH-Port
    username = 'your_username'  # should be obv.
    password = 'your_password'  # should be obv. (could also use SSH-Key with commented funct at line 

    # List of Services you wanna Check for! DONT FORGET TO CHANGE!
    services = ['service1', 'service2', 'service3']  # SET YOUR SERVICES HERE!

    try:
        # Create SSH-Client
        ssh = paramiko.SSHClient()
        # Setting the Host-Key-Policy with Paramiko for unknown Host-Keys
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logger.info(f'Verbindungsaufbau zu {hostname}...')
        # Connect to Server
        ssh.connect(hostname, port, username, password)
        logger.info('Verbindung hergestellt.')
        #Uncomment to Connect to Server via SSH-Key for more security. Dont forget to uncomment the other one if you use the SSH-Key...
        #ssh.connect(hostname, port, username, key_filename='path/to/private/key')
        #logger.info('Connection success.')
      
        # check for status
        for service in services:
            status = check_service_status(ssh, service)
            logger.info(f'Service {service} is {status}')

        # Close Connection
        ssh.close()
        logger.info('Connection closed.')

    except Exception as e:
        logger.error(f'An Error has occured: {e}')

if __name__ == '__main__':
    main()
