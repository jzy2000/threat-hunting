# Examine New and Modified Files

List all the files created or changed around the time of the incident in the last day:

`find / -mtime -1`

For the last week:

`find / -mtime -7`

Use `-ctime` instead of `-mtime` to check the file creation timestamp.

Look for unusual file names and permissive permissions such as world-readable or world-writeable. For example:

`find / -type f -perm -o=a`

`find / -type f -perm -o=w`

Pay close attention to following files, if any of these being modified or created suspiciously recently:

Cron:

* `/etc/crontab`

* `/etc/cron.hourly, daily, weekly, monthly`

* `/etc/cron.d`

* `/var/spool/cron/USERNAME`

* `Anacron`

Credentials:

* `/etc/passwd`

* `/etc/shadow`

* `/etc/gshadow`

* `/etc/secret-volume`

Shell configuration:

* `/etc/profile`

* `~/.bash_profile`

* `~/.bash_login`

* `~/.profile`

* `/home/USERNAME/.bashrc`

* `/etc/bash.bashrc`

* `/etc/profile.d/`

* BASH_ENV environment variable

Network configuration:

* `/etc/netns`

* `/etc/network/interfaces`

* `/etc/NetworkManager/NetworkManager.conf`

* `/etc/sysconfig/iptables-config`

Certificate authority:

* Using CLI below to search for unrecognized certificate installed on the system:

`awk -v cmd='openssl x509 -noout -subject' '`

`    /BEGIN/{close(cmd)};{print | cmd}' < /etc/ssl/certs/ca-certificates.crt`

If integrated with 3rd party authentication systems, check `/etc/pam.d` for malicious plug-in modules.
