# Examine Persistence and Backdoors

Any remote console service or network enabled daemon is a likely target for a back door. Examine the various timestamps for these files to determine if they have been modified more recently than expected. For example, all three timestamps can be examined for `/usr/bin/sshd` with these commands:

* `ls -al /usr/bin/sshd`

* `ls -cal /usr/bin/sshd`

* `ls -mal /usr/bin/sshd`

These same commands can be used to examine the contents of entire directories. Anomalous timestamps can indicate that an attacker has modified a binary.

Investigators should examine cron jobs with the `crontab -e` command, and search for unexpected or malicious commands executed via this mechanism.

Investigators should examine start-up scripts with the `ls -als -t /etc/init.d/` command (on some Linux distribution, start-up scripts are found in `/etc/rc.d`), and search for unexpected or malicious commands executed via this mechanism.

Investigators should examine kernel modules with the command `lsmod`. This output should be more or less the same as `cat /proc/modules`, although it is formatted in a more readable way. Any discrepancies between these lists could indicate that an attacker has tried to hide a  backdoor or rootkit.

Investigators should also search for binaries with the SUID bit set. A simple command to find these binaries is `find / -perm +5000 -uid root`. Under normal situations, this command will reveal some binaries that must be run as `root` in order to function. However, attackers might configure some executables with this bit for future privilege escalation. Any file that shows up on that list, which does not show up on a comparable trusted Linux host may be a backdoor.

The following commands perform the comparison to the baseline volume:

`find / -uid 0 -perm -4000 -print > suid_evidence`

`find /linux_base/ -uid 0 -perm -4000 -print > suid_base `

`cut suid_base -d"/" -f4- > suid_base_relative `

`cut suid_base -d"/" -f4- > suid_evidence_relative `

`diff suid_base_relative suid_evidence_relative`

Investigators should look for unusual accounts and multiple accounts with a user id (UID) set to zero. Also, note any new groups or services that have created an account as well.

Using `diff` to find new entries from baseline file:

`diff /etc/passwd <baseline_path>/etc/passwd`

`diff /etc/group <baseline_path>/etc/group`
