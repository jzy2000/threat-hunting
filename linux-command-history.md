# Examine Linux Command History

Examine shell history files for each user account on the system (`.bash_history`, `.history`, etc.). 

Indications that `.bash_history` has been altered or evaded is a noteworthy indicator of compromise.

Consider Osquery to fetch the command history if Osquery pre-installed: `select usr.username, sht.command, sht.history_file from shell_history sht JOIN users usr ON sht.uid = usr.uid WHERE sht.uid IN (SELECT uid from users)`

Look for any unusual commands, in particular:

* `wget` and `curl` used to download unexpected files, as these are often used to download malicious binaries.

* Commands used against files that contain OS or application user information, such as `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, or `/etc/secret-volume` files:

    * *Search utilities such as `grep` or `find`

    * *File viewing utilities such as `cat`, `less`, `head`, `more`, or `strings`

    * *Commonly used text editors such as `vim`, `vi`, `gedit`, `emacs`, `nano`, etc.

* Renaming of existing binaries.

* Explicit execution of shell binaries (`/bin/sh`, `/bin/bash`, `/bin/rbash`, `/bin/dash`, etc.).

* Uncommon commands such as `whoami`, `w`, `useradd`, `passwd`, `id`, `last`, `exec`, `history`,`chsh`, `mail`, `pico`, `uname`. Also pay attention to commonly used commands that are used in an interesting way, e.g: wget+chmod/chown+run shell

* Common attacker-used tools such as `nmap`, `masscan`, `ettercap` to collect info and move laterally --- see the [Kali tool](https://tools.kali.org/tools-listing) for list of commonly used offensive tool.

* Commands used to avoid bash history logging, such as:
`unset HISTFILE set +o history export history=0`
