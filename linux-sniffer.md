# Examine sniffers

If attackers run network "sniffers" to intercept data or other programs to spy on user activity, network traffic, it often creates real-time log files. Creating an empty “dummy” file followed by a successful authentication or other network traffic can reveal a sniffer:

1. Issue this command: `touch /tmp/newer`

2. Log into the server or perform any activity which you fear might be logged

3. Issue this command: `find / -newer /tmp/newer -type f > /tmp/filelog`

The file `/tmp/filelog` will contain a list of files created or updated since the beginning of this exercise. If the attacker is logging activity to a local file, that file should be included on that list along with several others.

The command `ifconfig -a` can sometimes also reveal a sniffer. If the string "PROMISC" appears with any clause describing a network interface, that indicates that the interface is processing traffic not destined for it. If the “PROMISC” flag is not visible after a sniffer like `tcpdump` is engaged, this may indicate that the attacker has modified `ifconfig` or the kernel itself.
