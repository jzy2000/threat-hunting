Sample of using SSH command to download files from the servers:
`ssh user@server.com '( cat /etc/passwd )' > /tmp/passwd
ssh user@server.com '( cp /var/log/auth.log /tmp/; cd /tmp/ && tar -jcvf - auth.log )' > /tmp/auth.tar.bz2`

Regex to detect SSH command line:
`\s*ssh.*\s*'\(.*\)'\s*>.*`
