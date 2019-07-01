# Windows servers provides several ways to identify users that are currently active:

Enumerate users who are currently logged on to the system using Windows built-in CLI query user to display information on local and remote about user sessions on a terminal server.
Alternatively, Microsoft internal CLI tool LogonSessions also lists not only the currently active logon sessions, along with other useful info such as processes running in each session:
`C:\>logonsessions -p`

Run `lusrmgr.msc`, check all user accounts on a local machine:
  - Select Users, and look for any new, suspicious accounts that are not supposed to be on the machine and active Guest accounts.
Alternatively, use Osquery query: `SELECT uid,username,shell,directory FROM users WHERE type = ‘local’;`
  - Select Groups, then Administrators, look for accounts that should not have Administrator privileges.
Alternatively, use Osquery query: `SELECT users.uid,users.username,users.shell FROM user_groups INNER JOIN users ON user_groups.uid = users.uid WHERE user_groups.gid = 544;`

When only terminal access is available, consider the following command line tools:
  - `net user` – displays all user accounts on a local machine. 
  - `net localgroup administrators` – display all local administrator user accounts.

# Windows servers keep a record of users had logged in previously in Security event log:
  - Event ID 4624 Logon Event
Logon event type: Local account vs. Domain account can be distinguished by examining “Account Domain” field.
In an AD managed domain, consider local account login suspicious event, should investigate further, vice versa.
In a RDP dominant management environment, first filter RDP logon by Logon Type field=10 for Terminal Services, Remote Desktop or Remote Assistance related logon & logoff events.

  - Event ID 4634, 4647 Logoff Event or 4608 System boot Event
Correlate with 4624 Logon event by Logon-ID field, can identify the beginning and ending of a logon session.
Search for many failed logon events followed by successful 4624 logon event.

  - Event ID 4672 Special privileges assigned to new logon
Any "super user" account logons

Also check logs of other remote access methods if any, such as VNC, RDP, or S/FTP, and perform the same analysis on the access logs for those services, check Look for Various Ways of Remote Execution, Look for Remote Desktop Access and Network Share Access sections for possible remote access & execution. 
