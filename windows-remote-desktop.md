# Examine Unauthorized Access by Remote Desktop



*   Search Windows-Remote-Desktop-Services-Rdp-CoreTS-Operational Event ID:
    *    131 – Connection Attempts
        *   Extract IP in “Source IP” field
        *   Search for successful brute-force attack when many failed attempts follow by a successful connection.
    *    98 – Successful Connections
*   Search Windows-Terminal-Services-LocalSession-Manager-Operational Event ID:
    *   Event ID 21, 22, 25
        *   Extract caller info in “Source IP/Logon User Name” field
    *   Event ID 41
        *   Extract username info in “Logon User Name” field
*   Search Security Event ID 4624 (An account was successfully logged on)
    *   Filter by “Logon Type”=10
    *   Extract caller info stored in “Source IP/Logon User Name” field 
*   Search Security Event ID 4778/4779 (A session was reconnected/disconnected to a Window Station)
    *   Extract caller info stored in “IP Address of Source/Source System Name”, “Logon User Name” fields
*   Search in ShimCache and AmCache for first time execution: \
_rdpclip.exe_, _tstheme.exe_.
*   Search Prefetch folder which records RDP executables: \
_C:\Windows\Prefetch\rdpclip.exe-{hash}.pf_  \
_C:\Windows\Prefetch\tstheme.exe-{hash}.pf_
