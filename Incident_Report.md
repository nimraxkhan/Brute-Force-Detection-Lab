Incident Report – Authentication Brute Force Detection
Incident Summary
During log analysis of Windows Security Event ID 4625 (Failed Logon), multiple failed authentication attempts were detected against the local account NIMRA$.
A total of 15 failed login attempts were observed from the source IP address 127.0.0.1 within the selected time range (Last 24 Hours).
The activity was identified using threshold-based detection logic in Splunk.

Timeline
Total Failed Attempts: 15


Source IP: 127.0.0.1


Target Account: NIMRA$


Logon Type: 2 (Interactive Login)


Authentication Package: Negotiate


The failed attempts occurred within a short time window, indicating repeated authentication attempts.

Technical Findings
Event ID: 4625 – Failed Logon
 Account Name: NIMRA$
 Account Domain: WORKGROUP
 Logon Type: 2
 Source Network Address: 127.0.0.1
 Process Name: C:\Windows\System32\svchost.exe
Failure Details:
Failure Reason: An error occurred during logon


Status: 0xC000006D


Sub Status: 0xC0000380



Analysis
Logon Type 2 indicates an interactive logon, meaning the authentication attempts were made locally on the machine.
The source IP address 127.0.0.1 confirms the activity originated from the local host.
While this lab simulated failed login attempts manually, the observed pattern (15 repeated failures against a single account within a short time frame) mirrors brute-force authentication behavior.
In a real enterprise environment, this pattern would warrant investigation to determine whether:
A user is repeatedly entering incorrect credentials


Malware is attempting credential guessing


An attacker has gained local system access



🛠 Detection Logic Used
index=Windows-logs EventCode=4625
| stats count by Account_Name, Source_Network_Address
| where count > 5

A threshold of greater than 5 failed attempts was applied to reduce noise and identify abnormal authentication behavior.

MITRE ATT&CK Mapping
Technique: T1110 – Brute Force
 Tactic: Credential Access

Severity
Medium (in production environment)
Although this activity originated locally in a controlled lab setting, repeated failed authentication attempts are consistent with brute-force attack patterns.

 Recommendations
Enable account lockout policy after multiple failed login attempts


Enforce multi-factor authentication (MFA)


Monitor repeated failed logins from single source IPs


Alert on threshold-based failed authentication events

