# Brute-Force-Detection-Lab
🔐 Authentication Brute Force Detection – Windows + Splunk
📌 Overview

This project simulates a brute-force authentication attempt against a Windows system and demonstrates detection using Splunk SPL queries and dashboard visualization.

The objective was to generate failed authentication logs (Event ID 4625), analyze them in Splunk, apply threshold-based detection logic, and document findings in a SOC-style incident report.

🖥 Environment

Windows 10 host generating Security Event Logs

Splunk Enterprise ingesting Windows logs

Manual failed login simulation

SPL (Search Processing Language) for detection

🚨 Attack Simulation

Multiple incorrect password attempts were generated to trigger:

Event ID 4625 – Failed Logon

Event ID 4624 – Successful Logon

The activity was analyzed within a 24-hour time window.

🔎 Detection Logic
index=Windows-logs EventCode=4625
| search Account_Name!="-" 
| stats count by Account_Name, Source_Network_Address
| where count > 5
| sort - count

A threshold of greater than 5 failed attempts was applied to reduce noise and identify abnormal authentication behavior.

📊 Dashboard Panels

The Splunk dashboard includes:

Authentication Failures Trend (Event ID 4625)

Top Targeted User Accounts

Source IP Distribution – Failed Authentication Attempts

📸 Dashboard Preview

🔎 Key Findings

15 failed login attempts detected

Target Account: NIMRA$

Source IP: 127.0.0.1

Logon Type: 2 (Interactive Login)

Repeated authentication failures exceeded normal behavior thresholds and resemble brute-force activity patterns.

🧠 Skills Demonstrated

Windows Security Event Log analysis

Splunk SPL query development

Threshold-based detection logic

Authentication anomaly detection

Dashboard visualization

MITRE ATT&CK mapping

Incident documentation

🎯 MITRE ATT&CK Mapping

Technique: T1110 – Brute Force
Tactic: Credential Access

📄 Detailed Incident Report

## 📄 Detailed Incident Report

See: [Incident Report](Incident_Report.md)
