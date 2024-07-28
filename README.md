# Honeynet-with-Azure-and-Microsoft-Sentinel
This project sets up a honeynet on Azure with weak security configurations to attract and monitor potential attackers using Microsoft Sentinel (SIEM). After an initial monitoring period, we will enhance security by hardening defenses—such as firewalls and Network Security Groups (NSGs)—and then compare the traffic data before and after hardening.

Honeynet with Azure and Microsoft Sentinel
Overview
This project sets up a honeynet on Azure with weak security configurations to attract and monitor potential attackers using Microsoft Sentinel (SIEM). After an initial monitoring period, we will enhance security by hardening defenses—such as firewalls and Network Security Groups (NSGs)—and then compare the traffic data before and after hardening.

**Features**:

Azure Honeynet Deployment: Honeynet with weak security settings.

Traffic Monitoring: Analyze traffic with Microsoft Sentinel.

Security Hardening: Improve defenses and re-monitor.

Comparative Analysis: Assess security impact.

**Installation**:

**Azure Setup: Deploy the honeynet.**

Sentinel Configuration: Set up Microsoft Sentinel for traffic analysis.

Initial Monitoring: Run the honeynet with weak security.

<img width="1184" alt="linux-ssh-auth-fail-before" src="https://github.com/user-attachments/assets/e9812d18-7a9c-4c3c-b5e9-7070185ee499">

<img width="1184" alt="mssql-auth-fail-before" src="https://github.com/user-attachments/assets/09eefd7e-3d63-4f87-ba90-0df9eeddfa3b">

<img width="1184" alt="nsg-malicious-allowed-in-before" src="https://github.com/user-attachments/assets/9bdafe8e-2780-43be-bddb-e38d747fd09f">

<img width="1184" alt="windows-rdp-auth-fail-before" src="https://github.com/user-attachments/assets/48aa3ee5-4443-4feb-8f6c-4903ba449453">

**Hardening: Apply and configure enhanced security measures.
**

**Incident Response:**

**Incident 1 - Brute Force Success (Windows) - Working Incidents and Incident Response**

// Brute Force Success Windows
let FailedLogons = SecurityEvent

| where EventID == 4625 and LogonType == 3

| where TimeGenerated > ago(60m)


| summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, LogonType, DestinationHostName = Computer

| where FailureCount >= 5;
let SuccessfulLogons = SecurityEvent


| where EventID == 4624 and LogonType == 3

| where TimeGenerated > ago(60m)

| summarize SuccessfulCount = count() by AttackerIP = IpAddress, LogonType, DestinationHostName = Computer, AuthenticationSuccessTime = TimeGenerated;
SuccessfulLogons

| join kind = leftouter FailedLogons on DestinationHostName, AttackerIP, LogonType

| project AuthenticationSuccessTime, AttackerIP, DestinationHostName, FailureCount, SuccessfulCount

**Incident 2 - Possible Privilege Escalation - Working Incidents and Incident Response**

// Updating a specific existing password Success
let CRITICAL_PASSWORD_NAME = "Tenant-Global-Admin-Password";

AzureDiagnostics

| where ResourceProvider == "MICROSOFT.KEYVAULT" 

| where OperationName == "SecretGet" or OperationName == "SecretSet"

| where id_s contains CRITICAL_PASSWORD_NAME

**Incident 3 - Brute Force Success (Linux) - Microsoft Sentinel Working Incidents and Incident Response
**

// Brute Force Success Linux
let FailedLogons = Syslog

| where Facility == "auth" and SyslogMessage startswith "Failed password for"

| where TimeGenerated > ago(1h)

| project TimeGenerated, SourceIP = extract(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type

| summarize FailureCount = count() by AttackerIP = SourceIP, DestinationHostName

| where FailureCount >= 5;
let SuccessfulLogons = Syslog

| where Facility == "auth" and SyslogMessage startswith "Accepted password for"

| where TimeGenerated > ago(1h)

| project TimeGenerated, SourceIP = extract(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type

| summarize SuccessfulCount = count() by SuccessTime = TimeGenerated, AttackerIP = SourceIP, DestinationHostName

| where SuccessfulCount >= 1

| project DestinationHostName, SuccessfulCount, AttackerIP, SuccessTime;
let BruteForceSuccesses = SuccessfulLogons 

| join kind = inner FailedLogons on AttackerIP, DestinationHostName;
BruteForceSuccesses

**Incident 4 - Possible Malware Outbreak - Working Incidents and Incident Response**

Event

| where EventLog == "Microsoft-Windows-Windows Defender/Operational"

| where EventID == "1116" or EventID == "1117"

Post-Hardening Monitoring: Evaluate traffic with new defenses.

<img width="1416" alt="linux-ssh-auth-fail-after" src="https://github.com/user-attachments/assets/c4fdc695-8eb8-4362-8ab1-0330edc01771">

<img width="1416" alt="mssql-auth-fail-after" src="https://github.com/user-attachments/assets/75c3d54e-1407-4485-9fff-0c3bdd8040e8">

<img width="1416" alt="nsg-malicious-allowed-in-after" src="https://github.com/user-attachments/assets/fbaffff3-6cbd-4256-9fce-14db3dc81ff0">

<img width="1416" alt="windows-rdp-auth-fail-after" src="https://github.com/user-attachments/assets/d9de2504-e1e2-4e84-9779-ae48e161f2ff">







