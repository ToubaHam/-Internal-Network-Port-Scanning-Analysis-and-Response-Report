# 🔒 Internal Network Port Scanning Analysis and Response Report

## 🔍 Scenario Overview


Goal: Set up the hunt by defining what you're looking for.

Background: The server team noticed significant network performance degradation on older devices in the 10.0.0.0/16 network.

Hypothesis: It’s possible that someone is either downloading large files or conducting port scanning within the network, as unrestricted PowerShell and application usage are allowed.

# Objective

Investigate and analyze potential internal reconnaissance or malicious activity through threat hunting techniques, and respond effectively to mitigate risks.
🔬 Timeline Summary and Findings

## Steps to Reproduce:
Provision a virtual machine with a public IP address
Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
Onboard the device to Microsoft Defender for Endpoint
Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
Execute the KQL query in the MDE advanced hunting to confirm detection.

# Initial Detection

Observation:
The device network-vm-touba was found failing several connection requests against itself and another host on the same network.

Query Used:
```
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```
![Screenshot 2025-02-06 at 3 17 18 PM](https://github.com/user-attachments/assets/eda2fe55-5ff9-4d64-b438-6ff9092b2cb3)

Behavior Analysis

Further Investigation:
Observing the log activity, failed connection requests from the suspected host (10.0.0.4) showed a sequential order of port access attempts.

Conclusion:
This sequential pattern indicates a potential port scan. While the connections failed, this activity is suspicious and warrants further investigation.

Query Used:
```
let IPInQuestion = "10.0.0.102";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```
![Screenshot 2025-02-06 at 3 21 26 PM](https://github.com/user-attachments/assets/1b269bd7-f228-47f4-8584-3ac48907cdf0)


Pivot to DeviceProcessEvents

Observation:
Upon inspecting the DeviceProcessEvents table, a PowerShell script named portscan.ps1 was launched at 2025-02-06T06:37:00.774381Z.

Query Used:
```
let VMName = "windows-target-1";
let specificTime = datetime(2025-02-06T06:37:00.774381Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```
![Screenshot 2025-02-06 at 5 56 51 PM](https://github.com/user-attachments/assets/26ed33c2-3804-4b80-85b7-410ebd464689)



Key Finding:
The port scanning script was executed by the SYSTEM account, which is highly suspicious and not expected behavior.
![Screenshot 2025-02-06 at 6 08 38 PM](https://github.com/user-attachments/assets/40d56c58-e1e5-4312-83ce-40c23cf0e41e)



Response Actions

Immediate Steps Taken

Isolated the Device: Prevented further network interaction from the compromised device.

Analyzed the Script: Inspected the portscan.ps1 script to confirm its purpose and behavior (screenshot included).

Blocked Suspicious IP Address: Blocked the IP 10.0.0.4 at the network level to stop further activity.

Performed Malware Scan: Conducted a full malware scan, which produced no results.

Reimaged the Device: Out of caution, the device was isolated and sent for reimaging.

## 🕹️ Key Findings (MITRE ATT&CK Mapping)
| **Category**             | **Technique Name**                               | **MITRE ID**      | **Details**                                                                                     |
|--------------------------|------------------------------------------------|-------------------|------------------------------------------------------------------------------------------------|
| **Reconnaissance**       | Active Scanning                                | T1595.002         | Port scanning aligns with **active reconnaissance** by attackers probing the network.          |
| **Discovery**            | Network Service Scanning                       | T1046             | Sequential failed connections indicate **port scanning** to identify open services.            |
| **Execution**            | Command and Scripting Interpreter: PowerShell  | T1059.001         | Use of `portscan.ps1` PowerShell script suggests **abuse of PowerShell** for network scans.    |
| **Privilege Escalation** | Abuse Elevation Control Mechanism              | T1548             | The `SYSTEM` account was used to execute the script, indicating potential privilege abuse.     |
| **Credential Access**    | Valid Accounts                                 | T1078             | The `SYSTEM` account’s activity could point to **unauthorized use** of a privileged account.   |


The SYSTEM account’s activity could point to unauthorized use of a privileged account.

## 🛑 Recommendations and Long-Term Measures

#Key Immediate Actions

1. Harden PowerShell Usage:

- Restrict PowerShell usage to authorized users.

- Use AppLocker or Group Policy to block unauthorized scripts.

2. Implement Network Security Best Practices:

- Enable strict firewall rules and limit unnecessary open ports.

- Use intrusion detection/prevention systems (IDS/IPS).

3. Conduct Security Awareness Training:

- Train users to identify malicious scripts and suspicious activities.

- Regularly review and refine incident response processes.

4. Adopt Zero Trust Principles:

- Assume all devices and accounts are potentially compromised.

- Enforce least privilege access to reduce lateral movement risks.


##🏆 Conclusion

The investigation revealed unauthorized internal port scanning activity executed via a PowerShell script by the SYSTEM account. Though no malware was detected, reimaging and hardening steps were taken to ensure network security. Continued monitoring and implementing the recommended long-term measures will mitigate risks of similar incidents in the future
