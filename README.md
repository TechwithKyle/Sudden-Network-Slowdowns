<img width="390" height="280" alt="image" src="https://github.com/user-attachments/assets/f1b1fda9-710a-418a-860e-897c3db56803" />


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

The server team has noticed a significant network performance degradation on
some of their older devices attached to the network in the 10.0.0.0/16 network.
After ruling out external DDoS attacks, the security team suspects something
might be going on internally.

All traffic originating from within the local network is by default allowed by all
hosts. There is also unrestricted use of PowerShell and other applications in the
environment. It’s possible someone is either downloading large files or doing
some kind of port scanning against hosts in the local network.

---

## Timeline Summary and Findings 

Kylesvm was found failing several connection requests against itself and another host on the same network

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "kylesvm"
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP | order by ConnectionCount
```

<img width="466" height="168" alt="image" src="https://github.com/user-attachments/assets/1c76439e-79aa-4324-ba5c-4a1debb6ba44" />

---

After observing failed connection requests from a suspected host (10.0.0.5) in chronological order, I noticed a port scan was taking place due to the sequential order of the ports. There were several port scans being conducted.

**Query used to locate events:**

```kql
let IPInQuestion = "10.0.0.73"; DeviceNetworkEvents
| where ActionType == "ConnectionFailed" | where LocalIP == IPInQuestion
| order by Timestamp desc
```

<img width="2440" height="1161" alt="image" src="https://github.com/user-attachments/assets/f0d93a63-82c3-4156-9d1d-82de1d19d0b9" />

---

## Investigation

I pivoted to the DeviceProcessEvents table to see anything suspicious around the time the port scan started. I noticed a Powershell script named portscan.ps1 launched at 22025-07-06T16:37:50.6462923Z

**Query used to locate events:**

```kql
let VMName = "kylesvm";
let specificTime = datetime(2025-07-06T16:38:21.0879149Z); DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m)) | where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

<img width="1227" height="557" alt="image" src="https://github.com/user-attachments/assets/988ba3fb-d156-43b9-a7b6-d31acc3001a2" />

---

I logged into the suspect computer and observed the Powershell script that was used to conduct the port scan.

<img width="737" height="248" alt="image" src="https://github.com/user-attachments/assets/1d54648b-4240-4c5b-a2a3-100ba6b2c709" />

---

## Response

I observed the portscan script was launched by the SYSTEM account. This is not expected behavior and was not set up by the Admins. So, I isolated the device and ran a malware scan.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "kylesvm"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

<img width="631" height="227" alt="image" src="https://github.com/user-attachments/assets/c69bcbaf-84db-4e5d-ad1a-8a6ef2f6ab5c" />

---
 
## Summary

The malware scan produced no results. Out of caution, I kept the device isolated and submitted a ticket for re-imaging.

---

## Relevant MITRE ATT&CK TTPs:

- T1046 – Network Service Scanning
-- Sequential failed connection attempts indicate a port scan (via `portscan.ps1`).

- T1059.001 – Command and Scripting Interpreter: PowerShell > Malicious PowerShell script used to conduct the scan.

- T1071.001 – Application Layer Protocol: Web Protocols *(inferred if script uses web communication)*
-- If `portscan.ps1` involved network enumeration via web or HTTP(S).

- T1204.002 – User Execution: Malicious Script *(if script was manually triggered)* > Could apply if script required user interaction.

- T1078.001 – Valid Accounts: Default Accounts *(inferred from SYSTEM account use)* > Script was launched by SYSTEM, possibly via exploitation or misconfiguration.

- T1562.001 – Impair Defenses: Disable or Modify Tools *(inferred)*
-- SYSTEM-level script execution not set by Admins may imply evasion or tampering with
defenses.

- T1105 – Ingress Tool Transfer *(inferred)*
-- If the `portscan.ps1` script was dropped remotely or transferred to the system.

- T1036 – Masquerading *(inferred)*
-- Legitimate-looking PowerShell script (`portscan.ps1`) could be hiding malicious intent.

## Response Actions:

- Isolated device
- Performed malware scan - no results
- Submitted ticket for reimaging 

