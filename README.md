<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/TsumaA/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "labuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-05-29T00:36:55.9887363Z`. These events began at `2025-05-28T23:39:07.562815Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "abe-mde-est"  
| where InitiatingProcessAccountName == "labuser"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-05-28T23:39:07.562815Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<![First tor screenshot](https://github.com/user-attachments/assets/ab859b52-931b-4067-b552-08dcc68229f2)
>

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.3". Based on the logs returned, at `2025-05-29T00:19:31.2361561Z`, an employee on the "abe-mde-est" device ran the file `tor-browser-windows-x86_64-portable-14.5.3` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "abe-mde-est"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![Second tor screenshot](https://github.com/user-attachments/assets/d534e4b5-3f76-4de9-9470-ee1827942fc2)
>

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at `2025-05-29T00:20:20.8985141Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "abe-mde-est"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
![Tor Screenshot #3](https://github.com/user-attachments/assets/e6c7bb7b-d7e0-45df-b202-bfcdfdfdfeb9)
>

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-05-29T00:22:13.9510456Z`, an employee on the "abe-mde-est" device successfully established a connection to the remote IP address `138.88.150.120` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "abe-mde-est"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
![four](https://github.com/user-attachments/assets/017415dc-d7fb-4e96-87eb-f92e32a4b6bc)
>

---

## Chronological Event Timeline 

### 1. File Preparation - TOR Installer
- **Timestamp:** `2025-05-28T19:39:07Z`
- **Event:** The user "labuser" on device "abe-mde-est" prepared a TOR browser installer file `tor-browser-windows-x86_64-portable-14.5.3.exe` by renaming/moving it to the Downloads folder.
- **Action:** File operation detected.
- **File Path:** `Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 2. Process Execution - TOR Browser Installation
- **Timestamp:** `2025-05-28T20:19:31Z`
- **Event:** The user "labuser" executed the file `tor-browser-windows-x86_64-portable-14.5.3.exe` in silent mode, initiating a background installation of the TOR Browser on device "abe-mde-est".
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.3.exe /S`
- **SHA256:** `3b7e78a4ccc935cfe71a0e4d41cc297d48a44e722b4a46f73b5562aed9c1d2ea`

### 3. Process Execution - TOR Browser Launch
- **Timestamp:** `2025-05-28T20:20:20Z`
- **Event:** User "labuser" opened the TOR browser on device "abe-mde-est". Multiple `firefox.exe` processes and the core TOR daemon `tor.exe` were created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `tor.exe` and `firefox.exe` (multiple instances)

### 4. Network Connection - TOR Network
- **Timestamp:** `2025-05-28T20:22:14Z`
- **Event:** A network connection to IP `144.76.223.174` on port `9001` by user "labuser" was established using `tor.exe` on device "abe-mde-est", confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `tor.exe`

### 5. Additional Network Connections - TOR Browser Activity
- **Timestamps:**
  - `2025-05-28T20:22:33Z` - SOCKS proxy connections to `127.0.0.1:9150`
  - `2025-05-28T20:22:47Z` - Connected to `107.189.10.143:9001`
  - `2025-05-28T20:27:04Z` - Connected to `198.96.155.3:9001` and `89.58.28.75:9001`
- **Event:** Additional TOR network connections were established by user "labuser" on device "abe-mde-est", indicating ongoing activity through the TOR browser and circuit establishment through multiple relay nodes.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List
- **Timestamp:** `2025-05-28T20:21:42Z`
- **Event:** The user "labuser" created a file named `tor-shopping-list.txt` on the desktop of device "abe-mde-est" during active browsing session, potentially indicating dark web marketplace activity.
- **Action:** File creation detected.
- **File Path:** `Desktop\tor-shopping-list.txt`

---

## Summary

The user "labuser" on the "abe-mde-est" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `abe-mde-est` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
