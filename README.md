<a name="readme-top"></a>
<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/alpine-sec/spectr3">
    <img width="488" alt="Spectr3_2" src="https://user-images.githubusercontent.com/143736/236651153-4bb4553b-52cb-4b28-adcb-7060ad68667f.png">
  </a>

  <h3 align="center">SPECTR3: Remote Acquisition Tool</h3>

  <p align="center">
    Acquire, triage and investigate remote evidence via portable iSCSI readonly access
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#usage">Usage</a>
      <ul>
        <li><a href="#Command-Line-Options">Command Line Options</a></li>
        <li><a href="#List-devices-of-the-endpoint">List devices of the endpoint</a></li>
        <li><a href="#Share-a-disk-or-volume-as-an-iSCSI-target">Share a disk or volume as an iSCSI target</a></li>
        <li><a href="#Connect-to-a-SPECTR3-iSCSI-target-with-Windows">Connect to a SPECTR3 iSCSI target with Windows</a></li>
        <li><a href="#Connect-to-a-SPECTR3-iSCSI-target-with-Linux">Connect to a SPECTR3 iSCSI target with Linux</a></li>
        <li><a href="#Connect-to-a-SPECTR3-iSCSI-target-with-OSx">Connect to a SPECTR3 iSCSI target with OSx</a></li>
        <li><a href="#Improved-security-through-IP-ACLs">Improved security through IP ACLs</a></li>
        <li><a href="#Encrypt-connection-over-reverse-SSH">Encrypt connection over reverse SSH</a></li>
      </ul>
    </li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#Acknowledgments">Acknowledgments</a></li>
    <li><a href="#scenarios">Scenarios</a></li>
  </ol>
</details>


<!-- ABOUT THE PROJECT -->
## About The Project

This project is based on the great work done by TalAloni with iSCSI Console but with a forensic objective more similar to F-Response in its approach to remote acquisition, analysis and triage.

The goal is to make available to the community a command line, open source and easy to use tool for scenarios where a complete forensic acquisition or a fast remote analysis is needed.

And of course... just for fun!

<!-- USAGE EXAMPLES -->
## Usage
[**DOWNLOAD EXECUTABLE**](https://github.com/alpine-sec/SPECTR3/releases/latest)

Copy portable executable of **SPECTR3** to the endpoint where you want to perform remote acquisition, triage or forensic analysis, **remember that you will need administrator permissions to access the block devices.**

### Command Line Options
```
SPECTR3 v0.4.6 - Remote acquisition and forensic tool by Alpine Security
Usage: SPECTR3.exe [options]
Options:
  -l, --list
    List available volumes and disks.
  -p, --port
    Set the port number to listen on.
  -i, --permitip
    Set the permited ip client to connect.
  -b, --bindip
    Set the bind ip where server will listen.
  -v, --volume
    Set the volume to share.
  -d, --disk
    Set the disk to share.
  -h, --help
    Print this help message.
  --sshuser
    Set the ssh user to connect.
  --sshpass
    Set the ssh password to connect in BASE64. NOTE: if the password is empty, the prompt will ask for the password, in this case it does not need to be entered in BASE64.
  --sshhost
    Set the ssh host to connect.
  --sshport
    Set the ssh port to connect. Default: 22
```

### List devices of the endpoint
```
C:\Users\dev\Desktop>SPECTR3.exe -l
- List Physical Disks:
    + Dsk 0:  Msft Virtual Disk    60GB
- List Volumes:
    + Vol 0:  EFI system partition Partition 100MB Healthy
    + Vol 1:  Microsoft reserved partition Partition 16MB Healthy
    + Vol 2:  Basic data partition Partition 59.4GB Healthy
    + Vol 3:  Noname Partition 530MB Healthy
```

### Share a disk or volume as an iSCSI target
Use -d if you want share a full disk or -v if only you want to share a volume. Use the index of de volume or disk in -l list. (Allow Access in firewall if popup)
```
C:\Users\dev\Desktop>SPECTR3.exe -d 0

  - SPECTR3 Server running at 172.29.10.42:3262
    + Target IQN: iqn.2023-05.io.alpine.desktop-j4r9lju:dsk0
    + Access Permited from: 0.0.0.0
  - Press ENTER key to stop sharing and close server ...
```
Press ENTER for sharing termination

---

### Connect to a SPECTR3 iSCSI target with Windows
In Windows Investigator machines you can use the windows native tool iSCSI Initiator:
1. Discover targets with "Discover Portal" in "Discovery Tab":

![image](https://user-images.githubusercontent.com/143736/236651296-daa10bd4-9f14-4683-83b0-91a7cc49eae1.png)

2. Use Spectr3 server IP and Port:

![image](https://user-images.githubusercontent.com/143736/236651365-441f5394-b99f-4148-8e3a-f82d7c0a86c6.png)

3. Connect to target in "Targets" tab:

![image](https://github.com/alpine-sec/SPECTR3/assets/143736/aaefcd2f-3b87-4876-96da-394302d1aed4)

![image](https://github.com/alpine-sec/SPECTR3/assets/143736/98873058-f912-4b53-a638-1370a419e4f1)

4. Acquire or analyze with your favorite tool:

![image](https://user-images.githubusercontent.com/143736/236651568-e81c4c1a-62fd-45ee-8858-377c5a33ae7d.png)

![image](https://user-images.githubusercontent.com/143736/236651589-1f187867-5230-4668-bf29-af5f414c049a.png)

```
C:\kape> .\kape.exe --tsource G: --tdest C:\Triages\RegistryFiles --target RegistryHives
KAPE version 1.3.0.2, Author: Eric Zimmerman, Contact: https://www.kroll.com/kape (kape@kroll.com)

KAPE directory: C:\kape
Command line:   --tsource G: --tdest RegistryFiles --target RegistryHives

System info: Machine name: STARK, 64-bit: True, User: KERO99 OS: Windows10 (10.0.22621)

Using Target operations
  Creating target destination directory C:\Triages\RegistryFiles
Found 2 targets. Expanding targets to file list...
Found 30 files in 0.173 seconds. Beginning copy...

Copied 30 out of 30 files in 6.5936 seconds. See C:\Triages\RegistryFiles\2023-05-09T15_06_21_5242679_CopyLog.csv for copy details

Total execution time: 6.5953 seconds
```

**NOTE**: if you simply want to do a quick view without the annoying permissions inherited from NTFS, you can use Double Commander (https://github.com/doublecmd/doublecmd) or Powershell as administrator for example

5. Disconnect when finish

---

### Connect to a SPECTR3 iSCSI target with Linux
In linux distros install open-iscsi with apt or yum.
1. Discover targets:
```
admuser@lindev:~$ sudo iscsiadm -m discovery -t sendtargets -p 172.29.10.42:3262
172.29.10.42:3262,-1 iqn.2023-05.io.alpine.desktop-j4r9lju:dsk0
```
2. Connect targets:
```
admuser@lindev:~$ sudo iscsiadm -m node -l
Logging in to [iface: default, target: iqn.2023-05.io.alpine.desktop-j4r9lju:dsk0, portal: 172.29.10.42,3262]
Login to [iface: default, target: iqn.2023-05.io.alpine.desktop-j4r9lju:dsk0, portal: 172.29.10.42,3262] successful.
```
![image](https://user-images.githubusercontent.com/143736/236651802-0c5699da-3ca3-4cb1-9580-7c55505eed99.png)

3. Acquire or analyze with your favorite tool:
```
admuser@lindev:/tmp$ sudo ewfacquire -u -S 5GiB -t /tmp/windev/windev /dev/sdb
```
![image](https://user-images.githubusercontent.com/143736/236651882-fa5280bb-8d26-451d-81a8-01c78fd58b7a.png)

4. Disconnect when finish:
```
admuser@lindev:/tmp$ sudo iscsiadm -m node -u
Logging out of session [sid: 1, target: iqn.2023-05.io.alpine.desktop-j4r9lju:dsk0, portal: 172.29.10.42,3262]
Logout of [sid: 1, target: iqn.2023-05.io.alpine.desktop-j4r9lju:dsk0, portal: 172.29.10.42,3262] successful.
```
5. (Optional) Remove Target from cache. Example:
```
admuser@lindev:~$ sudo iscsiadm -m node -o delete -T iqn.2023-05.io.alpine.desktop-j4r9lju:dsk0
```
---
### Connect to a SPECTR3 iSCSI target with OSx
In OSx install KernSafe ISCSI Initiator X.

https://www.kernsafe.com/product/macos-iscsi-initiator.aspx

1. Discover targets with "Discover" and Discover Menu:

![image](https://github.com/alpine-sec/SPECTR3/assets/39518955/41c733c6-a95d-42b7-a981-d29c3da813d2)

![image](https://github.com/alpine-sec/SPECTR3/assets/39518955/c7f8a60c-4540-4095-998c-14b66b47ee95)

2. Use Spectr3 server IP and Port:

![image](https://github.com/alpine-sec/SPECTR3/assets/39518955/13ca7eb6-46b3-4ca5-a909-c1f00d6f4607)

![image](https://github.com/alpine-sec/SPECTR3/assets/39518955/f213594f-28ae-492b-aec2-4d5b4e2c0620)

3. Connect to target:

![image](https://github.com/alpine-sec/SPECTR3/assets/39518955/622a866a-5a57-43de-af20-2e40c6332120)

![image](https://github.com/alpine-sec/SPECTR3/assets/39518955/71ef738c-e655-4aec-b5e1-1d022e7bc879)

4. Acquire or analyze with your favorite tool:

![image](https://github.com/alpine-sec/SPECTR3/assets/39518955/7daa7ecb-392b-4347-9721-0cb6ec033663)

5. **Disconnect when finish:**

:warning: Remember to disconnect your ISCSI drives before shutdown :warning:

---

### Improved security through IP ACLs
Use -i option to improve de security via IP ACL. Only the permited IP will access to target
```
C:\Users\dev\Desktop>SPECTR3.exe -d 0 -i 10.10.10.2
  - SPECTR3 Server running at 172.20.118.42:3262
    + Access Permited from: 10.10.10.2
  - Press any key to stop sharing and close server ...
```

### Encrypt connection over reverse SSH

1. Use --sshhost options. Optionally you can add sshuser, sshpass and sshport via arguments. If you want set password via argument, you need convert it to base64 (perfect for remote execution of SPECTR3):

![image](https://github.com/alpine-sec/SPECTR3/assets/143736/b492abf5-b996-475a-bbaf-aa34b7907980)

2. You can see the remote login and the iSCSI port in the remote machine:

![image](https://github.com/alpine-sec/SPECTR3/assets/143736/373c3b77-5616-4abc-a3de-254adc1d2c33)

![image](https://github.com/alpine-sec/SPECTR3/assets/143736/5bd275f3-50bc-49e0-8284-289e262ce395)

3. Show target in localhost and exported port:

![image](https://github.com/alpine-sec/SPECTR3/assets/143736/a75606e6-c5c1-4a9d-8265-64667d102f61)

4. Connect target as usual.

<!-- SCENARIOS -->
## Scenarios

![SPECTR3-Basic](https://github.com/alpine-sec/SPECTR3/assets/143736/0005fd7b-536d-4cb7-b994-34760e544334)


<!-- ROADMAP -->
## Roadmap

- [ ] Add option to share all drives in different targets
- [ ] Add option to install as a service
- [X] Tunnelized and encrypted connections
- [ ] Multiplatform easy client
- [ ] Others cool things...

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* [iScsi Console](https://github.com/TalAloni/iSCSIConsole)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



