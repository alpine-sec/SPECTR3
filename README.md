<a name="readme-top"></a>
<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/alpine-sec/spectr3">
    <img width="488" alt="Spectr3_2" src="https://user-images.githubusercontent.com/143736/236651153-4bb4553b-52cb-4b28-adcb-7060ad68667f.png">
  </a>

  <h3 align="center">Spectr3: Remote Acquisition Tool</h3>

  <p align="center">
    Acquire, triage and investigate remote evidences via portable iSCSI readonly access
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>


<!-- ABOUT THE PROJECT -->
## About The Project

This project is based on the great work done by TalAloni with iSCSI Console but with a forensic objective more similar to F-Response in its approach to remote acquisition, analysis and triage.

The goal is to make available to the community a command line, open source and easy to use tool for scenarios where a complete forensic acquisition or a fast remote analysis is needed.

And of course... just for fun!

<!-- USAGE EXAMPLES -->
## Usage
Copy portable executable of **Spectr3** to the endpoint where you want to perform remote acquisition, triage or forensic analysis, **remember that you will need administrator permissions to access the block devices.**

### Command Line Options
```
SPECTR3 v0.3 - Remote forensics tool by Alpine Security
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
```

### List devices of the endpoint
```
C:\Users\dev\Desktop>SPECTR3.exe -l
- List Physical Disks:
    + Disk 0: Msft Virtual Disk  60GB
- List Volumes:
    + Volume 0: EFI system partition Partition 100MB  Healthy
    + Volume 1: Microsoft reserved partition Partition 16MB  Healthy
    + Volume 2: Basic data partition Partition 59.4GB  Healthy
    + Volume 3:  Partition 530MB  Healthy
```

### Share a disk or volume as an iSCSI target
Use -d if you want share a full disk or -v if only you want to share a volume. Use the index of de volume or disk in -l list. (Allow Access in firewall if popup)
```
C:\Users\dev\Desktop>SPECTR3.exe -d 0
  - SPECTR3 Server running at 172.20.118.42:3262
    + Access Permited from: 0.0.0.0
  - Press any key to stop sharing and close server ...
```
Close terminal o press any key for sharing termination

### Connect to a Spectr3 iSCSI target  with Windows
In Windows Investigator machines you can use the windows native tool iSCSI Initiator:
1. Discover targets with "Discover Portal" in "Discovery Tab":

![image](https://user-images.githubusercontent.com/143736/236651296-daa10bd4-9f14-4683-83b0-91a7cc49eae1.png)

2. Use Spectr3 server IP and Port:

![image](https://user-images.githubusercontent.com/143736/236651365-441f5394-b99f-4148-8e3a-f82d7c0a86c6.png)

3. Connect to target in "Targets" tab:

![image](https://user-images.githubusercontent.com/143736/236651418-2dc784ae-5ccc-4608-8830-cf3ec3d98f39.png)

![image](https://user-images.githubusercontent.com/143736/236651459-7a7d2339-72d3-4a3e-b3ab-55cc1e08ecaa.png)

4. Acquire or analyze with your favorite tool:

![image](https://user-images.githubusercontent.com/143736/236651568-e81c4c1a-62fd-45ee-8858-377c5a33ae7d.png)

![image](https://user-images.githubusercontent.com/143736/236651589-1f187867-5230-4668-bf29-af5f414c049a.png)

**NOTE**: if you simply want to do a quick view without the annoying permissions inherited from NTFS, you can use Double Commander (https://github.com/doublecmd/doublecmd) for example)

5. Disconnect when finish

### Connect to a Spectr3 iSCSI target with Linux
In linux distros install open-iscsi with apt or yum.
1. Discover targets:
```
admuser@lindev:~$ sudo iscsiadm -m discovery -t sendtargets -p 172.20.118.42:3262
172.20.118.42:3262,-1 iqn.2023-05.io.alpine:dsk0
```
2. Connect targets:
```
admuser@lindev:~$ sudo iscsiadm -m node -l
Logging in to [iface: default, target: iqn.2023-05.io.alpine:dsk0, portal: 172.20.118.42,3262]
Login to [iface: default, target: iqn.2023-05.io.alpine:dsk0, portal: 172.20.118.42,3262] successful.
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
Logging out of session [sid: 1, target: iqn.2023-05.io.alpine:dsk0, portal: 172.20.118.42,3262]
Logout of [sid: 1, target: iqn.2023-05.io.alpine:dsk0, portal: 172.20.118.42,3262] successful.
```

### Improved security through IP ACLs
Use -i option to improve de security via IP ACL. Only the permited IP will access to target
```
C:\Users\dev\Desktop>SPECTR3.exe -d 0 -i 10.10.10.2
  - SPECTR3 Server running at 172.20.118.42:3262
    + Access Permited from: 10.10.10.2
  - Press any key to stop sharing and close server ...
```
<!-- ROADMAP -->
## Roadmap

- [ ] Add option to share all drives in different targets
- [ ] Add option to install as a service
- [ ] Tunnelized and encrypted connections
- [ ] Multiplatform easy client
- [ ] Others cool things...

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* [iScsi Console](https://github.com/TalAloni/iSCSIConsole)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



