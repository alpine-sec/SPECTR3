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
        <li><a href="#SPECTR3-for-Linux">SPECTR3 for Linux</a></li>
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
SPECTR3 v0.7 - Remote acquisition and forensic tool by Alpine Security
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
  -a, --shareall
    Share all disks.
  -t, --timeout
    Stop the service if the configured number of MINUTES without activity elapses. Ex. -t 60 (60 min)
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
  --daemon
    Run SPECTR3 as background unattended process. NOTE: Manually kill by PID needed.
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

![win01](https://github.com/alpine-sec/SPECTR3/assets/143736/3950442b-ec66-4989-800f-3704ebb73134)

2. Use Spectr3 server IP and Port:

![win02](https://github.com/alpine-sec/SPECTR3/assets/143736/2229a494-e36c-4072-ad1a-dabd9466964e)


3. Connect to target in "Targets" tab:

![win03](https://github.com/alpine-sec/SPECTR3/assets/143736/a8b7d39e-4d5c-478a-9254-a6693a4e1f2f)

![win04](https://github.com/alpine-sec/SPECTR3/assets/143736/7ea41776-4068-493c-9d15-60eb5ce39fbf)


4. Acquire or analyze with your favorite tool:

![win05](https://github.com/alpine-sec/SPECTR3/assets/143736/66e3a3b7-a629-4389-9641-297fd50624d6)

![win06](https://github.com/alpine-sec/SPECTR3/assets/143736/fde96dee-d5a7-4c41-b94f-f77e5b49166d)


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

![osx01](https://github.com/alpine-sec/SPECTR3/assets/143736/522dc464-b76e-49e2-b5f2-2a69a8f660c6)

![osx02](https://github.com/alpine-sec/SPECTR3/assets/143736/0211cbbe-712a-4cb0-8716-9b549221b86c)

2. Use Spectr3 server IP and Port:

![osx03](https://github.com/alpine-sec/SPECTR3/assets/143736/0d8af011-1433-4ac6-a677-6d6eb11ac1a3)

![osx04](https://github.com/alpine-sec/SPECTR3/assets/143736/84c80c34-8c84-4f0d-8b26-74b8445d6a96)

3. Connect to target:

![osx06](https://github.com/alpine-sec/SPECTR3/assets/143736/257aaa4f-336e-43b9-87b0-f164071529b5)

![osx07](https://github.com/alpine-sec/SPECTR3/assets/143736/17a9eb9c-fafd-46c1-8646-3854634793e9)

4. Acquire or analyze with your favorite tool:

![osx08](https://github.com/alpine-sec/SPECTR3/assets/143736/f9519e38-874d-4790-9b32-bf66da541038)

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

```
C:\Users\dev\Desktop>SPECTR3.exe -d 0 --sshhost 172.29.10.41
  - SSH Username: admuser
  - SSH Password: *************
  - SPECTR3 Server running at 127.0.0.1:3262
    + Target IQN: iqn.2023-05.io.alpine.desktop-j4r9lju:dsk0
    + Access Permited from: 127.0.0.1
  - Press ENTER key to stop sharing and close server ...
  - Connecting to SSH server ...
    + SSH tunnel successfully connected to 172.29.10.41:22
    + SSH connection state: Connected
 ```

2. You can see the remote login and the iSCSI port in the remote machine:
```
May 22 08:31:04 lindev sshd[1131]: Accepted password for admuser from 172.29.10.42 port 49928 ssh2
May 22 08:31:04 lindev sshd[1131]: pam_unix(sshd:session): session opened for user admuser(uid=1000) by (uid=0)
May 22 08:31:04 lindev systemd-logind[692]: New session 4 of user admuser.
```
```
admuser@lindev:~$ netstat -tulpna | grep 3262
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:3262          0.0.0.0:*               LISTEN      -
tcp6       0      0 ::1:3262                :::*                    LISTEN      -
```

3. Show target in localhost and exported port:

```
admuser@lindev:~$ sudo iscsiadm -m discovery -t sendtargets -p localhost:3262
[sudo] password for admuser:
[localhost]:3262,-1 iqn.2023-05.io.alpine.desktop-j4r9lju:dsk0
```

4. Connect target as usual.

### SPECTR3 for Linux
[**DOWNLOAD EXECUTABLE**](https://github.com/alpine-sec/SPECTR3/releases/tag/v0.7.2)
SPECTR3 for linux works as a wrapper for the https://github.com/fujita/tgt project and uses the tgtd and tgtadmin binaries. Both binaries are embedded in the portable version.
```
usage: spectr3 [-h] [-V] [-l] [-p PORT] [-i PERMITIP] [-b BINDIP] [-d DEVICE] [-a]
               [--chapuser CHAPUSER] [--chappass CHAPPASS] [--daemon]

SPECTR3 Linux v0.3 - Remote acquisition and forensic tool by Alpine Security

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -l, --list            List available volumes and disks.
  -p PORT, --port PORT  Set port to listen on.
  -i PERMITIP, --permitip PERMITIP
                        Set the permited ip client to connect.
  -b BINDIP, --bindip BINDIP
                        Set the bind ip to listen.
  -d DEVICE, --device DEVICE
                        Set device to share. Ex: -d sda1 (without /dev/)
  -a, --shareall        Share all block devices
  --chapuser CHAPUSER   Set CHAP username. Ex: --chapuser admin
  --chappass CHAPPASS   Set CHAP password in BASE64 with minimal password size of 12. Ex: --chappass
                        QWxwaW5lU2VjdXJpdHk=
  --daemon              Run SPECTR3 as background unattended process. NOTE: Manually kill by PID
                        needed.
```
NOTE: In Centos7/RHEL remember open allow port. Ex: sudo firewall-cmd --zone=public --add-port=3262/tcp

Execution Example:
```
admuser@lintest:~$ sudo ./spectr3 -l
- List Physical Disks:
    + sda:  VMware, VMware Virtual S    20.0GiB
    + sr0:  NECVMWar VMware Virtual SATA CDRW Drive    1.8GiB
- List Volumes:
    + sda1:                     1.0MiB
    + sda2:     ext4    /boot   1.8GiB
    + sda3:                     18.2GiB
- List LVM Volumes:
    + ubuntu-lv:        ext4    /       10.0GiB
```

```
admuser@lintest:~$ sudo ./spectr3 -d sda2
  - Starting TGTD...
    + TGTD PID: 38675
    + TGTD started successfully.

  - Creating target...
    + Adding device to target...
    + Setting target ACL...
    + Setting target readonly...

  - SPECTR3 Server running at 192.168.202.180:3262
    + Target IQN: iqn.2023-05.io.alpine.lintest:sda2
    + Target ACL: ALL
```

Compile linux portable
```
cd SPECTR3_LIN
make
sudo pip3 install -r requirements.txt
pyinstaller --onefile spectr3.py --add-binary tgtd:. --add-binary tgtadm:.
```


<!-- SCENARIOS -->
## Scenarios

![SPECTR3-Basic](https://github.com/alpine-sec/SPECTR3/assets/143736/406037df-7b52-4f67-9e7b-98f4921a7f01)



<!-- ROADMAP -->
## Roadmap

- [ ] Add option to share all drives in different targets
- [ ] Add option to install as a service
- [X] Add option to run as daemon in background
- [X] Tunnelized and encrypted connections
- [X] Linux Version
- [ ] Multiplatform easy client
- [ ] Others cool things...

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* [iScsi Console](https://github.com/TalAloni/iSCSIConsole)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



