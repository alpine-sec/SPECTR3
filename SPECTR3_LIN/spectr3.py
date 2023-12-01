#!/usr/bin/env python3
#
# spectr3.py
#
# (c) Authors: Miguel Quero (Based in TGT Project https://github.com/fujita/tgt)
# e-mail: motrilwireless@gmail.com
# Company: Alpine Security
#
# ***************************************************************
#
# The license below covers all files distributed with infofile unless 
# otherwise noted in the file itself.
#
# This program is free software: you can redistribute it and/or 
# modify it under the terms of the GNU General Public License as 
# published by the Free Software Foundation, version 3.
# 
# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License 
# along with this program. If not, see <https://www.gnu.org/licenses/>. 
#

import os
import re
import sys
import json
import time
import signal
import base64
import socket
import select
import getpass
import argparse
import netifaces
import subprocess

from blkinfo import BlkDiskInfo



VERSION="0.2"
INSTALL_PATH = os.path.dirname(os.path.abspath(__file__))


def get_args():
    argparser = argparse.ArgumentParser(
        description='SPECTR3 Linux v{} - Remote acquisition and forensic tool by Alpine Security'.format(VERSION))

    argparser.add_argument('-V', '--version',
                            action='version', 
                            version='%(prog)s {}'.format(VERSION))

    argparser.add_argument('-l', '--list',
                            required=False,
                            action='store_true',
                            help='List available volumes and disks.')
    
    argparser.add_argument('-p', '--port',
                            required=False,
                            action='store',
                            help='Set port to listen on.')
    
    argparser.add_argument('-i', '--permitip',
                            required=False,
                            action='store',
                            default=False,
                            help='Set the permited ip client to connect.')

    argparser.add_argument('-b', '--bindip',
                            required=False,
                            action='store',
                            default=False,
                            help='Set the bind ip to listen.')

    argparser.add_argument('-d', '--device',
                            required=False,
                            action='store',
                            help='Set device to share. Ex: -d sda1 (without /dev/)')
    
    argparser.add_argument('--chapuser',
                            required=False,
                            action='store',
                            help='Set CHAP username. Ex: --chapuser admin')

    argparser.add_argument('--chappass',
                            required=False,
                            action='store',
                            help='Set CHAP password in BASE64 with minimal password size of 12. Ex: --chappass QWxwaW5lU2VjdXJpdHk=')

    argparser.add_argument('--daemon',
                            required=False,
                            action='store_true',
                            default=False,
                            help='Run SPECTR3 as background unattended process. NOTE: Manually kill by PID needed.')

    args = argparser.parse_args()

    return args, argparser


def list_devices():
    devices = []
    
    # Read block device information using blkinfo
    blkd = BlkDiskInfo()
    disks = blkd.get_disks()
    
    # List Physical Disks
    print("- List Physical Disks:")
    for disk in disks:
        size = sizeof_fmt(disk['size'])
        print(f"    + {disk['name']}:  {disk['model']}    {size}".format(size=size))

    
    # List Volumes
    print("- List Volumes:")
    for disk in disks:
        if disk['children']:
            for volume in disk['children']:
                size = sizeof_fmt(volume['size'])
                if volume['mountpoint'] and volume['fstype']:
                    print(f"    + {volume['name']}:\t{volume['fstype']}\t{volume['mountpoint']}\t{size}".format(size=size))
                elif volume['mountpoint']:
                    print(f"    + {volume['name']}:\t\t{volume['mountpoint']}\t{size}".format(size=size))
                else:
                    print(f"    + {volume['name']}:\t\t\t{size}".format(size=size))

    # List LVM Volumes
    lvm_volumes = os.popen("sudo lvs --units b --nosuffix --options lv_name,lv_size,lv_path,vg_name").read()
    if lvm_volumes:
        print("- List LVM Volumes:")
    lvm_volumes = lvm_volumes.split("\n")
    for volume in lvm_volumes:
        # Skip first line
        if "LV" in volume:
            continue
        if volume:
            volume = volume.split(" ")
            volume = list(filter(None, volume))
            mountpoint = os.popen("sudo findmnt -n -o TARGET {}".format(volume[2])).read()
            if mountpoint:
                mountpoint = mountpoint.strip()
            else:
                mountpoint = ""
            fstype = os.popen("sudo findmnt -n -o FSTYPE {}".format(volume[2])).read()
            if fstype:
                fstype = fstype.strip()
            else:
                fstype = ""
            size = sizeof_fmt(volume[1])
            print (f"    + {volume[0]}:\t{fstype}\t{mountpoint}\t{size}".format(size=size))

def locate_block_device(device_name):
    for root, dirs, files in os.walk('/dev'):
        for file in files:
            if file == device_name:
                return os.path.join(root, file)
    return None

def kill_process(pid):
    try:
        os.kill(pid, signal.SIGKILL)
        return True
    except OSError:
        return False

def sizeof_fmt(num, suffix="B"):
    num = float(num)  # Convert num to a float
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"

def get_hostname():
    hostname = socket.gethostname()
    return hostname

def get_main_ip_address():
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET]
    
    for interface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addresses:
            for address in addresses[netifaces.AF_INET]:
                if 'addr' in address and address['addr'] != '127.0.0.1':
                    return address['addr']
    return None

def start_tgt_server(bindip, port):
    # Check if tgtd is installed or in path
    tgtd_path = os.path.join(INSTALL_PATH, "tgtd")
    if not os.path.exists(tgtd_path):
        print("  - ERROR: TGTD not found. Please install it or download binary from SPECTR3 linux package.")
        return False
    # Check if tgtd is running
    tgtd_running = os.system("ps -A | grep tgtd > /dev/null")
    if tgtd_running == 0:
        print("  - ERROR: TGTD is already running. Please stop it before running SPECTR3.")
        return False
    # Check if tgtadm is installed or in path
    tgtadm_path = os.path.join(INSTALL_PATH, "tgtadm")
    if not os.path.exists(tgtadm_path):
        print("  - ERROR: tgtadm not found. Please install it or download binary from SPECTR3 linux package.")
        return False
    
    # Start tgtd
    print("  - Starting TGTD...")
    # Run sudo tgtd with subprocess
    portal = "portal={}:{}".format(bindip, port)
    #portal = "portal=0.0.0.0:{}".format(port)
    tgtd = subprocess.Popen(["sudo", tgtd_path,"-d", "1", "--iscsi", portal])
    time.sleep(2)
    # Check if tgtd is running
    tgtd_running = os.system("ps -A | grep tgtd > /dev/null")
    if tgtd_running != 0:
        print("    + ERROR: TGTD failed to start.")
        return False
    # Get tgtd PID
    tgtd_pid = os.popen("ps -A | grep -m1 tgtd | awk '{print $1}'").read()
    tgtd_pid = tgtd_pid.strip()
    print(f"    + TGTD PID: {tgtd_pid}")
    print("    + TGTD started successfully.")
    print()
    return int(tgtd_pid)

def stop_tgt_server(tgtdpid):
    print()
    print("    + Stopping SPECTR3...")
    print("    + Stopping TGTD...")
    # Stop tgtd
    check_kill = kill_process(tgtdpid)
    time.sleep(5)
    # Check if tgtd is running
    if not check_kill:
        print("    + ERROR: TGTD failed to stop.")
        return False
    print("    + TGTD stopped successfully.")
    print()

def spectr3_start(port, permitip, bindip, device, daemon, chapuser, chappass, tgtdpid):
    # Configure targets
    hostname = get_hostname()
    targetname = "iqn.2023-05.io.alpine.{hostname}:{device}".format(hostname=hostname, device=device)
    vendor = "AlpineSec"
    model = "SPECTR3 iSCSI"

    # Create a target
    devicepath = locate_block_device(device)
    if not devicepath:
        print("  - ERROR: Device not found.")
        return False

    tgtadm_path = os.path.join(INSTALL_PATH, "tgtadm")
    
    # Execute tgtadm to create a target
    print("  - Creating target...")
    tgtadm = subprocess.Popen(["sudo", tgtadm_path, "--lld", "iscsi", "--op", "new", "--mode", "target", "--tid", "1", "-T", targetname])
    time.sleep(1)
    # Check if target was created
    target_created = os.system(f"sudo {tgtadm_path} --lld iscsi --op show --mode target | grep {targetname} > /dev/null")
    if target_created != 0:
        print("    + ERROR: Failed to create target.")
        return False
    
    # Add a device to the target
    print("    + Adding device to target...")
    tgtadm = subprocess.Popen(["sudo", tgtadm_path, "--lld", "iscsi", "--op", "new", "--mode", "logicalunit",
                               "--tid", "1", "--lun", "1", "-b", devicepath])
    time.sleep(1)
    # Check if device was added
    device_added = os.system(f"sudo {tgtadm_path} --lld iscsi --op show --mode target | grep {devicepath} > /dev/null")
    if device_added != 0:
        print("    + ERROR: Failed to add device to target.")
        return False
    
    # Accept connections only from localhost not for permitip
    print("    + Setting target ACL...")
    tgtadm = subprocess.Popen(["sudo", tgtadm_path, "--lld", "iscsi", "--op", "bind", "--mode", "target", "--tid", "1", "-I", permitip])
    time.sleep(1)

    # Set readonly: sudo tgtadm --lld iscsi --op update --mode logicalunit --tid 1 --lun 1 --params readonly=yes
    print("    + Setting target readonly...")
    tgtadm = subprocess.Popen(["sudo", tgtadm_path, "--lld", "iscsi", "--op", "update", "--mode", "logicalunit",
                               "--tid", "1", "--lun", "1", "--params", "readonly=1,vendor_id={},product_id={}".format(vendor, model)])
    time.sleep(1)

    # Set CHAP authentication.
    if chapuser:
        print("    + Setting CHAP authentication...")
        if not chappass:
            chappass = getpass.getpass("      - Enter CHAP password: ")

        if chappass:
            # Create CHAP user
            tgtadm = subprocess.Popen(["sudo", tgtadm_path, "--lld", "iscsi", "--op", "new", "--mode", "account", "--user", chapuser, "--password", chappass])
            time.sleep(1)
            # Add CHAP user to target
            tgtadm = subprocess.Popen(["sudo", tgtadm_path, "--lld", "iscsi", "--op", "bind", "--mode", "account", "--tid", "1", "--user", chapuser])
            time.sleep(1)

    connected_ips = []
    print()
    print(f"  - SPECTR3 Server running at {bindip}:{port}")
    print(f"    + Target IQN: {targetname}")
    print(f"    + Target ACL: {permitip}")
    if not daemon:
        print(f"  - Press ENTER key to stop sharing and close server ...")
        while True:
            try:
                ips = []
                # Check if a new initiator is connected
                check_initiator = subprocess.Popen(["sudo", tgtadm_path, "--lld", "iscsi", "--op", "show",
                                                    "--mode", "target"], stdout=subprocess.PIPE)
                check_initiator.wait()

                # Process the output to check if a new initiator is connected
                output = check_initiator.communicate()[0]
                output = output.decode("utf-8")

                # Check if "IP Address" is in output
                if "IP Address" in output:
                    # Split output by line
                    output = output.split("\n")
                    # Iterate over lines
                    for line in output:
                        # Check if "IP Address" is in line
                        if "IP Address" in line:
                            # Split line by space
                            line = line.split(" ")
                            # Iterate over line
                            for word in line:
                                # Check if word is an IP Address
                                if re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", word):
                                    ipaddress = word
                                    ips.append(ipaddress)
                                    if word not in connected_ips:
                                        print("    + Client Connected from: {}".format(word))
                                        connected_ips.append(word)

                if len(connected_ips) != len(ips):
                    # remove ips that are not connected anymore
                    for ip in connected_ips:
                        if ip not in ips:
                            print("    + Client Disconnected from: {}".format(ip))
                            connected_ips.remove(ip)

                time.sleep(5)  # Wait for 5 second before checking again
                # Check if user pressed ENTER key
                if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    line = input()
                    stop_tgt_server(tgtdpid)
                    break
            except KeyboardInterrupt:
                stop_tgt_server(tgtdpid)
                return True

            except Exception as e:
                print("  - SPECTR3 ERROR: {}".format(e))
                stop_tgt_server(tgtdpid)
    else:
        return True

def main():
    args, argparser = get_args()
    showdevices = args.list
    port = args.port
    permitip = args.permitip
    bindip = args.bindip
    device = args.device
    daemon = args.daemon
    chapuser = args.chapuser
    chappass = args.chappass

    # Check if root permissions
    if os.geteuid() != 0:
        print("  - ERROR: You must run this script as root.")
        return 1

    if showdevices:
        list_devices()
        return 0

    if not port:
        port = 3262
    
    if not permitip:
        permitip = "ALL"
    
    if not daemon:
        daemon = False

    if not bindip:
        bindip = get_main_ip_address()
    
    if not device:
        print("  - ERROR: You must specify a device to share.")
        # Print help
        print(argparser.print_help())
        return 1

    if chapuser and chappass:
        #decode base64 chappass
        chappass = base64.b64decode(chappass).decode("utf-8")
        chappass = str(chappass)
        if len(chappass) < 12 or len(chappass) > 16:
            print("  - ERROR: CHAP password must be at least 12 characters and maximum 16 characters.")
            return 1

    # Start TGT Server
    tgtdpid = start_tgt_server(bindip, port)
    if not tgtdpid:
        print ("  - ERROR: Failed to start TGTD.")
        return 1

    # Run SPECTR3
    spectr3_start(port, permitip, bindip, device, daemon, chapuser, chappass, tgtdpid)
    return 0

if __name__ == '__main__':
    main()