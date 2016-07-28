import os
import sys

import time
import lxc


LXC_CT_BASE = 'ctbase'
CONFIG_PATH = '/home/llorenj1/workspace/gitlab/customer_edge_switching_v2/LXC'
CONFIG_FILE = 'config'
ROOTFS_PATH = 'rootfs'
CWD = os.getcwd()

USER='ubuntu'
PASSWORD='ubuntu'
PACKAGES = ['sudo',
            'iptables',
            'conntrack',
            'openssh-server',
            'nano',
            'tmux',
            'python3',
            'python3-pip',
            'iperf',
            'htop',
            'ftp',
            'vsftpd',
            'curl',
            'wget',
            'ethtool',
            'tcpdump',
            'traceroute',
            'hping3',
            'lksctp-tools',
            'psmisc',
            'bind9',
            'bind9utils',
            'isc-dhcp-server',
            'nginx-core',
            'openvswitch-switch',
            'openvswitch-ipsec']
PACKAGES = []
DISABLED_SERVICES = ['bind9',
                     'isc-dhcp-server',
                     'openvswitch-switch',
                     'openvswitch-ipsec',
                     'racoon']


def sanitize_line(text, comment='#', token=''):
    if text.startswith(comment):
        return False
    if token not in text:
        return False
    return True
def get_key_value(text, token=''):
    k = text.strip().split('=')[0].strip()
    v = text.strip().split('=')[1].strip()
    return (k,v)

def load_config_container(ct, filename):
    print('Loading configuration: {} @ {}'.format(ct.name, filename))
    with open(filename, 'r') as infile:
        for line in infile:
            #Sanitize values
            if not sanitize_line(line, token='='):
                continue
            k,v = get_key_value(line)
            #print('Adding attribute: {} - {} / {}'.format(ct.name, k, v))
            ct.append_config_item(k, v)
        ct.save_config()

def sync_rootfs_container(ct, path):
    print('Syncing rootfs for: {} @ {}'.format(ct.name, path))
    os.chdir(path)
    for root, dirs, files in os.walk("."):
        #print('CURRENT PATH ', os.getcwd())
        #print((root, dirs, files))
        # Create directory in container rootfs
        if root[1:] != '':
            #print('{}# mkdir -p {}'.format(ct.name, root[1:]))
            ct.attach_wait(lxc.attach_run_command, ["mkdir", "-p", root[1:]])

        for file in files:
            # Make absolute file in host
            _file = os.path.join(os.getcwd(), root, file)
            # Make absolute path in container
            ct_file = os.path.join(root, file)[1:]
            #print('{}# sync {} -> {}'.format(ct.name, _file, ct_file))
            ct_sync_file(ct, _file, ct_file)

def ct_start(ct, verbose = False):
    try:
        ## Starting the container
        print("Starting container: {}".format(ct.name))
        ct.start()
        ct.wait("RUNNING", 10)

        # A few basic checks of the current state
        assert(ct.init_pid > 1)
        assert(ct.running)
        assert(ct.state == "RUNNING")
        if verbose:
            # Print container stats
            ct_stats(ct)
    except:
        print("Failed to start the container {}".format(ct.name))
        sys.exit(1)

def ct_stop(ct, verbose = False):
    try:
        ## Shutting down the container
        print("Shutting down container: {}".format(ct.name))
        if not ct.shutdown(10):
            ct.stop()
        if ct.running:
            print("Stopping container: {}".format(ct.name))
            ct.stop()
            ct.wait("STOPPED", 10)

        # A few basic checks of the current state
        assert(ct.init_pid == -1)
        assert(not ct.running)
        assert(ct.state == "STOPPED")
        if verbose:
            # Print container stats
            ct_stats(ct)
    except:
        print("Failed to stop the container {}".format(ct.name))
        sys.exit(1)

def ct_restart(ct, verbose = False):
    ct_stop(ct, verbose)
    ct_start(ct, verbose)

def ct_disable_service(ct, service):
    print("Stop & Disable service @ {} - {}".format(ct.name, service))
    ct.attach_wait(lxc.attach_run_command, ["systemctl", "stop", service])
    ct.attach_wait(lxc.attach_run_command, ["systemctl", "disable", service])

def ct_stats(ct):
    # Query some information
    print("Container {} state: {}".format(ct.name, ct.state))
    print("Container {} PID: {}".format(ct.name, ct.init_pid))

def ct_sync_file(ct, source, destination):
    import subprocess as _sysexec
    time.sleep(0.5)
    command = 'cat {} | lxc-attach -n {} -- /bin/sh -c "/bin/cat > {}"'.format(source, ct.name, destination)
    #print('sysexec: {}'.format(command))
    print('Writing file: @ {} - {}'.format(ct.name, destination))
    _sysexec.check_call(command, shell=True)

def _create_ctbase():
    ct = lxc.Container(LXC_CT_BASE)
    # Create the container rootfs
    if not ct.create("ubuntu", 0, {"user": USER, "password": PASSWORD, "packages": ','.join(p for p in PACKAGES)}):
        print("Failed to create the container rootfs")
        sys.exit(1)
    
    # Start the container
    ct_start(ct, True)
    # Disable all services from container base
    for service in DISABLED_SERVICES:
        ct_disable_service(ct, service)
    # Overwrite interfaces file
    ct_sync_file(ct, '/var/lib/lxc/interfaces.default', '/etc/network/interfaces')
    # Stop the container
    ct_stop(ct, True)
    # Clear all network configuration before the snapshots
    ct.clear_config_item("lxc.network")
    ct.save_config()

def _clone_container(name):
    ctbase = lxc.Container(LXC_CT_BASE)
    ct = lxc.Container(name)
    print('Cloning {} to {}'.format(ctbase.name, ct.name))
    if ct.defined:
        print('Container already exists: {}'.format(name))
        return

    # Clone LXC_CT_BASE with snapshot
    if not ctbase.clone(name, flags=lxc.LXC_CLONE_SNAPSHOT):
        print("Failed to clone the container")
        sys.exit(1)
    # Load container configuration
    load_config_container(ct, os.path.join(CONFIG_PATH, name, CONFIG_FILE))
    # Start the container
    ct_start(ct, True)
    # Sync container rootfs
    sync_rootfs_container(ct, os.path.join(CONFIG_PATH, name, ROOTFS_PATH))
    # Restart the container to take in effect new configuration
    ct_restart(ct)
        
###############################################################################
###############################################################################

ct = lxc.Container(LXC_CT_BASE)
if not ct.defined:
    print("Create base container: {}".format(LXC_CT_BASE))
    _create_ctbase()  
    #print("Re-run script to create clones")
    #sys.exit(0)

print("Base container found: {}".format(LXC_CT_BASE))
# Make sure the container is stopped before cloning
ct_stop(ct)

# Clone new containers
filename = os.path.join(CONFIG_PATH, CONFIG_FILE)
with open(filename, 'r') as main_config:
    for line in main_config:
        #Sanitize values
        if not sanitize_line(line):
            continue
        #Sanitize and clone container
        name = line.strip()
        _clone_container(name)


'''

c = lxc.Container('router')
c.append_config_item('lxc.network.type', 'macvlan')
c.append_config_item('lxc.network.macvlan.mode', 'bridge')
c.append_config_item('lxc.network.link', 'br-lana0')
c.append_config_item('lxc.network.flags', 'up')
c.append_config_item('lxc.network.ipv4', '1.2.3.4/32')

c.save_config()

c.get_config_item('lxc.network')

## Clone containers
for i in router proxya cesa hosta public proxyb cesb hostb
do
	echo "Cloning ctbase as $i"
	mkdir -p $i
	mkdir -p $i/rootfs
    rm -rf $i/files
    rm -rf $i/scripts
done

## Stop & Destroy containers
for i in router proxya cesa hosta public proxyb cesb hostb
do
	echo "Stopping container $i ..."
	lxc-stop -n $i
	echo "Destroying container $i ..."
	lxc-destroy -n $i
done


'''