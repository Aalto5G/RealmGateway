import os
import sys
import logging

import time
import stat
import lxc

LOGLEVEL = logging.DEBUG
#LOGLEVEL = logging.INFO
logging.basicConfig(level=LOGLEVEL)


LXC_CT_BASE = 'ctbase'
#CONFIG_PATH = '/home/llorenj1/workspace/gitlab/customer_edge_switching_v2/LXC'
CONFIG_PATH = './'
CONFIG_FILE = 'config'
ROOTFS_PATH = 'rootfs'

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
PACKAGES = ['iperf']
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

    
class LXC_Orchestration(object):
    def __init__(self, ctbasename, configfile):
        self.logger = logging.getLogger()
        self.configfile = configfile
        self.ctbasename = ctbasename
        
        self.ct_clone = self._ct_clone_lib
        self.ct_start = self._ct_start_lib
        self.ct_stop = self._ct_stop_lib
        #self.ct_clone = self._ct_clone_exec
        #self.ct_start = self._ct_start_exec
        #self.ct_stop = self._ct_stop_exec
    
    def start(self):
        ctbase = lxc.Container(self.ctbasename)
        if not ctbase.defined:
            self.logger.info('Create base container: {}'.format(self.ctbasename))
            self._create_ctbase()
            if 0:
                self.logger.warning('Re-run script to create clones')
                sys.exit(0)
        
        self.logger.info('Base container found: {}'.format(self.ctbasename))
        # Make sure the container is stopped before cloning
        self.ct_stop(self.ctbasename)

        # Clone new containers
        #filename = os.path.join(CONFIG_PATH, CONFIG_FILE)
        filename = self.configfile
        with open(filename, 'r') as config:
            time.sleep(0.5)
            for line in config:
                #Sanitize values
                if not sanitize_line(line):
                    continue
                #Sanitize and clone container
                ctname = line.strip()
                self._create_container(ctname)
        
    def load_config_container(self, name, filename):
        self.logger.info('Loading configuration: {}'.format(name))
        ct = lxc.Container(name)
        with open(filename, 'r') as config:
            for line in config:
                #Sanitize values
                if not sanitize_line(line, token='='):
                    continue
                k,v = get_key_value(line)
                self.logger.debug('Setting attribute: {} - {} / {}'.format(ct.name, k, v))
                ct.append_config_item(k, v)
            ct.save_config()
    
    def sync_rootfs_container(self, name, path):
        self.logger.info('Syncing rootfs: {}'.format(name))
        ct = lxc.Container(name)
        # Backup current working directory
        cwd = os.getcwd()
        # Change to rootfs path
        os.chdir(path)
        for root, dirs, files in os.walk('.'):
            for file in files:
                # Make absolute file in host
                _file = os.path.join(os.getcwd(), root, file)
                # Make absolute path in container
                ct_file = os.path.join(root, file)[1:]
                self.ct_sync_file(name, _file, ct_file)
        # Change to previous working directory
        os.chdir(cwd)
    
    def _ct_clone_lib(self, src, dst):
        ct_src = lxc.Container(src)
        ct_dst = lxc.Container(dst)
        if ct_dst.defined:
            self.logger.warning('Destination clone already exists: {}'.format(dst))
            return
        # Clone LXC_CT_BASE with snapshot
        if not ct_src.clone(dst, flags=lxc.LXC_CLONE_SNAPSHOT):
            self.logger.warning('Failed to clone the container')
            sys.exit(1)
    
    def _ct_clone_exec(self, src, dst):
        ct_src = lxc.Container(src)
        ct_dst = lxc.Container(dst)
        if ct_dst.defined:
            self.logger.warning('Destination clone already exists: {}'.format(dst))
            return
        # Clone LXC_CT_BASE with snapshot
        #command = 'lxc-copy -n {} -N {} -s'.format(src, dst) # Ubuntu 16.04
        command = 'lxc-clone -s {} {}'.format(src, dst) # Ubuntu 15.10
        lxc.subprocess.check_call(command, shell=True)
            
    def _ct_start_lib(self, name, verbose = False):
        try:
            ct = lxc.Container(name)
            ## Starting the container
            self.logger.debug('Starting container: {}'.format(name))
            ct.start()
            ct.wait('RUNNING', 15)
            if verbose:
                self.ct_stats(name)
            # A few basic checks of the current state
            assert(ct.init_pid > 1)
            assert(ct.running)
            assert(ct.state == 'RUNNING')
            if verbose:
                self.ct_stats(name)
        except Exception as e:
            self.logger.fatal('Failed to start the container {}'.format(name))
            raise(e)
    
    def _ct_start_exec(self, name, verbose = False):
        command = 'lxc-start -n {}'.format(name)
        lxc.subprocess.check_call(command, shell=True)
    
    def _ct_stop_lib(self, name, verbose = False):
        ct = lxc.Container(name)
        if not ct.running:
            self.logger.warning('Not running container cannot be stopped: {}'.format(name))
            return
        try:
            ## Shutting down the container
            self.logger.debug('Stopping container: {}'.format(name))
            ct.stop()
            ct.wait('STOPPED', 15)
            if verbose:
                self.ct_stats(name)
            # A few basic checks of the current state
            assert(ct.init_pid == -1)
            assert(not ct.running)
            assert(ct.state == 'STOPPED')
            if verbose:
                self.ct_stats(name)
        except Exception as e:
            self.logger.error('Failed to stop the container {}'.format(name))
            raise(e)
    
    def _ct_stop_exec(self, name, verbose = False):
        ct = lxc.Container(name)
        if not ct.running:
            self.logger.warning('Not running container cannot be stopped: {}'.format(name))
            return
        command = 'lxc-stop -n {}'.format(name)
        lxc.subprocess.check_call(command, shell=True)
        
    def ct_restart(self, name, verbose = False):
        self.ct_stop(name, verbose)
        self.ct_start(name, verbose)
    
    def ct_disable_service(self, name, service):
        ''' Use call instead of check_call because the service might not exist '''
        ct = lxc.Container(name)
        self.logger.info('Stop & Disable service: {} - {}'.format(name, service))
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'stop', service])
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'disable', service])
    
    def ct_stats(self, name):
        ct = lxc.Container(name)
        self.logger.info('Container {} state: {}'.format(name, ct.state))
        self.logger.info('Container {} PID:   {}'.format(name, ct.init_pid))
    
    def ct_sync_file(self, name, src, dst):
        # Create base directory
        ct = lxc.Container(name)
        ct.attach_wait(lxc.attach_run_command, ['mkdir', '-p', os.path.dirname(dst)])
        # Get file's permissions
        fmode = os.stat(src).st_mode
        fmode_str = stat.filemode(fmode)
        fmode_chmod = oct(fmode)[-3:]
        # Create file
        command = 'cat {} | lxc-attach -n {} -- /bin/sh -c "/bin/cat > {}"'.format(src, name, dst)
        self.logger.info('[{}] >> Copying {} {} ...'.format(name, dst, fmode_str))
        self.logger.debug('sysexec: {}'.format(command))
        lxc.subprocess.check_call(command, shell=True)
        # Set file permissions
        #ct.attach_wait(lxc.attach_run_command, ['chmod', fmode_chmod, dst])
        
    
    def _create_ctbase(self):
        ctbase = lxc.Container(self.ctbasename)
        # Create the container rootfs
        #verbosity = 0
        verbosity = lxc.LXC_CREATE_QUIET
        if not ctbase.create('ubuntu', verbosity, {'user': USER, 'password': PASSWORD, 'packages': ','.join(p for p in PACKAGES)}):
            self.logger.error('Failed to create the container rootfs {}'.format(self.ctbasename))
            sys.exit(1)
        
        # HACK - APPARMOR issues with kernel feature
        if True:
            ctbase.append_config_item('lxc.aa_allow_incomplete', '1')
            ctbase.save_config()
        
        # Start the container
        self.ct_start(self.ctbasename)
        # Disable all services from container base
        for service in DISABLED_SERVICES:
            self.ct_disable_service(self.ctbasename, service)
        # Overwrite interfaces file
        self.ct_sync_file(self.ctbasename, 'interfaces.default', '/etc/network/interfaces')
        # Stop the container
        self.ct_stop(self.ctbasename)
        # Clear all network configuration
        ctbase = lxc.Container(self.ctbasename)
        ctbase.clear_config_item('lxc.network')
        ctbase.save_config()
    
    def _create_container(self, name):
        try:
            ct = lxc.Container(name)
            self.logger.info('Cloning {} to {}'.format(self.ctbasename, name))
            if not ct.defined:
                # Clone LXC_CT_BASE with snapshot
                self.ct_clone(self.ctbasename, name)
                # Load container configuration
                self.load_config_container(name, os.path.join(CONFIG_PATH, name, CONFIG_FILE))
            else:
                self.logger.warning('Container already exists: {}'.format(name))
            # Start the container
            self.ct_start(name)
            # Sync container rootfs
            self.sync_rootfs_container(name, os.path.join(CONFIG_PATH, name, ROOTFS_PATH))
            # Restart the container to take in effect new configuration
            self.ct_restart(name)
        except FileNotFoundError as e:
            self.logger.warning(format(e))
    
    
###############################################################################
###############################################################################

if __name__ == '__main__':
    filename = os.path.join(CONFIG_PATH, CONFIG_FILE)
    obj = LXC_Orchestration(LXC_CT_BASE, filename)
    obj.start()
    
'''
# [COMMON]
## WAN side
ip link add dev br-wan0 type bridge
ip link set dev br-wan0 up
ip link add dev br-wan1 type bridge
ip link set dev br-wan1 up
# [RealmGateway-A]
## WAN side
ip link add dev br-wan0a type bridge
ip link set dev br-wan0a up
ip link add dev br-wan0b type bridge
ip link set dev br-wan0b up
## LAN side
ip link add dev br-lan0a type bridge
ip link set dev br-lan0a up
ip link add dev br-lan0b type bridge
ip link set dev br-lan0b up
#
'''
