import os
import sys
import logging
import yaml

import time
import stat
import lxc

#LOGLEVEL = logging.DEBUG
LOGLEVEL = logging.INFO
logging.basicConfig(level=LOGLEVEL)


LXC_CT_BASE = 'ctbase'
#CONFIG_PATH = '/home/llorenj1/workspace/gitlab/customer_edge_switching_v2/LXC'
CONFIG_PATH = './'
CONFIG_FILE = 'config'
ROOTFS_PATH = 'rootfs'

USER='ubuntu'
PASSWORD='ubuntu'

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
        self.config = yaml.load(open(configfile, 'r'))
        #self.configfile = configfile
        self.ctbasename = ctbasename

        #self.ct_clone = self._ct_clone_lib
        self.ct_start = self._ct_start_lib
        self.ct_stop = self._ct_stop_lib
        self.ct_clone = self._ct_clone_exec
        #self.ct_start = self._ct_start_exec
        #self.ct_stop = self._ct_stop_exec

    def start(self):
        ctbase = lxc.Container(self.ctbasename)
        if not ctbase.defined:
            self.logger.info('Create base container: {}'.format(self.ctbasename))
            self._create_ctbase(self.ctbasename)
            if 1:
                self.logger.warning('Re-run script to create clones')
                sys.exit(0)

        self.logger.info('Base container found: {}'.format(self.ctbasename))
        # Make sure the container is stopped before cloning
        self.ct_stop(self.ctbasename)
        # Remove root container from configuration
        self.config.pop(self.ctbasename)

        # Clone new containers
        '''
        #filename = os.path.join(CONFIG_PATH, CONFIG_FILE)
        filename = self.configfile
        with open(filename, 'r') as config:
            time.sleep(0.3)
            for line in config:
                #Sanitize values
                if not sanitize_line(line):
                    continue
                #Sanitize and clone container
                ctname = line.strip()
                self._spawn_container(ctname)
        '''
        # The root container is no longer in the configuration
        for name, config in self.config.items():
            self._spawn_container(self.ctbasename, name, config)


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
        command = 'lxc-copy -n {} -N {} -s -F'.format(src, dst) # Ubuntu 16.04
        #command = 'lxc-clone -s {} {}'.format(src, dst) # Ubuntu 15.10
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

    def ct_enable_service(self, name, service):
        ct = lxc.Container(name)
        self.logger.info('Enable & Start service: {} - {}'.format(name, service))
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'enable', service])
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'start', service])

    def ct_disable_service(self, name, service):
        ct = lxc.Container(name)
        self.logger.info('Disable & Stop service: {} - {}'.format(name, service))
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'disable', service])
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'stop', service])

    def ct_stats(self, name):
        ct = lxc.Container(name)
        self.logger.info('Container {} state: {}'.format(name, ct.state))
        self.logger.info('Container {} PID:   {}'.format(name, ct.init_pid))

    def ct_sync_file(self, name, src, dst):
        # Create base directory
        ct = lxc.Container(name)
        #print('mkdir -p {}'.format(os.path.dirname(dst)))
        #ct.attach_wait(lxc.attach_run_command, ['mkdir', '-p', os.path.dirname(dst)])
        # Get file's permissions
        fmode = os.stat(src).st_mode
        fmode_str = stat.filemode(fmode)
        fmode_chmod = oct(fmode)[-3:]
        # Create directory
        command = '/usr/bin/lxc-attach -n {} -- /bin/mkdir -p -m 755 {}'.format(name, os.path.dirname(dst))
        self.logger.info('[{}] >> Creating directory {} ...'.format(name, os.path.dirname(dst)))
        self.logger.debug('sysexec: {}'.format(command))
        time.sleep(0.3)
        lxc.subprocess.check_call(command, shell=True)
        # Create file
        command = '/bin/cat {} | /usr/bin/lxc-attach -n {} -- /bin/bash -c "/bin/cat > {}"'.format(src, name, dst)
        self.logger.info('[{}] >> Copying {} {} ...'.format(name, dst, fmode_str))
        self.logger.debug('sysexec: {}'.format(command))
        time.sleep(0.3)
        lxc.subprocess.check_call(command, shell=True)
        '''
        try:
            lxc.subprocess.check_call(command, shell=True)
        except Exception as e:
            self.logger.error('\n###\nFailed to copy a file {}: {}\n###\n'.format(dst, e))
        '''
        # Set file permissions
        #ct.attach_wait(lxc.attach_run_command, ['chmod', fmode_chmod, dst])
        # Set permissions to file
        command = '/usr/bin/lxc-attach -n {} -- /bin/chmod {} {}'.format(name, fmode_chmod, dst)
        self.logger.info('[{}] >> Setting file permissions {} ...'.format(name, os.path.dirname(dst)))
        self.logger.debug('sysexec: {}'.format(command))
        time.sleep(0.3)
        lxc.subprocess.check_call(command, shell=True)


    def _create_ctbase(self, name):
        ctbase = lxc.Container(name)
        config = self.config[name]
        print(config)

        # Create the container rootfs
        verbosity = 0
        #verbosity = lxc.LXC_CREATE_QUIET
        if not ctbase.create('ubuntu', verbosity, {'user': USER, 'password': PASSWORD, 'packages': ','.join(p for p in config.setdefault('packages',[]))}):
            self.logger.error('Failed to create the container rootfs {}'.format(name))
            sys.exit(1)

        # HACK - APPARMOR issues with kernel feature
        if True:
            ctbase.append_config_item('lxc.aa_allow_incomplete', '1')
            ctbase.save_config()

        # Start the container
        self.ct_start(name)
        # Enable services in container
        for service in config.setdefault('enabled_services',[]):
            self.ct_enable_service(name, service)
        # Disable services in container
        for service in config.setdefault('disabled_services', []):
            self.ct_disable_service(name, service)
        # Sync container rootfs
        self.sync_rootfs_container(name, os.path.join(CONFIG_PATH, config['rootfs']))
        # Overwrite interfaces file
        #self.ct_sync_file(name, 'interfaces.default', '/etc/network/interfaces')
        # Stop the container
        self.ct_stop(name)
        # Clear all network configuration
        #ctbase = lxc.Container(name)
        ctbase.clear_config_item('lxc.network')
        ctbase.save_config()
        # Overwrite container configuration
        #self.load_config_container(name, os.path.join(CONFIG_PATH, config['config']))

    def _spawn_container(self, base, name, config):
        try:
            ct = lxc.Container(name)
            self.logger.info('Cloning {} to {}'.format(base, name))
            print(config)
            if not ct.defined:
                # Clone LXC_CT_BASE with snapshot
                self.ct_clone(base, name)
                # Load container configuration
                self.load_config_container(name, os.path.join(CONFIG_PATH, config['config']))
            else:
                self.logger.warning('Container already exists: {}'.format(name))
            # Start the container
            self.ct_start(name)
            # Enable services in container
            for service in config.setdefault('enabled_services', []):
                self.ct_enable_service(name, service)
            # Disable services in container
            for service in config.setdefault('disabled_services', []):
                self.ct_disable_service(name, service)
            # Sync container rootfs
            self.sync_rootfs_container(name, os.path.join(CONFIG_PATH, config['rootfs']))
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

find ctbase/rootfs/ -type d -exec chmod 775 {} \;
find gwa/rootfs/    -type d -exec chmod 775 {} \;
find gwb/rootfs/    -type d -exec chmod 775 {} \;
find hosta/rootfs/  -type d -exec chmod 775 {} \;
find hostb/rootfs/  -type d -exec chmod 775 {} \;
find proxya/rootfs/ -type d -exec chmod 775 {} \;
find proxyb/rootfs/ -type d -exec chmod 775 {} \;
find public/rootfs/ -type d -exec chmod 775 {} \;
find router/rootfs/ -type d -exec chmod 775 {} \;

find ctbase/rootfs/ -type f -exec chmod 664 {} \;
find gwa/rootfs/    -type f -exec chmod 664 {} \;
find gwb/rootfs/    -type f -exec chmod 664 {} \;
find hosta/rootfs/  -type f -exec chmod 664 {} \;
find hostb/rootfs/  -type f -exec chmod 664 {} \;
find proxya/rootfs/ -type f -exec chmod 664 {} \;
find proxyb/rootfs/ -type f -exec chmod 664 {} \;
find public/rootfs/ -type f -exec chmod 664 {} \;
find router/rootfs/ -type f -exec chmod 664 {} \;

chmod 775 proxya/rootfs/ipt_synproxy.sh
chmod 775 proxyb/rootfs/ipt_synproxy.sh

'''
