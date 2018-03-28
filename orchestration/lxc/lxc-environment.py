#!/usr/bin/env python3

"""
BSD 3-Clause License

Copyright (c) 2018, Jesus Llorente Santos
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""

import logging
import lxc
import io
import os
import stat
import sys
import time
import yaml

# Export environmental variable for installing packages without user interaction
os.environ['DEBIAN_FRONTEND']='noninteractive'

# Define loglevel
#LOGLEVEL = logging.DEBUG
LOGLEVEL = logging.INFO
logging.basicConfig(level=LOGLEVEL)

# Define variables
SYSEXEC_BACKOFF = 0.25
LXC_CT_BASENAME = 'ctbase'
RESOURCE_PATH = './resources'
CONFIG_FILE   = './resources/config'
CTUSER='ubuntu'
CTPASSWORD='ubuntu'
# Define pre/post scripts
SCRIPT_PRE_UP='./resources/pre-up.sh'
SCRIPT_POST_DOWN='./resources/post-down.sh'

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


class LxcEnvironment(object):
    def __init__(self, ctbasename, configfile):
        self.logger = logging.getLogger()
        self.config = yaml.load(open(configfile, 'r'))
        self.ctbasename = ctbasename
        self.ct_clone = self._ct_clone_lib
        self.ct_start = self._ct_start_lib
        self.ct_stop = self._ct_stop_lib
        #self.ct_clone = self._ct_clone_exec
        #self.ct_start = self._ct_start_exec
        #self.ct_stop = self._ct_stop_exec

    def start(self):
        # Run pre-up script
        self._sysexec(SCRIPT_PRE_UP)
        ctbase = lxc.Container(self.ctbasename)
        if not ctbase.defined:
            self.logger.info('Create base container: {}'.format(self.ctbasename))
            self._create_ctbase(self.ctbasename)
            if False:
                self.logger.warning('Re-run script to create clones')
                sys.exit(0)

        self.logger.info('Base container found: {}'.format(self.ctbasename))
        # Make sure the container is stopped before cloning
        self.ct_stop(self.ctbasename)
        # Remove root container from the list of containers
        self.config.pop(self.ctbasename)
        # Clone new containers - The root container is no longer in the configuration
        for name, config in self.config.items():
            self._spawn_container(self.ctbasename, name, config)

    def load_config_container(self, name, filename):
        self.logger.debug('Loading configuration: {}'.format(name))
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
        self.logger.debug('Syncing rootfs: {}'.format(name))
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

    def fix_home_permissions(self, name):
        self.logger.debug('Fixing $HOME permissions: {}'.format(name))
        # Set recursive permissions to $HOME directory
        self.logger.debug('[{}] >> Fixing folder permissions {}'.format(name, os.path.dirname('/home/{}'.format(CTUSER))))
        command = '/usr/bin/lxc-attach -n {} -- /bin/chown -R {}:{} /home/{}'.format(name, CTUSER, CTUSER, CTUSER)
        self._sysexec(command, name)

    def fix_etc_hosts_file(self, name):
        self.logger.debug('Fixing /etx/hosts file: {}'.format(name))
        # Replace $LXC_CT_BASENAME with $HOSTNAME in /etc/hosts file
        self.logger.debug('[{}] >> Fixing /etc/hosts'.format(name))
        command = '/usr/bin/lxc-attach -n {} -- /bin/sed -i "s/{}/{}/g" /etc/hosts'.format(name, LXC_CT_BASENAME, name)
        #sed -i 's/ugly/beautiful/g' /home/bruno/old-friends/sue.txt
        self._sysexec(command, name)

    def _ct_clone_lib(self, src, dst):
        ct_src = lxc.Container(src)
        ct_dst = lxc.Container(dst)
        if ct_dst.defined:
            self.logger.warning('Destination clone already exists: {}'.format(dst))
            return
        # Clone base container with snapshot
        if not ct_src.clone(dst, flags=lxc.LXC_CLONE_SNAPSHOT):
            self.logger.warning('Failed to clone the container')
            sys.exit(1)

    def _ct_clone_exec(self, src, dst):
        ct_src = lxc.Container(src)
        ct_dst = lxc.Container(dst)
        if ct_dst.defined:
            self.logger.warning('Destination clone already exists: {}'.format(dst))
            return
        # Clone base container with snapshot
        command = 'lxc-copy -n {} -N {} -s -F'.format(src, dst) # Ubuntu 16.04
        self._sysexec(command, 'host')

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
        self._sysexec(command, 'host')

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
        self._sysexec(command, 'host')

    def ct_restart(self, name, verbose = False):
        self.ct_stop(name, verbose)
        self.ct_start(name, verbose)

    def ct_reload_services(self, name, verbose = False):
        ct = lxc.Container(name)
        self.logger.debug('Reload services: {}'.format(name))
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'daemon-reload'])

    def ct_enable_service(self, name, service, verbose = False):
        ct = lxc.Container(name)
        self.logger.info('Enable & Start service: {} - {}'.format(name, service))
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'daemon-reload'])
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'enable', service])
        ct.attach_wait(lxc.attach_run_command, ['systemctl', 'start', service])

    def ct_disable_service(self, name, service, verbose = False):
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
        # Get file's permissions
        fmode = os.stat(src).st_mode
        fmode_str = stat.filemode(fmode)
        fmode_chmod = oct(fmode)[-3:]
        # Create directory
        self.logger.debug('[{}] >> Creating directory {} ...'.format(name, os.path.dirname(dst)))
        command = '/usr/bin/lxc-attach -n {} -- /bin/mkdir -p -m {} {}'.format(name, '755', os.path.dirname(dst))
        self._sysexec(command, name)
        # Create file - Delete existing file to avoid problem with symbolic links
        self.logger.info('[{}] >> Copying {}'.format(name, dst))
        command = '/bin/cat {} | /usr/bin/lxc-attach -n {} -- /bin/rm -f {}'.format(src, name, dst)
        self._sysexec(command, name)
        command = '/bin/cat {} | /usr/bin/lxc-attach -n {} -- /bin/bash -c "/bin/cat > {}"'.format(src, name, dst)
        self._sysexec(command, name)
        # Set permissions to file
        self.logger.debug('[{}] >> Setting file permissions {}'.format(name, os.path.dirname(dst)))
        command = '/usr/bin/lxc-attach -n {} -- /bin/chmod {} {}'.format(name, fmode_chmod, dst)
        self._sysexec(command, name)

    def ct_apt_install(self, name, pkgs):
        if not len(pkgs):
            self.logger.info('Skipping installation of apt packages: {}'.format(name))
            return
        ct = lxc.Container(name)
        self.logger.info('Install packages via apt: {} - {}'.format(name, pkgs))
        command = '/usr/bin/lxc-attach -n {} -- bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -y {}"'.format(name, ' '.join(_ for _ in pkgs))
        self._sysexec(command, name)

    def ct_pip3_install(self, name, pkgs):
        if not len(pkgs):
            self.logger.info('Skipping installation of pip3 packages: {}'.format(name))
            return
        ct = lxc.Container(name)
        self.logger.info('Install packages via pip3: {} - {}'.format(name, pkgs))
        # Install python3-pip
        command = '/usr/bin/lxc-attach -n {} -- bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip"'.format(name)
        self._sysexec(command, name)
        # Upgrade pip and install setuptools
        command = '/usr/bin/lxc-attach -n {} -- bash -c "pip3 install --upgrade pip setuptools"'.format(name)
        self._sysexec(command, name)
        # Install pip3 packages
        command = '/usr/bin/lxc-attach -n {} -- bash -c "pip3 install {}"'.format(name, ' '.join(_ for _ in pkgs))
        self._sysexec(command, name)


    def _create_ctbase(self, name, verbose = False):
        ctbase = lxc.Container(name)
        config = self.config[name]
        self.logger.debug(config)

        # Set verbose level
        verbosity = 1
        if not verbose:
            verbosity = lxc.LXC_CREATE_QUIET
        # Create the container rootfs
        if not ctbase.create('ubuntu', verbosity, {'user': CTUSER, 'password': CTPASSWORD, 'packages': ','.join(p for p in config.setdefault('apt_packages',[]))}):
            self.logger.error('Failed to create the container rootfs {}'.format(name))
            sys.exit(1)

        # HACK - APPARMOR issues with kernel feature
        if True:
            ctbase.append_config_item('lxc.aa_allow_incomplete', '1')
            ctbase.save_config()

        # Start the container
        self.ct_start(name)
        # Sync container rootfs
        self.sync_rootfs_container(name, os.path.join(RESOURCE_PATH, config['rootfs']))
        self.fix_home_permissions(name)

        # Install apt packages
        self.ct_apt_install(name, config.setdefault('apt_packages', []))
        # Install pip3 packages
        self.ct_pip3_install(name, config.setdefault('pip3_packages', []))

        # Reload services
        self.ct_reload_services(name)
        # Enable services in container
        for service in config.setdefault('enabled_services',[]):
            self.ct_enable_service(name, service)
        # Disable services in container
        for service in config.setdefault('disabled_services', []):
            self.ct_disable_service(name, service)
        # Stop the container
        self.ct_stop(name)
        # Clear all network configuration
        ctbase = lxc.Container(name)
        ctbase.clear_config_item('lxc.network')
        ctbase.save_config()
        # Overwrite container configuration
        #self.load_config_container(name, os.path.join(RESOURCE_PATH, config['config']))

    def _spawn_container(self, base, name, config):
        try:
            ct = lxc.Container(name)
            self.logger.info('Cloning {} to {}'.format(base, name))
            self.logger.debug(config)

            if not ct.defined:
                self.ct_clone(base, name)
                self.load_config_container(name, os.path.join(RESOURCE_PATH, config['config']))
            else:
                self.logger.warning('Container already exists: {}'.format(name))

            self.ct_start(name)
            self.sync_rootfs_container(name, os.path.join(RESOURCE_PATH, config['rootfs']))
            self.fix_home_permissions(name)
            self.fix_etc_hosts_file(name)

            # Install apt packages
            self.ct_apt_install(name, config.setdefault('apt_packages', []))
            # Install pip3 packages
            self.ct_pip3_install(name, config.setdefault('pip3_packages', []))

            self.ct_reload_services(name)
            for service in config.setdefault('enabled_services', []):
                self.ct_enable_service(name, service)
            for service in config.setdefault('disabled_services', []):
                self.ct_disable_service(name, service)
            self.ct_restart(name)

        except FileNotFoundError as e:
            self.logger.warning(format(e))

    def _sysexec(self, command, name=''):
        self.logger.debug('_sysexec: @{}# {}'.format(command, name))
        try:
            time.sleep(SYSEXEC_BACKOFF)
            lxc.subprocess.check_call(command, shell=True)
        except Exception as e:
            self.logger.error('_sysexec: {}'.format(e))

if __name__ == '__main__':
    obj = LxcEnvironment(LXC_CT_BASENAME, CONFIG_FILE)
    obj.start()
