import os
import lxc


LXC_CT_BASE = 'ctbase'
CONFIG_PATH = '/home/llorenj1/workspace/gitlab/customer_edge_switching_v2/LXC'
CONFIG_FILE = 'config'
ROOTFS_PATH = 'rootfs'
CWD = os.getcwd()

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

def load_config_container(ct_obj, filename):
    print('Loading configuration for: {}'.format(ct_obj.name))
    with open(filename, 'r', encoding='utf-8') as infile:
        for line in infile:
            #Sanitize values
            if not sanitize_line(line, token='='):
                continue
            k,v = get_key_value(line)
            #print('Adding attribute to: {} - {} / {}'.format(ct_obj.name, k, v))
            ct_obj.append_config_item(k, v)
        ct_obj.save_config()

def sync_rootfs_container(ct_obj, path):
    print('Syncing rootfs for: {} @ {}'.format(ct_obj.name, path))
    os.chdir(path)
    for root, dirs, files in os.walk("."):
        #print('CURRENT PATH ', os.getcwd())
        #print((root, dirs, files))
        # Create directory in container rootfs
        if root[1:] != '':
            print('{}# mkdir -p {}'.format(ct_obj.name, root[1:]))
            ct_obj.attach_wait(lxc.attach_run_command, ["mkdir", "-p", root[1:]])

        for file in files:
            # Make absolute file in host
            _file = os.path.join(os.getcwd(), root, file)
            # Make absolute path in container
            ct_file = os.path.join(root, file)[1:]
            #print('{}# sync {} -> {}'.format(ct_obj.name, _file, ct_file))
            #cat eth0.dhcp | lxc-attach -n router -- /bin/sh -c "/bin/cat >> /etc/network/interfaces"
            command = 'cat {} | lxc-attach -n {} -- /bin/sh -c "/bin/cat >> {}"'.format(_file, ct_obj.name, ct_file)
            print(command)
            #lxc.subprocess.check_call([command, args])

def ct_start(ct_obj):
    ## Starting the container
    print("Starting the container {}".format(ct_obj.name))
    ct_obj.start()
    ct_obj.wait("RUNNING", 3)
    
    # A few basic checks of the current state
    assert(ct_obj.init_pid > 1)
    assert(ct_obj.running)
    assert(ct_obj.state == "RUNNING")

def ct_stop(ct_obj):
    ## Shutting down the container
    print("Shutting down the container {}".format(ct_obj.name))
    if not ct_obj.shutdown(3):
        ct_obj.stop()
    
    if ct_obj.running:
        print("Stopping the container {}".format(ct_obj.name))
        ct_obj.stop()
        ct_obj.wait("STOPPED", 3)
    
    # A few basic checks of the current state
    assert(ct_obj.init_pid == -1)
    assert(not ct_obj.running)
    assert(ct_obj.state == "STOPPED")


#Clone new containers
ctbase = lxc.Container(LXC_CT_BASE)
filename = os.path.join(CONFIG_PATH, CONFIG_FILE)
with open(filename, 'r', encoding='utf-8') as main_config:
    for line in main_config:
        #Sanitize values
        if not sanitize_line(line):
            continue
        c_name = line.strip()
        print('Read {}'.format(c_name))
        # Get container object
        ct_obj = lxc.Container(c_name)
        if ct_obj.defined:
            print('Container already exists: {}'.format(c_name))
            continue

        # Clone LXC_CT_BASE with snapshot
        ctbase.clone(c_name, flags=lxc.LXC_CLONE_SNAPSHOT)
        # Load container configuration
        load_config_container(ct_obj, os.path.join(CONFIG_PATH, c_name, CONFIG_FILE))
        # Start container
        ct_start(ct_obj)
        # Sync container rootfs
        sync_rootfs_container(ct_obj, os.path.join(CONFIG_PATH, c_name, ROOTFS_PATH))
        # Stop the container
        #ct_stop(ct_obj)




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