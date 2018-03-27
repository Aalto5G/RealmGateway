#!/bin/bash

echo "Mount folder in containers"

# Mount folder in containers
for CT_NAME in router public gwa gwb nest_gwa nest_gwb; do
  ssh -A -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -A ubuntu@${CT_NAME} "sudo -E ./mount_ces_folder_at_host.sh" &
done


secs=10
while [ $secs -gt 0 ]; do
   echo -ne "Waiting $secs seconds before starting tmux session\033[0K\r"
   sleep 1
   : $((secs--))
done

#echo ""
#echo "Waiting 10 seconds before starting tmux session"
#echo ""
#sleep 10

# Create new session and configure first window for gwa.demo
tmux new-session -d -s rgw_dev -n background

## Split window
tmux split-window -v -p 66
tmux split-window -v -p 50

### Access panes and run commands
tmux select-pane -t 1
tmux send-keys 'cd ./suricata' Enter
tmux send-keys './log.py' Enter
tmux select-pane -t 2
tmux send-keys 'cd ./suricata' Enter
tmux send-keys 'sudo -E ./suricatalive.sh' Enter

sleep 1

# Create new window for gwa.demo
tmux new-window -n gwa.demo

## Split window
tmux split-window -v -p 75
tmux split-window -v -p 66
tmux split-window -v -p 50
tmux split-window -h -p 50

### Access panes and run commands
tmux select-pane -t 0
tmux send-keys 'sshq -A gwa' Enter
tmux select-pane -t 1
tmux send-keys 'sshq -A proxya' Enter
tmux select-pane -t 2
tmux send-keys 'sshq -A nest_gwa' Enter
tmux select-pane -t 3
tmux send-keys 'sshq -A public' Enter
tmux select-pane -t 4
tmux send-keys 'sshq -A test_ngwa' Enter

tmux select-pane -t 0
tmux send-keys 'sudo -E ./run_gwa.demo.sh' Enter
tmux select-pane -t 1
tmux send-keys 'sudo journalctl -f -n 10 -u synproxy_netmap' Enter
tmux select-pane -t 2
tmux send-keys 'sudo -E ./run_nest.gwa.demo.sh' Enter
tmux select-pane -t 3
tmux send-keys 'cd /customer_edge_switching_v2/scripts' Enter
tmux send-keys 'ping test.nest.gwa.demo'
tmux select-pane -t 4
tmux send-keys 'iperf -s' Enter

### Select pane 3 // public
tmux select-pane -t 3

sleep 1

# Create new window for gwb.demo
tmux new-window -n gwb.demo

## Split window
tmux split-window -v -p 75
tmux split-window -v -p 66
tmux split-window -v -p 50
tmux split-window -h -p 50

### Access panes and run commands
tmux select-pane -t 0
tmux send-keys 'sshq -A gwb' Enter
tmux select-pane -t 1
tmux send-keys 'sshq -A proxyb' Enter
tmux select-pane -t 2
tmux send-keys 'sshq -A nest_gwb' Enter
tmux select-pane -t 3
tmux send-keys 'sshq -A public' Enter
tmux select-pane -t 4
tmux send-keys 'sshq -A test_ngwb' Enter

tmux select-pane -t 0
tmux send-keys 'sudo -E ./run_gwb.demo.sh' Enter
tmux select-pane -t 1
tmux send-keys 'sudo journalctl -f -n 10 -u synproxy_kernel' Enter
tmux select-pane -t 2
tmux send-keys 'sudo -E ./run_nest.gwb.demo.sh' Enter
tmux select-pane -t 3
tmux send-keys 'ping test.nest.gwb.demo'
tmux select-pane -t 4
tmux send-keys 'iperf -s' Enter

### Select pane 3 // public
tmux select-pane -t 3

sleep 1

# Create new window for synproxy
tmux new-window -n synproxy

## Split window
tmux split-window -h -p 50
### Select pane 0
tmux select-pane -t 0
tmux split-window -v -p 66
tmux split-window -v -p 50
### Select pane 3
tmux select-pane -t 3
tmux split-window -v -p 66
tmux split-window -v -p 50

### Access panes and run commands
### Left side
tmux select-pane -t 0
tmux send-keys 'sshq -A router' Enter
tmux select-pane -t 1
tmux send-keys 'sshq -A proxya' Enter
tmux select-pane -t 2
tmux send-keys 'sshq -A gwa' Enter
### Right side
tmux select-pane -t 3
tmux send-keys 'sshq -A router' Enter
tmux select-pane -t 4
tmux send-keys 'sshq -A proxyb' Enter
tmux select-pane -t 5
tmux send-keys 'sshq -A gwb' Enter

sleep 1

### Input commands in panes
### Left side
tmux select-pane -t 0
tmux send-keys 'cd /customer_edge_switching_v2/traffic_tests && LOG_LEVEL=WARNING sudo -E ./rgw_pbra_testsuite.py --config ./traffic_templates/synproxy_1_subnet.gwa.yaml'
tmux select-pane -t 1
tmux send-keys 'sudo journalctl -f -n 10 -u synproxy_netmap' Enter
tmux select-pane -t 2
tmux send-keys 'cd /customer_edge_switching_v2/traffic_tests && sudo -E ./run_async_echoserver_gwa.sh' Enter
### Right side
tmux select-pane -t 3
tmux send-keys 'cd /customer_edge_switching_v2/traffic_tests && LOG_LEVEL=WARNING sudo -E ./rgw_pbra_testsuite.py --config ./traffic_templates/synproxy_1_subnet.gwb.yaml'
tmux select-pane -t 4
tmux send-keys 'sudo watch -n1 iptables -t raw -L PREROUTING -nv' Enter
tmux select-pane -t 5
tmux send-keys 'cd /customer_edge_switching_v2/traffic_tests && sudo -E ./run_async_echoserver_gwb.sh' Enter


# Select window background and pane 2
tmux select-window -t 0
tmux select-pane -t 2


# Attach to session
tmux -2 attach-session -d
