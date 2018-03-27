#!/bin/bash

echo "Mount folder in containers"

# Mount folder in containers
for CT_NAME in gwa nest_gwa; do
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

# Create new session and configure first window for gwa.cesproto.re2ee.org
tmux new-session -d -s rgw_dev -n gwa.cesproto.re2ee.org

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
tmux select-pane -t 4
tmux send-keys 'sshq -A test_ngwa' Enter

tmux select-pane -t 0
tmux send-keys 'sudo -E ./run_gwa.cesproto.re2ee.org.sh' Enter
tmux select-pane -t 1
tmux send-keys 'sudo journalctl -f -n 10 -u synproxy_kernel' Enter
tmux select-pane -t 2
tmux send-keys 'sudo -E ./run_nest.gwa.cesproto.re2ee.org.sh' Enter
tmux select-pane -t 3
tmux send-keys 'ping test.nest.gwa.cesproto.re2ee.org'
tmux select-pane -t 4
tmux send-keys 'iperf -s' Enter

### Select pane 3
tmux select-pane -t 3


# Attach to session
tmux -2 attach-session -d
