#!/bin/bash

# NOTES: Run once to create session, then use session for final results!

PATH_TEMPLATE="./traffic_templates"
PATH_RESULTS="./traffic_results"

# Declare test files in order
declare -a testfiles=(
                      "ideal.test1.yaml"
                      "ideal.test2.yaml"
                      "ideal.test3.yaml"
                      "noise.test1.dns.1%.yaml"
                      "noise.test1.dns.5%.yaml"
                      "noise.test1.dns.10%.yaml"
                      "noise.test1.dns.20%.yaml"
                      "noise.test1.dns.50%.yaml"
                      "noise.test2.data.1%.yaml"
                      "noise.test2.data.5%.yaml"
                      "noise.test2.data.10%.yaml"
                      "noise.test2.data.20%.yaml"
                      "noise.test2.data.50%.yaml"
                      "noise.test3.dnsspoof.1%.yaml"
                      "noise.test3.dnsspoof.5%.yaml"
                      "noise.test3.dnsspoof.10%.yaml"
                      "noise.test3.dnsspoof.20%.yaml"
                      "noise.test3.dnsspoof.50%.yaml"
                      "noise.test4.dataspoof.1%.yaml"
                      "noise.test4.dataspoof.5%.yaml"
                      "noise.test4.dataspoof.10%.yaml"
                      "noise.test4.dataspoof.20%.yaml"
                      "noise.test4.dataspoof.50%.yaml"
                      )

echo "Initiating the execution of ${#testfiles[@]} test(s)!"
echo ""

## now loop through the above array
for TEST in "${testfiles[@]}"
do
    echo "### Processing test file <$TEST> ###"
    echo ""

    # Restart code in RealmGateway
    echo "> Starting RealmGateway!"
    nohup bash -c "lxc-attach -n gwa -- /home/ubuntu/run_gwa.demo.sh" &
    echo ">> Waiting 20 sec(s) to allow RealmGateway initialization..."
    sleep 20
    # Get current PID of RealmGateway
    RGW_PID=`/bin/ps -ef | grep "rgw.py" | grep "\-\-name gwa.demo" | grep -v "grep" | awk '{print $2}'`
    echo "> Running RealmGateway @ $RGW_PID"

    # Run test!
    echo "> Executing test <$TEST>"
    #lxc-attach -n router -- bash -c "cd /customer_edge_switching_v2/traffic_tests && LOG_LEVEL=WARNING python3 ./rgw_pbra_testsuite.py --config $PATH_TEMPLATE/$TEST               --results $PATH_RESULTS/${TEST:0:-5}"
    lxc-attach -n router -- bash -c "cd /customer_edge_switching_v2/traffic_tests && LOG_LEVEL=WARNING python3 ./rgw_pbra_testsuite.py --session $PATH_TEMPLATE/$TEST.session.json --results $PATH_RESULTS/${TEST:0:-5}"
    echo "> Terminated execution of test <$TEST>"
    echo ""
    echo "> Terminating RealmGateway @ $RGW_PID"
    kill -SIGTERM $RGW_PID
    sleep 10
    kill -SIGKILL $RGW_PID
    sleep 2
    echo ""
    echo ""
done
