#!/bin/bash

# 1. Create the session files in a dry-run manner
# 2. Run basic tests and collect results
# 3. Run compound tests adding noise to a previous session and collect results


PATH_TEMPLATE="./traffic_templates"
PATH_RESULTS="./traffic_results"


####################################################################################################
# Create basic session tests                                                                       #
####################################################################################################

# Declare test files in order
declare -a configfiles=(
                        "ideal.test1.yaml"
                        "ideal.test2.yaml"
                        "ideal.test3.yaml"
                        "noise.test1.dns.1%.yaml"
                        "noise.test1.dns.5%.yaml"
                        "noise.test1.dns.10%.yaml"
                        "noise.test1.dns.20%.yaml"
                        "noise.test1.dns.50%.yaml"
                        "noise.test1b.dns.1%.yaml"
                        "noise.test1b.dns.5%.yaml"
                        "noise.test1b.dns.10%.yaml"
                        "noise.test1b.dns.20%.yaml"
                        "noise.test1b.dns.50%.yaml"
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

# Uncomment next line if session files are already created
declare -a configfiles=()

echo "Initiating dry-run execution of ${#configfiles[@]} test(s) to generate session files"
echo ""

## loop through the configfiles array to generate session files
for TEST in "${configfiles[@]}"
do
    echo "### Processing test file <$TEST> ###"
    echo ""

    # Run test!
    echo "> Executing test <$TEST> in dry-mode"
    # Run this to generate session files out of config
    lxc-attach -n router -- bash -c "cd /customer_edge_switching_v2/traffic_tests && LOG_LEVEL=WARNING python3 ./rgw_pbra_testsuite.py --config $PATH_TEMPLATE/$TEST --session-name $PATH_TEMPLATE/${TEST:0:-5}.session.json --dry-run"

    echo "> Terminated execution of test <$TEST>"
    echo ""
    echo ""
done



####################################################################################################
# Execute ideal tests                                                                              #
####################################################################################################

# Declare test files in order
declare -a sessionfiles=(
                         "ideal.test1.session.json"
                         "ideal.test2.session.json"
                         "ideal.test3.session.json"
                         )

# Uncomment next line if basic tests have already run
#declare -a sessionfiles=()

echo "Initiating execution of ${#sessionfiles[@]} basic test(s) from session files"
echo ""

## loop through the sessionfiles array to execute session files
for TEST in "${sessionfiles[@]}"
do
    echo "### Processing basic test file <$TEST> ###"
    echo ""

    # Restart code in RealmGateway
    echo "> Starting RealmGateway!"
    nohup bash -c "lxc-attach -n gwa -- /home/ubuntu/run_gwa.demo.sh" &
    echo ">> Waiting 10 sec(s) to allow RealmGateway initialization..."
    sleep 10
    # Get current PID of RealmGateway
    RGW_PID=`/bin/ps -ef | grep "rgw.py" | grep "\-\-name gwa.demo" | grep -v "grep" | awk '{print $2}'`
    echo "> Running RealmGateway @ $RGW_PID"

    # Run test!
    echo "> Executing test <$TEST>"
    # Run this to execute session files out of config
    lxc-attach -n router -- bash -c "cd /customer_edge_switching_v2/traffic_tests && LOG_LEVEL=WARNING python3 ./rgw_pbra_testsuite.py --session $PATH_TEMPLATE/$TEST --results $PATH_RESULTS/${TEST:0:-5}"

    echo "> Terminated execution of test <$TEST>"
    echo ""
    echo "> Terminating RealmGateway @ $RGW_PID"
    kill -SIGTERM $RGW_PID
    sleep 8
    kill -SIGKILL $RGW_PID
    sleep 2
    echo ""
    echo ""
done


####################################################################################################
# Execute compound noisy tests                                                                     #
####################################################################################################

# Declare test files in order
declare -a sessionfiles=(
                         "noise.test1.dns.1%.session.json"
                         "noise.test1.dns.5%.session.json"
                         "noise.test1.dns.10%.session.json"
                         "noise.test1.dns.20%.session.json"
                         "noise.test1.dns.50%.session.json"
                         "noise.test1b.dns.1%.session.json"
                         "noise.test1b.dns.5%.session.json"
                         "noise.test1b.dns.10%.session.json"
                         "noise.test1b.dns.20%.session.json"
                         "noise.test1b.dns.50%.session.json"
                         "noise.test2.data.1%.session.json"
                         "noise.test2.data.5%.session.json"
                         "noise.test2.data.10%.session.json"
                         "noise.test2.data.20%.session.json"
                         "noise.test2.data.50%.session.json"
                         "noise.test3.dnsspoof.1%.session.json"
                         "noise.test3.dnsspoof.5%.session.json"
                         "noise.test3.dnsspoof.10%.session.json"
                         "noise.test3.dnsspoof.20%.session.json"
                         "noise.test3.dnsspoof.50%.session.json"
                         "noise.test4.dataspoof.1%.session.json"
                         "noise.test4.dataspoof.5%.session.json"
                         "noise.test4.dataspoof.10%.session.json"
                         "noise.test4.dataspoof.20%.session.json"
                         "noise.test4.dataspoof.50%.session.json"
                         )

echo "Initiating execution of ${#sessionfiles[@]} compound test(s) from session files"
echo ""

# Define the test base session to add the noise
BASE_SESSION="ideal.test2.session.json"

## loop through the sessionfiles array to execute session files
for TEST in "${sessionfiles[@]}"
do
    echo "### Processing compound test file <$TEST> ###"
    echo ""

    # Restart code in RealmGateway
    echo "> Starting RealmGateway!"
    nohup bash -c "lxc-attach -n gwa -- /home/ubuntu/run_gwa.demo.sh" &
    echo ">> Waiting 10 sec(s) to allow RealmGateway initialization..."
    sleep 10
    # Get current PID of RealmGateway
    RGW_PID=`/bin/ps -ef | grep "rgw.py" | grep "\-\-name gwa.demo" | grep -v "grep" | awk '{print $2}'`
    echo "> Running RealmGateway @ $RGW_PID"

    # Run test!
    echo "> Executing test <$TEST>"
    # Run this to execute session files out of config
    lxc-attach -n router -- bash -c "cd /customer_edge_switching_v2/traffic_tests && LOG_LEVEL=WARNING python3 ./rgw_pbra_testsuite.py --session $PATH_TEMPLATE/$BASE_SESSION $PATH_TEMPLATE/$TEST --results $PATH_RESULTS/${TEST:0:-5}"

    echo "> Terminated execution of test <$TEST>"
    echo ""
    echo "> Terminating RealmGateway @ $RGW_PID"
    kill -SIGTERM $RGW_PID
    sleep 8
    kill -SIGKILL $RGW_PID
    sleep 2
    echo ""
    echo ""
done
