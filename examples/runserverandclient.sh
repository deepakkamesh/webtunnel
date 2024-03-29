#!/bin/bash

# This is a simple script to quickly test the server and client code
# you need a remote host which will run the server
# the host running the script will run the client
# The server will create a loopback interface running with the IP
# 172.16.0.2 which is part of the default server route prefix.

# The server is started on a separate screen session
# also on the remote host another screen session is started with
# nc -l -k 172.16.0.2 4567
#

# On the client side once the vpn is established
# you can try to connect to 172.16.0.2 with telnet or nc
# and type anything and see if it gets shown on the server side

# Option parsing and default values
ssh_command="ssh"
scp_command="scp"
# those are for Debian/Ubuntu, RHEL may differ
ssl_cert="/etc/ssl/certs/ssl-cert-snakeoil.pem"
ssl_key="/etc/ssl/private/ssl-cert-snakeoil.key"

while getopts ":s:c:" opt; do
  case $opt in
    s) ssh_command="$OPTARG"
       ;;
    c) scp_command="$OPTARG"
       ;;
    t) ssl_cert="$OPTARG"
       ;;
    k) ssl_key="$OPTARG"
       ;;
    \?) echo "Invalid option: -$OPTARG" >&2
        exit 1
        ;;
    :) echo "Option -$OPTARG requires an argument." >&2
       exit 1
       ;;
  esac
done
shift $((OPTIND-1))  # Remove parsed options from arguments

remotehost=$1

function wait_for_command_success() {
    command="$1"  # The command to execute and wait for
    timeout=$2    # Timeout in seconds

    start_time=$(date +%s)

    while ! $command; do  # Note: we run the command directly here
        current_time=$(date +%s)
        if (( current_time - start_time >= timeout )); then
            echo "Error: Command timed out: $command"
            return 1  # Return an error code on timeout
        fi
        sleep 1
    done

    return 0  # Return success if the loop finishes normally
}

function setup_server() {
  go build servercli/server.go
  $scp_command server $remotehost:~/
  # you may need some time to ssh to the remote host to put your sudo password
  # so nc will start only 3 minutes later
  gnome-terminal -- bash -c "$ssh_command -t $remotehost \
    \"echo Server session; \
    sudo ./server -alsologtostderr -v 1 -httpsCertFile $ssl_cert \
    -httpsKeyFile $ssl_key\""
  gnome-terminal -- bash -c "$ssh_command -t $remotehost \
    \"echo Listener waiting...; sleep 45; echo Listening...; \
    sudo if config lo:1 172.16.0.2 netmask 255.255.255.252; \
    nc -l -k 172.16.0.2 4567\""

}

function setup_client() {
  go build webtunclient/webtunclient.go webtunclient/webtunclient_linux.go
  gnome-terminal -- bash -c "$ssh_command -t $remotehost -L33893:localhost:8811 \"echo SSH TUNNEL... press key to end;read -t 1800\""

  timeout=60  # Customize based on expected setup duration
  start_time=$(date +%s)
  # wait a bit for the tunnel to establish before attempting connection
  wait_for_command_success "nc -vz localhost 33893" 60

  ./webtunclient -alsologtostderr -v 1 -webtunServer localhost:33893 &
  sleep 15;
  sudo ifconfig tun0 192.168.0.2 netmask 255.255.255.0

  # wait for tun0 to be up
  wait_for_command_success "ip link show dev tun0" 60
  sudo route add 172.16.0.2 tun0
}

function main() {
    # Basic check for required argument
    if [[ -z "$1" ]]; then
        echo "Error: Please provide remote host as an argument."
        exit 1
    fi

    setup_server "$remotehost"
    setup_client

    echo "You have 300 seconds to press any key to stop the script. Otherwise, it will continue executing."

    if read -t 300; then
        echo "Key pressed. Script will stop."
        exit 0  # Exit successfully
    fi

    echo "Timeout reached. Script will exit."
    rm -f server
    rm -f webtunclient
}

main "$@"
