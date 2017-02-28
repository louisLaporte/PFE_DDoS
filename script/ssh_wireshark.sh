#!/bin/bash - 
#===============================================================================
#
#          FILE: ssh_wireshark.sh
# 
#         USAGE: ./ssh_wireshark.sh 
# 
#   DESCRIPTION: launch wireshark from remote 
# 
#       OPTIONS: [HOST@IP]
#  REQUIREMENTS: wireshark on local machine and tcpdump on remote
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Louis Laporte, 
#  ORGANIZATION: 
#       CREATED: 02/25/2017 19:20
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error

usage()
{
    echo "$0 test@127.0.0.1"
}
if [ $# -ne 1 ];
then
    echo "You must specify"
    usage
    exit
fi

ssh $1 "sudo /usr/sbin/tcpdump -s0 -w - 'port 8080'" | wireshark -k -i -


