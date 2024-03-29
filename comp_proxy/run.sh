#!/bin/bash

set -x ## Display commands
set -e ## Enable error check


if [ $# -eq 0 ]; then
    echo "No arguments provided. [c/s]"
    exit 1
fi

export UCX_TCP_CM_REUSEADDR=y
export UCX_NET_DEVICES=enp3s0f1s0

LOG_LEVEL=40
case $1 in
    "s")
        # rdstore-bf
        ./buildarm/compress_proxy --log-level $LOG_LEVEL -r 0c:00.1 -p 03:00.1
        ;;

    "c") # deepl-bf
        ./buildarm/compress_proxy --log-level $LOG_LEVEL -a 192.168.200.13 -r 83:00.1 -p 03:00.1
        ;;

    *)
        echo "Invalid argument."
        exit 1
        ;;
esac


