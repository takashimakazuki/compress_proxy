#!/bin/bash

set -x ## Display commands
set -e ## Enable error check

make


if [ $# -eq 0 ]; then
    echo "No arguments provided. [c/s]"
    exit 1
fi

case $1 in
    "s")
        make clean
        make cc_server
        ./cc_server
        ;;

    "c")
        make clean
        make cc_client
        ./cc_client
        ;;

    *)
        echo "Invalid argument."
        exit 1
        ;;
esac


