#!/bin/bash

set -x ## Display commands
set -e ## Enable error check

make


if [ $# -eq 0 ]; then
    echo "No arguments provided. [c/s]"
    exit 1
fi

# Processing the first argument
case $1 in
    "s")
        sudo ./compress_proxy 
        # Add commands for routine 1 here
        ;;

    "c")
        sudo ./compress_proxy -a 192.168.200.12
        ;;

    *)
        echo "Invalid argument."
        exit 1
        ;;
esac


