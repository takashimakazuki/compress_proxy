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
        sudo ./compress_proxy ${@:2}
        ;;

    "c")
        sudo ./compress_proxy -a 192.168.200.12 ${@:2}
        ;;

    *)
        echo "Invalid argument."
        exit 1
        ;;
esac

