#!/bin/bash

set -x ## Display commands
set -e ## Enable error check



if [ $# -eq 0 ]; then
    echo "No arguments provided. [c/s]"
    exit 1
fi

case $1 in
    "s")
        ./cc_server
        ;;

    "c")
        ./build/cc_client
        ;;

    *)
        echo "Invalid argument."
        exit 1
        ;;
esac


