#!/bin/bash

set -x ## Display commands
set -e ## Enable error check


if [ $# -eq 0 ]; then
    echo "No arguments provided. [s/r]"
    exit 1
fi

HOSTNAME=$(uname -n)
if [[ "$HOSTNAME" == "rdstore" ]]; then
    PCI_ADDR="0c:00.1"
elif [[ "$HOSTNAME" == "deepl" ]]; then
    PCI_ADDR="83:00.1"
else
    echo "Hostname $HOSTNAME is unkown"
fi


case $1 in
    "s")
        ./buildx86/mpi_dpuoffload --pci-addr $PCI_ADDR --is-sender
        ;;

    "r")
        ./buildx86/mpi_dpuoffload --pci-addr $PCI_ADDR
        ;;

    *)
        echo "Invalid argument."
        exit 1
        ;;
esac
