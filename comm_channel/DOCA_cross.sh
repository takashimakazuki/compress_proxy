#!/bin/bash

#
# Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

#############################Setting variables#################################
doca_apps="/opt/mellanox/doca/applications"
meson_version=$(meson --version)
linaro_dir="/opt/gcc-linaro"
tar_file="gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu"
latest="latest-7"
linaro_path="https://releases.linaro.org/components/toolchain/binaries/$latest/aarch64-linux-gnu/$tar_file.tar.xz"
arm_directories="/doca_devel/arm_directories.txt"
cross_file_name="arm64_armv8_linux_gcc"
ARC=$(uname -mrs | cut -d " " -f 3)
###############################################################################

# From within the container - Create the directories and copy the depencdencies:
if [[ "${ARC}" == *"aarch64"* ]];
then
    echo "Running from within the QEMU-emulated DOCA Development Arm Container"

    # Create the needed directories
    while IFS= read -r line
    do
        printf '%s\n' "Creating $line"
        mkdir -p $line 

    done <"$arm_directories"

    # Copy DOCA itself - Includes & Libraries
    cp -r /opt/mellanox/doca/include opt/mellanox/doca
    cp -r /opt/mellanox/doca/lib opt/mellanox/doca
    # Copy the dependencies - Includes
    cp -r /usr/include/bsd usr/include
    cp -r /usr/include/json-c usr/include
    cp -r /usr/include/ucp usr/include/
    cp -r /usr/include/ucm usr/include/
    cp -r /usr/include/ucs usr/include/
    cp -r /usr/include/uct usr/include/
    cp -r /usr/include/glib-2.0 usr/include/
    cp -r /usr/include/gio-unix-2.0 usr/include/
    # Copy the dependencies - Libraries
    cp -r /lib/aarch64-linux-gnu/libbsd* usr/lib/aarch64-linux-gnu/
    cp -r /lib/aarch64-linux-gnu/libjson-c* usr/lib/aarch64-linux-gnu/
    cp -r /lib/aarch64-linux-gnu/glib-2.0/include usr/lib/aarch64-linux-gnu/glib-2.0/
    cp -r /lib/libuc*.so* usr/lib/
    cp -r /lib/ucx usr/lib/
    cp -r /lib/aarch64-linux-gnu/libg*.so* usr/lib/aarch64-linux-gnu/
    # Copy the dependencies - pkgconfig (all of them)
    cp -r /lib/aarch64-linux-gnu/pkgconfig usr/lib/aarch64-linux-gnu/
    cp -r /usr/lib/pkgconfig/ucx.pc usr/lib/pkgconfig
    # Copy the dependencies - Full folders
    cp -r /opt/mellanox/dpdk/ opt/mellanox
    cp -r /opt/mellanox/grpc/ opt/mellanox

# From the Host's side:
elif [[ "${ARC}" == *"x86"* ]];
then
    echo "Running from within x86 Host"
    # Make sure DOCA metapackage for host is installed
    if [[ $(apt list --installed | grep -i doca-sdk | wc -c) -ne 0 ]];
    then
        echo "The following DOCA-SDK component is installed"
        
    else
        echo "Please install the DOCA-SDK Metapackage for Host"
    fi

    # Ensure meson version == 0.61.2, if not install it
    if [[ ${meson_version} == 0.61.2 ]];
    then
        echo "A suitable Meson version 0.61.2 is already installed, skipping to the next step"
    else
        echo "Please install Meson version 0.61.2"
    fi

    # Install linaro cross compiler if it doesn't exist
    if [[ $(ls $linaro_dir | grep -i $tar_file | wc -c) -ne 0 ]];
    then
        echo "Linaro cross compiler is already installed, skipping to the next step"
    else
        echo "Installing Linaro $latest"
        wget $linaro_path -P /var/tmp
        mkdir $linaro_dir
        cd $linaro_dir
        tar xf /var/tmp/$tar_file.tar.xz
    fi


    # install pkg-config-aarch64-linux-gnu
    if [[ $(apt list --installed | grep -i pkg-config-aarch64-linux-gnu | wc -c) -ne 0 ]];
    then
        echo "pkg-config-aarch64-linux-gnu is already installed, skipping to the next step"
    else
        apt install pkg-config-aarch64-linux-gnu
    fi


    cp /root/doca-cross/$cross_file_name $doca_apps
    
fi