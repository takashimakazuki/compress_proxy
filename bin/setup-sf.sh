#!/bin/bash

# ##### SF（Scalable Function）作成用のスクリプト #####
# SF（BlueField-2 DPUのOSで提供される仮想ネットワークインタフェース機能，VFをさらに拡張拡張したもの）
# Create→Setup→Deployの3手順で設定する

set -x ## Display commands
#set -e

if [ $# -eq 0 ]; then
    echo "No arguments provided. 'setup-sf.sh [pfnum] "
    exit 1
fi

# create sf
sf_out=$(/opt/mellanox/iproute2/sbin/mlxdevm port add pci/0000:03:00.$pfnum flavour pcisf pfnum $pfnum sfnum 10)
dev_port_index=$(echo $sf_out | grep -o "pci/0000:03:00.[0-1]/[0-9]\{6\}")

echo $dev_port_index

# setup sf
/opt/mellanox/iproute2/sbin/mlxdevm port function set $dev_port_index hw_addr 02:25:f2:8d:a2:10 state active


# deploy sf
echo mlx5_core.sf.4  > /sys/bus/auxiliary/drivers/mlx5_core.sf_cfg/unbind
echo mlx5_core.sf.4  > /sys/bus/auxiliary/drivers/mlx5_core.sf/bind

/opt/mellanox/iproute2/sbin/mlxdevm port show
