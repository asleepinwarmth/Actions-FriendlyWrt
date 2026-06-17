#!/bin/bash

sed -i -e '/CONFIG_MAKE_TOOLCHAIN=y/d' configs/rockchip/01-nanopi
sed -i -e 's/CONFIG_IB=y/# CONFIG_IB is not set/g' configs/rockchip/01-nanopi
sed -i -e 's/CONFIG_SDK=y/# CONFIG_SDK is not set/g' configs/rockchip/01-nanopi

cat >> configs/rockchip/01-nanopi <<'EOL'

# Custom packages for NanoPC-T6 DS-Lite/OpenVPN image.
CONFIG_PACKAGE_ds-lite=y
CONFIG_PACKAGE_kmod-ip6-tunnel=y
CONFIG_PACKAGE_kmod-iptunnel6=y
CONFIG_PACKAGE_openvpn-openssl=y
CONFIG_PACKAGE_liblz4-1=y
CONFIG_PACKAGE_luci-app-openvpn=y
CONFIG_PACKAGE_luci-app-uhttpd=y
EOL
