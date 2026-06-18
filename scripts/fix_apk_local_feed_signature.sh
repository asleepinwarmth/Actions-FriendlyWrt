#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${1:-$(pwd)}"

cd "${PROJECT_DIR}"
source .current_config.mk

ROOTFS_DIR="${FRIENDLYWRT_SRC}/${FRIENDLYWRT_ROOTFS}"
PACKAGE_DIR="${FRIENDLYWRT_SRC}/${FRIENDLYWRT_PACKAGE_DIR}"
APK_BIN="${FRIENDLYWRT_SRC}/staging_dir/host/bin/apk"
HELPER="${SCRIPT_DIR}/apk_local_feed_signature.py"

if [ ! -x "${APK_BIN}" ]; then
    echo "ERROR: host apk not found or not executable: ${APK_BIN}" >&2
    exit 1
fi

if [ ! -d "${ROOTFS_DIR}" ]; then
    echo "ERROR: rootfs directory not found: ${ROOTFS_DIR}" >&2
    exit 1
fi

if [ ! -d "${PACKAGE_DIR}" ]; then
    echo "ERROR: package directory not found: ${PACKAGE_DIR}" >&2
    exit 1
fi

mapfile -t ADB_FILES < <(
    {
        [ -f "${PACKAGE_DIR}/packages.adb" ] && printf '%s\n' "${PACKAGE_DIR}/packages.adb"
        [ -f "${ROOTFS_DIR}/usr/local/packages/packages.adb" ] && printf '%s\n' "${ROOTFS_DIR}/usr/local/packages/packages.adb"
        find "${PACKAGE_DIR}" "${ROOTFS_DIR}/usr/local/packages" \
            -maxdepth 2 -type f -name packages.adb 2>/dev/null || true
    } | awk '!seen[$0]++'
)

if [ "${#ADB_FILES[@]}" -eq 0 ]; then
    echo "ERROR: no local packages.adb found under ${PACKAGE_DIR} or ${ROOTFS_DIR}/usr/local/packages" >&2
    exit 1
fi

echo "Local APK indexes to verify:"
printf '  %s\n' "${ADB_FILES[@]}"

first_sig_id="$(python3 "${HELPER}" sig-id "${ADB_FILES[0]}" | head -n1)"
if [ -z "${first_sig_id}" ]; then
    echo "ERROR: ${ADB_FILES[0]} has no signature block" >&2
    exit 1
fi
echo "Current local feed signature id: ${first_sig_id}"

MATCHING_PUBLIC_KEY=""
while IFS= read -r key; do
    key_id="$(python3 "${HELPER}" key-id "${key}" 2>/dev/null || true)"
    if [ -n "${key_id}" ]; then
        echo "Candidate key ${key}: ${key_id}"
    fi
    if [ "${key_id}" = "${first_sig_id}" ]; then
        matches_all=1
        for adb in "${ADB_FILES[@]}"; do
            if ! python3 "${HELPER}" verify "${adb}" "${key}" >/dev/null 2>&1; then
                matches_all=0
                break
            fi
        done
    else
        matches_all=0
    fi
    if [ "${matches_all}" = "1" ]; then
        MATCHING_PUBLIC_KEY="${key}"
        break
    fi
done < <(
    find "${FRIENDLYWRT_SRC}" \
        \( -name '*.pem' -o -name '*.pub' -o -name 'public-key*' \) \
        -type f 2>/dev/null | sort
)

install_public_key() {
    local public_key="$1"
    install -d -m 0755 "${ROOTFS_DIR}/etc/apk/keys"
    install -m 0644 "${public_key}" "${ROOTFS_DIR}/etc/apk/keys/public-key.pem"
    echo "Installed local feed public key to ${ROOTFS_DIR}/etc/apk/keys/public-key.pem"
}

if [ -n "${MATCHING_PUBLIC_KEY}" ]; then
    echo "Found matching public key: ${MATCHING_PUBLIC_KEY}"
    install_public_key "${MATCHING_PUBLIC_KEY}"
else
    echo "No matching public key found; regenerating local feed signature with an ephemeral key."
    KEY_DIR="$(mktemp -d)"
    trap 'rm -rf "${KEY_DIR}"' EXIT
    PRIVATE_KEY="${KEY_DIR}/local-feed-private.pem"
    PUBLIC_KEY="${KEY_DIR}/public-key.pem"

    openssl ecparam -name prime256v1 -genkey -noout -out "${PRIVATE_KEY}"
    openssl ec -in "${PRIVATE_KEY}" -pubout -out "${PUBLIC_KEY}"
    new_key_id="$(python3 "${HELPER}" key-id "${PUBLIC_KEY}")"
    echo "Generated local feed public key id: ${new_key_id}"

    "${APK_BIN}" --sign-key "${PRIVATE_KEY}" adbsign --reset-signatures "${ADB_FILES[@]}"
    install_public_key "${PUBLIC_KEY}"
fi

public_key="${ROOTFS_DIR}/etc/apk/keys/public-key.pem"
public_key_id="$(python3 "${HELPER}" key-id "${public_key}")"

for adb in "${ADB_FILES[@]}"; do
    python3 "${HELPER}" verify "${adb}" "${public_key}"
done

echo "Verified local feed signature against installed public key id: ${public_key_id}"
