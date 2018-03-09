#!/bin/bash
#
# This is a collection of shared functions used by SDElements products
#
# Copyright (c) 2018 SD Elements Inc.
#
#  All Rights Reserved.
#
# NOTICE:  All information contained herein is, and remains
# the property of SD Elements Incorporated and its suppliers,
# if any.  The intellectual and technical concepts contained
# herein are proprietary to SD Elements Incorporated
# and its suppliers and may be covered by U.S., Canadian and other Patents,
# patents in process, and are protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this material
# is strictly forbidden unless prior written permission is obtained
# from SD Elements Inc..

# If there is no TTY then it's not interactive
if ! [[ -t 1 ]]; then
    interactive=false
fi
# Default is interactive mode unless already set
interactive="${interactive:-true}"

# Set strict mode only for non-interactive (see bash tab completion bug):
# https://github.com/scop/bash-completion/issues/44
# https://bugzilla.redhat.com/show_bug.cgi?id=1055784
if ! ${interactive} ; then
    set -euo pipefail
fi

# Store full path to this script
script_full_path="${0}"
if [ ! -f "${script_full_path}" ] ; then
    script_full_path="$(pwd)"
fi

# Allows checking of exit status, on error print debugging info and exit.
# Takes an optional error message in which case only it will be shown
# This is typically only used when running in non-strict mode but when errors
# should be raised and to help with debugging
function exit_on_fail {
    message="${*:-}"
    if [ -z "${message}" ] ; then
        echo "Last command did not execute successfully but is required!" >&2
    else
        echo "${*}" >&2
    fi
    echo "[$( caller )] ${*}"
    echo "BASH_SOURCE: ${BASH_SOURCE[*]}"
    echo "BASH_LINENO: ${BASH_LINENO[*]}"
    echo  "FUNCNAME: ${FUNCNAME[*]}"
    # Exit if we are running as a script
    if [ -f "${script_full_path}" ]; then
        exit 1
    fi
}

# Construct command to call
cerlet_binary="$(which cerlet 2>/dev/null || find $(getent passwd ${SUDO_USER:-root} | cut -f6 -d:) -executable -type f -name cerlet 2>/dev/null)"
cerlet_command="${cerlet_binary} || exit_on_fail \"Failure during '${CERTMONGER_OPERATION}' testing\""

test_domain="example.cerlet.com"
tmp_dir="$(mktemp -d)"
chmod 0700 "${tmp_dir}"
key_path="${tmp_dir}/${test_domain}.key.pem"
csr_path="${tmp_dir}/${test_domain}.csr.pem"
subject="/C=ZZ/ST=Unknown State/L=Nowhere/O=Cerlet/OU=Test Example/CN=${test_domain}"
export CERTMONGER_REQ_HOSTNAME="${HOSTNAME}"
export CERTMONGER_REQ_SUBJECT="${test_domain}"

openssl req -nodes -newkey 'rsa:2048' -sha256 -keyout "${key_path}" -out "${csr_path}" -subj "${subject}"
export CERTMONGER_OPERATION='SUBMIT'
export CERTMONGER_CSR="$(<${csr_path})"
#export CERTMONGER_CA_PROFILE
#export CERTMONGER_CA_NICKNAME
#export CERTMONGER_CA_ISSUER
${cerlet_command}
# Clean up
rm -f "${key_path}"
rm -f "${csr_path}"
rmdir "${tmp_dir}"
unset CERTMONGER_OPERATION
unset CERTMONGER_CSR
#unset CERTMONGER_CA_PROFILE
#unset CERTMONGER_CA_NICKNAME
#unset CERTMONGER_CA_ISSUER


#export CERTMONGER_OPERATION='POLL'
#export CERTMONGER_CA_COOKIE='BLEH'

#unset CERTMONGER_OPERATION
#unset CERTMONGER_CA_COOKIE

export CERTMONGER_OPERATION='GET-NEW-REQUEST-REQUIREMENTS'
unset CERTMONGER_OPERATION

export CERTMONGER_OPERATION='GET-RENEW-REQUEST-REQUIREMENTS'
unset CERTMONGER_OPERATION

export CERTMONGER_OPERATION='GET-SUPPORTED-TEMPLATES'
unset CERTMONGER_OPERATION

export CERTMONGER_OPERATION='GET-DEFAULT-TEMPLATE'
unset CERTMONGER_OPERATION

export CERTMONGER_OPERATION='FETCH-SCEP-CA-CAPS'
unset CERTMONGER_OPERATION

export CERTMONGER_OPERATION='FETCH-SCEP-CA-CERTS'
unset CERTMONGER_OPERATION

export CERTMONGER_OPERATION='FETCH-ROOTS'
${cerlet_command}
unset CERTMONGER_OPERATION

unset CERTMONGER_REQ_HOSTNAME
