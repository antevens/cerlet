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

test_domain="example.cerlet.com"
tmp_dir="$(mktemp -d)"
chmod 0700 "${tmp_dir}"
key_path="${tmp_dir}/${test_domain}.key.pem"
csr_path="${tmp_dir}/${test_domain}.csr.pem"
subject='/C=ZZ/ST=Unknown State/L=Nowhere/O=Cerlet/OU=Test Example/CN=example.cerlet.com'


openssl genrsa -out  2048
openssl req -nodes -newkey 'rsa:2048' -sha256 -keyout "${key_path}" -out "${csr_path}" -subj "${subject}"
export CERTMONGER_OPERATION='SUBMIT'
export CERTMONGER_CSR="$(<${csr_path})"
#export CERTMONGER_CA_PROFILE
#export CERTMONGER_CA_NICKNAME
#export CERTMONGER_CA_ISSUER
# Replace with something better for testing and prod
/home/vagrant/Revisions/certbot/venv/bin/cerlet

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
unset CERTMONGER_OPERATION

