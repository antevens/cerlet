# -*- coding: utf-8 -*-
"""
Copyright © 2017 SDElements Inc.
"""

import argparse
import asn1crypto
import asn1crypto.csr
import asn1crypto.pem
import dns
import dns.name
import ipalib
import logging
import re

__version__ = '0.0.3'

# Patterns
IPADDRESS_PATTERN =re.compile('(?:host/|\s|^)*((([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9])))(?:@|\s|$)*')
FQDN_PATTERN = re.compile('(?:host/|\s)*((?:[a-z0-9]+(?:[-_][a-z0-9]+)*\.)+[a-z]{2,})(?:@|\s)*')

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    """ Main entry point to program """
    # Parse command line arguments
    args = parse_args()

    # Set up IPA API connection
    ipalib.api.bootstrap_with_global_options(context='cerlet')
    ipalib.api.finalize()

    if ipalib.api.env.in_server:
        ipalib.api.Backend.ldap2.connect()
    else:
        ipalib.api.Backend.rpcclient.connect()

    # Read CSR File and extract/get relevant data
    with open(args.csr_file, 'rb') as f:
        der_bytes = f.read()
        if asn1crypto.pem.detect(der_bytes):
            type_name, headers, der_bytes = asn1crypto.pem.unarmor(der_bytes)

    request = asn1crypto.csr.CertificationRequest.load(der_bytes)
    info = request['certification_request_info']
    subject = info['subject'].native
    common_name = subject['common_name']
    host = ipalib.api.Command.host_show(common_name)['result']
    principals = host['krbprincipalname']
    fqdn = host['fqdn']
    # Create unique list of FQDNs from principals and hostname (CSR Subject)
    subjects = set(list(fqdn) + [match.group(1) for principal in principals for match in
            [FQDN_PATTERN.match(principal), IPADDRESS_PATTERN.match(principal)]
            if match])

    # Find the DNS Zone to add/modify records to/in
    for subject_alt_name in subjects:
        dns_zone_candidate = dns.name.from_text(subject_alt_name)
        while True:
            try:
                ipalib.api.Command.dnszone_show(dns_zone_candidate.to_text())
                break
            except ipalib.errors.NotFound:
                try:
                    dns_zone_candidate = dns_zone_candidate.parent()
                except dns.name.NoParent:
                    raise ipalib.errors.NotFound('Unable to find DNS Zone on IPA server')

        # Add/Modify DNS records used for authorization by Let's Encrypt
        acme_record = "_acme-challenge.{0}.".format(subject_alt_name)
        challenge = "bogus_challenge"
        try:
            ipalib.api.Command.dnsrecord_mod(dns_zone_candidate.to_text(), acme_record, txtrecord=challenge)
            logging.debug('Added DNS record "{0} -> {1}" for authorization'.format(acme_record, challenge))
        except ipalib.errors.NotFound:
            ipalib.api.Command.dnsrecord_add(dns_zone_candidate.to_text(), acme_record, txtrecord=challenge)
            logging.debug('Modified DNS record "{0} -> {1}" for authorization'.format(acme_record, challenge))
        except ipalib.errors.EmptyModlist:
            logging.info("No DNS Changes required for authorization")

    import pdb; pdb.set_trace()


def lookup_ipa_host():
    """ Lookup the default IPA Hostname """
    return None


def lookup_ipa_domain():
    """ Lookup the default IPA Domain """
    return None


def generate_ipa_xml_rpc_url():
    """
    Generate a URL/URI to the XML RPC interface of the IPA/Satellite server
    using the IPA hostname and standard URI paths
    """
    return None


def parse_args():
    parser = argparse.ArgumentParser(description="Apply for Let's Encrypt Certificates", add_help=False)
    parser.add_argument('-h', '--host_name', '--host', dest='ipa_host',
                        help='Hostname or IP Address of the IPA (Satellite) server')
    parser.add_argument('-d', '--domain_name', '--domain', dest='ipa_domain',
                        help='Domain in IPA (Satellite) to register under')
    parser.add_argument('-H', '--xml_rpc_url', '--xmlrpc-url', dest='ipa_xml_rpc_url',
                        help='XML RPC service location')
    parser.add_argument('-C', '--ca_path', '--capath', dest='ca_path',
                        help='Path do a directory containing PEM encoded CA files')
    parser.add_argument('-c', '--ca_file', '--cafile', dest='ca_file',
                        help='Path do a file containing PEM encoded CA certificates')
    parser.add_argument('-t', '--keytab_name', '--keytab-name', dest='keytab_file',
                        help='Path to a keytab file containing credentials for IPA server authentication')
    parser.add_argument('-k', '--submitter_principal', '--submitter-principal', dest='submitter_principal',
                        help='Kerberos principal for IPA server authentication')
    parser.add_argument('-K', '--use_ccache_creds', '--use-ccache-creds', dest='use_ccache_creds',
                        default=False, action='store_true',
                        help='Use default ccache for authorization instead of authenticating')
    parser.add_argument('-P', '--request_principal', '--principal-of-request', dest='request_principal',
                        help='Principal(s) (FQDN) used in signing request, comma separated')
    parser.add_argument('-T', '--request_profile', '--profile', dest='request_profile',
                        help='Use a specific profile when requesting enrollment')
    parser.add_argument('-v', '--verbose', dest='verbose', default=False, action='store_true',
                        help='Use verbose logging')
    parser.add_argument('--help', action='help', help='Show this help message and exit')
    parser.add_argument('options', help='Options')
    parser.add_argument('csr_file', help='Path to a PEM encoded Certificate Signing Request (CSR)')

    return parser.parse_args()
