# -*- coding: utf-8 -*-
"""
Copyright © 2017 SDElements Inc.
"""

default_ca_path = '/tmp/ca.pem'
default_ca_file = '/tmp/ca_files'
default_keytab_path = '/tmp/keytab'
default_submitter_principal = 'hostname'
default_request_profile = None
default_request_principal = 'hostname'


def main():
    """ Main entry point to program """
    parse_args()


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
    import argparse
    parser = argparse.ArgumentParser(description="Apply for Let's Encrypt Certificates", add_help=False)
    parser.add_argument('-h', '--host_name', '--host', dest='ipa_host',
                        default=lookup_ipa_host(),
                        help='Hostname or IP Address of the IPA (Satellite) server')
    parser.add_argument('-d', '--domain_name', '--domain', dest='ipa_domain',
                        default=lookup_ipa_domain(),
                        help='Domain in IPA (Satellite) to register under')
    parser.add_argument('-H', '--xml_rpc_url', '--xmlrpc-url', dest='ipa_xml_rpc_url',
                        default=generate_ipa_xml_rpc_url(),
                        help='XML RPC service location')
    parser.add_argument('-C', '--ca_path', '--capath', dest='ca_path',
                        default=default_ca_path,
                        help='Path do a directory containing PEM encoded CA files')
    parser.add_argument('-c', '--ca_file', '--cafile', dest='ca_file',
                        default=default_ca_file,
                        help='Path do a file containing PEM encoded CA certificates')
    parser.add_argument('-t', '--keytab_name', '--keytab-name', dest='keytab_file',
                        default=default_keytab_path,
                        help='Path to a keytab file containing credentials for IPA server authentication')
    parser.add_argument('-k', '--submitter_principal', '--submitter-principal', dest='submitter_principal',
                        default=default_submitter_principal,
                        help='Kerberos principal for IPA server authentication')
    parser.add_argument('-K', '--use_ccache_creds', '--use-ccache-creds', dest='use_ccache_creds',
                        default=False, action='store_true',
                        help='Use default ccache for authorization instead of authenticating')
    parser.add_argument('-P', '--request_principal', '--principal-of-request', dest='request_principal',
                        default=default_request_principal,
                        help='Principal(s) (FQDN) used in signing request, comma separated')
    parser.add_argument('-T', '--request_profile', '--profile', dest='request_profile',
                        default=default_request_profile,
                        help='Use a specific profile when requesting enrollment')
    parser.add_argument('-v', '--verbose', dest='verbose',
                        default=False, action='store_true',
                        help='Use verbose logging')
    parser.add_argument('--help', action='help', help='Show this help message and exit')
    parser.add_argument('options', help='Options')
    parser.add_argument('csr_file', help='Path to a PEM encoded Certificate Signing Request (CSR)')

    args = parser.parse_args()
    print(args)
