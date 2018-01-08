# -*- coding: utf-8 -*-
"""
Copyright © 2017 SDElements Inc.
"""

import certbot
import dns
import dns.name
import logging
import ipalib
import re
import zope

__version__ = '0.0.5'

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Patterns
IPADDRESS_PATTERN = re.compile('(?:host/|\s|^)*((([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9])))(?:@|\s|$)*')
FQDN_PATTERN = re.compile('(?:host/|\s)*((?:[a-z0-9]+(?:[-_][a-z0-9]+)*\.)+[a-z]{2,})(?:@|\s)*')


@zope.interface.implementer(certbot.interfaces.IAuthenticator)
@zope.interface.provider(certbot.interfaces.IPluginFactory)
class FreeIPAAuthenticator(certbot.plugins.dns_common.DNSAuthenticator):
    """ FreeIPA Authentication using DNS challenges """

    def __init__(self, *args, **kwargs):
        # Set up IPA API connection
        try:
            ipalib.api.bootstrap_with_global_options(context='cerlet')
            ipalib.api.finalize()
        except ipalib.errors.KerberosError:
            logger.exception('Exception occurred authenticating with IPA server')
            raise

        if ipalib.api.env.in_server:
            ipalib.api.Backend.ldap2.connect()
        else:
            ipalib.api.Backend.rpcclient.connect()

        super(FreeIPAAuthenticator, self).__init__(*args, **kwargs)

    def get_chall_pref(self, domain):  # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [certbot.challenges.DNS01]

    return [certbot.challenges.HTTP01, certbot.challenges.DNS01, certbot.challenges.TLSSNI01]

    @classmethod
    def add_parser_arguments(cls, add, default_propagation_seconds=10):
        super(FreeIPAAuthenticator, cls).add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="Loopia API credentials INI file.")
        add('-h', '--host_name', '--host', dest='ipa_host', help='Hostname or IP Address of the IPA (Satellite) server')
        add('-d', '--domain_name', '--domain', dest='ipa_domain', help='Domain in IPA (Satellite) to register under')
        add('-H', '--xml_rpc_url', '--xmlrpc-url', dest='ipa_xml_rpc_url', help='XML RPC service location')
        add('-C', '--ca_path', '--capath', dest='ca_path', help='Path do a directory containing PEM encoded CA files')
        add('-c', '--ca_file', '--cafile', dest='ca_file', help='Path do a file containing PEM encoded CA certificates')
        add('-t', '--keytab_name', '--keytab-name', dest='keytab_file', help='Path to a keytab file containing credentials for IPA server authentication')
        add('-k', '--submitter_principal', '--submitter-principal', dest='submitter_principal', help='Kerberos principal for IPA server authentication')
        add('-K', '--use_ccache_creds', '--use-ccache-creds', dest='use_ccache_creds', default=False, action='store_true', help='Use default ccache for authorization instead of authenticating')
        add('-P', '--request_principal', '--principal-of-request', dest='request_principal', help='Principal(s) (FQDN) used in signing request, comma separated')
        add('-T', '--request_profile', '--profile', dest='request_profile', help='Use a specific profile when requesting enrollment')
    #add_argument('options', help='Options')
    #add_argument('csr_file', help='Path to a PEM encoded Certificate Signing Request (CSR)')

    def more_info(self):
        """
        More in-depth description of the plugin.
        """

        return "\n".join(line[4:] for line in __doc__.strip().split("\n"))

    def perform(self, domain, validation_name, validation):
        request = asn1crypto.csr.CertificationRequest.load(der_bytes)
        info = request['certification_request_info']
        subject = info['subject'].native
        common_name = subject['common_name']
        host = ipalib.api.Command.host_show(common_name)['result']
        principals = host['krbprincipalname']
        fqdn = host['fqdn']
        # Create unique list of FQDNs from principals and hostname (CSR Subject)
        subjects = set(list(fqdn) + [match.group(1) for principal in principals for match in [FQDN_PATTERN.match(principal), IPADDRESS_PATTERN.match(principal)] if match])

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

    def cleanup(self, domain, validation_name, validation):
        pass


def main(self):
    """ Entry point when run from CertMonger or standalone """
    pass
