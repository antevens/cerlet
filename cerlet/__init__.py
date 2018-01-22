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

#from acme import challengesd
#from certbot import errors
#from certbot import interfaces
#from certbot.display import ops
#from certbot.display import util as display_util
#from certbot.plugins import common

__version__ = '0.0.5'

# Set up logging
logger = logging.getLogger(__name__)

# Patterns
IPADDRESS_PATTERN = re.compile('(?:host/|\s|^)*((([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9])))(?:@|\s|$)*')
FQDN_PATTERN = re.compile('(?:host/|\s)*((?:[a-z0-9]+(?:[-_][a-z0-9]+)*\.)+[a-z]{2,})(?:@|\s)*')

@zope.interface.implementer(certbot.interfaces.IAuthenticator)
@zope.interface.provider(certbot.interfaces.IPluginFactory)
class Authenticator(certbot.plugins.dns_common.DNSAuthenticator):
    """ FreeIPA / Red Hat Enterprise Linux IdM authentication using DNS challenges """

    description = __doc__.strip().split("\n", 1)[0]

    def __init__(self, *args, **kwargs):
        # Maps provided domains to IPA zones
        self.zone_map = {}
        super(Authenticator, self).__init__(*args, **kwargs)

    def more_info(self):
        return self.__doc__

    def _setup_credentials(self):
        # Set up IPA API connection
        logger.info('Setting up IPA Connection using kerberos credentials')
        try:
            ipalib.api.bootstrap_with_global_options(context=__name__)
            ipalib.api.finalize()
        except ipalib.errors.KerberosError:
            logger.exception('Exception occurred authenticating with IPA server')
            raise

        if ipalib.api.env.in_server:
            ipalib.api.Backend.ldap2.connect()
        else:
            ipalib.api.Backend.rpcclient.connect()

    def _perform(self, domain, validation_domain_name, validation):  # pragma: no cover
        logger.debug('Adding DNS Records {0} to zone: {1} with value: {2}'.format(validation_domain_name, domain, validation))
        dns_zone_candidate = dns.name.from_text(domain)
        while True:
            try:
                ipalib.api.Command.dnszone_show(idnsname=unicode(dns_zone_candidate.to_text()))
                record = dns.name.from_text(validation_domain_name).relativize(dns_zone_candidate)
                try:
                    ipalib.api.Command.dnsrecord_add(dnszoneidnsname=unicode(dns_zone_candidate.to_text()), idnsname=unicode(record), txtrecord=validation)
                except ipalib.errors.EmptyModlist:
                    logger.warning('DNS entry already exists: {0} with value: {1}'.format(record, validation))
                self.zone_map[validation_domain_name] = (dns_zone_candidate, record)
                break
            except (ipalib.errors.NotFound, ipalib.errors.ConversionError):
                logger.debug('Unable to find Zone: {0}, checking for parent'.format(dns_zone_candidate.to_text(omit_final_dot=True)))
                try:
                    dns_zone_candidate = dns_zone_candidate.parent()
                except dns.name.NoParent:
                    message = 'Unable to find DNS Zone on IPA server'
                    logger.exception(message)
                    raise ipalib.errors.NotFound(format=None, message=message.decode())


        #request = asn1crypto.csr.CertificationRequest.load(der_bytes)
        #info = request['certification_request_info']
        #subject = info['subject'].native
        #common_name = subject['common_name']
        #host = ipalib.api.Command.host_show(common_name)['result']
        #principals = host['krbprincipalname']
        #fqdn = host['fqdn']

        # Create unique list of FQDNs from principals and hostname (CSR Subject)
        #subjects = set(list(fqdn) + [match.group(1) for principal in principals for match in [FQDN_PATTERN.match(principal), IPADDRESS_PATTERN.match(principal)] if match])
        #logger.debug('Requesting certificate for following subjects')
        #logger.debug(subjects)
        # Find the DNS Zone to add/modify records to/in

    def _cleanup(self, domain, validation_domain_name, validation):
        logger.debug('Removing DNS entry: {0} to zone: {1} with value: {2}'.format(validation_domain_name, domain, validation))
        ipalib.api.Command.dnsrecord_del(dnszoneidnsname=unicode(self.zone_map[validation_domain_name][0].to_text()), idnsname=unicode(self.zone_map[validation_domain_name][1]), txtrecord=validation)

@zope.interface.implementer(certbot.interfaces.IInstaller)
@zope.interface.provider(certbot.interfaces.IPluginFactory)
class Installer(certbot.plugins.common.Plugin):
    """Stdout installer."""

    description = "Stdout Installer"

    def prepare(self):
        pass  # pragma: no cover

    def more_info(self):
        return "Installer that only prints to stdout"

    def get_all_names(self):
        return []

    def deploy_cert(self, domain, cert_path, key_path,
                    chain_path=None, fullchain_path=None):
        pass  # pragma: no cover

    def enhance(self, domain, enhancement, options=None):
        pass  # pragma: no cover

    def supported_enhancements(self):
        return []

    def save(self, title=None, temporary=False):
        pass  # pragma: no cover

    def rollback_checkpoints(self, rollback=1):
        pass  # pragma: no cover

    def recovery_routine(self):
        pass  # pragma: no cover

    def view_config_changes(self):
        pass  # pragma: no cover

    def config_test(self):
        pass  # pragma: no cover

    def restart(self):
        pass  # pragma: no cover

    @classmethod
    def add_parser_arguments(cls, add, default_propagation_seconds=10):
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds)
        add("credentials", help="Loopia API credentials INI file.")
        add('-h', '--host_name', '--host', dest='ipa_host', help='Hostname or IP Address of the IPA (Satellite) server')
        add('-d', '--ipa_domain_name', '--ipa_domain', dest='ipa_domain', help='Domain in IPA (Satellite) to register under')
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

#    def cleanup(self, domain, validation_name, validation):
#        pass

#@zope.interface.implementer(certbot.interfaces.IInstaller)
#@zope.interface.provider(certbot.interfaces.IPluginFactory)
#class Installer(certbot.plugins.common.Plugin):
#    """Certmonger Installer."""
#
#    description = __doc__.strip().split("\n", 1)[0]
#
#    print()



    # Implement all methods from IInstaller, remembering to add
    # "self" as first argument, e.g. def get_all_names(self)...


def main(self):
    """ Entry point when run from CertMonger or standalone """
    pass
