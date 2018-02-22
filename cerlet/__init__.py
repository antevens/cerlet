# -*- coding: utf-8 -*-
"""
Copyright © 2017 SDElements Inc.

This application/module/plugin functions as a certmonger helper and a certbot
plugin. The operation depends on the entry point.

TBD Explain different entry points and flows

https://pagure.io/certmonger/blob/master/f/doc/helpers.txt
Add documentation for certbot plugins
"""

import certbot
import certbot.main
import certbot.plugins
import certbot.plugins.dns_common
import certbot.interfaces
import dns
import dns.name
import logging
import os
import ipalib
import re
import sys
import zope
import zope.component
import zope.interface

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
#IPADDRESS_PATTERN = re.compile('(?:host/|\s|^)*((([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9])))(?:@|\s|$)*')
#FQDN_PATTERN = re.compile('(?:host/|\s)*((?:[a-z0-9]+(?:[-_][a-z0-9]+)*\.)+[a-z]{2,})(?:@|\s)*')

class CertMongerAction(object):
    """ Represents an action requested by Certmonger

        * (not set)
        To ease troubleshooting, my suggestion is to treat the CERTMONGER_OPERATION
        not being set as if it was set to SUBMIT, or POLL if a cookie value is passed
        to your helper via a command-line option.
        * Anything else.
        For future-proofing, exit with status 6.

    """
    # Supported Exit Codes
    EXIT_ISSUED = 0
    EXIT_WAIT = 1
    EXIT_REJECTED = 2
    EXIT_UNREACHABLE = 3
    EXIT_UNCONFIGURED = 4
    EXIT_WAIT_WITH_DELAY = 5
    EXIT_OPERATION_NOT_SUPPORTED = 6

    def __init__(self, config_dir='/etc/certmonger/letsencrypt',
                       work_dir='/var/lib/certmonger/letsencrypt',
                       log_dir='/var/log/letsencrypt',
                       email=None):
        email = email or self.environment['CERTMONGER_CSR']
        logger.debug('Config dir set to: {0}'.format(config_dir)
        logger.debug('Work dir set to: {0}'.format(work_dir)
        logger.debug('Email set to: {0}'.format(email)
        namespace = {'config_dir': config_dir,
                     'work_dir': work_dir,
                     'logs_dir': log_dir,
                     'email': email,
                     'register_unsafely_without_email': True}
        self.config = configuration.NamespaceConfig(namespace)

        # Load and store relevant environment variables
        environment = self.load_environment_variables()

        # Set up logging to use syslog
        logger.setLevel(logging.DEBUG)
        handler = logging.handlers.SysLogHandler(address = '/dev/log')
        formatter = logging.Formatter('%(module)s.%(funcName)s: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # Configure certbot plugins
        certbot_plugins = certbot.plugins.disco.PluginsRegistry.find_all()
        logger.debug('Certbot version: {0}'.format(certbot.__version__))
        logger.debug('Discovered plugins: {0}'.format(plugins))

        # Set Reporter, Displayer and Config
        zope.component.provideUtility(self.config)
        self.displayer = display_util.NoninteractiveDisplay(open(os.devnull, "w"))
        zope.component.provideUtility(displayer)
        self.report = reporter.Reporter(self.config)
        zope.component.provideUtility(report)

    @staticmethod
    def _raise_not_implemented(exception=NotImplementedError):
        """ Raises the provided exception """
        raise exception

    @staticmethod
    def load_environment_variables(pattern='CERTMONGER'):
        """ Loads environment variables matching a pattern """
        matches = {}
        for key, value in os.environ.items():
            if pattern in key:
                matches[key] = value

        return matches

    @classmethod
    def operation_factory(cls, operation):
        """
        Returns the appopriate method for an operation as they are
        specified by CertMonger in environment variables.
        """
        logger.debug('Certmonger operation detected, evaluating environment variables and performing actions as requested')
        valid_operations = {'SUBMIT':cls.submit,
                            'POLL':cls.poll,
                            'IDENTIFY':cls.identify,
                            'GET-NEW-REQUEST-REQUIREMENTS':cls.requirements,
                            'GET-RENEW-REQUEST-REQUIREMENTS':cls.renew_requirements,
                            'GET-SUPPORTED-TEMPLATES':cls.templates,
                            'GET-DEFAULT-TEMPLATE':cls.default_template,
                            'FETCH-SCEP-CA-CAPS':cls._raise_not_implemented,
                            'FETCH-SCEP-CA-CERTS':cls._raise_not_implemented,
                            'FETCH-ROOTS':cls.get_ca_root_certs}
        return valid_operations[operation]()

    def register(self, config=None):
        certbot.main.register(config or self.config, unused_plugins=None)

    def submit(self, csr=None, ca_profile=None, ca_nickname=None, ca_issuer=None):
        """
        Accepts a single Certificate Signing Request, PKCS#10/PEM encoded

        First time enrollment requested by Certmonger

        Keyword arguments:

        csr -- Enrollment request in PEM form. PKCS#10 format, PEM encoded
        ca_profile -- Name of enrollment profile/template/certtype
        ca_nickname --  Name by which the CA is known, and would have been specified to the -c
            option to the "getcert" command. For example "prod" or "test"
        ca_issuer --  Requested issuer for enrollment

        Issues certificates will be returned in PEM encoded x.509 format
        and an exit status of 0 will be returned.

        If the certificates can't be issued immediately a "cookie" value/token
        will be returned and an exit status of 1 returned. The requestor is
        free to try again at their convenience presenting the cookie/token.

        If the request is rejected an error will returned along with an exit
        status of 2.

        If there was a connection or networking exception the error will be
        returned along with an exit status of 3.

        If additional data is required the specific error will be returned
        along with an exit status of 4.


        * If the client should wait for a specific period of time (for example, if
            the CA has told it when to try again), output a delay size in seconds, a
            newline, and a "cookie" value, and exit with status 5.  The daemon will try
            again after the specified amount of time has passed.

        * If the CA indicates that the client needs to try again using a different
            key pair in the signing request (for example, if its policy limits the
            number of times a particular key pair can be enrolled, or the length of
            time one can be in service), exit with status 17.  The daemon will generate
            a new key pair and try again.

        * If the helper does not understand what is being asked of it, exit with
            status 6.  You should never return this value for "SUBMIT" or "POLL", but
            it is mentioned here so that we can refer to this list later.
        """
        logger.debug('Submitting certificate signing request')
        csr = csr or self.environment['CERTMONGER_CSR']
        ca_profile = ca_profile or self.environment['CERTMONGER_CA_PROFILE']
        ca_nickname = ca_nickname or self.environment['CERTMONGER_CA_NICKNAME']
        ca_issuer = ca_issuer or self.environment['CERTMONGER_CA_ISSUER']

        certbot.main.certonly(self.config, self.plugins)
        certbot.main.renew_cert(self.config, self.plugins, lineage)

    def poll(self, cookie=None):
        """
        Poll status of previously submitted request

        Keyword arguments:

        cookie -- A cookie/token to identify a previously submitted request

        If the submit method previously returned with status 1 or 5, this can
        be called to retry.

        Returned certificates and exit statuses are the same as the submit
        method.
        """
        logger.debug('Polling for certificate signing request status')
        cookie = cookie or self.environment['CERTMONGER_CA_COOKIE']

    @staticmethod
    def identify():
        """
        Outputs the version of the helper and returns an exit status of 0
        """
        logger.debug('Returning version of helper/plugin')
        return __version__

    def requirements(self, renew=False):
        """
        Returns a list of required arguments/environment variables for the
        poll and submit methods, if renew is true it lists those required when
        renewing a certificate rather than requesting a new one.
        """
        logger.debug('Returning list of required attributes/arguments')

        print('EMAIL')

    def renew_requirements(self):
        return self.requirements(renew=True)

    def templates(default_only=False):
        """
        Returns list of all profiles/templates/cert-types, by default all
        supported templates are returned.
        """
        logger.debug('Returning templates/profiles')

    def default_template(self):
        return self.templates(default_only=True)


    def get_ca_root_certs():
        """
        Return a dictionary of nickname/cert with the cert in PEM format.
        """
        logger.debug('Returning CA Root certificates')


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

def main():
    """ Entry point when run directly """
    env = CertMongerAction.load_environment_variables()
    if env:
        print('env')
        print(CertMongerAction.operation_factory(os.getenv('CERTMONGER_OPERATION')))
    from pkg_resources import load_entry_point
    sys.argv += ['--authenticator', 'cerlet:ipa']
    sys.exit(load_entry_point('certbot', 'console_scripts', 'certbot')())
