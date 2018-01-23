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
import certbot.plugins
import certbot.plugins.dns_common
import certbot.interfaces
import dns
import dns.name
import logging
import ipalib
import re
import sys
import zope
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
    """ Represents an action requested by Certmonger """
    # Supported Exit Codes
    EXIT_ISSUED = 0
    EXIT_WAIT = 1
    EXIT_REJECTED = 2
    EXIT_UNREACHABLE = 3
    EXIT_UNCONFIGURED = 4
    EXIT_WAIT_WITH_DELAY = 5
    EXIT_OPERATION_NOT_SUPPORTED = 6

    def __init__(self):
        pass


class SubmitAction(CertMongerAction):
    """
    First time enrollment requested by Certmonger

    * "SUBMIT"
    This is called the first time the daemon attempts to send an enrollment
    request to a CA.  The signing data, in PEM form, is provided in the
    environment.  Some of the data from the request is also broken out and
    provided in the environment:
    * CERTMONGER_REQ_SUBJECT
        The subject name from the request, in text form.
    * CERTMONGER_REQ_EMAIL
        Any rfc822Name subject alt name values from the request.
    * CERTMONGER_REQ_HOSTNAME
        Any dNSName subject alt name values from the request.
    * CERTMONGER_REQ_PRINCIPAL
        Any Kerberos principal name subject alt name values from the request.
    * CERTMONGER_CA_PROFILE
        The name of the enrollment profile/template/certtype to use, if one
        was specified.
    * CERTMONGER_CSR
        The actual enrollment request, PKCS#10 format, PEM-encoded.
    * CERTMONGER_CERTIFICATE
        An older certificate, if we were previously issued one.
    These are also present starting with version 0.73:
    * CERTMONGER_CA_NICKNAME
        The name by which the CA is known, and would have been specified to the -c
        option to the "getcert" command.  If your helper is called in multiple CA
        configurations, you may want to use this value to distinguish between them
        in order to provide different behavior.
    * CERTMONGER_SPKAC
        The signing request as a signed public key and challenge (SPKAC).
    * CERTMONGER_SPKI
        The subjectPublicKeyInfo field from the signing request.
    * CERTMONGER_KEY_TYPE
        The type of key included in the signing request.
    These may also be present starting with version 0.77, though you probably
    won't use them:
    * CERTMONGER_SCEP_CA_IDENTIFIER
        An identifier to pass to an SCEP server when requesting its capabilities
        list or copies of it and its CA's certificate.
    * CERTMONGER_PKCSREQ
        An SCEP PKCSReq pkiMessage.  If the daemon is attempting to change keys,
        this will be signed with the old key.
    * CERTMONGER_PKCSREQ_REKEY
        An SCEP PKCSReq pkiMessage.  If the daemon is attempting to change keys,
        this will be signed with the new key, otherwise it is not set.
    * CERTMONGER_GETCERTINITIAL
        An SCEP GetCertInitial pkiMessage.  If the daemon is attempting to change
        keys, this will be signed with the old key.
    * CERTMONGER_GETCERTINITIAL_REKEY
        An SCEP GetCertInitial pkiMessage.  If the daemon is attempting to change
        keys, this will be signed with the new key, otherwise it is not set.
    * CERTMONGER_SCEP_RA_CERTIFICATE
        The SCEP server's RA certificate.
    * CERTMONGER_SCEP_CA_CERTIFICATE
        The SCEP server's CA certificate.
    * CERTMONGER_SCEP_CERTIFICATES
        Additional certificates in the SCEP server's certifying chain.
    These are also present starting with version 0.78:
    * CERTMONGER_REQ_IP_ADDRESS
        Any iPAddress subject alt name values from the request.
    These are also present starting with version 0.79:
    * CERTMONGER_CA_ISSUER
        The requested issuer for enrollment.
    The helper is expected to use this information, along with whatever
    credentials it has or is passed on the command line, to send the signing
    request to the CA.


    * If a certificate is issued, output it in PEM form and exit with status 0.
        See footnote 1 for information about formatting the result.

    * If the client should wait for a period of time, output a "cookie" value and
        exit with status 1.  The daemon will try again later at a time of its
        choosing (the default is currently 7 days).

    * If the request was rejected outright, output an error message, and exit
        with status 2.

    * If there was an error connecting to the server, output an error message and
        exit with status 3.  The daemon will try again later.

    * If the helper requires additional configuration data, output an error
        message and exit with status 4.

    * If the client should wait for a specific period of time (for example, if
        the CA has told it when to try again), output a delay size in seconds, a
        newline, and a "cookie" value, and exit with status 5.  The daemon will try
        again after the specified amount of time has passed.

    * If the helper needs SCEP data, exit with status 16.  Your helper probably
        won't need to do this.

    * If the CA indicates that the client needs to try again using a different
        key pair in the signing request (for example, if its policy limits the
        number of times a particular key pair can be enrolled, or the length of
        time one can be in service), exit with status 17.  The daemon will generate
        a new key pair and try again.

    * If the helper does not understand what is being asked of it, exit with
        status 6.  You should never return this value for "SUBMIT" or "POLL", but
        it is mentioned here so that we can refer to this list later.
    """

    def __init__(self,
        csr,  # PKCS#10/PEM encoded certificate signing request
        request_subject=None,  # Text form of request subject from CSR
        request_email=None,  # Alternative email addresses
        request_hostname=None,  # Alternative host names
        request_principal=None,  # Alternative principals
        request_ip_address=None  # Alternative ip addresses
        ca_profile=None,  # Name of profile, template or certtype
        old_certificate=None,  # Previously issued certificate to be replaced
        ca_nickname=None,  # CA short name, e.g. test or prod (default)
        ca_issuer=None,  # URI to CA issuer
         # TBD
#        spkac=None,  # Signed Public Key or Challenge
#        spki=None,  # Signed Public Key Info
#        key_type=None,  # Key type included in the signing request
        ):

class PollAction(CertMongerAction):
    """
    Poll status of previously submitted request

    * "POLL"
    If the helper previously returned with status 1 or 5, this is the daemon
    trying again.  The same information supplied for "SUBMIT" requests will be
    provided in the environment.  Additionally, the "CERTMONGER_CA_COOKIE"
    variable will hold the cookie value returned by the previous call to the
    helper.  If your process requires multiple steps, the cookie is suitable for
    keeping track of which step is next.
    If your helper never returns status 1 or 5, this will not be used, and you
    need not implement logic for it.
    Report results as you would for the "SUBMIT" operation.
    """

    def __init__(self):
        pass

class IdentifyAction(CertMongerAction):
    """
    Poll status of previously submitted request

    * "IDENTIFY":
    Output version information for your helper, and exit with status 0.  This
    information is tracked by the daemon and included in the output of the
    "getcert list-cas -v" command.  Optional.
    """

    def __init__(self):
        pass

class RequestRequirementsAction(CertMongerAction):
    """
    Return list of required arguments for SUBMIT or POLL actions


    * "GET-NEW-REQUEST-REQUIREMENTS"
    Output a list of environment variable names which are expected to have
    non-empty values when the helper is run in SUBMIT or POLL mode.  The list can
    be either comma- or newline-separated.
    At some point, we'll teach getcert to instruct people to supply values that
    are required by the CA that they intend to use if it finds that they didn't
    supply one of these.
    Support for this operation is optional.
    """

    def __init__(self):
        pass

class RequestRenewRequirementsAction(RequestRequirements):
    """
    Return list of required arguments for SUBMIT or POLL when renewing an
    already issues certificate.

    * "GET-RENEW-REQUEST-REQUIREMENTS"
    Just like "GET-NEW-REQUEST-REQUIREMENTS", except for cases when the client
    attempts to renew an already-issued certificate.  In most cases, your helper
    will want to do the same thing for "GET-RENEW-REQUEST-REQUIREMENTS" as it
    does for "GET-NEW-REQUEST-REQUIREMENTS"
    Support for this operation is optional.
    """

    def __init__(self):
        pass

class GetSupportedTemplatesAction(CertMongerAction):
    """
    Return a list of supported profiles, templates or cert types

    * "GET-SUPPORTED-TEMPLATES"
    Output a list of supported profile/template/certtype names offered and
    recognized by the CA.  The list can be either comma- or newline-separated.
    At some point, we'll teach getcert to validate values it receives for its -T
    option against this list.
    Support for this operation is optional.
    """

    def __init__(self):
        pass

class GetDefaultTemplateAction(CertMongerAction):
    """
    Return default profile (template/certtype)

    * "GET-DEFAULT-TEMPLATE"
    Output a single supported profile/template/certtype name offered and
    recognized by the CA.  If there is no default, output nothing.
    At some point, we'll teach getcert to use this value as a default if it is
    not passed the -T option.
    Support for this operation is optional.
    """

    def __init__(self):
        pass

class FetchRootsAction(CertMongerAction):
    """
    Return default profile (template/certtype)

    * "FETCH-ROOTS"
    If the helper has a way to read the CA's root certificate over an
    authenticated and integrity-protected channel, output a suggested nickname,
    the certificate in PEM format.  If there are other trusted certificates,
    follow that with a blank line and one or more nickname/certificate sequences.
    If there are other certificates which the client might need (for example,
    others in the certifying chain), repeat for those.  Note that if there are
    chain certificates but no supplemental root certificates, the root
    certificate should be followed by two blank lines.
    Support for this operation is optional.  If you can not guarantee that the
    data produced is authenticated and has not been tampered with, do not
    implement this.
    The format described here is recognized to be error-prone and will be
    replaced with a JSON object in the future.
    """

    def __init__(self):
        pass





* (not set)
  To ease troubleshooting, my suggestion is to treat the CERTMONGER_OPERATION
  not being set as if it was set to SUBMIT, or POLL if a cookie value is passed
  to your helper via a command-line option.
* Anything else.
  For future-proofing, exit with status 6.






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

def load_environment_variables(pattern='CERTMONGER'):
    """ Loads environment variables matching a pattern """
    matches = {}
    for key, value in os.environ.items():
        if pattern in key:
            matches[key] = value

    return matches

def main():
    """ Entry point when run directly """
    operation = os.getenv("CERTMONGER_OPERATION")
    from pkg_resources import load_entry_point
    sys.argv += ['--authenticator', 'cerlet:ipa']
    sys.exit(load_entry_point('certbot', 'console_scripts', 'certbot')())
