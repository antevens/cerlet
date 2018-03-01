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
import certbot.account
import certbot.constants
import certbot.main
import certbot.plugins
import certbot.plugins.dns_common
import certbot.interfaces
import errno
import dns
import dns.name
import grp
import logging
import namedlist
import os
import pwd
import ipalib
import shutil
import stat
import sys
import zope
import zope.component
import zope.interface

__version__ = '0.0.6'

# Set up logging
logger = logging.getLogger(__name__)


class PermError(Exception):
    """ Raised if permissions don't match specifications/requirments or unsafe permissions are found """
    pass


def check_permission(perm_mode, flags=stat.S_IWOTH):
    """
    Check if a bit is is set in an integer, very useful for checking if
    a particular permission is set of a file by comparing os.stat.st.mode

    Multiple modes can be combined by using by using the bitwise OR operator
     e.g.
    check_permission(0o754, stat.S_IROTH | stat.S_IWGRP)
    -> True

    Valid modes from stat:

        S_ISUID = 04000
        S_ISGID = 02000
        S_ENFMT = S_ISGID
        S_ISVTX = 01000
        S_IREAD = 00400
        S_IWRITE = 00200
        S_IEXEC = 00100
        S_IRWXU = 00700
        S_IRUSR = 00400
        S_IWUSR = 00200
        S_IXUSR = 00100
        S_IRWXG = 00070
        S_IRGRP = 00040
        S_IWGRP = 00020
        S_IXGRP = 00010
        S_IRWXO = 00007
        S_IROTH = 00004
        S_IWOTH = 00002
        S_IXOTH = 00001
    """
    return bool(perm_mode & flags)


def check_dir_perms(path, dir_perm=stat.S_IWOTH, file_perm=stat.S_IWOTH, users=('root',), groups=('root',), recurse=True):
    """
    Check dir structure and verify only specified users/groups have access

    If any directories have the dir_perm bits set we'll raise an error and the
    same goes for files matching file_perm bits.

    See check_permission for more info on how permission bit checking works.
    """
    directories = ((path, (), ()),) if not recurse else os.walk(path)
    for dir_name, sub_dirs, files in directories:
        attrib = os.stat(dir_name)
        if attrib.st_uid not in [pwd.getpwnam(user).pw_uid for user in users]:
            err_msg = 'Directory: "{0}" is owned by {1} which is not in the list of allowed users: "{2!s}"'
            raise PermError(err_msg.format(dir_name, pwd.getpwuid(attrib.st_uid).pw_name, users))

        if attrib.st_gid not in [grp.getgrnam(group).gr_gid for group in groups]:
            err_msg = 'The group for directory: "{0}" is {1} which is not in the list of allowed groups: "{2!s}"'
            raise PermError(err_msg.format(dir_name, grp.getgrgid(attrib.st_gid).gr_name, groups))

        if check_permission(attrib.st_mode, dir_perm):
            # Could add strmode for python one day and make nice human errors
            err_msg = 'The permissions on directory: "{0}" are "{1!s}" and violate restriction "{2!s}"'
            raise PermError(err_msg.format(dir_name, oct(attrib.st_mode), oct(dir_perm)))

        for f in files:
            file_attrib = os.stat(os.path.join(dir_name, f))
            if check_permission(file_attrib.st_mode, file_perm):
                # Could add strmode for python one day and make nice human errors
                err_msg = 'The permissions on file: "{0}" are "{1!s}" and violate restriction "{2!s}"'
                raise PermError(err_msg.format(os.path.join(dir_name, f), oct(file_attrib.st_mode), oct(file_perm)))


def match_owner_group(dest_path, source_path):
    """ Matches owner/group from one filesystem object to another """
    source_stat = os.stat(source_path)
    return os.chown(dest_path, source_stat[stat.ST_UID], source_stat[stat.ST_GID])


def mkdirp(path, inherit_owner_group=False, permission_mode=None, strict=False):
    """ Recursive mkdir (mkdir -p) """
    try:
        if permission_mode:
            os.makedirs(path, permission_mode)
        else:
            os.makedirs(path)
        logger.debug('Created directory: {0}'.format(path))
        if inherit_owner_group is True:
            match_owner_group(path, os.path.abspath(os.path.join(path, '../')))
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            if permission_mode and strict:
                try:
                    check_dir_perms(path,
                                    dir_perm=permission_mode,
                                    recurse=False)
                except PermError:
                    logger.debug('Provided path {0} exists and has incorrect permissions'.format(path))
                    raise
            pass
        else:
            raise


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

    PATHS = {'config_dir': '/etc/certmonger/letsencrypt',
             'work_dir': '/var/lib/certmonger/letsencrypt',
             'log_dir': '/var/log/letsencrypt'}

    defaults = certbot.constants.CLI_DEFAULTS

    def __init__(self,
                 paths=PATHS,
                 email=None,
                 key_size=4096,
                 verify_ssl=True,
                 user_agent='{0}/{1}'.format(__name__, __version__),
                 staging=True,
                 verbosity=logging.INFO):

        # Set up logging to use syslog
        logger.setLevel(verbosity)
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        formatter = logging.Formatter('%(module)s.%(funcName)s: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        # Load and store relevant environment variables
        self.environment = self.load_environment_variables()

        # If no email is specified we try to get one from the request
        if not email:
            try:
                email = self.environment['CERTMONGER_REQ_EMAIL']
            except KeyError:
                email = None
                self.defaults['register_unsafely_without_email'] = True

        self.defaults['email'] = email

        # Set key size
        self.defaults['key_size'] = key_size

        # Configure SSL/TLS Server cert verification
        self.defaults['verify_ssl'] = verify_ssl

        # Set prod/staging server selector
        if staging:
            self.defaults['staging'] = staging

        # Find all plugins and set
        self.defaults['plugins'] = certbot.plugins.disco.PluginsRegistry.find_all()

        # Set User Agent
        self.defaults['user_agent'] = user_agent

        # Override account directory
        self.defaults['accounts_dir'] = os.path.join(paths['config_dir'],
                                                     certbot.constants.ACCOUNTS_DIR,
                                                     self.environment['CERTMONGER_REQ_HOSTNAME'])

        # Create any directories which don't exist with correct
        # permisisons/owner/group and set in config
        for key, path in paths.iteritems():
            mkdirp(path, permission_mode=0o700)
            self.defaults[key] = path

        # Create config object from defaults in certbot and assign defaults
        Config = namedlist.namedlist('Config', ' '.join(self.defaults.keys()))
        self.namespace = Config(**self.defaults)
        self.config = certbot.configuration.NamespaceConfig(namespace=self.namespace)
        zope.component.provideUtility(self.config)

        # Configure displayer depending on if we have a tty or not
        if sys.stdout.isatty():
            self.displayer = certbot.display.util.NoninteractiveDisplay(sys.stdout)
        else:
            self.displayer = certbot.display.util.NoninteractiveDisplay(open(os.devnull, "w"))

        zope.component.provideUtility(self.displayer)

        # Set up Certbot Account Storage, at some point this should be moved
        # and stored by IPA in LDAP. For now we create separate accounts per
        # host and store details on the filesystem.
        account_storage = certbot.account.AccountFileStorage(self.config)
        accounts = account_storage.find_all()

        # Assume there will only be one account per host and that it will never
        # need to be updated with a new email address ...
        if len(accounts) == 0:
            # Register account with Let's Encrypt Server if needed, we always agree
            # to the TOS terms (see lambda).
            account, acme = certbot.client.register(config=self.config,
                                                    account_storage=account_storage,
                                                    tos_cb=lambda *_, **__: True)

            account_storage.save_regr(account, acme)
        else:
            acme = None
            account = accounts[0]

        # Instantiate authenticator using DNS/FreeIPA
        self.plugin = self.defaults['plugins']['cerlet:ipa'].init()
        # Instantiate the installer using Certmonger
        #self.installer = certbot.plugins.disco.PluginsRegistry.find_all()['cerlet:ipa']

        # Instantiate client
        self.client = certbot.client.Client(config=self.config,
                                            account_=account,
                                            auth=self.plugin,
                                            installer=self.plugin,
                                            acme=acme)

        return self.EXIT_ISSUED

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
        valid_operations = {'SUBMIT': cls().submit,
                            'POLL': cls().poll,
                            'IDENTIFY': cls().identify,
                            'GET-NEW-REQUEST-REQUIREMENTS': cls().requirements,
                            'GET-RENEW-REQUEST-REQUIREMENTS': cls().renew_requirements,
                            'GET-SUPPORTED-TEMPLATES': cls().templates,
                            'GET-DEFAULT-TEMPLATE': cls().default_template,
                            'FETCH-SCEP-CA-CAPS': cls()._raise_not_implemented,
                            'FETCH-SCEP-CA-CERTS': cls()._raise_not_implemented,
                            'FETCH-ROOTS': cls().get_ca_root_certs}
        return valid_operations[operation]()

    def register(self, config=None):
        certbot.main.register(config or self.config, unused_plugins=None)

    def submit(self, csr=None, domains=None, ca_profile=None, ca_nickname=None, ca_issuer=None):
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
        domains = domains or [self.environment['CERTMONGER_REQ_SUBJECT']]

        return self.client.obtain_certificate_from_csr(domains, csr)

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

        print('EMAIL and hostname at least')

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
        return self.description

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


@zope.interface.implementer(certbot.interfaces.IInstaller)
@zope.interface.provider(certbot.interfaces.IPluginFactory)
class Installer(certbot.plugins.common.Installer):
    """Certmonger Installer, outputs the cert to stdout"""
    description = __doc__.strip().split("\n", 1)[0]

    # pylint: disable=missing-docstring,no-self-use

    def prepare(self):
        pass  # pragma: no cover

    def more_info(self):
        return self.description

    def get_all_names(self):
        return []

    def deploy_cert(self, domain, cert_path, key_path,
                    chain_path=None, fullchain_path=None):
        with open(cert_path, "r") as f:
            shutil.copyfileobj(f, sys.stdout)

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


    # Implement all methods from IInstaller, remembering to add
    # "self" as first argument, e.g. def get_all_names(self)...

def main():
    """ Entry point when run directly """
    env = CertMongerAction.load_environment_variables()
    if env:
        CertMongerAction.operation_factory(os.getenv('CERTMONGER_OPERATION'))
    from pkg_resources import load_entry_point
    sys.argv += ['--authenticator', 'cerlet:ipa']
    sys.exit(load_entry_point('certbot', 'console_scripts', 'certbot')())
