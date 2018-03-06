# CerLet

## Certbot plugin and CertMonger Helper

# WORK IN PROGRESS, INCOMPLETE!

CertLet is both a Certbot plugin to allow IPA (FreeIPA/Redhat Satellite) DNS
authentication for authentication of and a Certmonger Helper to allow FreeIPA
to use Let's Encrypt certificates.

This allows hosts in FreeIPA to automatically get publicly trusted certificates
for all purposes and allows hosts to get valid certificates for multiple domain
names.

Due to using DNS based authentication certificates can be issued for private
servers as well as public ones without any service interruptions. This also
allows certificates to include multiple principals or up to 99 host/DNS names.

### Steps to install

 sudo getcert add-ca -c LetsEncrypt -e $(which cerlet)

### Steps to set up a development environment on a Fedora box:
umask 0002
sudo dnf update -y
sudo dnf -y install wget git gcc openldap-devel krb5-devel libffi-devel
sudo dnf -y install ca-certificates
sudo dnf install python3-virtualenv
sudo wget https://letsencrypt.org/certs/isrgrootx1.pem -O /etc/pki/ca-trust/source/anchors/isrgrootx2.pem
sudo update-ca-trust force-enable && sudo update-ca-trust extract
sudo ipa-client-install --ca-cert-file=/etc/pki/ca-trust/source/anchors/isrgrootx1.pem
mkdir -p $HOME/Revisions && cd $HOME/Revisions
git clone git@github.com:antevens/cerlet.git && cd $HOME/Revisions/cerlet
virtualenv-3.6 -p python3.6 /home/vagrant/Virtualenv
source /home/vagrant/Virtualenv/bin/activate
python setup.py develop
kinit && cerlet

## FAQ
### What does it mean when I get an error like:
KerberosError: No valid Negotiate header in server response

This means you don't have a valid kerberos ticket to communicate with FreeIPA
and perform the required API calls to modify DNS entries as required.
Try using kinit to get a valid kerberos ticket with the permissions to modify
DNS entries.

## How does the following error mean:
ipalib.errors.KerberosError: Major (851968): Unspecified GSS failure.  Minor code may provide more information, Minor (2529638949): Clock skew too great

This is usually because you're using a virtual machine and it's been suspended
for a while, this causes the clock on the virtual machine to go out of sync and will need to be re-adjusted, if NTP is installed the easiest way to update the clock is:
*sudo ntpdate -u pool.ntp.org*
