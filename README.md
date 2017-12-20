# CerLet CertMonger Let's Encrypt Helper

WORK IN PROGRESS, INCOMPLETE!

Helper integration to allow certmonger to communicate with the Let's Encrypt CA

This package integrates Certmonger (and by extension FreeIPA/Sattellite) with
the Let's Encrypt community Certificate Authority.

This allows hosts in FreeIPA to automatically get publically trusted certificates
for all purposes.

Due to using DNS based authentication certificates ban be issued for private
servers as well as public ones without any service interruptions. This also
allows certificates to include an alias per principal or any number of host/DNS
names.

This package includes python libraries which will be installed in the default
site-packages directory of your python distribution (or virtualenv) and an entry
point script that will be installed under /usr/libexec/certmonger.


#Steps to set up a development environment on a Fedora box:
umask 0002
sudo dnf update -y
sudo dnf -y install wget git gcc openldap-devel krb5-devel
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
