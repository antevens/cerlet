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
