#!/bin/sh

# taken from http://forum.centos-webpanel.com/ssl/ssl-certificate-generator-bash-script/
# in parts available at https://gist.github.com/bradland/1690807

fail_if_error() {
  [ $1 != 0 ] && {
    unset PASSPHRASE
    exit 10
  }
}

DOMAIN="server"

export PASSPHRASE="secret"

# solution from http://stackoverflow.com/questions/11153058/java7-refusing-to-trust-certificate-in-trust-store
# to enable a java 7+ using a self signed ca certificate
sed -i 's/^#\s*keyUsage/keyUsage/' /etc/ssl/openssl.cnf

# enable the default
sed -i 's/^#\s*input_password/input_password/' /etc/ssl/openssl.cnf
sed -i 's/^#\s*output_password/output_password/' /etc/ssl/openssl.cnf


subj="
C=DE
ST=Berlin
O=Hypoport AG
localityName=Berlin
commonName=Hypoport AG
organizationalUnitName=IT
emailAddress=info@hypoport.de
"


# makeca
echo "\nmakeca..."
openssl genrsa -des3 -out ${DOMAIN}CA.key -passout env:PASSPHRASE 4096
openssl req -new -x509 -days 3660 -keyout ${DOMAIN}CA.key -out ${DOMAIN}CA.crt -config /etc/ssl/openssl.cnf -extensions v3_ca -passin env:PASSPHRASE -batch
fail_if_error $?

#makekey
echo "\nmakekey..."
openssl genrsa -des3 -out ${DOMAIN}.key -passout env:PASSPHRASE 2048
fail_if_error $?

#makecsr
echo "\nmakecsr..."
openssl req \
    -new \
    -batch \
    -subj "$(echo -n "$subj" | tr "\n" "/")" \
    -key ${DOMAIN}.key \
    -out ${DOMAIN}.csr \
    -passin env:PASSPHRASE
fail_if_error $?

# remove passphrase
cp ${DOMAIN}.key ${DOMAIN}.key.org
openssl rsa -in ${DOMAIN}.key.org -out ${DOMAIN}.key -passin env:PASSPHRASE
fail_if_error $?

#signcrt
echo "\nsigncrt..."
#openssl x509 -req -days 3650 -in ${DOMAIN}.csr -signkey ${DOMAIN}.key -out ${DOMAIN}.crt
openssl x509 -req -days 1825 -in ${DOMAIN}.csr -CA ${DOMAIN}CA.crt -CAkey ${DOMAIN}CA.key -set_serial 01 -out ${DOMAIN}.crt -passin env:PASSPHRASE
fail_if_error $?

#makedh
#/bin/dd if=/dev/urandom of=ssldh.rand count=1 2>/dev/null
#/usr/bin/openssl gendh -rand ssldh.rand 512 > ${DOMAIN}.dh
#fail_if_error $?

#makepem
cat ${DOMAIN}.key > ${DOMAIN}Chain.pem
cat ${DOMAIN}.crt >> ${DOMAIN}Chain.pem

exit 0