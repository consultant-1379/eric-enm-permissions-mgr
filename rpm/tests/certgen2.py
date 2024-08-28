import os
import sys
from OpenSSL import crypto, SSL
from random import randint

def kubernetes_cert_gen(
    emailAddress="ericsson@ericsson.com",
    countryName="SE",
    localityName="NA",
    stateOrProvinceName="NA",
    organizationName="Ericsson",
    organizationUnitName="BUCI_DUAC_NAM",
    validityStartInSeconds=0,
    validityEndInSeconds=10*365*24*60*60):
    try:

        try:
            ca_key  = crypto.PKey()
            ca_key.generate_key(crypto.TYPE_RSA, 4096)
            
            ca_cert = crypto.X509()
            ca_cert.set_version(2)
            ca_cert.set_serial_number(randint(50000000,100000000))
            
            ca_subj = ca_cert.get_subject()
            ca_subj.C = "SE"
            ca_subj.O = "ERICSSON"
            ca_subj.OU = "BUCI_DUAC_NAM"
            ca_subj.CN = "ENM_UI_CA"

            ca_cert.add_extensions([
                crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
                crypto.X509Extension(b"basicConstraints", False, b"CA:TRUE"),
                crypto.X509Extension(b"keyUsage", False, b"keyCertSign, cRLSign"),
            ])
            
            ca_cert.gmtime_adj_notBefore(0)
            ca_cert.gmtime_adj_notAfter(validityEndInSeconds)
            ca_cert.set_issuer(ca_subj)
            ca_cert.set_pubkey(ca_key)
            ca_cert.sign(ca_key, 'sha256')

        except Exception as e:
            print("failed to create ca certificate")
            print(e)
        #####################
        #  Server Cert
        #####################

        try:
            client_key  = crypto.PKey()
            client_key.generate_key(crypto.TYPE_RSA, 4096)
            req = crypto.X509Req()
            req.set_version(2)
            serialNumber = randint(50000000,100000000)
            subject = req.get_subject()
            subject.commonName = "eric-enm-permissions-mgr-task"
            subject.C = "SE"
            subject.O = "ERICSSON"
            subject.OU = "BUCI_DUAC_NAM"
            subject.CN = "eric-enm-permissions-mgr-task"
            san_list = ["DNS:*.eric-enm-permissions-mgr-task", "DNS:eric-enm-permissions-mgr-task"]
            
            req.set_pubkey(client_key)
            req.sign(ca_key, "sha512")   

            client_cert = crypto.X509()
            client_cert.add_extensions([
                crypto.X509Extension(b"subjectAltName", False, ", ".join(san_list).encode("UTF-8")),
                crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
                crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
                crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert),
                crypto.X509Extension(b"extendedKeyUsage", False, b"clientAuth"),
                crypto.X509Extension(b"keyUsage", False, b"digitalSignature"),
            ])
            client_cert.gmtime_adj_notBefore(0)
            client_cert.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
            client_cert.set_serial_number(serialNumber)
            client_cert.set_issuer(ca_cert.get_subject())
            client_cert.set_subject(req.get_subject())
            client_cert.set_pubkey(req.get_pubkey())
            client_cert.sign(ca_key, 'sha512') 
        except Exception as e:
            print("failed to create server certificate")
            print(e)
    except Exception as e:
        print("test")
        print(e)

kubernetes_cert_gen()