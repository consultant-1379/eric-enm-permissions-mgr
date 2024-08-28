import os
import sys
from OpenSSL import crypto, SSL
from random import randint

def cert_gen(
    emailAddress="emailAddress",
    commonName="localhost",
    countryName="NT",
    localityName="localityName",
    stateOrProvinceName="stateOrProvinceName",
    organizationName="organizationName",
    organizationUnitName="organizationUnitName",
    serialNumber=randint(50000000,100000000),
    validityStartInSeconds=0,
    validityEndInSeconds=10*365*24*60*60,
    KEY_FILE = "server.key",
    PUBLIC_KEY_FILE = "serverp.key",
    CERT_FILE="server.crt"):

    from cryptography.hazmat.primitives.asymmetric import rsa


    ca_key  = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 4096)
    
    ca_cert = crypto.X509()
    ca_cert.set_version(2)
    ca_cert.set_serial_number(randint(50000000,100000000))
    
    ca_subj = ca_cert.get_subject()
    ca_subj.O = "ERICSSON"
    ca_subj.OU = "BUCI_DUAC_NAM"

    # san_list = ["DNS:*.localhost", "DNS:localhost"]
    # ca_cert.add_extensions([
    #     crypto.X509Extension(b"subjectAltName", False, ", ".join(san_list).encode("UTF-8")),
    # ])
    
    ca_cert.add_extensions([
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
        crypto.X509Extension(b"basicConstraints", False, b"CA:TRUE"),
        crypto.X509Extension(b"keyUsage", False, b"keyCertSign, cRLSign"),
    ])
    
    import base64
    print(str(base64.b64encode(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))))
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(validityEndInSeconds)
    ca_cert.set_issuer(ca_subj)
    ca_cert.set_pubkey(ca_key)
    ca_cert.sign(ca_key, 'sha512')

    # ca_cert.set_issuer(req.get_subject())
    # ca_cert.set_subject(req.get_subject())
    # ca_cert.set_pubkey(req.get_pubkey())
    # ca_cert.sign(pkey, "sha256")

    
    with open("ca.crt", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode("utf-8"))
    with open("ca.key", "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key).decode("utf-8"))
    with open("cap.key", "wt") as f:
        f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, ca_key).decode("utf-8"))

    #####################
    #  Server Cert
    #####################
    
    server_key  = crypto.PKey()
    server_key.generate_key(crypto.TYPE_RSA, 4096)
    req = crypto.X509Req()
    req.set_version(2)
    serialNumber = randint(50000000,100000000)
    subject = req.get_subject()
    subject.O = "ERICSSON"
    subject.OU = "BUCI_DUAC_NAM"
    subject.CN = "localhost"
    san_list = ["DNS:*.localhost", "DNS:localhost"]

    req.set_pubkey(server_key)
    req.sign(ca_key, "sha512")   

    server_cert = crypto.X509()
    server_cert.add_extensions([
        crypto.X509Extension(b"subjectAltName", False, ", ".join(san_list).encode("UTF-8")),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_cert),
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
        crypto.X509Extension(b"keyUsage", False, b"digitalSignature, keyEncipherment, dataEncipherment"),
    ])
    server_cert.gmtime_adj_notBefore(0)
    server_cert.gmtime_adj_notAfter(5 * 365 * 24 * 60 * 60)
    server_cert.set_serial_number(serialNumber)
    server_cert.set_issuer(ca_cert.get_subject())
    server_cert.set_subject(req.get_subject())
    server_cert.set_pubkey(req.get_pubkey())
    server_cert.sign(ca_key, 'sha512') 
    
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key).decode("utf-8"))
    with open(PUBLIC_KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, server_key).decode("utf-8"))

    ###############
    # Client Cert #
    ###############

    client_key  = crypto.PKey()
    client_key.generate_key(crypto.TYPE_RSA, 4096)
    req = crypto.X509Req()
    req.set_version(2)
    serialNumber = randint(50000000,100000000)
    subject = req.get_subject()
    subject.commonName = "eric-enm-permissions-mgr-job"
    subject.C = "SE"
    subject.O = "Default Company"
    subject.OU = "BUCI_DUAC_NAM"
    subject.CN = "localhost"
    san_list = ["DNS:*.localhost", "DNS:localhost"]
    
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

    # Save certificate
    with open("client.crt", "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert).decode("utf-8"))
    with open("client.key", "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key).decode("utf-8"))

    print(base64.b64encode(
       b"".join([crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert), crypto.dump_certificate(crypto.FILETYPE_PEM, server_cert)]
    )).decode("utf-8"))
cert_gen()