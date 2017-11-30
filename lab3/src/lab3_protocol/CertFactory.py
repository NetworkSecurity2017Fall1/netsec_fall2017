import os


def getPrivateKeyForAddr(addr):
    pwd = os.path.dirname(__file__)
    with open(pwd + '/client_certificate/local.key', 'r+b') as root_cert_file:
        return root_cert_file.read()


def getCertsForAddr(addr):
    cert = []
    pwd = os.path.dirname(__file__)
    with open(pwd + '/client_certificate/local.cert', 'r+b') as cert_file:
        cert.append(cert_file.read())
    with open(pwd + '/client_certificate/int.cert', 'r+b') as int_cert_file:
        cert.append(int_cert_file.read())
    with open(pwd + '/client_certificate/root.crt', 'r+b') as root_cert_file:
        cert.append(root_cert_file.read())
    return cert


def getRootCert():
    pwd = os.path.dirname(__file__)
    with open(pwd + '/client_certificate/root.crt', 'r+b') as root_cert_file:
        return root_cert_file.read()
