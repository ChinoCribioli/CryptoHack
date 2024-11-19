from Crypto.PublicKey import RSA
raw = open('2048b-rsa-example-cert.der', 'rb').read()

from cryptography.x509 import load_der_x509_certificate

cert = load_der_x509_certificate(raw)
print(cert.public_key().public_numbers().n)
