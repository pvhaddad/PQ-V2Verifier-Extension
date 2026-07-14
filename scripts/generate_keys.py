import os
import oqs
from fastecdsa import keys, curve, ecdsa
from fastecdsa.keys import import_key, export_key
import sys
import argparse

def generate_ecdsa_p256_keypairs():

    publicKeyPathRoot = os.getcwd() + "/keys/"
    privateKeyPathRoot = os.getcwd() + "/keys/"

    for i in range(0, 10):
        privateKey, publicKey = keys.gen_keypair(curve.P256)

        privateKeyPath = privateKeyPathRoot + "/" + str(i) + "/p256.key"
        publicKeyPath = publicKeyPathRoot + "/" + str(i) + "/p256.pub"

        export_key(privateKey, curve=curve.P256, filepath=privateKeyPath)
        export_key(publicKey, curve=curve.P256, filepath=publicKeyPath)

def generate_rainbow_keypairs():
    publicKeyPathRoot = os.getcwd() + "/rainbow_keys/"  # points to "current working directory" and then directory where keys are stored
    privateKeyPathRoot = os.getcwd() + "/rainbow_keys/"

    for i in range(0, 10):
        # from sig.py:
        # create signer and verifier with default signature mechanisms
        sigalg = "Rainbow-I-Classic"
        with oqs.Signature(sigalg) as signer:
            # pprint(signer.details)
            # print("Key Generation",i)
            # signer generates its keypair
            publicKey = signer.generate_keypair()
            privateKey = signer.export_secret_key()
            # end sig.py

            privateKeyPath = privateKeyPathRoot + "/" + str(
                i) + "/rainbow.key"  # stating path to where each key pair is stored
            publicKeyPath = publicKeyPathRoot + "/" + str(i) + "/rainbow.pub"

            privateKey_hex = privateKey.hex()  # bytes to hex encoding
            publicKey_hex = publicKey.hex()

            outF = open(privateKeyPath, "w")  # print keys out
            # write line to output file
            outF.write(privateKey_hex)
            outF.close()

            outF = open(publicKeyPath, "w")
            # write line to output file
            outF.write(publicKey_hex)
            outF.close()

def generate_dilithium_keypairs():
    publicKeyPathRoot = os.getcwd() + "/dilithium_keys/"  # points to "current working directory" and then directory where keys are stored
    privateKeyPathRoot = os.getcwd() + "/dilithium_keys/"

    for i in range(0, 10):
        # from sig.py:
        # create signer and verifier with default signature mechanisms
        sigalg = "Dilithium2"
        with oqs.Signature(sigalg) as signer:
            # pprint(signer.details)
            # print("Key Generation",i)
            # signer generates its keypair
            publicKey = signer.generate_keypair()
            privateKey = signer.export_secret_key()
            # end sig.py

            privateKeyPath = privateKeyPathRoot + "/" + str(
                i) + "/dilithium.key"  # stating path to where each key pair is stored
            publicKeyPath = publicKeyPathRoot + "/" + str(i) + "/dilithium.pub"

            privateKey_hex = privateKey.hex()  # bytes to hex encoding
            publicKey_hex = publicKey.hex()

            outF = open(privateKeyPath, "w")  # print keys out
            # write line to output file
            outF.write(privateKey_hex)
            outF.close()

            outF = open(publicKeyPath, "w")
            # write line to output file
            outF.write(publicKey_hex)
            outF.close()

def generate_falcon_keypairs():
    from hashlib import sha256  # do we need this?
    from pprint import pprint
    import os  # python module for interacting with the OS
    import oqs  # liboqs python module

    if __name__ == "__main__":

        publicKeyPathRoot = os.getcwd() + "/falcon_keys/"  # points to "current working directory" and then directory where keys are stored
        privateKeyPathRoot = os.getcwd() + "/falcon_keys/"

        for i in range(0, 10):
            # from sig.py:
            # create signer and verifier with default signature mechanisms
            sigalg = "Falcon-512"
            with oqs.Signature(sigalg) as signer:
                # pprint(signer.details)
                # print("Key Generation",i)
                # signer generates its keypair
                publicKey = signer.generate_keypair()
                privateKey = signer.export_secret_key()
                # end sig.py

                privateKeyPath = privateKeyPathRoot + "/" + str(
                    i) + "/falcon.key"  # stating path to where each key pair is stored
                publicKeyPath = publicKeyPathRoot + "/" + str(i) + "/falcon.pub"

                privateKey_hex = privateKey.hex()  # bytes to hex encoding
                publicKey_hex = publicKey.hex()

                outF = open(privateKeyPath, "w")  # print keys out
                # write line to output file
                outF.write(privateKey_hex)
                outF.close()

                outF = open(publicKeyPath, "w")
                # write line to output file
                outF.write(publicKey_hex)
                outF.close()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Generate key pairs for one of several algorithms")
    parser.add_argument("algorithm",
                        help="choice of algorithm for generated key pairs",
                        choices=["falcon-512", "dilithium", "rainbow", "ecdsa-p256", "all"]
                        )

    args = parser.parse_args()

    if args.algorithm == "ecdsa-p256":
        if not os.path.exists('keys'):
            os.mkdir('keys')
            os.chdir('keys')
            for i in range(10):
                os.mkdir(str(i))
            os.chdir('..')
        generate_ecdsa_p256_keypairs()
    elif args.algorithm == "falcon-512":
        if not os.path.exists('falcon_keys'):
            os.mkdir('falcon_keys')
            os.chdir('falcon_keys')
            for i in range(10):
                os.mkdir(str(i))
            os.chdir('..')
        generate_falcon_keypairs()
    elif args.algorithm == "dilithium":
        if not os.path.exists('dilithium_keys'):
            os.mkdir('dilithium_keys')
            os.chdir('dilithium_keys')
            for i in range(10):
                os.mkdir(str(i))
            os.chdir('..')
        generate_dilithium_keypairs()
    elif args.algorithm == "rainbow":
        generate_rainbow_keypairs()
    elif args.algorithm == "all":
        generate_rainbow_keypairs()
        generate_dilithium_keypairs()
        generate_falcon_keypairs()
        generate_ecdsa_p256_keypairs()