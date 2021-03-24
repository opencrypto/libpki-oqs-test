# libpki-oqs-test
Quick tool for building the OQS OpenSSL and LibPKI w/ Support for Post-Quantum Algorithms

# Usage
This is a quick tool we use to ease building LibPKI and OpenSSL w/ Open Quantum Safe support and an initial implementation for Composite Crypto.

To fetch and build the libraries and tools, you can run:
```
$ ./build.sh
```
the script will fetch the liboqs repo and build that first. After installation it is the turn for the OQS OpenSSL's repo. After the openssl w/ OQS support is built and installed, the script fetches the libpki (libpki-oqs branch), builds it, and installs it in the same location.

All compiled software is installed in /opt/libpki-oqs.

Please review the build.sh script and change the configuration there.

# Enabling Different OQS algorithms

In the config-n-patch/oqs-config inside the repo, you will find a YML config file (libpki-generate-template.yml) that you can use to generate support for different post-quantum algorithms in OpenSSL.

To use it, you edit and add/remove the options that are not needed in your environment and follow the procedures described in the OQS repo (https://github.com/open-quantum-safe/openssl) - see the code generation section from here (https://github.com/open-quantum-safe/openssl/wiki/Using-liboqs-algorithms-not-in-the-fork#code-generation).

# Enabling Composite Crypto (Besides OQS Composite Crypto Support)

In order to enable the use of Composite Crypto as a generic Algorithm OID and then use the PKEY creation to combine different Keys into your multi-key (Composite) one, you need to look into the config-n-patch/ossl_patch directory - there you will find the current skeleton for implementing the EVP_PKEY_METHOD and EVP_PKEY_ASN1_METHOD (and all pointers in different include files).
