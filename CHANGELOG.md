# Changelog

## 0.3.1

* Add restrictions on `cryptography` package to avoid 
  [CVE-2020-25659](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25659).
  python-cryptography 3.2 is vulnerable to Bleichenbacher timing attacks in the
  RSA decryption API, via timed processing of valid PKCS#1 v1.5 ciphertext. 

## 0.3.0

* Increased maximum allowed version of Cryptography library.
  Now it requires cryptography < 4.0.
* Added running tests on Python 3.6-3.8.
* Stop running tests on Python 3.4.

## 0.2.1

* Increased maximum allowed version of Cryptography library.
  Now it requires cryptography < 3.0.

## 0.2.0

* Replaced use of M2Crypto with Cryptography library
* Added python3 support
* Drop support for python 2.6

## 0.1.0

* Added a timeout parameter to verify() and get_ticket_data(). Defaults
  to 2 hours, like mod_auth_tkt.

## 0.0.1

* Initial release.
