## Calculate the MD5 and SHA256 fingerprints from a Cisco crypto public rsa key

When accessing a Cisco router with a ssh or putty session, at the first
attempt you will be asked to verify the displayed fingerprint of the rsa key.
Cisco provides a command "show crypto key mypubkey rsa", but the generated
output does not provide the needed fingerprint.

Some years ago Didier Stevens offered a solution for the MD5 fingerprint:

https://blog.didierstevens.com/2012/01/01/calculating-a-ssh-fingerprint-from-a-cisco-public-key/

https://blog.didierstevens.com/2014/09/01/update-calculating-a-ssh-fingerprint-from-a-cisco-public-key/

Anyway, meanwhile the ssh clients have changed to use the SHA256 fingerprint.
The source of the python 2 script cisco-calculate-ssh-fingerprint.py found in

https://github.com/DidierStevens/DidierStevensSuite/blob/master/cisco-calculate-ssh-fingerprint.py

does not generates the SHA256 fingerprint, in spite of the indication in the above
web pages.

The included file cisco_ssh_fingerprint.py is the above mentioned script reengineered
for python3, which also generates the SHA256 fingerprint.

### Usage
from the Cisco output (my_crypto_key.txt) extract the 5 lines of the pubilc
key hex dump und put them in a file (e.g.: my_crypto_key.hex).
Then run the script with this file as input:

```
$ python3 cisco_ssh_fingerprint.py -f my_crypto_key.hex
MD5:    04:ec:ff:f9:f0:dc:60:b6:10:7f:dc:d6:7d:5e:ea:25
SHA256: pksSqc5yH2lRFn1UGTd7d9PqKER1w62Udgwwrn5rhw8=
```

An additional goodie: if the -f option is not used, the required hex dump can
be entered with a cut&paste operation.
