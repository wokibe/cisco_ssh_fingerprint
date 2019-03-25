# Calculate the SHA256 fingerprint from a Cisco crypto public rsa key

When accessing a Cisco router with a ssh or putty session, at the first
attempt you will be asked to verify the displayed fingerprint of the rsa key.
Cisco provides a command "show crypto key mypubkey rsa", but the generated
output does not provide the needed fingerprint.

Some years ago Didier Stevens offered a solution for the MD5 fingerprint:

https://blog.didierstevens.com/2012/01/01/calculating-a-ssh-fingerprint-from-a-cisco-public-key/

https://blog.didierstevens.com/2014/09/01/update-calculating-a-ssh-fingerprint-from-a-cisco-public-key/

Anyway, meanwhile the ssh clients have changed to use the SHA256 fingerprint.
The included Python2(!) script solves this challenge.

### Usage
from the Cisco output (my_crypto_key.txt) extract the 5 lines of the pubilc
key hex dump und put them in a file (e.g.: my_crypto_key.hex).
Then run the script with this file as input:

$ python cisco-calculate-ssh-fingerprint.py my_crypto_key.hex

SHA256: pksSqc5yH2lRFn1UGTd7d9PqKER1w62Udgwwrn5rhw8=
