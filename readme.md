# Advanced Encryption Standard (Rijndael)

### Usage

```
AES-128 encryption | Usage:
	-k, --key-len      mention the key length in bytes, possible options are 16, 24 or 32.
	-m, --mode         mention the procedure, either 'encrypt' or 'decrypt' without quotes.
	-f, --file         provide the filename with relative/absolute path to encrypt/decrypt it.
	                   not to be used with: -h, --hex, -c, --console.
	-c, --console      encrypt/decrypt ASCII plaintext through console.
	                   not to be used with: -f, --file.
	-h, --hex          when in console mode, output encrypted bytes and input to decrypt bytes in hexadecimal string.
	                   to be used with: -c or --console.
	                   not to be used with: -f, --file.
```

For example, to encrypt a `file.ext` with a 128 bits key, execute
```
./aes.py -m encrypt -f file.ext -k 16
```
and input the key after the console prompt. `file.ext` will be changed (overwritten, encrypted).

Similarly to decrypt the encrypted file `file.ext` with the same key, execute
```
./aes.py -m decrypt -f file.ext -k 16
```
and input the key like before.

You must make `aes.py` to be executable to execute the previous commands.
```
chmod +x aes.py
```
If you don't want to do that however, add `python3` to the prefix of those encryption and decryption commands.

### Caution

Don't pull the following stunt:
```
./aes.py -m encrypt -f aes.py
```

This script doesn't keep info over which files are encrypted, which are not. So, a single file can very well be encrypted multiple times, with different keys. Make sure to decrypt them in a reverse manner. Also, make sure not to decrypt a non-encrypted file. (The behaviour is untested.)
