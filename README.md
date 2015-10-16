# tpmadmin.py

Administration tool for [Team Password Manager](http://teampasswordmanager.com/). Currently, the only functionallity implemented is to export passwords to a CSV file, possibly unlocking all passwords where needed.

Requires Python 3. Code is easely extended to other parts of the [TPM API](http://teampasswordmanager.com/docs/api/).


## Usage


```
usage: tpmadmin.py [-h] --mode {export} --url URL [--private-key KEY]
                   [--public-key KEY] [--user USER] [--password PASSWORD]
                   [--unlock REASON]

Team Password Manager administration

optional arguments:
  -h, --help           show this help message and exit
  --mode {export}      export: exports all passwords in a CSV format
  --url URL            URL of TPM like https://tpm.mydomain.com/index.php
  --private-key KEY    private key from the user settings in TPM
  --public-key KEY     public key from the user settings in TPM
  --user USER          username to log into TPM
  --password PASSWORD  password to log into TPM
  --unlock REASON      unlock passwords

Use either private/public key (preferred) or username/password authentication.
```

## License
MIT license, see LICENSE file.