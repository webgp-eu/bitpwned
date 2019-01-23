# Bitpwned
Bitpwned allows to check if the passwords stored in a [Bitwarden](https://www.bitwarden.com) vault are present in the database of stolen passwords hosted by Troy Hunt at [haveibeenpwned](https://haveibeenpwned.com/Passwords) website. It can now check for duplicate passwords in the password's list.

In order to use it, one has to have installed [Bitwarden CLI Tool](https://help.bitwarden.com/article/cli/) and Python 3.5+.

I Have Been Pwned implements a  [k-Anonymity model](https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange) that allows a password to be searched sending only a part of its hash to the website. So, the password is not sent to I Have Been Pwned (and nowhere else, obviously). But in any case, use this tool at your own risk.

## Usage

```
usage: Check your Bitwarden stored passwords against haveibeenpwned.com database of stolen passwords. It can also check if there are duplicate passwords in your vault.
[-h] [-p BW_PASSWORD] [-o OUTPUT_FILE] [-d] bw_email

positional arguments:
  bw_email        Bitwarden login email

optional arguments:
  -h, --help      show this help message and exit
  -p BW_PASSWORD  Bitwarden master password
  -o OUTPUT_FILE  Path of the file where the report should be written
  -d              Check for duplicate passwords
```

You have to give your Bitwarden username as first argument. With the flag ``-d``, you check duplicate passwords. Without this flag, the passwords are checked against the database of passwords hosted at ihavebeenpwned.com.  
There are two optional arguments: the master password of your Bitwarden vault (if it is not passed as an argument, Bitwarden CLI tool will ask for it, and probably it is safer...), and the file in which the report should be stored.

### Example: 
```
python bitpwned.py example@example.com -p myverystrongpassword -o pwnedpasswords.txt
python bipwned.py example@example.com -d -o suplicatepasswords.txt
```
### License
This script is released under GNU General Public License v3.0 license and it is not in any way affiliated or endorsed by Bitwarden or I Have Been Pwned.
