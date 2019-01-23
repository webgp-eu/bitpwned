import hashlib
import requests
import subprocess
import sys
import json
import argparse


def test_pw(password):
    """
    Test password against haveibeenpwned.com

    args:
        password: string
    returns:
        -1 if the request status code is different from 200
        0 if the password is not in the database
        an int representin the number of breaches in which the password is present, otherwise
    """
    password = password.encode()
    m = hashlib.sha1(password)
    digest = m.hexdigest().upper()
    response = requests.get(f'https://api.pwnedpasswords.com/range/{digest[:5]}')
    if response.status_code != 200:
        return -1
    for line in response.text.split('\n'):
        res = line.split(':')
        if res[0] == digest[5:]:
            return int(res[1])
    else:
        return 0
    

"""
Helper functions to deal with Bitwarden CLI
"""
def run_command(cmd, *args):
    ls = [cmd] + [a for a in args]
    result = subprocess.run(ls, stdout=subprocess.PIPE)
    return result.stdout.decode('utf-8')

def bw_login(email, password):
    return run_command('bw', 'login', email, password, '--raw')

def bw_logout():
    return run_command('bw', 'logout')

def bw_sync(key):
    return run_command('bw', 'sync', '--session', key)

def bw_get_items(key):
    return run_command('bw', 'list', 'items', '--session', key)


def write(stri, f):
    """
    Write on file or on screen
    """
    if f:
        f.write(stri + "\n")
    else:
        print(stri)

def get_item(item):
    name = item.get('name', 'Name missing')
    login = item.get('login', None)
    if login:
        username = login.get('username', 'Username missing')
        password = login.get('password', None)
    else:
        username = None
        password = None
    return name, username, password


def check_pwned(items_list, f):
    # check passwords one by one against ihavebeenpwned database
    # and add result to the report
    for item in items_list:
        res = 0
        name, username, password = get_item(item)
        try:
            if password:
                res = test_pw(password)
            if res > 0:
                out_stri = "{} {} {} {}".format(name, username, password, res)
                write(out_stri, f)
            elif res == -1:
                stri = "Error with the request...{} skipped...".format(name)
                write(stri, f)
        except KeyError:
            stri = "{} skipped...".format(name)
            write(stri, f)

def check_duplicates(items_list, f):
    # check password list for duplicates and add duplicates to the report
    print("checking duplicates...")
    pwds = dict()
    for item in items_list:
        name, username, password = get_item(item)
        if password:
            ps = pwds.get(password, [])
            ps.append((name, username))
            pwds[password] = ps
    duplicates = [pwd for pwd, values in pwds.items() if len(values) > 1]
    for d in duplicates:
        write(d,f)
        for it in pwds[d]:
            write(str(it[0]) + ' ' + str(it[1]),f)
        write("\n", f)


f = None
try:
    bw_password = ""
    output_file = None

    ## Parse arguments
    parser = argparse.ArgumentParser("Check your Bitwarden stored passwords against haveibeenpwned.com database of stolen passwords. It can also check if there are duplicate passwords in your vault.")
    parser.add_argument('bw_email', help="Bitwarden login email")
    parser.add_argument('-p', dest="bw_password", help="Bitwarden master password")
    parser.add_argument('-o', dest="output_file", help="Path of the file where the report should be written")
    parser.add_argument('-d', action='store_true', dest="duplicate", help="Check for duplicate passwords")    

    args = parser.parse_args()
    bw_email = args.bw_email
    if args.bw_password:
        bw_password = args.bw_password  
    if args.output_file:
        output_file = args.output_file
    if args.duplicate:
        duplicate = args.duplicate
    else:
        duplicate = False
    # Login in Bitwarden
    session_key = bw_login(bw_email, bw_password)
    if "incorrect" in session_key:
        print(session_key)
        sys.exit()
    else:
        logged = True
   
   # sync vault
    sync = bw_sync(session_key)
    print(sync)
    if " complete" not in sync:
        print('Cannot sync...Exiting...')
        print(bw_logout())
        sys.exit()

    # retrieve passwords    
    items = bw_get_items(session_key)
    try:
        items_list = json.loads(items)
    except json.decoder.JSONDecodeError:
        print('Cannot retrieve objects....Exiting...')
        print(bw_logout())
        sys.exit()

    # write on file or on screen?
    print("Checking {} passwords...".format(len(items_list)))
    if output_file:
        f = open(output_file, 'w')
        print("Saving report in: {}".format(output_file))
    if duplicate:
        check_duplicates(items_list, f)
    else:
        check_pwned(items_list, f)
    print()
except Exception:
    print("Unknown error...Exiting...")
    raise
finally:
    # in any case, close file if it is open and log out from Bitwarden
    try:
        if f:
            f.close()
            print("File closed")
        if logged:
            print(bw_logout())
    except NameError:
        pass
