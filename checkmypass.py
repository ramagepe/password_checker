import requests
import hashlib
from sys import argv, exit

# TODO: Secure file traffic and storage --no-flags
# TODO: Accept raw format as an argument (symbols not taken as valid chars)


def request_api_data(query_char):
    url = f'https://api.pwnedpasswords.com/range/{query_char}'
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(
            f'Error fetching ({response.status_code}) => check API and try again')
    return response


def generate_hash(password):
    return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()


def get_leaks(hashes, hash_to_check):
    hashes = [line.split(':') for line in hashes.splitlines()]
    for hash, leaks in hashes:
        if hash_to_check == hash:
            return leaks
    return 0


def pass_api_check(password):
    hash = generate_hash(password)
    hash_first5, hash_tail = hash[:5], hash[5:]
    res = request_api_data(hash_first5)
    leaks = get_leaks(res.text, hash_tail)
    return leaks

##### FILE RELATED FUNCS #####
def get_file(filepath):
    with open(filepath, 'r') as pass_file:
        return pass_file.readlines()


def generate_hashedfile(filepath, new_filepath):
    with open(filepath, 'r') as plain_file:
        hashed_list = [generate_hash(pass_to_hash)
                       for pass_to_hash in plain_file.readlines()]
    with open(new_filepath, 'w') as hashed_file:
        for hashed_pass in hashed_list:
            hashed_file.write(hashed_pass)

def main(args):
    for password in args:
        leaks = pass_api_check(password)
        if leaks:
            print(
                f'WARNING!! --> Password "{password}" was found {leaks} times. You should change that one...')
        else:
            print(f'Password "{password}" not found. That\'s a good one!')
    return 'done!'


if __name__ == '__main__':
    # file = './passwords.txt'
    # # generate_hashedfile(file, './hashed_passwords.txt')
    # passwords_list = get_file('./passwords.txt')
    # exit(main(passwords_list))

    # sys.exit() prints the value returned by main
    exit(main(argv[1:]))
