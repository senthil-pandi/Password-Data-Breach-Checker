import requests
import hashlib
import sys

def request_api_data(query_char):
  '''This function is used to get the breach data
  of passwords from pwned.com website.
  '''  
  url = 'https://api.pwnedpasswords.com/range/' + query_char
  res = requests.get(url)
  if res.status_code != 200:
    raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
  return res

def get_password_leaks_count(hashes, hash_to_check):
  '''This function is used to count the number of 
  times your password got breached'''
  hashes = (line.split(':') for line in hashes.text.splitlines())
  for h, count in hashes:
    if h == hash_to_check:
      return count
  return 0

def pwned_api_check(password):
  '''This function is used to convert our password 
  into SHA1 hash and to pass the first 5 chars to request_api_data function'''
  sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
  first5_char, tail = sha1password[:5], sha1password[5:]
  response = request_api_data(first5_char)
  return get_password_leaks_count(response, tail)

def main(args):
  '''To communicate with all the functions we built and
  to return the status of breach'''  
  for password in args:
    count = pwned_api_check(password)
    if count:
      print(f'Your Password ==> {password} <== was found in {count} Breaches...\n You must change your password to stay safe.')
    else:
      print(f'Your Password ==> {password} <== was NOT found in any Data Breaches...\n But to be in safer side consider changing your password once in a month')
  return 'done!'

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
  #we are using argv function to accept any number of passwords[arguments] from the terminal to check