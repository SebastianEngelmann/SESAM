#!/usr/bin/python3
# -*- coding: utf-8 -*-
from hashlib import pbkdf2_hmac

lower_case_letters = list('abcdefghijklmnopqrstuvwxyz')
upper_case_letters = list(' ABCDEFGHIJKLMNOPQRSTUVWXYZ')
numbers = list('0123456789')
special_characters = list('#!"§$%&/()[]{}=-_+*<>;:.')
password_characters = lower_case_letters + upper_case_letters + numbers + special_characters
salt = "pepper"

def convert_bytes_to_password(hashed_bytes, length):
    number = int.from_bytes(hased_bytes, byteorder = 'big')
    password = ''
    while number > 0 and len(password) < length:
        password = password + password_characters[number % len(password_characters)]
        number = number // len(password_characters)
    return password

master_password = input('Masterpassword: ')
domain = input('Domain: ')
while len(domain) < 1:
    print('Bitte gib eine Domain an, für die das Passwort generiert werden soll.')
    domain = input('Domain: ')
hash_string = domain + master_password
hased_bytes = pbkdf2_hmac('sha512', hash_string.encode('utf-8'), salt.encode('utf-8'), 4096)
print('Password: ' + convert_bytes_to_password(hased_bytes, 10))