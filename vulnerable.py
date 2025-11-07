# Test file with vulnerability
import os
user_input = input('Enter command: ')
os.system('ls ' + user_input)  # Command injection vulnerability

