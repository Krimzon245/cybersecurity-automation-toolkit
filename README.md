# Python: Automating File Access Controls

## Project Description
This project automates the process of updating an access control allow-list file. The script opens a text file containing approved IP addresses, checks it against a remove-list of unauthorized IPs, and updates the file to maintain network security compliance.

## Skills Demonstrated
* File handling in Python (`open()`, `.read()`, `.write()`)
* Working with strings and converting them to lists (`.split()`)
* Iteration and conditional logic (`for` loops and `if` statements)
* Algorithmic thinking for security analyst tasks

## How It Works
1. Opens the `allow_list.txt` file containing current users.
2. Reads the file and converts the string of IP addresses into a list.
3. Iterates through a `remove_list` to find unauthorized users.
4. Uses `.remove()` to update the list and converts it back to a string.
5. Overwrites the original file with the new, secured access list.
