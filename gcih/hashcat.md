# Hashcat Notes

identifying hash types

```
hashcat slingshot.hashes --identify
```

cracking DES Crypt password hashes

```
hashcat -a 0 -m 1500 slingshot.hashes /usr/share/wordlists/passwords.txt
```

 - hashcat: Run the Hashcat command
 - -a 0: Perform a straight attack (e.g., crack password hashes using a wordlist of password guesses)
 - -m 1500: Use hash mode 1500 (DES crypt password hashes)
 - slingshot.hashes: Read password hashes from the slingshot.hashes file (our copy of the /etc/shadow file)
 - /usr/share/wordlists/passwords.txt: Use the words in /usr/share/wordlists/passwords.txt as the source of password guesses
