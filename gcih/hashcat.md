# Hashcat Notes

### identifying hash types

```
hashcat slingshot.hashes --identify
```

### cracking DES Crypt password hashes

```
hashcat -a 0 -m 1500 slingshot.hashes /usr/share/wordlists/passwords.txt
```

 - hashcat: Run the Hashcat command
 - -a 0: Perform a straight attack (e.g., crack password hashes using a wordlist of password guesses)
 - -m 1500: Use hash mode 1500 (DES crypt password hashes)
 - slingshot.hashes: Read password hashes from the slingshot.hashes file (our copy of the /etc/shadow file)
 - /usr/share/wordlists/passwords.txt: Use the words in /usr/share/wordlists/passwords.txt as the source of password guesses

### showing the cracked hashes

```
hashcat -m 1500 slingshot.hashes --show
hashcat -m 1500 slingshot.hashes --show --user
hashcat -m 1500 slingshot.hashes --left --user
```

### crack MD5 

```
hashcat -a 0 -m 500 slingshot.hashes /usr/share/wordlists/passwords.txt
```

### windows domain passwords

```
secretsdump.py -system registry/SYSTEM -ntds "Active Directory/ntds.dit" LOCAL -outputfile w99 -history
cat w99.ntds | awk -F: '{print $3}' | sort | uniq -c
sed -i '/$:/d' w99.ntds
hashcat -a 0 w99.ntds /usr/share/wordlists/passwords.txt
hashcat w99.ntds --show --user
```

### Mask attacks

hashcat mask attacks allow you to describe the format of passwords to crack, if we know a windows domain has the password policy set as:
- at least 8 characters length
- one uppercase letter
- one lowercase letter
- one digit

mask attack markers:
- ?l = abcdefghijklmnopqrstuvwxyz
- ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ
- ?d = 0123456789
- ?s = !"#$%&'()*+,-./:;<=>?@[]^_`{|}~
- ?a = ?l?u?d?s
- ?b = 0x00 - 0xff

Example applying a mask to crack passwords consisting of an initial uppercase letter followed by 6 lowercase letters and one trailing digit

```
hashcat -a 3 w99.ntds ?u?l?l?l?l?l?l?d
```

### Crack NT passwords with wordlists and rules

```
hashcat -a 0 w99.ntds /usr/share/wordlists/passwords.txt -r /opt/hashcat/rules/best64.rule
```
