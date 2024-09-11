# Password Cracking Notes

## Wordlists

Utilize [Sec Lists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) with hashcat, this cracks NTLM hashes
```
hashcat.exe -a 0 -m 1000 ntlm.txt rockyou.txt
```
-a 0 specifies the wordlist attack mode.
-m 1000 specifies that the hash is NTLM.
ntlm.txt is a text file containing the NTLM hash to crack.
rockyou.txt is the wordlist.

## Wordlist Rules

Check the wiki for rules [info](https://hashcat.net/wiki/doku.php?id=rule_based_attack)

```
hashcat.exe -a 0 -m 1000 ntlm.txt rockyou.txt -r rules\add-year.rule
cat hashcat\rules\add-year.rule
  $2$0$2$0
```

## Masks

```
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d
```
-a 3 specifies the mask attack.
?u?l?l?l?l?l?l?l?d is the mask.

## Mask Length and Mask Files

By default, this mask attack sets a static password length - ?u?l?l?l?l?l?l?l?1 defines 9 characters, 
which means we can only crack a 9-character password. To crack passwords of different lengths, we have to manually adjust the mask accordingly.

Hashcat mask files make this process a lot easier for custom masks that you use often.

```
cat example.hcmask
  ?d?s,?u?l?l?l?l?1
  ?d?s,?u?l?l?l?l?l?1
  ?d?s,?u?l?l?l?l?l?l?1
  ?d?s,?u?l?l?l?l?l?l?l?1
  ?d?s,?u?l?l?l?l?l?l?l?l?1
hashcat.exe -a 3 -m 1000 ntlm.txt example.hcmask
```

## Combinator

Combines lists together
```
hashcat.exe -a 1 -m 1000 ntlm.txt list1.txt list2.txt -j $- -k $!
```

## Hybrid

you can mix all of these together
```
hashcat.exe -a 6 -m 1000 ntlm.txt list.txt ?d?d?d?d
```
-a 6 specifies the hybrid wordlist + mask mode.
?d?d?d?d is the mask.

## Kwprocessor

Another cracking tool to make passwords that use [keyboard walks](https://github.com/hashcat/kwprocessor)
```
kwp64.exe basechars\custom.base keymaps\uk.keymap routes\2-to-10-max-3-direction-changes.route -o keywalk.txt
```

