# Command Injection Notes

## Detection

If some type of functionality is given with input we can enter try to abuse, like in the case of a website with a ping checker.

|Injection Operator|	Injection Character |	URL-Encoded Character 	|Executed Command|
|:----|:----|:----|:----|
|Semicolon |	; 	|%3b |	Both|
|New Line| 	\n |	%0a 	|Both|
|Background| 	& 	|%26 	|Both (second output generally shown first)|
|Pipe 	| 	%7c 	|Both |(only second output is shown)|
|AND 	|&& 	|%26%26 	|Both (only if first succeeds)|
|OR 	|\|| |	%7c%7c| 	|Second (only if first fails)|
|Sub-Shell |	`` 	|%60%60 	|Both (Linux-only)|
|Sub-Shell| 	$() 	|%24%28%29 	|Both (Linux-only)|
