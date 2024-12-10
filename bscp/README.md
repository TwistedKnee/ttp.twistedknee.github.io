# BSCP Notes

Here is where I'll start on my notes for BSCP, I'll be basing this off of what some people have already done at [botesjuan](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study?tab=readme-ov-file) and [DingyShark](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner?tab=readme-ov-file)

So for the exam there are two sites that you have to get access to a user, promote yourself to admin or steal data, then read the contents of the /home/carlos/secret on the system.

Here are my separated points based on the above note preps. I am going to take loose notes as I reread the material. I have already done all of these labs before but I am reinforcing this by rereading and taking notes. I recommend everyone to at least take notes while they study if you stumble across this.  

In preparation I am also going through Rana Khalil's course as well [here](https://academy.ranakhalil.com/), I thought why not do this on top of it all since this would also be good primer for OSWE. I am writing her code for the manual testing in the scripts section of this github, but these are all based on her's from her [github](https://github.com/rkhal101/Web-Security-Academy-Series/). I might make some changes or not. 

- Get access to any user
  - [XSS](/bscp/xss.md)
  - [DOM-based vulns](/bscp/dom_based.md)
  - [Authentication](/bscp/auth.md)
  - [Web Cache Poisoning](/bscp/web_cache_poisoning.md)
  - [HTTP host header attacks](/bscp/http_host_header_attacks.md)
  - [HTTP request smuggling](/bscp/http_req_smuggling.md)

- Promote yourself to admin or steal his data
  - [SQL Injection](/bscp/sqli.md)
  - [CSRF](/bscp/csrf.md)
  - [Insecure Deserialization](/bscp/insecure_deserialization.md)
  - OAuth authentication
  - JWT
  - [Access control vulnerabilities](/bscp/access_control.md)

- Read the content of /home/carlos/secret
  - [SSRF](/bscp/ssrf.md)
  - [XXE Injection](/bscp/xxe.md)
  - [OS Cmd Injection](/bscp/os_cmdi.md)
  - [Server-side template injection](/bscp/ssti.md)
  - [Directory traversal](/bscp/path_traversal.md)
  - [insecure deserialization](/bscp/insecure_deserialization.md)
  - File upload vulnerabilities
 
- Misc
  - [CORS](/bscp/cors.md)
  - [information disclosure](/bscp/info_disclosure.md)
  - [WebSockets](/bscp/web_sockets.md)
  - Prototype polution

In Portswigger they have 31 current topics, this may increase over time. Here they are listed in their categories

- Server Side
  - [SQLi](/bscp/sqli.md)
  - [Authentication](/bscp/auth.md)
  - [Path traversal](/bscp/path_traversal.md)
  - [Command Injection](/bscp/os_cmdi.md)
  - [Business logic vulnerabilities](/bscp/business_logic.md)
  - [Information Disclosure](/bscp/info_disclosure.md)
  - [Access control](/bscp/access_control.md)
  - File upload vulnerabilities
  - Race conditions
  - [SSRF](/bscp/ssrf.md)
  - [XXE Injection](/bscp/xxe.md)
  - NoSQL injection
  - API testing
  - Web cache deception
 
- Client side
  - [XSS](/bscp/xss.md)
  - [CSRF](/bscp/csrf.md)
  - [CORS](/bscp/cors.md)
  - [Clickjacking](/bscp/clickjacking.md)
  - [DOM-based vulns](/bscp/dom_based.md)
  - [Websockets](/bscp/web_sockets.md)

- Advanced topics
  - [Insecure deserialization](/bscp/insecure_deserialization.md)
  - Web LLM Attacks
  - GraphQL Vulns
  - [SSTI](/bscp/ssti.md)
  - [Web cache poisoning](/bscp/web_cache_poisoning.md)
  - [HTTP Host header attacks](/bscp/http_host_header_attacks.md)
  - [HTTP request smuggling](/bscp/http_req_smuggling.md)
  - OAuth authentication
  - JWT attacks
  - Prototype pollution
  - Essential skills

