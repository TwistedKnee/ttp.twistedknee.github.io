# BSCP Notes

Here is where I'll start on my notes for BSCP, I'll be basing this off of what some people have already done at [botesjuan](https://github.com/botesjuan/Burp-Suite-Certified-Practitioner-Exam-Study?tab=readme-ov-file) and [DingyShark](https://github.com/DingyShark/BurpSuiteCertifiedPractitioner?tab=readme-ov-file)

So for the exam there are two sites that you have to get access to a user, promote yourself to admin or steal data, then read the contents of the /home/carlos/secret on the system.

Here are my separated points based on the above note preps. I am going to take loose notes as I reread the material. I have already done all of these labs before but I am reinforcing this by rereading and taking notes. I recommend everyone to at least take notes while they study if you stumble across this.  

In preparation I am also going through Rana Khalil's course as well [here](https://academy.ranakhalil.com/), I thought why not do this on top of it all since this would also be good primer for OSWE. I am writing her code for the manual testing in the scripts section of this github, but these are all based on her's from her [github](https://github.com/rkhal101/Web-Security-Academy-Series/). I might make some changes or not. 

- Get access to any user
  - [XSS](/bscp/xss.md)
  - [DOM-based vulns](bscp/dom_based.md)
  - Authentication
  - Web Cache Poisoning
  - HTTP host header attacks
  - HTTP request smuggling

- Promote yourself to admin or steal his data
  - [SQL Injection](/bscp/sqli.md)
  - [CSRF](/bscp/csrf.md)
  - Insecure Deserialization
  - OAuth authentication
  - JWT
  - Access control vulnerabilities

- Read the content of /home/carlos/secret
  - SSRF
  - XXE Injection
  - OS Cmd Injection
  - Server-side template injection
  - Directory traversal
  - insecure deserialization
  - File upload vulnerabilities
 
- Misc
  - [CORS](bscp/cors.md)
  - information disclosure
  - WebSockets
  - Prototype polution

In Portswigger they have 31 current topics, this may increase over time. Here they are listed in their categories

- Server Side
  - [SQLi](/bscp/sqli.md)
  - Authentication
  - Path traversal
  - Command Injection
  - Business logic vulnerabilities
  - Information Disclosure
  - Access control
  - File upload vulnerabilities
  - Race conditions
  - SSRF
  - XXE injection
  - NoSQL injection
  - API testing
  - Web cache deception
 
- Client side
  - [XSS](/bscp/xss.md)
  - [CSRF](/bscp/csrf.md)
  - [CORS](bscp/cors.md)
  - [Clickjacking](/bscp/clickjacking.md)
  - [DOM-based vulns](bscp/dom_based.md)
  - Websockets

- Advanced topics
  - Insecure deserialization
  - Web LLM Attacks
  - GraphQL Vulns
  - SSTI
  - Web cache poisoning
  - HTTP Host header attacks
  - HTTP request smuggling
  - OAuth authentication
  - JWT attacks
  - Prototype pollution
  - Essential skills

