- [ ] Conduct search engine discovery and recon for info leakage, tools like google dorking, sitedigger, shodan, FOCA, punkspider, bbot. Use a search engine to search for Network diagrams and Configurations, Credentials, Error message content
- [ ] Fingerprint web server - Find the version and type of a running web server to determine known vulnerabilities and the appropriate exploits. Using "HTTP header field ordering" and "Malformed requests test".
- [ ] Review webserver metafiles for information leakage - robots.txt, sitemap.xml, security.txt, etc.
- [ ] Enumerate applications on webserver - find applications hosted in the webserver, vhosts, subdomains, non-standard ports, DNS zone transfers
- [ ] Review webpage comments and metadata for information leakage - review the page sources for dev comments
- [ ] Identify application entry points - review hidden fields, parameters, methods HTTP header analysis
- [ ] Map the target application and understand the principal workflows - review sign in/sign out, and map out all functionality of a site
- [ ] Fingerprint web application framework - find the type of web app framework/CMS from HTTP headers, cookies, source code, specific files and folder structure
- [ ] Fingerprint web application - Identify the web application and version to determine known vulns and the appropriate exploits
- [ ] Map application architecture - identify app architecture including web language, WAF, reverse proxy, application server, Backend Database, etc.
