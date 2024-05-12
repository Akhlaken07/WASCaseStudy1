# WASCaseStudy1

## Group Name
AWASP

## Group Members
- Muhammad Azhad (2015905)
- Qoys Al Hanif (2016863)
- Saufi ()

## Assigned Tasks

### Muhammad Azhad (2015905)
### Identify, evaluate, and prevent vulnerabilities of:
  #### Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.)
  - Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)
    - Identify:
        - URL: https://www.mbot.org.my/about-us/organization-structure/
        - CWE ID: 200 - Exposure of Sensitive Information to an Unauthorized Actor
        - Risk: Low
        - Confidence: Medium 
        - <img width="641" alt="Screenshot 2024-05-11 at 9 58 36 PM" src="https://github.com/Akhlaken07/WASCaseStudy1/assets/148112697/eecb2b41-b640-4e34-9166-fb0d209bf3a3">
        - <img width="1005" alt="Screenshot 2024-05-11 at 10 10 51 PM" src="https://github.com/Akhlaken07/WASCaseStudy1/assets/148112697/ef04772a-628b-4ac4-bb05-0b8c6e9c1d2b">
    - Evaluate:
        - The web/application server is leaking information via one or more "X-Powered-By" HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.
    - Prevention:
        - Ensure that your web server, application server, load balancer, etc. is configured to suppress "X-Powered-By" headers.

  - Server Leaks Version Information via "Server" HTTP Response Header Field (Manual)
    - Identify:
        - URL: https://www.google-analytics.com/analytics.js
        - CWE ID: 200 - Exposure of Sensitive Information to an Unauthorized Actor
        - Risk: Low
        - Confidence: High
        - <img width="509" alt="Screenshot 2024-05-12 at 11 34 14 AM" src="https://github.com/Akhlaken07/WASCaseStudy1/assets/148112697/385854de-b697-442f-ac4d-e41185e83b57">
        - <img width="575" alt="Screenshot 2024-05-12 at 11 28 13 AM" src="https://github.com/Akhlaken07/WASCaseStudy1/assets/148112697/777718e6-3604-4591-9107-5800b9f9cb23">
    - Evaluate:
        - The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.
    - Prevention:
        - Ensure that your web server, application server, load balancer, etc. is configured to suppress the "Server" header or provide generic details.
  - Cross-Domain JavaScript Source File Inclusion
    - Identify:
        - URL: https://www.mbot.org.my/
        - CWE ID: 829 - Inclusion of Functionality from Untrusted Control Sphere
        - Risk: Low
        - Confidence: Medium 
        - <img width="382" alt="Screenshot 2024-05-11 at 10 18 26 PM" src="https://github.com/Akhlaken07/WASCaseStudy1/assets/148112697/3c2ff08f-281d-47a5-97b6-2ac17cb7f328">
        - <img width="900" alt="Screenshot 2024-05-11 at 10 33 36 PM" src="https://github.com/Akhlaken07/WASCaseStudy1/assets/148112697/382d198b-1205-458b-ae1e-40dbc8defcdd">
    - Evaluate:
        - The page includes one or more script files from a third-party domain.
    - Prevention:
        - Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.headers.
  - Cross-Domain Misconfiguration (Manual)
    - Identify:
        - URL: https://ajax.googleapis.com/ajax/libs/jquery/3.6.4/jquery.min.js
        - CWE ID: 264 - Permissions, Privileges, and Access Controls
        - Risk: Medium
        - Confidence: Medium 
        - <img width="382" alt="Screenshot 2024-05-11 at 10 18 26 PM" src="https://github.com/Akhlaken07/WASCaseStudy1/assets/148112697/3c2ff08f-281d-47a5-97b6-2ac17cb7f328">
        - <img width="900" alt="Screenshot 2024-05-11 at 10 33 36 PM" src="https://github.com/Akhlaken07/WASCaseStudy1/assets/148112697/382d198b-1205-458b-ae1e-40dbc8defcdd">
    - Evaluate:
        - Web browser data loading may be possible, due to a Cross Origin Resource Sharing (CORS) misconfiguration on the web server
        - The CORS misconfiguration on the web server permits cross-domain read requests from arbitrary third party domains, using unauthenticated APIs on this domain. Web browser implementations do not permit arbitrary third parties to read the response from authenticated APIs, however. This reduces the risk somewhat. This misconfiguration could be used by an attacker to access data that is available in an unauthenticated manner, but which uses some other form of security, such as IP address white-listing.
    - Prevention:
        - Ensure that sensitive data is not available in an unauthenticated manner (using IP address white-listing, for instance).
        - Configure the "Access-Control-Allow-Origin" HTTP header to a more restrictive set of domains, or remove all CORS headers entirely, to allow the web browser to enforce the Same Origin Policy (SOP) in a more restrictive manner.
  
  #### Hash Disclosure
  #### CSRF (Cross-Site Request Forgery)
  #### Secured Cookies
  - Cookie with Samesite Attribute None
  - Cookie without Samesite Attribute 

### Qoys Al Hanif (2016863)
- Identify, evaluate, and prevent vulnerabilities of:
  - Content Security Policy (CSP)
  - JavaScript Libraries
  - HTTPS implementation (TLS/SSL)

### Saufi ()
- Identify, evaluate, and prevent vulnerabilities of:
  
  ## Cookie Poisoning
  ### 1. Identify: Reliance on Cookies without Validation and Integrity Checking
  - CWE ID: 565
  - Risk: Information (low)
  - Source: Passive (10029 - Cookie Poisoning)

  - dentified at URL “https://www.mbot.org.my/accreditation/mbot-accredited-programmes” was vulnerable.
 
  Evaluate:

   When carrying out security-critical tasks, the website depends on the usage or values of cookies, but it does not appropriately verify that the setting is valid for the corresponding user. Attackers may modify cookies by executing client-side code outside of the browser or from within the browser. If cookies are used without thorough validation and integrity testing, attackers may be able to perform injection attacks like SQL injection and cross-site scripting, bypass authentication, and alter inputs in other unanticipated ways.
  In this case, An attacker may be able to poison cookie values through POST parameters. To test if this is a more serious issue, try resending that request as a GET, with the POST parameter included as a query string parameter.
  - For instance:  https://nottrusted.com/page?value=maliciousInput.
User-input was found in the following cookie:
CMSPreferredCulture=en-US; expires=Tue, 06-May-2025 04:47:37 GMT; path=/; secure; HttpOnly
The user input was: lng=en-US)

  Prevent: 

  - Do not allow user input to control cookie names and values. Ensure that semicolons, which can function as name/value pair delimiters, are filtered out if any query string parameters need to be placed in cookie values.
  - Limiting multipurpose cookies, limiting each cookie to a specific activity is crucial since multipurpose cookies pose many safety risks.
  
 
    
  ## Potential XSS (Cross-Site Scripting)
   ### 1. Identify: Protection Mechanism Failure
  - CWE ID: 693
  - Risk: Medium
  - Source: Passive (10038 - Content Security Policy (CSP) Header Not Set)
  - Content Security Policy (CSP) was not set for https://www.mbot.org.my/mbot.com

  Evaluate:

  The website isn't provided with a protection mechanism, or it uses one improperly, which leaves it vulnerable to directed attacks.
  In this case, the Content Security Policy (CSP) Header Not Set) Content Security Policy (CSP) is an extra security layer that helps in the identification and prevention of specific attack types, such as data injection and Cross Site Scripting (XSS) attacks. Such attacks are used for a variety of purposes, including as malware transmission, site defacement, and data theft. With the help of a set of standard HTTP headers called CSP, website owners can specify which content sources—JavaScript, CSS, HTML frames, fonts, images, and embeddable objects like Java applets, ActiveX, audio, and video files—browsers are permitted to load on their page.

  Related Attack Patterns: ![attackpattern](https://github.com/Akhlaken07/WASCaseStudy1/assets/148375277/df2096a8-6715-42ec-9a3b-5e91b5edbda1)

  Prevent:
  
  - Make that the Content-Security-Policy header is set on web server, application server, load balancer, etc. through configuration.
  - for example: the <meta> element can be used to configure a policy ![csp](https://github.com/Akhlaken07/WASCaseStudy1/assets/148375277/29c45a92-0b81-400b-b0a8-69428e3fe1de)

 ## Information disclosure
   ### 1. Identify: Exposure of Sensitive Information to an Unauthorized Actor
  - CWE ID: 200
  - WASC ID: 13 (information leakage)
  - Risk:low
  - Source: Passive (10027 - Information Disclosure - Suspicious  Comments)
  - The response appears to contain suspicious comments which may help an attacker.

  Evaluate:

  Exposure of sensetive information to an unauthorized actor mean when a user of the web server accesses sensitive information, they are not granted express authorization to do so.
  Errors can in many different forms and can lead to information exposures. Depending on the environment in which the product functions, the kind of private information that is disclosed, and the advantages it can offer an attacker, the error's severity could differ significantly.

  Some kinds of sensitive information include:
  - private, personal information, such as personal messages, financial data, health records,  geographic location, or contact details
  - system status and environment, such as the operating system and installed packages
  - business secrets and intellectual property
  - network status and configuration
  - the product's own code or internal state
  - metadata, e.g. logging of connections or message headers
  - indirect information, such as a discrepancy between two internal operations that can be observed by an outsider

  In this case, a bug is found which the response appears to contain suspicious comments which may help an attacker. The following pattern was used: \bBUG\b and was detected in the element starting with: "<script src="/CMSPages/GetResource.ashx?scriptfile=%7e%2fCMSScripts%2fCustom%2fMBOT%2fie10-viewport-bug-workaround.js" type="tex", see evidence field for the suspicious comment/snippet.

  Related info

  - CWE-200 is commonly misused to represent the loss of confidentiality in a vulnerability, but confidentiality loss is a technical impact - not a root cause error. As of CWE 4.9, over 400 CWE entries can lead to a loss of confidentiality.
![observer](https://github.com/Akhlaken07/WASCaseStudy1/assets/148375277/1f4de974-5413-4f45-82b0-cce119701fa1)

  Prevent:

  - Eliminate any comments that go back to information that could aid an attacker and fix any underlying issues they bring up.
  - Disable directory listing to prevent exposure of web site structure and potentially sensitive files
  - Disable error reporting output into the client's browser
  - Use custom error pages that prevent from displaying excessive system information


## Table of Contents

## List of Figures

## List of Tables

## References

- https://cwe.mitre.org/data/definitions/565.html
- https://www.techtarget.com/searchsecurity/definition/cookie-poisoning
- https://cwe.mitre.org/data/definitions/693.html
- https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
- https://cwe.mitre.org/data/definitions/200.html
- http://projects.webappsec.org/w/page/13246936/Information%20Leakage
