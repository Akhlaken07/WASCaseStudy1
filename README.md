# WASCaseStudy1

## Group Name
AWASP

## Group Members
- Muhammad Azhad (2015905)
- Qoys Al Hanif (2016863)
- Saufi (2018781)

## Description of Case Study

## Table of Contents

## Assigned Tasks
- Muhammad Azhad (2015905)
  1. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.)
  2. Hash Disclosure
  3. CSRF (Cross-Site Request Forgery)
  4. Secured Cookies
- Qoys Al Hanif (2016863)
  5. CSP
  6. JS Library
  7. HTTPS implentation (TLS/SSL)
- Saufi ()
  8. Cookie Poisoning
  9. Potential XSS
  10. Information Disclosure


## Observation Result
### Muhammad Azhad (2015905)
  ### 1. Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.)
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
  
  ### 2. Hash Disclosure
  - Hash Disclosure
    - Identify:
        - URL: https://www.mbot.org.my/MBOT/files/51/51541f6b-7e33-459d-a7e8-33264eae25ca.pdf
        - CWE ID: 200 - Exposure of Sensitive Information to an Unauthorized Actor
        - Risk: High
        - Confidence: Medium
        - <img width="316" alt="Screenshot 2024-05-12 at 11 33 45 AM" src="https://github.com/Akhlaken07/WASCaseStudy1/assets/148112697/2dbeea97-898e-4d9b-90bf-cf8a11a0bcc6">
        - <img width="396" alt="Screenshot 2024-05-12 at 11 31 05 AM" src="https://github.com/Akhlaken07/WASCaseStudy1/assets/148112697/ad6dde43-d10b-4539-a45e-c310e8faa641">
    - Evaluate:
        - A hash was disclosed by the web server. - Mac OSX salted SHA-1
    - Prevention:
        - Ensure that hashes that are used to protect credentials or other resources are not leaked by the web server or database. There is typically no requirement for password hashes to be accessible to the web browser. 
  ### 3. CSRF (Cross-Site Request Forgery) 
  - No alert for this category
  ### 4. Secured Cookies
  - Cookie with Samesite Attribute None
  - Cookie without Samesite Attribute 

### Qoys Al Hanif (2016863)

### 5. Content Security Policy (CSP)

- Identify:

  -   Risk level: medium
  -   Confidence: high
  -   CWE ID: 693
  -   Content Security Policy (CSP) Header Not Set in 553 files
  -   ![image](https://github.com/Akhlaken07/WASCaseStudy1/assets/96472091/0c7306f9-e20a-4cdf-ac2f-ee6b02063d53)
  
  -  One of them is the main file: https://www.mbot.org.my/
  -  ![image](https://github.com/Akhlaken07/WASCaseStudy1/assets/96472091/9a4160ec-934b-4abe-8adc-41c995d5ed5b)
  - Attackers can inject malicious scripts into web pages viewed by other users when the loaded script sources are revealed in the script tags. This is why CSP often disallows inline JavaScript within HTML/PHP



- Evaluate:

  Content Security Policy (CSP) acts as a robust security tool that helps websites detect and prevent various threats, such as Cross-Site Scripting (XSS) attacks and data injection vulnerabilities. Essentially, CSP serves as a protective barrier for websites, identifying and blocking potentially harmful content. For example, in XSS attacks, hackers exploit the trustworthiness of websites to insert malicious code, which browsers then unwittingly execute alongside legitimate content from trusted sources.
  
  CWE-693, known as "protection mechanism failure," refers to situations where a web application either lacks or inadequately implements protective measures against targeted attacks. This failure can occur in three different scenarios: a "missing" protection mechanism indicates a complete absence of defenses against specific attack methods, an "insufficient" mechanism provides only partial protection against common threats, leaving vulnerabilities, and an "ignored" mechanism implies that although the protective measure exists, developers have not applied it in certain parts of the codebase.

- Prevent:
  -   Configure the webserver to return the Content-Security-Policy HTTP Header with values controlling which resources the browser can load for the page
  -   Writing JavaScript and CSS with CSP in mind
      -   Because it constantly executes in the current context, inline code is a major injection vector that cannot be restricted. When CSP is enabled, it, by default, blocks all inline code. This implies no inline styles or scripts, including inline event handlers or javascript: URLs. Thus any new code should adhere to best practices and only utilize external script and style files.
  -   Page-level CSP directives
      -   Use the sandbox directive to treat the page as if inside a sandboxed iframe. To increase security on older websites with many legacy HTTP pages, use the upgrade-unsafe-requests directive to rewrite insecure URLs. This directs user agents to transition HTTP to HTTPS in URL schemes and is useful when still having various HTTP URLs.

Reference:

-   [https://www.invicti.com/blog/web-security/content-security-policy/](https://www.invicti.com/blog/web-security/content-security-policy/)
-   [https://cwe.mitre.org/data/definitions/693.html](https://cwe.mitre.org/data/definitions/693.html)

### 6. JavaScript Libraries



- Identify:



  -   Identifies as Vulnerable JS Library
  -   The risk is medium
  -   CWE ID 829 (Inclusion of Functionality from Untrusted Control Sphere)
  -   The identified library bootstrap, version 3.3.7 is vulnerable in the file https://www.mbot.org.my/CMSPages/GetResource.ashx?scriptfile=%7e%2fCMSScripts%2fCustom%2fMBOT%2fbootstrap.js
  -   ![image](https://github.com/Akhlaken07/WASCaseStudy1/assets/96472091/c69acda2-61dc-4bca-925c-01687bb9b249)
  
  -   The identified library moment.js, version 2.9.0 is vulnerable in the file https://www.mbot.org.my/CMSPages/GetResource.ashx?scriptfile=%7e%2fCMSScripts%2fCustom%2fMBOT%2fmoment-with-locales.js
  -   ![image](https://github.com/Akhlaken07/WASCaseStudy1/assets/96472091/6127d117-2e80-40a3-a7ff-4b35cc7a8a9a)
  
  -   The identified library jquery, version 2.2.4 is vulnerable in the file https://www.mbot.org.my/CMSPages/GetResource.ashx?scriptfile=%7e%2fCMSScripts%2fjquery%2fjquery-core.js
  -   ![image](https://github.com/Akhlaken07/WASCaseStudy1/assets/96472091/0d16a3b7-d32c-4fbc-b198-11f855a08a3b)






- Evaluate:



  A JS library that is missing security patches can make the website extremely vulnerable to various attacks. Third-party JS libraries can draw a variety of DOM-based vulnerabilities, including DOM-XSS, which can be exploited to hijack user accounts. Popular JS libraries typically have the advantage of being heavily audited. This also means that the flaws are quickly recognized and patched, resulting in a steady stream of security updates. Using a library with missing security patches can make the website exceptionally easy to abuse, making it crucial to ensure that any available security updates are to be applied immediately.

  Related:
  
  -   CVE-2020-11023: In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.
  -   CVE-2020-11022: In jQuery versions greater than or equal to 1.2 and before 3.5.0, passing HTML from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.
  -   CVE-2015-9251: jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS) attacks when a cross-domain Ajax request is performed without the dataType option, causing text/javascript responses to be executed.
  -   CVSS Score 4.3
  -   This vulnerability is related with cross site scripting.

- Prevent:


  -   Upgrade to the latest version of jquery.
  -   Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.
  -   When the set of acceptable objects, such as filenames or URLs, is limited or known, create a mapping from a set of fixed input values (such as numeric IDs) to the actual filenames or URLs, and reject all other inputs.
  -   For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602 (Client-Side Enforcement of Server-Side Security). Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.

References: 
-  [https://cwe.mitre.org/data/definitions/829.html](https://cwe.mitre.org/data/definitions/829.html)
-  [https://beaglesecurity.com/blog/vulnerability/vulnerable-javascript-library.html](https://beaglesecurity.com/blog/vulnerability/vulnerable-javascript-library.html)

### 7. HTTPS implementation (TLS/SSL)

- Identify:
  -   There is no alert found on OWASP ZAP and no risk level and CWE ID can be identified.

- Evaluate:
  -   Not available since there is https implementation for this website that can be seen at the URL of the website. However, content which was initially accessed via HTTPS (i.e.: using SSL/TLS encryption) is also accessible via HTTP (without encryption).

- Prevent:
  -   Not available for the website. However, the solution for this alert is ensure that the web server, application server, load balancer, etc. is configured to only serve such content via HTTPS. Consider implementing HTTP Strict Transport Security.



## Saufi (2018781)
  ### 8. Cookie Poisoning
  - Identify: Reliance on Cookies without Validation and Integrity Checking
    - CWE ID: 565
    - Risk: Information (low)
    - Source: Passive (10029 - Cookie Poisoning)
    - dentified at URL “https://www.mbot.org.my/accreditation/mbot-accredited-programmes” was vulnerable.
 
  - Evaluate:

    When carrying out security-critical tasks, the website depends on the usage or values of cookies, but it does not appropriately verify that the setting is valid for the corresponding user. Attackers may modify cookies by executing client-side code outside of the browser or from within the browser. 
    If cookies are used without thorough validation and integrity testing, attackers may be able to perform injection attacks like SQL injection and cross-site scripting, bypass authentication, and alter inputs in other unanticipated ways.

    In this case, An attacker may be able to poison cookie values through POST parameters. To test if this is a more serious issue, try resending that request as a GET, with the POST parameter included as a query string parameter.
   
    - For instance:  https://nottrusted.com/page?value=maliciousInput.
    User-input was found in the following cookie:
    CMSPreferredCulture=en-US; expires=Tue, 06-May-2025 04:47:37 GMT; path=/; secure; HttpOnly
    The user input was: lng=en-US)

  - Prevent: 

    - Do not allow user input to control cookie names and values. Ensure that semicolons, which can function as name/value pair delimiters, are filtered out if any query string parameters need to be placed in cookie values.
    - Limiting multipurpose cookies, limiting each cookie to a specific activity is crucial since multipurpose cookies pose many safety risks.
  
  Reference:
  - https://cwe.mitre.org/data/definitions/565.html
  - https://www.techtarget.com/searchsecurity/definition/cookie-poisoning
    
  ### 9. Potential XSS (Cross-Site Scripting)
  - Identify: Protection Mechanism Failure
    - CWE ID: 693
    - Risk: Medium
    - Source: Passive (10038 - Content Security Policy (CSP) Header Not Set)
    - Content Security Policy (CSP) was not set for https://www.mbot.org.my/mbot.com

  - Evaluate:

    The website isn't provided with a protection mechanism, or it uses one improperly, which leaves it vulnerable to directed attacks.
    In this case, the Content Security Policy (CSP) Header Not Set) Content Security Policy (CSP) is an extra security layer that helps in the identification and prevention of specific attack types, such as data injection and Cross Site Scripting (XSS) attacks. Such attacks are used for a variety of purposes, including as malware transmission, site defacement, and data theft. With the help of a set of standard HTTP headers called CSP, website owners can specify which content sources—JavaScript, CSS, HTML frames, fonts, images, and embeddable objects like Java applets, ActiveX, audio, and video files—browsers are permitted to load on their page.

   Related Attack Patterns: ![attackpattern](https://github.com/Akhlaken07/WASCaseStudy1/assets/148375277/df2096a8-6715-42ec-9a3b-5e91b5edbda1)

  - Prevent:
  
    - Make that the Content-Security-Policy header is set on web server, application server, load balancer, etc. through configuration.
   for example: the meta element can be used to configure a policy ![csp](https://github.com/Akhlaken07/WASCaseStudy1/assets/148375277/29c45a92-0b81-400b-b0a8-69428e3fe1de)
 
  Reference:
  - https://cwe.mitre.org/data/definitions/693.html
  - https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy


  - Identify: Improper Input Validation
    - CWE ID: 20
    - Risk: Low
    - Passive (10031 - User Controllable HTML Element Attribute (Potential XSS))
    - User-controlled HTML attribute values were found , The page at the following URL: https://www.mbot.org.my/registration/mbot-professional-member

  - Evaluate:

    When the web server receives input or data, it either fails to validate or validates the data improperly that the input does not contain the necessary attributes for processing the data in a safe and accurate manner.

    A commonly used method for ensuring that potentially hazardous inputs are safe for processing within the code or for connecting with other components is input validation. An attacker can manipulate input into a format that is not anticipated by the rest of the program when software fails to properly validate input. Unintended input will enter the system as a result, changing control flow, allowing arbitrary control over resources, or causing arbitrary code execution.

    In this case, at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability. injecting special characters might be possible. The page at the following URL: https://www.mbot.org.my/registration/mbot-professional-member appears to include user input in: 

    a(n) [input] tag [value] attribute 

    The user input found was:
    lng=en-US

  - Prevent:

    - Validate all input and sanitize output it before writing to any HTML attributes
  
  Reference :
  - https://cwe.mitre.org/data/definitions/20.html

 ### 10. Information disclosure
  - Identify: Exposure of Sensitive Information to an Unauthorized Actor
    - CWE ID: 200
    - WASC ID: 13 (information leakage)
    - Risk:low
    - Source: Passive (10027 - Information Disclosure - Suspicious  Comments)
    - The response appears to contain suspicious comments which may help an attacker.

  - Evaluate:

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

  - Related info

    - CWE-200 is commonly misused to represent the loss of confidentiality in a vulnerability, but confidentiality loss is a technical impact - not a root cause error. As of CWE 4.9, over 400 CWE entries can lead to a loss of confidentiality.
![observer](https://github.com/Akhlaken07/WASCaseStudy1/assets/148375277/1f4de974-5413-4f45-82b0-cce119701fa1)

  - Prevent:

    - Eliminate any comments that go back to information that could aid an attacker and fix any underlying issues they bring up.
    - Disable directory listing to prevent exposure of web site structure and potentially sensitive files
    - Disable error reporting output into the client's browser
    - Use custom error pages that prevent from displaying excessive system information

  Reference:
  - https://cwe.mitre.org/data/definitions/200.html
  - http://projects.webappsec.org/w/page/13246936/Information%20Leakage




