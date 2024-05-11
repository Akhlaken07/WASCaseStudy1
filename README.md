# WASCaseStudy1

## Group Name
AWASP

## Group Members
- Muhammad Azhad (2015905)
- Qoys Al Hanif (2016863)
- Saufi ()

## Assigned Tasks

### Muhammad Azhad (2015905)
- Identify, evaluate, and prevent vulnerabilities of:
  - Server OS and Server-Side Scripting used (Windows or Linux, PHP or ASP.net or JavaScript, etc.)
  - Hash Disclosure
  - CSRF (Cross-Site Request Forgery)
  - Secured Cookies

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
   ### 1. Identify: 
  - CWE ID: 
  - Risk:
  - Source:
  - 

  Evaluate:

  Prevent:
  


## Table of Contents

## List of Figures

## List of Tables

## References

- https://cwe.mitre.org/data/definitions/565.html
- https://www.techtarget.com/searchsecurity/definition/cookie-poisoning
- https://cwe.mitre.org/data/definitions/693.html
- https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
