[Back to Contents](README.md)


### The Security Checklist 

##### AUTHENTICATION SYSTEMS (Signup/Signin/2 Factor/Password reset) 
- [ ] Force the server to serve HTTPS when the access HTTP.
- [ ] Always store the password in encrypted format and not in plaintext.
- [ ] Destroy or terminate the session upon logout.
- [ ] Destroy all active sessions on reset password
- [ ] Must have the `state` parameter in OAuth2.
- [ ] No open redirects upon successful login. (Hackers can use these attacks: Unvalidated Redirect and Forward)
- [ ] Set cookie with httpOnly and secure flag set.
- [ ] When generating OTP or calling Resend OTP API, do not send the OTP back in the response to avoid account takeover.
- [ ] Limit attempts in Login, Verify OTP, Resend OTP, Generate OTP, Change Password, or other related critical functions for a particular user. Have an exponential backoff set or/and something like a captcha based challenge.
- [ ] Check for randomness of reset password token in the emailed link or SMS.
- [ ] Make sure that the reset password token is random and unguessable.
- [ ] Set an expiration on the reset password token for a reasonable period. 24 hours is enough.
- [ ] Destroy the reset token upon successful usage.
- [ ] Implement strong password required in Registration, Change Password, Reset Password.
- [ ] Always add autocomplete=”off” attribute in the critical fields.
- [ ] Have a block list of usernames (check the list [here](https://github.com/marteinn/The-Big-Username-Blacklist) and add internal routes)


##### USER DATA & AUTHORIZATION
- [ ] Serially iterable resource id should be avoided. Use /me/orders instead of /user/31337/orders. (You may use this approach as long as you have the proper authorization validation)
- [ ] Edit email address/phone number feature should be accompanied by a verification email to the owner of the account.
- [ ] During signup, email or mobile verification must be required to prevent users from signing up using other users’ email and mobile number.
- [ ] Photo upload feature should sanitize all the metadata including EXIF tags
- [ ] For user ids and other ids, use [RFC compliant ](http://www.ietf.org/rfc/rfc4122.txt) `UUID` instead of integers.
- [ ] JWT are awesome. Use them if required for your single page app/APIs.


##### ANDROID / IOS APP
- [ ] `salt` from payment gateways should not be hardcoded.
- [ ] `secret` / `auth token` from 3rd party SDK's should not be hardcoded.
- [ ] API calls intended to be done `server to server` should not be done from the app.
- [ ] In Android, all the granted  [permissions](https://developer.android.com/guide/topics/security/permissions.html) should be carefully evaluated.
- [ ] On iOS, store sensitive information (authentication tokens, API keys, etc.) in the system keychain. Do __not__ store this kind of information in the user defaults.
- [ ] [Certificate pinning](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning) is highly recommended.


##### SECURITY HEADERS & CONFIGURATIONS
- [ ] `Add` [CSP](https://en.wikipedia.org/wiki/Content_Security_Policy) header to mitigate XSS and data injection attacks. This is important.
- [ ] `Add` [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) header to prevent cross site request forgery. Also add [SameSite](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00) attributes on cookies.
- [ ] `Add` [HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) header to prevent SSL stripping attack.
- [ ] `Add` your domain to the [HSTS Preload List](https://hstspreload.org/)
- [ ] `Add` [X-Frame-Options](https://en.wikipedia.org/wiki/Clickjacking#X-Frame-Options) to protect against Clickjacking.
- [ ] `Add` [X-XSS-Protection](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#X-XSS-Protection) header to mitigate XSS attacks.
- [ ] Update DNS records to add [SPF](https://en.wikipedia.org/wiki/Sender_Policy_Framework) record to mitigate spam and phishing attacks.
- [ ] Add [subresource integrity checks](https://en.wikipedia.org/wiki/Subresource_Integrity) if loading your JavaScript libraries from a third party CDN. For extra security, add the [require-sri-for](https://w3c.github.io/webappsec-subresource-integrity/#parse-require-sri-for) CSP-directive so you don't load resources that don't have an SRI sat.  
- [ ] Use random CSRF tokens and expose business logic APIs as HTTP POST requests. Do not expose CSRF tokens over HTTP for example in an initial request upgrade phase.
- [ ] Do not use critical data or tokens in GET request parameters. Exposure of server logs or a machine/stack processing them would expose user data in turn.  
  
  
##### SANITIZATION OF INPUT
- [ ] `Sanitize` all user inputs or any input parameters exposed to user to prevent [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting).
- [ ] Always use parameterized queries to prevent [SQL Injection](https://en.wikipedia.org/wiki/SQL_injection).  
- [ ] Sanitize user input if using it directly for functionalities like CSV import.
- [ ] `Sanitize` user input for special cases like robots.txt as profile names in case you are using a url pattern like coolcorp.io/username. 
- [ ] Do not hand code or build JSON by string concatenation ever, no matter how small the object is. Use your language defined libraries or framework.
- [ ] Sanitize inputs that take some sort of URLs to prevent [SSRF](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit#heading=h.t4tsk5ixehdd).
- [ ] Sanitize Outputs before displaying to users.

##### OPERATIONS
- [ ] If you are small and inexperienced, evaluate using AWS elasticbeanstalk or a PaaS to run your code.
- [ ] Use a decent provisioning script to create VMs in the cloud.
- [ ] Check for machines with unwanted publicly `open ports`.
- [ ] Check for no/default passwords for `databases` especially MongoDB & Redis.
- [ ] Use SSH to access your machines; do not setup a password, use SSH key-based authentication instead.
- [ ] Install updates timely to act upon zero day vulnerabilities like Heartbleed, Shellshock.
- [ ] Modify server config to use TLS 1.2 for HTTPS and disable all other schemes. (The tradeoff is good.)
- [ ] Do not leave the DEBUG mode on. In some frameworks, DEBUG mode can give access full-fledged REPL or shells or expose critical data in error messages stacktraces.
- [ ] Be prepared for bad actors & DDOS - use a hosting service that has DDOS mitigation.
- [ ] Set up monitoring for your systems, and log stuff (use [New Relic](https://newrelic.com/) or something like that).
- [ ] If developing for enterprise customers, adhere to compliance requirements. If AWS S3, consider using the feature to [encrypt data](http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html). If using AWS EC2, consider using the feature to use encrypted volumes (even boot volumes can be encrypted now).

##### PEOPLE
- [ ] Set up an email (e.g. security@coolcorp.io) and a page for security researchers to report vulnerabilities.
- [ ] Depending on what you are making, limit access to your user databases.
- [ ] Be polite to bug reporters.
- [ ] Have your code review done by a fellow developer from a secure coding perspective. (More eyes)
- [ ] In case of a hack or data breach, check previous logs for data access, ask people to change passwords. You might require an audit by external agencies depending on where you are incorporated.
