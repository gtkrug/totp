# totp
----
This is a simple singleton class that implements a handful of useful Time based One-Time Passcodes in accordance with 
IETF RFC 6238 - https://tools.ietf.org/html/rfc6238

Use it as follows:

Generate a String that is a base32 encoded 10 byte random Shared Secret.  This is shared between the client and server.
totp.getTotp().genSharedSecret()

Get a QR Code that a user can scan with Google Authenticator to transfer the shared secret to their device.  This 
function returns a URL that will generate a QR code using Google's Charts API (this URL can be included in an 
<img> tag in HTML). 
totp.getTotp().getGoogleApiQrURL (sharedSecret, "user", "system")

This function returns the code for the specified time (in totp time chunks).  In general this function should never
need to be called, unless this library is included in a client.
totp.getTotp().getCode (sharedSecret, time);

This function verifies an input code (by default it checks a 6 minute window, 3 minutes in the past and 3 in the future):
totp.getTotp().verifyCode(sharedSecret, code)

If there is more time desynchronization than 3 minutes possible, then the skew may be specified in seconds:
totp.getTotp().verifyCodeWithSkew(sharedSecret, code, secondsToCheck)

