/*
 * Licensed by GTRI under the Apache License, Version 2.0.  
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gtri;

import java.security.NoSuchAlgorithmException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.net.URLEncoder;

import javax.security.auth.login.LoginException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.codec.binary.Base32;

/**
 *  This class implements a set of simple static functions supporting time-based one time passcodes
 *  in accordance with IETF RFC 6238 - https://tools.ietf.org/html/rfc6238
 */
public class totp {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(totp.class);
    private String googleApiPrefix = "https://chart.googleapis.com/chart?chs=200x200&chld=M%7C0&cht=qr&chl=";
    private static totp totpInstance = null;

    public totp() {
       log.trace("New totp Class Created");
    }

    public static totp getTotp() {
       if (totpInstance == null) {
           totpInstance = new totp();
       }
       return totpInstance;
    }

    /** Gen Shared Secret
      *  - TOTP relies on a 10 byte shared secret encoded as a 16 character base32 string
      */
    public String genSharedSecret () {
      byte[] bBuffer = new byte[10];
      new SecureRandom().nextBytes(bBuffer);
      log.debug ("Generating Base32 TOTP Shared Secret");
      return new String(new Base32().encode(bBuffer));
    }

    /** Verify Code
      *    Secret - The shared secret between client and server.
      *    code   - The code provided by the client
      *    Checks 10 minutes in the past and future, 40 possible correct codes compared to input code. 
      */
    public boolean verifyCode (String sharedSecret,
                                      int    code) {
        return verifyCodeWithSkew (sharedSecret, code, 600);
    }

    /** verifyCodeWithSkew
      *    Secret - The shared secret between client and server.
      *    code   - The code provided by the client
      *    clockSkew - The amount of time in the past and future to check, in seconds. 
      */
    public boolean verifyCodeWithSkew (String sharedSecret,
                                       int    code,
                                       int    clockSkew) {
       // TOTP works on 30 second increments based on Unix Epoch Time
       long timeNow  = System.currentTimeMillis()/1000/30;
       // Increments to check
       int  variance = clockSkew/30; 

       try {
          for (int i = -variance; i <= variance; i++) {
             int testCode = getCode(sharedSecret, timeNow + i);
             if ( testCode == code ) {
                return true;
             }
          }
       }
       catch (Exception e) {
          log.error ("Exception while attempting to calculate one time passcodes for 2nd factor verification: {}", e);
       }
       return false;
    }

    /** getCode
      *   Calculates the code for the provided time and shared secret.
      */
   public int getCode (String sharedSecret, long time) throws NoSuchAlgorithmException, InvalidKeyException {
      byte[] secret = new Base32().decode(sharedSecret);
      SecretKeySpec signKey = new SecretKeySpec(secret, "HmacSHA1");
      ByteBuffer buffer = ByteBuffer.allocate(8);
      buffer.putLong(time);
      byte[] timeBytes = buffer.array();
      Mac mac = Mac.getInstance("HmacSHA1");
      mac.init(signKey);
      byte[] hash = mac.doFinal(timeBytes);
      int offset = hash[19] & 0xf;
      long truncatedHash = hash[offset] & 0x7f;
      for (int i = 1; i < 4; i++) {
        truncatedHash <<= 8;
        truncatedHash |= hash[offset + i] & 0xff;
      }
      return (int) (truncatedHash %= 1000000);
   }

   /** getGoogleApiQrUrl
     *    String sharedSecret - base32 shared secret
     *    String description  - identifer that will show up in the user's smart phone totp application
     */
    public String getGoogleApiQrURL (String sharedSecret, String user, String host) {
       String QrCode = String.format("otpauth://totp/%s@%s&secret=%s", user, host, sharedSecret);
       try {
           String EncodedQrCode = URLEncoder.encode (QrCode, "UTF-8");
           return googleApiPrefix + EncodedQrCode;
       } catch (Exception e) {
           log.error ("Encoding Exception while attempting to URL encode QrCode {}", QrCode, e);
           return new String("http://failbot.org/");
       }
    } 

}

