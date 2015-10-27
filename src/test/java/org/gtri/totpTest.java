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

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;


/**
 *  This class implements a set of simple static functions supporting time-based one time passcodes
 *  in accordance with IETF RFC 6238 - https://tools.ietf.org/html/rfc6238
 */
@Test
public class totpTest {

    @Test public void testGenSecret() {
        System.out.println ("Generated Secret = " + totp.getTotp().genSharedSecret() );
        System.out.println ("Generated Secret = " + totp.getTotp().genSharedSecret() );
        System.out.println ("Generated Secret = " + totp.getTotp().genSharedSecret() );
    }

    @Test public void testUrlGen() {
        String sec = totp.getTotp().genSharedSecret();
        System.out.println ("API URL = " + totp.getTotp().getGoogleApiQrURL (sec, "test1", "system1"));
        sec = new String("PT5UMQIYF2O4ZEIG");
        System.out.println ("API URL = " + totp.getTotp().getGoogleApiQrURL (sec, "test1", "assure"));
    }

    @Test public void testVerify() {
        long timeTest = System.currentTimeMillis()/1000/30;
        timeTest = timeTest + 5;
        String sec = totp.getTotp().genSharedSecret();
        int code;

        try {
          code = totp.getTotp().getCode (sec, timeTest);
        } catch (Exception e) {
          Assert.fail ("Exception generating totp code, likely a platform or crypto misconfiguration");
          return;
        }

        // totp.getTotp().verifyCode should be true, we will test 10 minutes before and after by default
        Assert.assertTrue  (totp.getTotp().verifyCode(sec,code));
        // Assert totp.getTotp().verifyCodeWithSkew (60) we skewed our code by 150 seconds, so this should fail
        Assert.assertFalse (totp.getTotp().verifyCodeWithSkew(sec,code,60));
    }
}

