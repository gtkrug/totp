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

    @Test public void testAll() {
        System.out.println ("Generated Secret = " + totp.getTotp().genSharedSecret() );
        System.out.println ("Generated Secret = " + totp.getTotp().genSharedSecret() );
        System.out.println ("Generated Secret = " + totp.getTotp().genSharedSecret() );


        String sec = totp.getTotp().genSharedSecret();
        System.out.println ("API URL = " + totp.getTotp().getGoogleApiQrURL (sec, "test1", "assure"));
        sec = totp.getTotp().genSharedSecret();
        System.out.println ("API URL = " + totp.getTotp().getGoogleApiQrURL (sec, "test2", "assure"));
    }
}

