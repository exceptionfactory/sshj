/*
 * Copyright (C)2009 - SSHJ Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.schmizz.sshj.transport.kex;

import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.transport.random.Random;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class Curve25519DHTest {

    private static final byte[] CONSTANT_SECRET_KEY = {
            8, 7, 6, 5, 4, 3, 2, 1,
            8, 7, 6, 5, 4, 3, 2, 1,
            8, 7, 6, 5, 4, 3, 2, 1,
            8, 7, 6, 5, 4, 3, 2, 1
    };

    private static final byte[] PEER_PUBLIC_KEY = {
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8,
            1, 2, 3, 4, 5, 6, 7, 8
    };

    private static final BigInteger COMPUTED_SHARED_SECRET_KEY = new BigInteger("80598713105289180166403182905030653706751055872722604830148130813237290633539");

    private static final byte[] COMPUTED_PUBLIC_KEY = {
            73, 115, -13, 101, 84, -29, -64, 51,
            6, 32, -61, 97, 10, 98, -119, -73,
            73, -75, -12, 79, 79, 88, -80, 0,
            -35, 97, 93, -122, 78, 32, 89, 18
    };

    @Test
    public void testInitPublicKeyLength() {
        final Curve25519DH dh = new Curve25519DH();
        dh.init(null, new ConstantFactory());

        final byte[] generatedKeyEncoded = dh.getE();

        assertArrayEquals(COMPUTED_PUBLIC_KEY, generatedKeyEncoded);
    }

    @Test
    public void testInitComputeSharedSecretKey() {
        final Curve25519DH dh = new Curve25519DH();
        dh.init(null, new ConstantFactory());

        dh.computeK(PEER_PUBLIC_KEY);
        final BigInteger sharedSecretKey = dh.getK();

        assertEquals(COMPUTED_SHARED_SECRET_KEY, sharedSecretKey);
    }

    private static class ConstantFactory implements Factory<Random> {

        @Override
        public Random create() {
           return new Random() {
               @Override
               public void fill(byte[] bytes) {
                   System.arraycopy(CONSTANT_SECRET_KEY, 0, bytes, 0, CONSTANT_SECRET_KEY.length);
               }

               @Override
               public void fill(byte[] bytes, int start, int len) {
                   System.arraycopy(CONSTANT_SECRET_KEY, start, bytes, 0, len);
               }
           };
        }
    }
}
