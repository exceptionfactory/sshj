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

import com.hierynomus.sshj.common.KeyAlgorithm;
import net.schmizz.sshj.common.Factory;
import net.schmizz.sshj.transport.random.Random;
import org.bouncycastle.math.ec.rfc7748.X25519;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

public class Curve25519DH extends DHBase {

    private static final int KEY_LENGTH = 32;

    private byte[] privateKey;

    public Curve25519DH() {
        super(KeyAlgorithm.ECDSA, "ECDH");
    }

    /**
     * Compute Shared Secret Key using Diffie-Hellman Curve25519 known as X25519
     *
     * @param peerPublicKey Peer public key bytes
     */
    @Override
    void computeK(final byte[] peerPublicKey) {
        byte[] sharedSecretKey = new byte[KEY_LENGTH];
        X25519.calculateAgreement(privateKey, 0, peerPublicKey, 0, sharedSecretKey, 0);
        setK(new BigInteger(1, sharedSecretKey));
    }

    /**
     * Initialize Public and Private Key Pair
     *
     * @param params Parameters are not used
     * @param randomFactory Random Factory for generating private key
     */
    @Override
    public void init(final AlgorithmParameterSpec params, final Factory<Random> randomFactory) {
        generatePrivateKey(randomFactory);
        generatePublicKey();
    }

    private void generatePrivateKey(final Factory<Random> randomFactory) {
        final Random random = randomFactory.create();
        privateKey = new byte[KEY_LENGTH];
        random.fill(privateKey);
    }

    private void generatePublicKey() {
        final byte[] publicKey = new byte[KEY_LENGTH];
        X25519.generatePublicKey(privateKey, 0, publicKey, 0);
        setE(publicKey);
    }
}
