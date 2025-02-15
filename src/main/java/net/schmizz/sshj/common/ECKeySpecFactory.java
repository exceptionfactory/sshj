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
package net.schmizz.sshj.common;

import com.hierynomus.sshj.common.KeyAlgorithm;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Objects;

/**
 * Factory for generating Elliptic Curve Key Specifications using Java Security components for NIST Curves
 */
public class ECKeySpecFactory {

    private ECKeySpecFactory() {

    }

    /**
     * Get Elliptic Curve Private Key Spec for private key value and Curve Name
     *
     * @param privateKeyInteger Private Key
     * @param curveName Curve Name
     * @return Elliptic Curve Private Key Spec
     * @throws GeneralSecurityException Thrown on failure to create parameter specification
     */
    public static ECPrivateKeySpec getPrivateKeySpec(final BigInteger privateKeyInteger, final CurveName curveName) throws GeneralSecurityException {
        Objects.requireNonNull(privateKeyInteger, "Private Key integer required");
        Objects.requireNonNull(curveName, "Curve Name required");

        final ECParameterSpec parameterSpec = getParameterSpec(curveName);
        return new ECPrivateKeySpec(privateKeyInteger, parameterSpec);
    }

    /**
     * Get Elliptic Curve Public Key Spec for public key value and Curve Name
     *
     * @param point Public Key point
     * @param curveName Curve Name
     * @return Elliptic Curve Public Key Spec
     * @throws GeneralSecurityException Thrown on failure to create parameter specification
     */
    public static ECPublicKeySpec getPublicKeySpec(final ECPoint point, final CurveName curveName) throws GeneralSecurityException {
        Objects.requireNonNull(point, "Elliptic Curve Point required");
        Objects.requireNonNull(curveName, "Curve Name required");

        final ECParameterSpec parameterSpec = getParameterSpec(curveName);
        return new ECPublicKeySpec(point, parameterSpec);
    }

    private static ECParameterSpec getParameterSpec(final CurveName curveName) throws GeneralSecurityException {
        final ECGenParameterSpec genParameterSpec = new ECGenParameterSpec(curveName.getParameterName());
        final AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance(KeyAlgorithm.EC_KEYSTORE);
        algorithmParameters.init(genParameterSpec);
        return algorithmParameters.getParameterSpec(ECParameterSpec.class);
    }

    public enum CurveName {
        SECP256R1("secp256r1"),

        SECP384R1("secp384r1"),

        SECP521R1("secp521r1");

        private final String parameterName;

        CurveName(final String parameterName) {
            this.parameterName = parameterName;
        }

        public String getParameterName() {
            return parameterName;
        }
    }
}
