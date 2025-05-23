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
package com.hierynomus.sshj.signature;

import net.schmizz.sshj.common.KeyType;
import net.schmizz.sshj.common.SSHRuntimeException;
import net.schmizz.sshj.common.SecurityUtils;
import net.schmizz.sshj.signature.AbstractSignature;
import net.schmizz.sshj.signature.Signature;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

public class SignatureEdDSA extends AbstractSignature {
    public static class Factory implements net.schmizz.sshj.common.Factory.Named<Signature> {

        @Override
        public String getName() {
            return KeyType.ED25519.toString();
        }

        @Override
        public Signature create() {
            return new SignatureEdDSA();
        }
    }

    SignatureEdDSA() {
        super(getEngine(), KeyType.ED25519.toString());
    }

    private static java.security.Signature getEngine() {
        try {
            return SecurityUtils.getSignature("Ed25519");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new SSHRuntimeException("Ed25519 Signatures not supported", e);
        }
    }

    @Override
    public byte[] encode(byte[] signature) {
        return signature;
    }

    @Override
    public boolean verify(byte[] sig) {
        try {
            return signature.verify(extractSig(sig, "ssh-ed25519"));
        } catch (SignatureException e) {
            throw new SSHRuntimeException(e);
        }
    }
}
