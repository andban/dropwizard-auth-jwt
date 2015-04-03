/*
 * Copyright 2015 Andreas Bannach (andreas@borntohula.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

package de.borntohula.dropwizard.auth.jwt;

import com.google.common.base.Optional;
import io.dropwizard.auth.AuthenticationException;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Created by andreas on 03/04/15.
 */
public class BaseJwtAuthenticatorTest {

    private JsonWebKey jsonWebKey;
    private TestBaseJwtAuthenticator authenticator;

    @Before
    public void setup() {
        jsonWebKey = OctJwkGenerator.generateJwk(2048);

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setVerificationKey(jsonWebKey.getKey())
                .setRequireSubject()
                .build();

        authenticator = new TestBaseJwtAuthenticator(jwtConsumer);
    }

    @Test
    public void returnsResultOfValidateClaim() throws Exception {
        assertThat(authenticator.authenticate(createJwt("good-one")).get()).isEqualTo("good-one");
    }

    @Test(expected = AuthenticationException.class)
    public void letsAuthenticationExceptionsThrough() throws Exception {
        authenticator.authenticate(createJwt("bad-one"));
    }

    @Test
    public void returnsAbsentWhenTokenIsInvalid() throws Exception {
        assertThat(authenticator.authenticate("herpderpderp").isPresent()).isFalse();
    }

    private String createJwt(String subject) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setSubject(subject);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(jsonWebKey.getKey());
        jws.setKeyIdHeaderValue(jsonWebKey.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);

        return jws.getCompactSerialization();
    }

    private static class TestBaseJwtAuthenticator extends BaseJwtAuthenticator<String> {

        public TestBaseJwtAuthenticator(JwtConsumer consumer) {
            super(consumer);
        }

        @Override
        protected Optional<String> validateClaims(JwtClaims jwtClaims) throws AuthenticationException {
            try {
                final String subject = jwtClaims.getSubject();
                if ("good-one".equals(subject)) {
                    return Optional.of("good-one");
                }

                if ("bad-one".equals(subject)) {
                    throw new AuthenticationException("server ran out of entropy");
                }
            } catch (MalformedClaimException e) {
                return Optional.absent();
            }

            return Optional.absent();
        }
    }
}
