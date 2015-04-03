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
import io.dropwizard.auth.Authenticator;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Abstract base class for simple JWT authenticators.
 *
 * It validates the given token and calls JwtAuthenticator#validateClaims for
 * principal retrieval using the claims of the JWT.
 */
public abstract class BaseJwtAuthenticator<P> implements Authenticator<String, P> {

    protected  final JwtConsumer jwtConsumer;

    /**
     * Constructor.
     *
     * @param consumer the JWT consumer to use for token validation.
     */
    protected BaseJwtAuthenticator(JwtConsumer consumer) {
        checkNotNull(consumer, "consumer must not be null");

        this.jwtConsumer = consumer;
    }

    @Override
    public Optional<P> authenticate(String jwt) throws AuthenticationException {
        try {
            final JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            return validateClaims(jwtClaims);
        } catch (InvalidJwtException e) {
            return Optional.absent();
        }
    }

    /**
     * Validates the given claims and returns an optional principal.
     *
     * If the claims cannot be mapped to a valid principal, an Optional.absent() is returned.
     *
     * @param jwtClaims the claims sent inside the JWT.
     * @return an optional authenticated principal that is absent when the claims are invalid.
     * @throws AuthenticationException if the claims cannot be processed due technical reasons.
     */
    protected abstract Optional<P> validateClaims(JwtClaims jwtClaims) throws AuthenticationException;
}
