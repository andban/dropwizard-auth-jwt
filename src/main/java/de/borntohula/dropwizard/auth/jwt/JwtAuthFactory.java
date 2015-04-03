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
import com.google.common.net.HttpHeaders;
import io.dropwizard.auth.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;

/**
 * JWT authentication factory.
 */
public class JwtAuthFactory<T> extends AuthFactory<String, T> {
    private static final Logger LOG = LoggerFactory.getLogger(JwtAuthFactory.class);

    private final boolean required;
    private final String realm;
    private final Class<T> generatedClass;

    private String prefix = "Bearer";
    private UnauthorizedHandler unauthorizedHandler = new DefaultUnauthorizedHandler();

    @Context
    private HttpServletRequest request;

    /**
     * Constructor.
     *
     * @param authenticator the authenticator to use.
     * @param realm the name of the secured realm.
     * @param generatedClass the principal class.
     */
    public JwtAuthFactory(Authenticator<String, T> authenticator,
                          String realm,
                          Class<T> generatedClass) {
        this(false, authenticator, realm, generatedClass);
    }

    /**
     * Internal constructor for cloning.
     *
     * @param required whether authentication is required.
     * @param authenticator the authenticator to use.
     * @param realm the name of the secured realm.
     * @param generatedClass the principal class.
     */
    private JwtAuthFactory(boolean required,
                           Authenticator<String, T> authenticator,
                           String realm,
                           Class<T> generatedClass) {
        super(authenticator);

        this.required = required;
        this.realm = realm;
        this.generatedClass = generatedClass;
    }

    /**
     * SSets the handler for building custom responses to unauthorized requests.
     *
     * @param unauthorizedHandler the handler instance.
     * @return the factory instance for method chaining.
     */
    public JwtAuthFactory unauthorizedHandler(UnauthorizedHandler unauthorizedHandler) {
        this.unauthorizedHandler = unauthorizedHandler;
        return this;
    }

    /**
     * Sets the expected authentication header prefix.
     * <p><b>Example:</b> <code>Authorization: $prefix ...token...</code></p>
     *
     * @param prefix a string with the prefix.
     * @return the factory instance for method chaining.
     */
    public JwtAuthFactory prefix(String prefix) {
        if (prefix == null || prefix.contains(" ")) {
            throw new IllegalArgumentException("the prefix must not be not null nor contain any spaces");
        }

        this.prefix = prefix;
        return this;
    }

    @Override
    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }

    @Override
    public AuthFactory<String, T> clone(boolean required) {
        return new JwtAuthFactory<>(required, authenticator(), realm, generatedClass);
    }

    @Override
    public Class<T> getGeneratedClass() {
        return generatedClass;
    }

    @Override
    public T provide() {
        try {
            final String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (header != null) {
                final int separator = header.indexOf(' ');
                if (separator > 0) {
                    final String method = header.substring(0, separator);
                    if (prefix.equalsIgnoreCase(method)) {
                        final String jwt = header.substring(separator + 1);
                        final Optional<T> result = authenticator().authenticate(jwt);
                        if (result.isPresent()) {
                            return result.get();
                        }
                    }
                }
            }
        } catch (AuthenticationException ex) {
            LOG.warn("Error while authenticating credentials", ex);
            throw new InternalServerErrorException();
        }

        if (required) {
            throw new WebApplicationException(unauthorizedHandler.buildResponse(prefix, realm));
        }

        return null;
    }
}
