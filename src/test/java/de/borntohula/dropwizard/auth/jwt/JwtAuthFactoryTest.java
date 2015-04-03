/*
 * The MIT License (MIT)
 *
 * Copyright (c)  2015 Andreas Bannach <andreas@borntohula.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package de.borntohula.dropwizard.auth.jwt;

import com.codahale.metrics.MetricRegistry;
import com.google.common.base.Optional;
import io.dropwizard.auth.Auth;
import io.dropwizard.auth.AuthFactory;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.jersey.DropwizardResourceConfig;
import io.dropwizard.logging.LoggingFactory;
import org.glassfish.grizzly.http.util.HttpStatus;
import org.glassfish.jersey.servlet.ServletProperties;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.glassfish.jersey.test.spi.TestContainerException;
import org.glassfish.jersey.test.spi.TestContainerFactory;
import org.junit.Test;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.failBecauseExceptionWasNotThrown;


public class JwtAuthFactoryTest extends JerseyTest {
    private static final String PREFIX = "Bearer";
    private static final String REALM = "test";

    static {
        LoggingFactory.bootstrap();
    }

    @Test
    public void respondsToMissingCredentialsWith401() throws Exception {
        try {
            target("/test").request().get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED_401.getStatusCode());
            assertThat(e.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE))
                    .containsOnly(String.format("%s realm=\"%s\"", PREFIX, REALM));
        }
    }

    @Test
    public void respondsToInvalidCredentialsWith401() throws Exception {
        try {
            target("/test")
                    .request()
                    .header(HttpHeaders.AUTHORIZATION, PREFIX + " " + "herpderpderp!!!1!")
                    .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED_401.getStatusCode());
            assertThat(e.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE))
                    .containsOnly(String.format("%s realm=\"%s\"", PREFIX, REALM));
        }
    }

    @Test
    public void transformsCredentialsToPrincipals() throws Exception {
        String result = target("/test")
                .request()
                .header(HttpHeaders.AUTHORIZATION, PREFIX + " good-one")
                .get(String.class);
        assertThat(result).isEqualTo("good-one");
    }

    @Test
    public void respondsToUnknownPrefixWith401() throws Exception {
        try {
            target("/test")
                    .request()
                    .header(HttpHeaders.AUTHORIZATION, "HERPDERP good-one")
                    .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED_401.getStatusCode());
            assertThat(e.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE))
                    .containsOnly(String.format("%s realm=\"%s\"", PREFIX, REALM));
        }
    }

    @Test
    public void respondsOnExceptionWith500() throws Exception {
        try {
            target("/test")
                    .request()
                    .header(HttpHeaders.AUTHORIZATION, PREFIX + " bad-one")
                    .get(String.class);
            failBecauseExceptionWasNotThrown(WebApplicationException.class);
        } catch (WebApplicationException e) {
            assertThat(e.getResponse().getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR_500.getStatusCode());
        }
    }

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.builder(new JWTAuthTestResourceConfig())
                .initParam(ServletProperties.JAXRS_APPLICATION_CLASS, JWTAuthTestResourceConfig.class.getName())
                .build();
    }

    @Override
    protected TestContainerFactory getTestContainerFactory() throws TestContainerException {
        return  new GrizzlyWebTestContainerFactory();
    }

    private static class JWTAuthTestResourceConfig extends DropwizardResourceConfig {
        public JWTAuthTestResourceConfig() {
            super(true, new MetricRegistry());

            final Authenticator<String, String> authenticator = new Authenticator<String, String>() {
                @Override
                public Optional<String> authenticate(String credentials) throws AuthenticationException {
                    if ("good-one".equals(credentials)) {
                        return Optional.of("good-one");
                    }

                    if ("bad-one".equals(credentials)) {
                        throw new AuthenticationException("server ran out of entropy");
                    }

                    return Optional.absent();
                }
            };

            register(AuthFactory.binder(new JwtAuthFactory<>(authenticator, REALM, String.class).prefix(PREFIX)));
            register(AuthResource.class);
        }
    }

    @Path("/test")
    public static class AuthResource {
        @GET
        public String show(@Auth String principal) {
            return principal;
        }
    }
}