# dropwizard-auth-jwt

JSON Web Token based authentication for Dropwizard 0.8.x using the [jose4j](https://bitbucket.org/b_c/jose4j) library.


## Getting Started

TODO: upload to maven repo


## Examples

The `JwtAuthFactory` enables JSON Web Token authentication, and requires
an authenticator which transforms the token string into a principal
(see [jose4j](https://bitbucket.org/b_c/jose4j) on how to consume JWTs):

```java
@Override
public void run(ExampleConfiguration config, Environment environment) {
    final JsonWebKey jwk = OctJwkGenerator.generateJwk(2048);

    environment.jersey().register(AuthFactory.binder(
            new JwtAuthFactory<User>(new ExampleAuthenticator(jwk.getKey()),
                                     "MyRealm",
                                      User.class));
}
```

The abstract `BaseJwtAuthenticator` class provides simple validation and
processing through a given `JwtConsumer`. Only the creation
of the principal from the the claims send through the token needs
to be implemented:

```java
public class ExampleAuthenticator extends BaseJwtAuthenticator<User> {
    public ExampleAuthenticator(Key verificationKey) {
        super(new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setRequireSubject()
                .setExpectedIssuer("Issuer")
                .setExpectedAudience("Audience")
                .setVerificationKey(verificationKey)
                .build());
    }

    @Override
    public Optional<User> validateClaims(JwtClaims claims)
            throws AuthenticationException {
        if (TokenRegistry.getInstance().isRevoked(claims.getJwtId()) {
            return Optional.absent();
        }

        return Optional.of(new User(jwtClaims.getSubject()));
    }
}
```

## License

Apache 2.0 License. See LICENSE for further information.