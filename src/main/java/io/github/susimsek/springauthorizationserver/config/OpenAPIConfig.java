package io.github.susimsek.springauthorizationserver.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.ArraySchema;
import io.swagger.v3.oas.models.media.BooleanSchema;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.IntegerSchema;
import io.swagger.v3.oas.models.media.MapSchema;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.parameters.QueryParameter;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.tags.Tag;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

@Configuration
public class OpenAPIConfig {

    private static final String TAG_NAME = "OAuth2 Authorization Server";
    private static final String TAG_DESCRIPTION = "Default OAuth2 Authorization Server Endpoints";
    private static final String SCHEME_NAME = "bearer-jwt";
    private static final String SCHEME_TYPE = "bearer";
    private static final String BEARER_FORMAT = "JWT";
    private static final String SECURITY_SCHEME_TYPE = "HTTP";
    private static final String RESPONSE_200 = "200";
    private static final String RESPONSE_302 = "302";
    private static final String RESPONSE_400 = "400";
    private static final String RESPONSE_401 = "401";
    private static final String RESPONSE_500 = "500";
    private static final String RESPONSE_TYPE = "response_type";
    private static final String CLIENT_ID = "client_id";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String SCOPE = "scope";
    private static final String STATE = "state";
    public static final String RS256 = "RS256";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String CODE_CHALLENGE = "code_challenge";
    public static final String CODE_CHALLENGE_METHOD = "code_challenge_method";
    public static final String CODE_VERIFIER = "code_verifier";
    public static final String NONCE = "nonce";

    @Bean
    public OpenAPI customOpenAPI() {
        OpenAPI openAPI = new OpenAPI()
            .components(new Components()
                .addSecuritySchemes(SCHEME_NAME,
                    new SecurityScheme()
                        .type(SecurityScheme.Type.valueOf(SECURITY_SCHEME_TYPE))
                        .scheme(SCHEME_TYPE)
                        .bearerFormat(BEARER_FORMAT)
                )
                .addSecuritySchemes("basicAuth",
                    new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("basic")
                )
            )
            .info(new Info()
                .title("OAuth2 Authorization Server API")
                .version("1.0.0")
                .description("This is the OAuth2 Authorization Server API documentation."))
            .addTagsItem(new Tag().name(TAG_NAME).description(TAG_DESCRIPTION));

        // Adding default OAuth2 Authorization Server endpoints
        addOAuth2AuthorizationEndpoints(openAPI);

        return openAPI;
    }

    private void addOAuth2AuthorizationEndpoints(OpenAPI openAPI) {
        // /oauth2/authorize
        openAPI.path("/oauth2/authorize", new PathItem()
            .get(new io.swagger.v3.oas.models.Operation()
                .addTagsItem(TAG_NAME)
                .summary("Authorize")
                .description("Endpoint to request authorization. This will redirect to the login/authorization page.")
                .addParametersItem(new QueryParameter()
                    .name(RESPONSE_TYPE)
                    .description("The type of response desired. Typically set to 'code'.")
                    .required(true)
                    .schema(new StringSchema().example("code"))
                )
                .addParametersItem(new QueryParameter()
                    .name(CLIENT_ID)
                    .description("The client ID issued to the client during registration.")
                    .required(true)
                    .schema(new StringSchema().example("client_id_here"))
                )
                .addParametersItem(new QueryParameter()
                    .name(REDIRECT_URI)
                    .description(
                        "The URI to which the authorization server will redirect the user after granting authorization.")
                    .required(true)
                    .schema(new StringSchema().example("http://127.0.0.1:8080/login/oauth2/code/oidc-client"))
                )
                .addParametersItem(new QueryParameter()
                    .name(SCOPE)
                    .description("A space-delimited list of scopes that the client is requesting.")
                    .required(true)
                    .schema(new StringSchema().example("openid profile"))
                )
                .addParametersItem(new QueryParameter()
                    .name(STATE)
                    .description(
                        "An opaque value used by the client to maintain state between the request and callback.")
                    .required(false)
                    .schema(new StringSchema())
                    .example("SU8nskju26XowSCg3bx2LeZq7MwKcwnQ7h6vQY8twd9QJECHRKs14OwXPdpNBI58")
                )
                .addParametersItem(new QueryParameter()
                    .name(CODE_CHALLENGE)
                    .description("PKCE code challenge.")
                    .required(false)
                    .schema(new StringSchema().example("pZYPKf2ddpIU4tYULYh17IEpnj_8FCLsQahC02EnNdU"))
                )
                .addParametersItem(new QueryParameter()
                    .name(CODE_CHALLENGE_METHOD)
                    .description(
                        "PKCE code challenge method. The method used to derive the code challenge. Supported values: plain, S256.")
                    .required(false)
                    .schema(new StringSchema().example("S256"))
                )
                .addParametersItem(new QueryParameter()
                    .name(NONCE)
                    .description(
                        "A string value used to associate a client session with an ID token to mitigate replay attacks.")
                    .required(false)
                    .schema(
                        new StringSchema().example("iAXdcF77sQ2ejthPM5xZtytYUjqZkJTXcHkgdyY2NinFx6y83nKssxEzlBtvnSY2"))
                )
                .responses(createAuthorizeResponses())
                .externalDocs(new ExternalDocumentation()
                    .description("Authorization Endpoint Usage")
                    .url("http://localhost:8080/oauth2/authorize"))
            )
        );

        // /oauth2/token
        openAPI.path("/oauth2/token", new PathItem()
            .post(new io.swagger.v3.oas.models.Operation()
                .addTagsItem(TAG_NAME)
                .summary("Token")
                .description("Endpoint to request access token or refresh token")
                .responses(createTokenResponses())
                .requestBody(new io.swagger.v3.oas.models.parameters.RequestBody()
                    .content(new Content()
                        .addMediaType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                            new MediaType()
                                .schema(new MapSchema()
                                    .properties(Map.of(
                                        "grant_type", new StringSchema()
                                            .description("The type of grant being requested.")
                                            ._enum(List.of("authorization_code", REFRESH_TOKEN))
                                            .example("authorization_code"),
                                        "code", new StringSchema()
                                            .description(
                                                "The authorization code received from the authorization server. Required if grant_type is 'authorization_code'.")
                                            .example("authorization_code_here"),
                                        REDIRECT_URI, new StringSchema()
                                            .description(
                                                "The redirect URI registered with the authorization server. Required if grant_type is 'authorization_code'.")
                                            .example("http://127.0.0.1:8080/login/oauth2/code/oidc-client"),
                                        CLIENT_ID, new StringSchema()
                                            .description("The client ID issued to the client during registration.")
                                            .example("oidc-client"),
                                        CLIENT_SECRET, new StringSchema()
                                            .description("The client secret issued to the client during registration.")
                                            .example("secret"),
                                        REFRESH_TOKEN, new StringSchema()
                                            .description(
                                                "The refresh token used to obtain new access tokens. Required if grant_type is 'refresh_token'.")
                                            .example("refresh_token_here"),
                                        CODE_VERIFIER, new StringSchema()
                                            .description("The PKCE code verifier used to obtain the access token.")
                                            .example("4f965ce13b29210276d4faa8444bf6dfb7b453c1621bdfb90474254f")
                                    ))
                                    .required(List.of("grant_type"))
                                )
                        )
                    )
                )
                .addSecurityItem(new SecurityRequirement().addList("basicAuth"))
            )
        );

        // /oauth2/jwks
        openAPI.path("/oauth2/jwks", new PathItem()
            .get(new io.swagger.v3.oas.models.Operation()
                .addTagsItem(TAG_NAME)
                .summary("JWKS")
                .description("Endpoint to get JSON Web Key Set")
                .responses(createJwksResponses())
            )
        );


        // /openid-configuration
        openAPI.path("/.well-known/openid-configuration", new PathItem()
            .get(new io.swagger.v3.oas.models.Operation()
                .addTagsItem(TAG_NAME)
                .summary("OpenID Connect Discovery")
                .description("OpenID Connect Discovery endpoint providing metadata about the authorization server.")
                .responses(new ApiResponses()
                    .addApiResponse(String.valueOf(HttpStatus.OK.value()), new ApiResponse()
                        .description(HttpStatus.OK.getReasonPhrase())
                        .content(new Content()
                            .addMediaType(org.springframework.http.MediaType.APPLICATION_JSON_VALUE, new MediaType()
                                .schema(new MapSchema()
                                    .properties(createOpenIDConfigProperties())
                                )
                            )
                        )
                    )
                    .addApiResponse(String.valueOf(HttpStatus.BAD_REQUEST.value()),
                        new ApiResponse().description(HttpStatus.BAD_REQUEST.getReasonPhrase()))
                    .addApiResponse(String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value()),
                        new ApiResponse().description(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase()))
                )
            )
        );

        // /oauth2/revoke
        openAPI.path("/oauth2/revoke", new PathItem()
            .post(new io.swagger.v3.oas.models.Operation()
                .addTagsItem(TAG_NAME)
                .summary("Revoke Token")
                .description("Endpoint to revoke an access or refresh token")
                .requestBody(new io.swagger.v3.oas.models.parameters.RequestBody()
                    .content(new Content()
                        .addMediaType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                            new MediaType()
                                .schema(new MapSchema()
                                    .properties(createRevokeTokenProperties())
                                    .required(List.of("token_type_hint", "token"))
                                )
                        )
                    )
                )
                .responses(new ApiResponses()
                    .addApiResponse(String.valueOf(HttpStatus.OK.value()), new ApiResponse()
                        .description(HttpStatus.OK.getReasonPhrase())
                    )
                    .addApiResponse(String.valueOf(HttpStatus.BAD_REQUEST.value()),
                        new ApiResponse().description(HttpStatus.BAD_REQUEST.getReasonPhrase()))
                    .addApiResponse(String.valueOf(HttpStatus.UNAUTHORIZED.value()),
                        new ApiResponse().description(HttpStatus.UNAUTHORIZED.getReasonPhrase()))
                    .addApiResponse(String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value()),
                        new ApiResponse().description(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase()))
                )
                .addSecurityItem(new SecurityRequirement().addList("basicAuth"))
            )
        );

        // /oauth2/introspect
        openAPI.path("/oauth2/introspect", new PathItem()
            .post(new io.swagger.v3.oas.models.Operation()
                .addTagsItem(TAG_NAME)
                .summary("Introspect Token")
                .description("Endpoint to introspect the token")
                .requestBody(new io.swagger.v3.oas.models.parameters.RequestBody()
                    .content(new Content()
                        .addMediaType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                            new MediaType()
                                .schema(new MapSchema()
                                    .properties(Map.of(
                                        "token", new StringSchema()
                                            .description("The token to be introspected.")
                                            .example("access_token_here"),
                                        "token_type_hint", new StringSchema()
                                            .description(
                                                "A hint about the type of the token submitted for introspection.")
                                            .example("access_token")
                                            ._enum(List.of("access_token", "refresh_token")),
                                        CLIENT_ID, new StringSchema()
                                            .description("The client ID issued to the client during registration.")
                                            .example("oidc-client"),
                                        CLIENT_SECRET, new StringSchema()
                                            .description("The client secret issued to the client during registration.")
                                            .example("secret")
                                    ))
                                    .required(List.of("token", "token_type_hint"))
                                )
                        )
                    )
                )
                .responses(new ApiResponses()
                    .addApiResponse(String.valueOf(HttpStatus.OK.value()), new ApiResponse()
                        .description(HttpStatus.OK.getReasonPhrase())
                        .content(new Content()
                            .addMediaType(org.springframework.http.MediaType.APPLICATION_JSON_VALUE, new MediaType()
                                .schema(new MapSchema()
                                    .properties(createTokenIntrospectProperties())
                                )
                            )
                        )
                    )
                    .addApiResponse(String.valueOf(HttpStatus.BAD_REQUEST.value()), new ApiResponse()
                        .description(HttpStatus.BAD_REQUEST.getReasonPhrase()))
                    .addApiResponse(String.valueOf(HttpStatus.UNAUTHORIZED.value()), new ApiResponse()
                        .description(HttpStatus.UNAUTHORIZED.getReasonPhrase()))
                    .addApiResponse(String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value()), new ApiResponse()
                        .description(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase()))
                )
                .addSecurityItem(new SecurityRequirement().addList("basicAuth"))
            )
        );

        // /oauth2/userinfo
        openAPI.path("/userinfo", new PathItem()
            .get(new io.swagger.v3.oas.models.Operation()
                .addTagsItem(TAG_NAME)
                .summary("User Info")
                .description("Endpoint to get information about the authenticated user.")
                .addSecurityItem(new SecurityRequirement().addList(SCHEME_NAME))
                .responses(new ApiResponses()
                    .addApiResponse(RESPONSE_200, new ApiResponse()
                        .description("Successful response")
                        .content(new Content()
                            .addMediaType(org.springframework.http.MediaType.APPLICATION_JSON_VALUE, new MediaType()
                                .schema(new MapSchema()
                                    .properties(createUserInfoProperties())
                                )
                            )
                        )
                    )
                    .addApiResponse(RESPONSE_400,
                        new ApiResponse().description(HttpStatus.BAD_REQUEST.getReasonPhrase()))
                    .addApiResponse(RESPONSE_401,
                        new ApiResponse().description(HttpStatus.UNAUTHORIZED.getReasonPhrase()))
                    .addApiResponse(RESPONSE_500,
                        new ApiResponse().description(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase()))
                )
            )
        );
    }

    private static Map<String, Schema> createTokenIntrospectProperties() {
        Map<String, Schema> properties = new HashMap<>();
        properties.put("active", new BooleanSchema()
            .description("Boolean indicator of whether or not the presented token is currently active.")
            .example(true));
        properties.put(SCOPE, new StringSchema()
            .description("A JSON string containing a space-separated list of scopes associated with this token.")
            .example("read write"));
        properties.put(CLIENT_ID, new StringSchema()
            .description("Client identifier for the token.")
            .example("oidc-client"));
        properties.put("username", new StringSchema()
            .description("Human-readable identifier for the resource owner who authorized this token.")
            .example("user"));
        properties.put("token_type", new StringSchema()
            .description("Type of the token.")
            .example("Bearer"));
        properties.put("exp", new IntegerSchema()
            .description(
                "Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire.")
            .example(1614871140));
        properties.put("iat", new IntegerSchema()
            .description(
                "Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued.")
            .example(1614867540));
        properties.put("nbf", new IntegerSchema()
            .description(
                "Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token is not to be used before.")
            .example(1614867540));
        properties.put("sub", new StringSchema()
            .description("Subject of the token.")
            .example("user"));
        properties.put("aud", new ArraySchema()
            .description(
                "Service-specific string identifier or list of string identifiers representing the intended audience for this token.")
            .items(new StringSchema().example("oidc-client")));
        properties.put("iss", new StringSchema()
            .description("String representing the issuer of this token.")
            .example("http://localhost:7080"));
        properties.put("jti", new StringSchema()
            .description("String identifier for the token.")
            .example("unique-jti-id"));
        return properties;
    }


    private ApiResponses createAuthorizeResponses() {
        return new ApiResponses()
            .addApiResponse(RESPONSE_302, new ApiResponse()
                .description("Found")
                .content(new Content()
                    .addMediaType(org.springframework.http.MediaType.APPLICATION_JSON_VALUE, new MediaType()
                        .schema(new StringSchema()
                            .example("Redirection to login/authorization page"))
                    )
                )
            )
            .addApiResponse(RESPONSE_400, new ApiResponse().description(HttpStatus.BAD_REQUEST.getReasonPhrase()))
            .addApiResponse(RESPONSE_401, new ApiResponse().description(HttpStatus.UNAUTHORIZED.getReasonPhrase()))
            .addApiResponse(RESPONSE_500,
                new ApiResponse().description(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase()));
    }

    private ApiResponses createTokenResponses() {
        return new ApiResponses()
            .addApiResponse(RESPONSE_200, new ApiResponse()
                .description("Token Response")
                .content(new Content()
                    .addMediaType(org.springframework.http.MediaType.APPLICATION_JSON_VALUE, new MediaType()
                        .schema(new MapSchema()
                            .properties(Map.of(
                                "access_token", new StringSchema()
                                    .description("The access token issued by the authorization server")
                                    .example("access_token_here"),
                                "token_type", new StringSchema()
                                    .description("The type of the token issued")
                                    .example(SCHEME_TYPE),
                                "expires_in", new Schema<Integer>().type("integer")
                                    .description("The lifetime in seconds of the access token")
                                    .example(3600),
                                REFRESH_TOKEN, new StringSchema()
                                    .description("The refresh token, which can be used to obtain new access tokens")
                                    .example("refresh_token_here"),
                                SCOPE, new StringSchema()
                                    .description("The scope of the access token")
                                    .example("read write")
                            ))
                            .required(List.of("access_token", "token_type", "expires_in"))
                        )
                    )
                )
            )
            .addApiResponse(RESPONSE_400, new ApiResponse().description(HttpStatus.BAD_REQUEST.getReasonPhrase()))
            .addApiResponse(RESPONSE_401, new ApiResponse().description(HttpStatus.UNAUTHORIZED.getReasonPhrase()))
            .addApiResponse(RESPONSE_500,
                new ApiResponse().description(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase()));
    }

    private ApiResponses createJwksResponses() {
        return new ApiResponses()
            .addApiResponse(String.valueOf(HttpStatus.OK.value()), new ApiResponse()
                .description(HttpStatus.OK.getReasonPhrase())
                .content(new Content()
                    .addMediaType(org.springframework.http.MediaType.APPLICATION_JSON_VALUE, new MediaType()
                        .schema(new MapSchema()
                            .properties(Map.of(
                                "keys", new ArraySchema()
                                    .description("List of keys used to sign tokens.")
                                    .items(new MapSchema()
                                        .properties(Map.of(
                                            "kty", new StringSchema()
                                                .description("Key type")
                                                .example("RSA"),
                                            "e", new StringSchema()
                                                .description("Exponent")
                                                .example("AQAB"),
                                            "use", new StringSchema()
                                                .description("Public key use")
                                                .example("sig"),
                                            "kid", new StringSchema()
                                                .description("Key ID")
                                                .example("1234"),
                                            "alg", new StringSchema()
                                                .description("Algorithm")
                                                .example(RS256),
                                            "n", new StringSchema()
                                                .description("Modulus")
                                                .example("public_key_here")
                                        ))
                                    )
                            ))
                        )
                    )
                )
            )
            .addApiResponse(String.valueOf(HttpStatus.BAD_REQUEST.value()),
                new ApiResponse().description(HttpStatus.BAD_REQUEST.getReasonPhrase()))
            .addApiResponse(String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value()),
                new ApiResponse().description(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase()));
    }

    private Map<String, Schema> createOpenIDConfigProperties() {
        Map<String, Schema> properties = new HashMap<>();
        properties.put("issuer", new StringSchema()
            .description(
                "URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier.")
            .example("https://example.com"));
        properties.put("authorization_endpoint", new StringSchema()
            .description("URL of the authorization server's authorization endpoint.")
            .example("https://example.com/oauth2/authorize"));
        properties.put("token_endpoint", new StringSchema()
            .description("URL of the authorization server's token endpoint.")
            .example("https://example.com/oauth2/token"));
        properties.put("userinfo_endpoint", new StringSchema()
            .description("URL of the authorization server's userinfo endpoint.")
            .example("https://example.com/oauth2/userinfo"));
        properties.put("jwks_uri", new StringSchema()
            .description("URL of the authorization server's JSON Web Key Set (JWKS) document.")
            .example("https://example.com/oauth2/jwks"));
        properties.put("response_types_supported", new ArraySchema()
            .description("List of the OAuth 2.0 response type strings that this authorization server supports.")
            .items(new StringSchema().example("code"))
            .example(List.of("code", "token", "id_token")));
        properties.put("subject_types_supported", new ArraySchema()
            .description("List of the Subject Identifier types that this authorization server supports.")
            .items(new StringSchema().example("public"))
            .example(List.of("public", "pairwise")));
        properties.put("id_token_signing_alg_values_supported", new ArraySchema()
            .description(
                "List of the JWS signing algorithms (alg values) supported by the authorization server for the ID Token to encode the Claims in a JWT.")
            .items(new StringSchema().example(RS256))
            .example(List.of(RS256)));
        properties.put("scopes_supported", new ArraySchema()
            .description("List of the OAuth 2.0 scope values that this authorization server supports.")
            .items(new StringSchema().example("openid"))
            .example(List.of("openid", "profile", "email")));
        properties.put("token_endpoint_auth_methods_supported", new ArraySchema()
            .description("List of the client authentication methods supported by this token endpoint.")
            .items(new StringSchema().example("client_secret_post"))
            .example(List.of("client_secret_post", "client_secret_basic")));
        properties.put("claims_supported", new ArraySchema()
            .description(
                "List of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for.")
            .items(new StringSchema().example("sub"))
            .example(List.of("sub", "iss", "name", "email")));
        return properties;
    }

    private Map<String, Schema> createRevokeTokenProperties() {
        return Map.of(
            "token", new StringSchema()
                .description("The token to be revoked.")
                .example("ACCESS_TOKEN_HERE"),
            "token_type_hint", new StringSchema()
                .type("string")
                .description("A hint about the type of the token submitted for revocation.")
                .example("access_token")
                ._enum(List.of("access_token", REFRESH_TOKEN)),
            CLIENT_ID, new StringSchema()
                .description("The client ID issued to the client during registration.")
                .example("oidc-client"),
            CLIENT_SECRET, new StringSchema()
                .description("The client secret issued to the client during registration.")
                .example("secret")
        );
    }

    private static Map<String, Schema> createUserInfoProperties() {
        Map<String, Schema> properties = new HashMap<>();

        properties.put("sub", new StringSchema()
            .description("Subject - Identifier for the end user.")
            .example("admin"));  // Typically the user ID or unique identifier

        properties.put("name", new StringSchema()
            .description("Full name of the end user.")
            .example("John Doe"));

        properties.put("preferred_username", new StringSchema()
            .description("Preferred username of the end user.")
            .example("admin"));

        properties.put("email", new StringSchema()
            .description("Email address of the end user.")
            .example("admin@example.com"));

        properties.put("email_verified", new BooleanSchema()
            .description("Boolean value indicating whether the end user's email has been verified.")
            .example(true));

        properties.put("phone_number", new StringSchema()
            .description("Phone number of the end user.")
            .example("+1-202-555-0100"));

        properties.put("phone_number_verified", new BooleanSchema()
            .description("Boolean value indicating whether the end user's phone number has been verified.")
            .example(false));

        properties.put("locale", new StringSchema()
            .description("Locale of the end user in IETF BCP 47 format.")
            .example("en-US"));

        properties.put("updated_at", new IntegerSchema()
            .description("Time the end user's information was last updated in seconds since January 1, 1970.")
            .example(689242400));

        properties.put("picture", new StringSchema()
            .description("URL of the end user's profile picture.")
            .example("https://example.com/admin/me.jpg"));

        return properties;
    }
}
