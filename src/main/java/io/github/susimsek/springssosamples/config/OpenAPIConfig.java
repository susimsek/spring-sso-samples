package io.github.susimsek.springssosamples.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.ArraySchema;
import io.swagger.v3.oas.models.media.Content;
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
    private static final String PARAM_RESPONSE_TYPE = "response_type";
    private static final String PARAM_CLIENT_ID = "client_id";
    private static final String PARAM_REDIRECT_URI = "redirect_uri";
    private static final String PARAM_SCOPE = "scope";
    private static final String PARAM_STATE = "state";
    public static final String RS256 = "RS256";

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
            )
            .addSecurityItem(new SecurityRequirement().addList(SCHEME_NAME))
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
                    .name(PARAM_RESPONSE_TYPE)
                    .description("The type of response desired. Typically set to 'code'.")
                    .required(true)
                    .schema(new StringSchema().example("code"))
                )
                .addParametersItem(new QueryParameter()
                    .name(PARAM_CLIENT_ID)
                    .description("The client ID issued to the client during registration.")
                    .required(true)
                    .schema(new StringSchema().example("client_id_here"))
                )
                .addParametersItem(new QueryParameter()
                    .name(PARAM_REDIRECT_URI)
                    .description(
                        "The URI to which the authorization server will redirect the user after granting authorization.")
                    .required(true)
                    .schema(new StringSchema().example("http://localhost:8080/callback"))
                )
                .addParametersItem(new QueryParameter()
                    .name(PARAM_SCOPE)
                    .description("A space-delimited list of scopes that the client is requesting.")
                    .required(true)
                    .schema(new StringSchema().example("read write"))
                )
                .addParametersItem(new QueryParameter()
                    .name(PARAM_STATE)
                    .description(
                        "An opaque value used by the client to maintain state between the request and callback.")
                    .required(false)
                    .schema(new StringSchema()).example("xyz")
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
                .description("Endpoint to request access token")
                .responses(createTokenResponses())
                .requestBody(new io.swagger.v3.oas.models.parameters.RequestBody()
                    .content(new Content()
                        .addMediaType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE,
                            new MediaType()
                            .schema(new MapSchema()
                                .properties(Map.of(
                                    "grant_type", new StringSchema()
                                        .description("The type of grant being requested")
                                        .example("authorization_code"),
                                    "code", new StringSchema()
                                        .description("The authorization code received from the authorization server")
                                        .example("authorization_code_here"),
                                    PARAM_REDIRECT_URI, new StringSchema()
                                        .description("The redirect URI registered with the authorization server")
                                        .example("http://localhost:8080/callback"),
                                    PARAM_CLIENT_ID, new StringSchema()
                                        .description("The client ID issued to the client during registration")
                                        .example("client_id_here"),
                                    "client_secret", new StringSchema()
                                        .description("The client secret issued to the client during registration")
                                        .example("client_secret_here")
                                ))
                                .required(
                                    List.of("grant_type", "code", PARAM_REDIRECT_URI, PARAM_CLIENT_ID, "client_secret"))
                            )
                        )
                    )
                )
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
                                "refresh_token", new StringSchema()
                                    .description("The refresh token, which can be used to obtain new access tokens")
                                    .example("refresh_token_here"),
                                PARAM_SCOPE, new StringSchema()
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
            .addApiResponse(String.valueOf(HttpStatus.BAD_REQUEST.value()), new ApiResponse().description(HttpStatus.BAD_REQUEST.getReasonPhrase()))
            .addApiResponse(String.valueOf(HttpStatus.INTERNAL_SERVER_ERROR.value()), new ApiResponse().description(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase()));
    }

    private Map<String, Schema> createOpenIDConfigProperties() {
        Map<String, Schema> properties = new HashMap<>();
        properties.put("issuer", new StringSchema()
            .description("URL using the https scheme with no query or fragment component that the OP asserts as its Issuer Identifier.")
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
            .description("List of the JWS signing algorithms (alg values) supported by the authorization server for the ID Token to encode the Claims in a JWT.")
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
            .description("List of the Claim Names of the Claims that the OpenID Provider MAY be able to supply values for.")
            .items(new StringSchema().example("sub"))
            .example(List.of("sub", "iss", "name", "email")));
        return properties;
    }
}
