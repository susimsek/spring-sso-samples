package io.github.susimsek.springssosamples.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.tags.Tag;
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
    private static final String MEDIA_TYPE_JSON = org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
    private static final String MEDIA_TYPE_FORM = org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
    private static final String PARAM_RESPONSE_TYPE = "response_type";
    private static final String PARAM_CLIENT_ID = "client_id";
    private static final String PARAM_REDIRECT_URI = "redirect_uri";
    private static final String PARAM_SCOPE = "scope";
    private static final String PARAM_STATE = "state";
    private static final String SCHEMA_TYPE_STRING = "string";
    private static final String SCHEMA_TYPE_OBJECT = "object";
    private static final String SCHEMA_TYPE_ARRAY = "array";
    public static final String QUERY = "query";

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
                .addParametersItem(new Parameter()
                    .name(PARAM_RESPONSE_TYPE)
                    .in(QUERY)
                    .description("The type of response desired. Typically set to 'code'.")
                    .required(true)
                    .schema(new Schema<String>().type(SCHEMA_TYPE_STRING).example("code"))
                )
                .addParametersItem(new Parameter()
                    .name(PARAM_CLIENT_ID)
                    .in(QUERY)
                    .description("The client ID issued to the client during registration.")
                    .required(true)
                    .schema(new Schema<String>().type(SCHEMA_TYPE_STRING).example("client_id_here"))
                )
                .addParametersItem(new Parameter()
                    .name(PARAM_REDIRECT_URI)
                    .in(QUERY)
                    .description(
                        "The URI to which the authorization server will redirect the user after granting authorization.")
                    .required(true)
                    .schema(new Schema<String>().type(SCHEMA_TYPE_STRING).example("http://localhost:8080/callback"))
                )
                .addParametersItem(new Parameter()
                    .name(PARAM_SCOPE)
                    .in(QUERY)
                    .description("A space-delimited list of scopes that the client is requesting.")
                    .required(true)
                    .schema(new Schema<String>().type(SCHEMA_TYPE_STRING).example("read write"))
                )
                .addParametersItem(new Parameter()
                    .name(PARAM_STATE)
                    .in(QUERY)
                    .description(
                        "An opaque value used by the client to maintain state between the request and callback.")
                    .required(false)
                    .schema(new Schema<String>().type(SCHEMA_TYPE_STRING).example("xyz"))
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
                        .addMediaType(MEDIA_TYPE_FORM, new MediaType()
                            .schema(new Schema<Map<String, String>>()
                                .type(SCHEMA_TYPE_OBJECT)
                                .properties(Map.of(
                                    "grant_type", new Schema<String>().type(SCHEMA_TYPE_STRING)
                                        .description("The type of grant being requested")
                                        .example("authorization_code"),
                                    "code", new Schema<String>().type(SCHEMA_TYPE_STRING)
                                        .description("The authorization code received from the authorization server")
                                        .example("authorization_code_here"),
                                    PARAM_REDIRECT_URI, new Schema<String>().type(SCHEMA_TYPE_STRING)
                                        .description("The redirect URI registered with the authorization server")
                                        .example("http://localhost:8080/callback"),
                                    PARAM_CLIENT_ID, new Schema<String>().type(SCHEMA_TYPE_STRING)
                                        .description("The client ID issued to the client during registration")
                                        .example("client_id_here"),
                                    "client_secret", new Schema<String>().type(SCHEMA_TYPE_STRING)
                                        .description("The client secret issued to the client during registration")
                                        .example("client_secret_here")
                                ))
                                .required(List.of("grant_type", "code", PARAM_REDIRECT_URI, PARAM_CLIENT_ID, "client_secret"))
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
    }

    private ApiResponses createAuthorizeResponses() {
        return new ApiResponses()
            .addApiResponse(RESPONSE_302, new ApiResponse()
                .description("Found")
                .content(new Content()
                    .addMediaType(MEDIA_TYPE_JSON, new MediaType()
                        .schema(new Schema<>()
                            .example("Redirection to login/authorization page"))
                    )
                )
            )
            .addApiResponse(RESPONSE_400, new ApiResponse().description(HttpStatus.BAD_REQUEST.getReasonPhrase()))
            .addApiResponse(RESPONSE_401, new ApiResponse().description(HttpStatus.UNAUTHORIZED.getReasonPhrase()))
            .addApiResponse(RESPONSE_500, new ApiResponse().description(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase()));
    }

    private ApiResponses createTokenResponses() {
        return new ApiResponses()
            .addApiResponse(RESPONSE_200, new ApiResponse()
                .description("Token Response")
                .content(new Content()
                    .addMediaType(org.springframework.http.MediaType.APPLICATION_JSON_VALUE, new MediaType()
                        .schema(new Schema<Map<String, Object>>()
                            .type(SCHEMA_TYPE_OBJECT)
                            .properties(Map.of(
                                "access_token", new Schema<String>().type(SCHEMA_TYPE_STRING)
                                    .description("The access token issued by the authorization server")
                                    .example("access_token_here"),
                                "token_type", new Schema<String>().type(SCHEMA_TYPE_STRING)
                                    .description("The type of the token issued")
                                    .example(SCHEME_TYPE),
                                "expires_in", new Schema<Integer>().type("integer")
                                    .description("The lifetime in seconds of the access token")
                                    .example(3600),
                                "refresh_token", new Schema<String>().type(SCHEMA_TYPE_STRING)
                                    .description("The refresh token, which can be used to obtain new access tokens")
                                    .example("refresh_token_here"),
                                PARAM_SCOPE, new Schema<String>().type(SCHEMA_TYPE_STRING)
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
            .addApiResponse(RESPONSE_500, new ApiResponse().description(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase()));
    }

    private ApiResponses createJwksResponses() {
        return new ApiResponses()
            .addApiResponse(RESPONSE_200, new ApiResponse()
                .description("JWKS Response")
                .content(new Content()
                    .addMediaType(MEDIA_TYPE_JSON, new MediaType()
                        .schema(new Schema<Map<String, Object>>()
                            .type(SCHEMA_TYPE_OBJECT)
                            .properties(Map.of(
                                "keys", new Schema<List<Map<String, Object>>>()
                                    .type(SCHEMA_TYPE_ARRAY)
                                    .items(new Schema<Map<String, Object>>()
                                        .properties(Map.of(
                                            "kty", new Schema<String>().type(SCHEMA_TYPE_STRING)
                                                .description("Key type")
                                                .example("RSA"),
                                            "e", new Schema<String>().type(SCHEMA_TYPE_STRING)
                                                .description("Exponent")
                                                .example("AQAB"),
                                            "use", new Schema<String>().type(SCHEMA_TYPE_STRING)
                                                .description("Public key use")
                                                .example("sig"),
                                            "kid", new Schema<String>().type(SCHEMA_TYPE_STRING)
                                                .description("Key ID")
                                                .example("1234"),
                                            "alg", new Schema<String>().type(SCHEMA_TYPE_STRING)
                                                .description("Algorithm")
                                                .example("RS256"),
                                            "n", new Schema<String>().type(SCHEMA_TYPE_STRING)
                                                .description("Modulus")
                                                .example("public_key_here")
                                        ))
                                    )
                            ))
                        )
                    )
                )
            )
            .addApiResponse(RESPONSE_400, new ApiResponse().description(HttpStatus.BAD_REQUEST.getReasonPhrase()))
            .addApiResponse(RESPONSE_500, new ApiResponse().description(HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase()));
    }
}
