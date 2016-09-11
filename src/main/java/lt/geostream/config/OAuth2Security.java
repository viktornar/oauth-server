package lt.geostream.config;

import lt.geostream.security.DefaultUserAuthenticationConverter;
import lt.geostream.security.GoogleAccessTokenConverter;
import lt.geostream.security.GoogleTokenServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.embedded.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import javax.annotation.Resource;
import javax.servlet.Filter;
import java.util.Collections;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;

@Configuration
@EnableOAuth2Client
public class OAuth2Security {
    @Autowired
    private Environment env;

    @Autowired
    OAuth2ClientContext oauth2ClientContext;

    @Resource
    @Qualifier("accessTokenRequest")
    private AccessTokenRequest accessTokenRequest;

    @Bean
    @Scope("session")
    public OAuth2ProtectedResourceDetails googleResource() {
        AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setId("google-oauth-client");
        details.setClientId(env.getProperty("google.client.id"));
        details.setClientSecret(env.getProperty("google.client.secret"));
        details.setAccessTokenUri(env.getProperty("google.accessTokenUri"));
        details.setUserAuthorizationUri(env.getProperty("google.userAuthorizationUri"));
        details.setTokenName(env.getProperty("google.authorization.code"));
        String commaSeparatedScopes = env.getProperty("google.auth.scope");
        details.setScope(parseScopes(commaSeparatedScopes));
        details.setPreEstablishedRedirectUri(env.getProperty("google.preestablished.redirect.url"));
        details.setUseCurrentUri(true);
        details.setAuthenticationScheme(AuthenticationScheme.query);
        details.setClientAuthenticationScheme(AuthenticationScheme.form);
        return details;
    }

    private List<String> parseScopes(String commaSeparatedScopes) {
        List<String> scopes = newArrayList();
        Collections.addAll(scopes, commaSeparatedScopes.split(","));
        return scopes;
    }

    @Bean(name = "restTemplate")
    @Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
    public OAuth2RestTemplate googleRestTemplate() {
        return new OAuth2RestTemplate(googleResource(), new DefaultOAuth2ClientContext(accessTokenRequest));
    }

    @Bean
    public OAuth2ClientContextFilter oAuth2ClientContextFilter() {
        return new OAuth2ClientContextFilter();
    }

    @Bean
    DefaultUserAuthenticationConverter userTokenConverter() {
        return new DefaultUserAuthenticationConverter();
    }

    @Bean
    GoogleAccessTokenConverter accessTokenConverter(DefaultUserAuthenticationConverter userTokenConverter) {
        GoogleAccessTokenConverter accessTokenConverter = new GoogleAccessTokenConverter();
        accessTokenConverter.setUserTokenConverter(userTokenConverter);

        return accessTokenConverter;
    }

    @Bean
    GoogleTokenServices tokenServices(GoogleAccessTokenConverter accessTokenConverter) {
        GoogleTokenServices tokenServices = new GoogleTokenServices();
        tokenServices.setCheckTokenEndpointUrl(env.getProperty("google.tokenInfo"));
        tokenServices.setClientId(env.getProperty("google.client.id"));
        tokenServices.setClientSecret(env.getProperty("google.client.secret"));
        tokenServices.setAccessTokenConverter(accessTokenConverter);

        return tokenServices;
    }

    @Bean
    Filter oAuth2AuthenticationProcessingFilter(
            OAuth2RestOperations restTemplate,
            GoogleTokenServices tokenServices
    ) {
        OAuth2ClientAuthenticationProcessingFilter oAuth2AuthenticationProcessingFilter =
                new OAuth2ClientAuthenticationProcessingFilter(env.getProperty("google.preestablished.redirect.path"));

        oAuth2AuthenticationProcessingFilter.setRestTemplate(restTemplate);
        oAuth2AuthenticationProcessingFilter.setTokenServices(tokenServices);

        return oAuth2AuthenticationProcessingFilter;
    }

    @Bean
    LoginUrlAuthenticationEntryPoint clientAuthenticationEntryPoint() {
        return new LoginUrlAuthenticationEntryPoint(env.getProperty("google.preestablished.redirect.path"));
    }

    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration(
            OAuth2ClientContextFilter oAuth2ClientContextFilter) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(oAuth2ClientContextFilter);
        registration.setOrder(-100);
        return registration;
    }
}
