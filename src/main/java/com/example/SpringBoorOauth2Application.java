package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
@RestController
public class SpringBoorOauth2Application {

	@RequestMapping("/user")
	public Principal user(final Principal principal) {
		return principal;
	}

	public static void main(String[] args) {
		SpringApplication.run(SpringBoorOauth2Application.class, args);
	}

	@EnableOAuth2Client
	@Configuration
	static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

		@Autowired
		private OAuth2ClientContext oauth2ClientContext;

		@Override
		protected void configure(final HttpSecurity http) throws Exception {
			//@formatter:off
			http
				.antMatcher("/**")
				.authorizeRequests()
					.antMatchers("/", "/login**", "/webjars/**")
					.permitAll()
				.anyRequest()
					.authenticated()
					.and()
				.logout().logoutSuccessUrl("/").permitAll()
					.and()
				.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				.and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
			//@formatter:on
		}

		private Filter ssoFilter() {
			final CompositeFilter compositeFilter = new CompositeFilter();
			final List<Filter> filters = new ArrayList<>();
			filters.add(ssoFilter(facebook(), "/login/facebook"));
			filters.add(ssoFilter(github(), "/login/github"));
			compositeFilter.setFilters(filters);
			return compositeFilter;
		}

		private Filter ssoFilter(final ClientResources client, final String path) {
			final OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
			filter.setRestTemplate(new OAuth2RestTemplate(client.getClient(), oauth2ClientContext));
			filter.setTokenServices(new UserInfoTokenServices(client.getResource().getUserInfoUri(), client.getClient().getClientId()));
			return filter;
		}

		@Bean
		@ConfigurationProperties("facebook")
		public ClientResources facebook() {
			return new ClientResources();
		}

		@Bean
		@ConfigurationProperties("github")
		public ClientResources github() {
			return new ClientResources();
		}

		@Bean
		public FilterRegistrationBean oauth2ClientFilterRegistration(final OAuth2ClientContextFilter filter) {
			final FilterRegistrationBean registration = new FilterRegistrationBean();
			registration.setFilter(filter);
			registration.setOrder(-100);
			return registration;
		}
	}

	static class ClientResources {

		@NestedConfigurationProperty
		private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

		@NestedConfigurationProperty
		private ResourceServerProperties resource = new ResourceServerProperties();

		@SuppressWarnings("WeakerAccess")
		public AuthorizationCodeResourceDetails getClient() {
			return client;
		}

		@SuppressWarnings("WeakerAccess")
		public ResourceServerProperties getResource() {
			return resource;
		}
	}
}
