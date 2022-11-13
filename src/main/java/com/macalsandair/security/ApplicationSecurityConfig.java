package com.macalsandair.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.macalsandair.auth.ApplicationUserService;

import static com.macalsandair.security.ApplicationUserRole.*;

import java.util.concurrent.TimeUnit;

import static com.macalsandair.security.ApplicationUserPermission.*;



@SuppressWarnings("deprecation")
@Configuration 
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final PasswordEncoder passwordEncoder;
	private final ApplicationUserService applicationUserService;

	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
		super();
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
	}

	@Override
	protected void configure (HttpSecurity http) throws Exception {
		http
			//.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			//.and()
			.csrf().disable()
			.authorizeRequests()
			.antMatchers("/", "/index", "/css/*", "/js/*").permitAll()
			.antMatchers("/api/*").hasRole(ApplicationUserRole.STUDENT.name())
//			.antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//			.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//			.antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//			.antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
			.anyRequest()
			.authenticated()
			.and()
			.formLogin()
				.loginPage("/login")
				.permitAll()
				.defaultSuccessUrl("/courses", true)
				.passwordParameter("password")
				.usernameParameter("username")
			.and()
			.rememberMe()//defaults to 2 week 
				.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
				.key("somethingverysecured")
				.rememberMeParameter("remember-me")
			.and()
			.logout()
				.logoutUrl("/logout")
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) //Use it, if csrf enabled, and you want "GET" request
				.clearAuthentication(true)
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID", "remember-me")
				.logoutSuccessUrl("/login");
	}

//	@Override
//	@Bean
//	protected UserDetailsService userDetailsService() {
//		UserDetails annaSmithUser = User
//				.builder()
//				.username("annasmith")
//				.password(passwordEncoder.encode("password"))
//				//.roles(ApplicationUserRole.STUDENT.name())
//				.authorities(STUDENT.getGrantedAuthorities())
//				.build();
//		
//		UserDetails lindaUser = User.builder()
//				.username("linda")
//				.password(passwordEncoder.encode("password"))
//				//.roles(ApplicationUserRole.ADMIN.name())
//				.authorities(ADMIN.getGrantedAuthorities())
//				.build();
//		
//		UserDetails tomUser = User.builder()
//				.username("tom")
//				.password(passwordEncoder.encode("password"))
//				//.roles(ApplicationUserRole.ADMINTRAINEE.name())
//				.authorities(ADMINTRAINEE.getGrantedAuthorities())
//				.build();
//		
//		return new InMemoryUserDetailsManager(annaSmithUser, lindaUser, tomUser);
//	}
	
	
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider () {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
		
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}

	
}
