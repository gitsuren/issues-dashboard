package io.spring.demo.issuesdashboard;

import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

//	@Bean
//	public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
//		return new InMemoryUserDetailsManager(
//				User.withDefaultPasswordEncoder().username("user").password("password")
//						.authorities("ROLE_USER").build(),
//				User.withDefaultPasswordEncoder().username("admin").password("admin")
//						.authorities("ROLE_ACTUATOR", "ROLE_ADMIN", "ROLE_USER").build());
//	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		http.authorizeRequests()
//				.mvcMatchers("/admin").hasRole("ADMIN")
//				.requestMatchers(EndpointRequest.to("info", "health")).permitAll()
//				.requestMatchers(EndpointRequest.toAnyEndpoint()).hasRole("ACTUATOR")
//				.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
//				.antMatchers("/events/**").hasRole("USER")
//				.antMatchers("/**").permitAll()
//				.and()
//				.authorizeRequests().antMatchers("/h2-console/**").permitAll()
//				.and().httpBasic();
		http.authorizeRequests()
				.antMatchers("/**").permitAll()
				.antMatchers("/h2-console/**").hasRole("ADMIN")//allow h2 console access to admins only
				.anyRequest().authenticated()//all other urls can be access by any authenticated role
				.and().formLogin()//enable form login instead of basic login
				.and().csrf().ignoringAntMatchers("/h2-console/**")//don't apply CSRF protection to /h2-console
				.and().headers().frameOptions().sameOrigin();//allow use of frame to same origin urls
	}

//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http.authorizeRequests()
//				.antMatchers("/h2-console/**").hasRole("ADMIN")//allow h2 console access to admins only
//				.anyRequest().authenticated()//all other urls can be access by any authenticated role
//				.and().formLogin()//enable form login instead of basic login
//				.and().csrf().ignoringAntMatchers("/h2-console/**")//don't apply CSRF protection to /h2-console
//				.and().headers().frameOptions().sameOrigin();//allow use of frame to same origin urls
//	}
}
