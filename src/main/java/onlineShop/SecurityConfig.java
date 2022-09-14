package onlineShop;

import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private DataSource dataSource;
	
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable() // http.csrf --> cross-site request forgery: handle safety threat of redirecting;
			.formLogin()      // we don't have this implementation, thus disabled;
				.loginPage("/login")
				
			.and()
			.authorizeRequests()
			.antMatchers("/cart/**").hasAuthority("ROLE_USER")
			.antMatchers("/get*/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
			.antMatchers("/admin*/**").hasAuthority("ROLE_ADMIN")
			.anyRequest().permitAll() // all other requests are allowed to every user
			.and()
			.logout() // this logout() is embedded in the system
				.logoutUrl("/logout");
			
	}
	
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// two authentication methods;
		auth
			.inMemoryAuthentication().withUser("stefanlaioffer@gmail.com").password("1234").authorities("ROLE_ADMIN"); // administrator
		
		auth
			.jdbcAuthentication()
			.dataSource(dataSource)
			.usersByUsernameQuery("SELECT emailId, password, enabled FROM users WHERE emailId=?") // AND password=? is automatically implemented
			.authoritiesByUsernameQuery("SELECT emailId, authorities FROM authorities WHERE emailId=?");
		
	}
	
}

