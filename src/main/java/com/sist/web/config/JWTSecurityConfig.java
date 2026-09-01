package com.sist.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
/*
 *    사용자
 *      | /member/login
 *    login.html
 *    ----------
 *      | id / pwd => spring security (username,password)
 *    AuthenticationManager
 *      |
 *    UserDetailsService
 *      |
 *    DB => MyBatis
 *      |
 *    인증완료
 *      |
 *    JwtProvider
 *      |
 *    JWT 토큰 생성
 *      |
 *    JWT 토큰 발급
 *      |
 *    메인 이동
 *      
 */
public class JWTSecurityConfig {
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http)
	throws Exception
	{
		http
		  .csrf(csrf-> csrf.disable())//위조방지
		  .formLogin(form->form.disable())
		  .httpBasic(basic->basic.disable())
		  .authorizeHttpRequests(auth->auth
			  .requestMatchers("/","/login","/member").permitAll()
			  .requestMatchers("/admin").hasRole("ADMIN")
			  .anyRequest().permitAll()
		   );
		  return http.build();
	}
}
