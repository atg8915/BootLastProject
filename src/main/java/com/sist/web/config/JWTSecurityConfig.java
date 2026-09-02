package com.sist.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.sist.web.security.JWTAuthenticationFilter;
import com.sist.web.security.JWTAuthenticationProvider;
import com.sist.web.service.CustomUserDetailsService;

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
	
	@Bean // 메모리 할당 <bean>
	public JWTAuthenticationFilter jwtAuthenticationFilter(
		CustomUserDetailsService uds,
		JWTAuthenticationProvider provider
	)
	{
		return new JWTAuthenticationFilter(uds, provider);
	}
	
	@Bean
	public SecurityFilterChain securityFilterChain(
			HttpSecurity http,JWTAuthenticationFilter filter)
	throws Exception
	{
		http
		  .csrf(csrf-> csrf.disable())//위조방지
		  .sessionManagement(session-> 
		  		session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			)
		  .formLogin(form->form.disable())
		  .httpBasic(basic->basic.disable())
		  .authorizeHttpRequests(auth->auth
			  .requestMatchers("/","/login","/member").permitAll()
			  .requestMatchers("/admin").hasRole("ADMIN")
			  .anyRequest().permitAll()
		   )
		  .addFilterBefore(filter,
				  UsernamePasswordAuthenticationFilter.class);
		  return http.build();
	}
	// 비밀번호 암호화
	@Bean
	public PasswordEncoder passwordEncoder()
	{
		return new BCryptPasswordEncoder();
		// => 암호화 => encode()
		// => 검색 => matcher()
		// => 같은 비밀번호 => 여러개의 패턴을 이용한다
	}
	// 인가 관리자 등록
	@Bean
	public AuthenticationManager authenticationManager(
		AuthenticationConfiguration config
	)
	throws Exception
	{
		return config.getAuthenticationManager();
	}
}
