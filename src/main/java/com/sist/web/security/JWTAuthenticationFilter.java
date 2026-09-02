package com.sist.web.security;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import com.sist.web.service.CustomUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
/*
 * 	  사용자 정보 저장 : UserDetail
 * 
 */
public class JWTAuthenticationFilter extends OncePerRequestFilter{
	private final CustomUserDetailsService uds;
	private final JWTAuthenticationProvider provider;
	public JWTAuthenticationFilter(
		CustomUserDetailsService uds,
		JWTAuthenticationProvider provider
	)
	{
		this.uds=uds;
		this.provider=provider;
	}
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		String token=null;
		// 1. header 2. cookie
		// ------> Vue/React => header
		String header=request.getHeader("Authorization"); //JSON
		// {"Authorization":"Bearer eewroeroeroeroeroer"}
		//							=> subject:id , role 권한
		if(header!=null && header.startsWith("Bearer "))
		{
			token=header.substring(7);
		}
		
		// Cokkie 처리
		if(token==null && request.getCookies()!=null)
		{
			for(Cookie cookie:request.getCookies())
			{
				if("accessToken".equals(cookie.getName()))
				{
					token=cookie.getValue();
					break;
				}
			}
		}
		
		// JWT 검중
		if(token!=null && provider.validate(token))
		{
			String username=provider.getUsername(token);
			UserDetails user=
					uds.loadUserByUsername(username);
			UsernamePasswordAuthenticationToken auth=
					new UsernamePasswordAuthenticationToken(
						user,
						null,//자격 정보
						user.getAuthorities()
					);
			SecurityContextHolder
					.getContext()
					.setAuthentication(auth);
		}
		// => 다음 Filter 사용 => Controller 실행
		filterChain.doFilter(request, response);
		// 요청 = DispatcherServlet
		// 요청 = Security = DispatcherServlet
	}

}
/*
 * 	  요청
 *     |
 *    Spring Security => Filter Chain
 *     | => 인증 / 인가 검사
 *    DispatcherServlet
 *     | => Controller 찾기 => @GetMapping / @PostMapping
 *    Controller / RestController
 *     |
 *    Service
 *     |
 *    Repository (Mapper)
 *     |
 *    Controller
 *     |
 *    DispatcherServlet
 *     |
 *    Vue / ThymeLeaf/React
 *     |
 *    브라우저 출력
 *    => Spring Security > DispatcherServlet
 */