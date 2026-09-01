package com.sist.web.security;

import java.util.Date;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.io.Encoders;
@Component
public class JWTAuthenticationProvider {
	/*public static void main(String[] args) {
		JWTAuthenticationProvider a=
				new JWTAuthenticationProvider();
		String key=a.createSecretKey();
		System.out.println(key);
	}
	public String createSecretKey() {
		SecretKey key=Keys.secretKeyFor(
		  SignatureAlgorithm.HS256
		);
		String secretKey=Encoders.BASE64.encode(key.getEncoded());
		return secretKey;
	}*/
	private final String SECRET="one-secret-key-two-secret-key-three-secret-key";
	public String createToken(String username,String role)
	{
		// Payload => {sub:"admin",role:"ROLE_ADMIN"}
		return Jwts.builder()
				.setSubject(username) // 사용자 ID
				.claim("role", role) // 사용자 권한
				.setIssuedAt(new Date()) // JWT 발급 시간
				.setExpiration(new Date(System.currentTimeMillis()+3600000))
				// 만료 시간 계산 => 60*60^1000
				.signWith(Keys.hmacShaKeyFor(SECRET.getBytes()))
				.compact();
	}
	// 사용자 ID를 추출
	public String getUsername(String token)
	{
		return Jwts.parserBuilder()
				.setSigningKey(SECRET.getBytes())
				.build()
				.parseClaimsJws(token)
				.getBody()
				.getSubject();				
	}
	// 위조 확인
	public boolean validate(String taken)
	{
		try
		{
			Jwts.parserBuilder()
			.setSigningKey(SECRET.getBytes())
			.build()
			.parseClaimsJws(taken);
			return true;
		}catch(Exception ex)
		{
			return false;
		}
	}
}
