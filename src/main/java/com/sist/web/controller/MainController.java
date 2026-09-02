package com.sist.web.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class MainController {
	@GetMapping("/")
	public String main(Authentication auth,Model model)
	{
		boolean isLogin=auth!=null
						&& auth.isAuthenticated()
						&& auth.getPrincipal()
							   .toString()
							   .equals("")==false;
		model.addAttribute("isLogin", isLogin);
		
		if(isLogin) {
			String username=auth.getName();
			String role=auth.getAuthorities()
							.iterator()
							.next()
							.getAuthority();
			model.addAttribute("username",username);
			model.addAttribute("role",role);
		}
		return "main/main";
	}
	@GetMapping("/member/login")
	public String member_login()
	{
		
		return "member/login";
	}
}
