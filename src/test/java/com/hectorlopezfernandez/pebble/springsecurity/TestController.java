package com.hectorlopezfernandez.pebble.springsecurity;

import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class TestController {

	@RequestMapping(value="/authenticated.page")
	public String authenticated(ModelMap model) {
		return "authenticated";
	}

	@RequestMapping(value="/authorized1.page")
	public String authorized1(ModelMap model) {
		return "authorized1";
	}

	@RequestMapping(value="/authorized2.page")
	public String authorized2(ModelMap model) {
		return "authorized2";
	}

	@RequestMapping(value="/principal.page")
	public String principal(ModelMap model) {
		return "principal";
	}

}