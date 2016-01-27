package com.hectorlopezfernandez.pebble.springsecurity;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import com.mitchellbosecke.pebble.extension.Function;

public class PrincipalFunction implements Function {

    public PrincipalFunction() {
    }

    @Override
    public List<String> getArgumentNames() {
        return Collections.emptyList();
    }

    @Override
    public Object execute(Map<String, Object> args) {
    	if (SecurityContextHolder.getContext() == null 
    			|| !(SecurityContextHolder.getContext() instanceof SecurityContext) 
    			|| SecurityContextHolder.getContext().getAuthentication() == null) {
    		return null;
    	} else {
    		return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    	}
    }

}