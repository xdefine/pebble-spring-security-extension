package com.hectorlopezfernandez.pebble.springsecurity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.mitchellbosecke.pebble.extension.AbstractExtension;
import com.mitchellbosecke.pebble.extension.Filter;
import com.mitchellbosecke.pebble.extension.Function;
import com.mitchellbosecke.pebble.tokenParser.TokenParser;

public class SecurityExtension extends AbstractExtension {
	
    public SecurityExtension() {
    }

    @Override
    public Map<String, Filter> getFilters() {
        return Collections.emptyMap();
    }
    
    @Override
    public Map<String, Function> getFunctions() {
    	Map<String, Function> functions = new HashMap<>(2);
    	functions.put("principal", new PrincipalFunction());
        return functions;
    }

    @Override
    public List<TokenParser> getTokenParsers() {
        List<TokenParser> parsers = new ArrayList<>(2);
        parsers.add(new AuthorizeTokenParser());
        parsers.add(new AuthorizeUrlTokenParser());
        return parsers;
    }

}