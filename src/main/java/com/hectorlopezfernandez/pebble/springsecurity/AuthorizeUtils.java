package com.hectorlopezfernandez.pebble.springsecurity;

import java.io.IOException;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.core.GenericTypeResolver;
import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.context.support.SecurityWebApplicationContextUtils;

import com.mitchellbosecke.pebble.error.PebbleException;

final class AuthorizeUtils {

	private AuthorizeUtils() {
		// non-instantiable
	}

	public static boolean authorizeUsingAccessExpression(String expression, ServletRequest request, ServletResponse response) throws PebbleException {
		assert SecurityContextHolder.getContext() != null && SecurityContextHolder.getContext().getAuthentication() != null;

		SecurityExpressionHandler<FilterInvocation> handler = getExpressionHandler(request.getServletContext());

		Expression accessExpression;
		try {
			accessExpression = handler.getExpressionParser().parseExpression(expression);
		} catch (ParseException e) {
			throw new PebbleException(e, "The provided security expression is malformed: " + expression);
		}

		FilterInvocation f = new FilterInvocation(request, response,
				new FilterChain() {
					public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
						throw new UnsupportedOperationException();
					}
				});
		return ExpressionUtils.evaluateAsBoolean(accessExpression,
				handler.createEvaluationContext(SecurityContextHolder.getContext()
						.getAuthentication(), f));
	}

	public static boolean authorizeUsingUrlCheck(String url, String method, ServletRequest request) {
		assert SecurityContextHolder.getContext() != null;
		
		String contextPath = ((HttpServletRequest) request).getContextPath();
		Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
		return getPrivilegeEvaluator(request).isAllowed(contextPath, url, method, currentUser);
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	private static SecurityExpressionHandler<FilterInvocation> getExpressionHandler(ServletContext servletContext) {
		ApplicationContext appContext = SecurityWebApplicationContextUtils.findRequiredWebApplicationContext(servletContext);
		Map<String, SecurityExpressionHandler> handlers = appContext.getBeansOfType(SecurityExpressionHandler.class);

		for (SecurityExpressionHandler h : handlers.values()) {
			if (FilterInvocation.class.equals(GenericTypeResolver.resolveTypeArgument(h.getClass(), SecurityExpressionHandler.class))) {
				return h;
			}
		}

		throw new IllegalStateException("Configuration error. No visible WebSecurityExpressionHandler instance could be found"
				+ " in the application context. There must be at least one in order to support expressions in Pebble 'authorize' tags.");
	}

	private static WebInvocationPrivilegeEvaluator getPrivilegeEvaluator(ServletRequest request) {
		WebInvocationPrivilegeEvaluator privEvaluatorFromRequest = (WebInvocationPrivilegeEvaluator) request
				.getAttribute(WebAttributes.WEB_INVOCATION_PRIVILEGE_EVALUATOR_ATTRIBUTE);
		if (privEvaluatorFromRequest != null) {
			return privEvaluatorFromRequest;
		}

		ApplicationContext ctx = SecurityWebApplicationContextUtils.findRequiredWebApplicationContext(request.getServletContext());
		Map<String, WebInvocationPrivilegeEvaluator> wipes = ctx.getBeansOfType(WebInvocationPrivilegeEvaluator.class);

		if (wipes.size() == 0) {
			throw new IllegalStateException("Configuration error. No visible WebInvocationPrivilegeEvaluator instance could be found"
					+ " in the application context. There must be at least one in order to support the use of URL access"
					+ " checks in Pebble 'authorizeUrl' tags.");
		}

		return (WebInvocationPrivilegeEvaluator) wipes.values().toArray()[0];
	}

}