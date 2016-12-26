package com.hectorlopezfernandez.pebble.springsecurity;

import java.io.IOException;
import java.io.Writer;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.security.core.context.SecurityContextHolder;

import com.mitchellbosecke.pebble.error.PebbleException;
import com.mitchellbosecke.pebble.extension.NodeVisitor;
import com.mitchellbosecke.pebble.node.AbstractRenderableNode;
import com.mitchellbosecke.pebble.node.BodyNode;
import com.mitchellbosecke.pebble.node.expression.Expression;
import com.mitchellbosecke.pebble.spring4.PebbleView;
import com.mitchellbosecke.pebble.template.EvaluationContext;
import com.mitchellbosecke.pebble.template.PebbleTemplateImpl;
import com.mitchellbosecke.pebble.template.ScopeChain;

public class AuthorizeNode extends AbstractRenderableNode {

    private final Expression<?> securityExpression;
    private final BodyNode body;
    private final BodyNode elseBody;

    public AuthorizeNode(int lineNumber, Expression<?> securityExpression, BodyNode body, BodyNode elseBody) {
        super(lineNumber);
        this.securityExpression = securityExpression;
        this.body = body;
        this.elseBody = elseBody;
    }

    @Override
    public void render(PebbleTemplateImpl self, Writer writer, EvaluationContext context) throws PebbleException, IOException {
    	// decide if main body should be rendered
    	boolean renderMainBody = false;
    	if (SecurityContextHolder.getContext() != null && SecurityContextHolder.getContext().getAuthentication() != null) {
    		ScopeChain scope = context.getScopeChain();
    		// framework provided arguments
    		ServletRequest request = (ServletRequest)scope.get(PebbleView.REQUEST_VARIABLE_NAME);
    		if (request == null) {
    			throw new IllegalStateException("Configuration error. No visible ServletRequest instance could be found"
    					+ " in the evaluation context. Check if pebble-spring4 is well configured.");
    		}
    		ServletResponse response = (ServletResponse)scope.get(PebbleView.RESPONSE_VARIABLE_NAME);
    		if (response == null) {
    			throw new IllegalStateException("Configuration error. No visible ServletResponse instance could be found"
    					+ " in the evaluation context. Check if pebble-spring4 is well configured.");
    		}
    		// evaluate expression
    		Object evaluatedExpression = securityExpression.evaluate(self, context);
    		if (!(evaluatedExpression instanceof String)) {
    			throw new IllegalArgumentException("Authorize block only supports String expressions. Actual argument was: " + (evaluatedExpression == null ? "null" : evaluatedExpression.getClass().getName()));
    		}
    		renderMainBody = AuthorizeUtils.authorizeUsingAccessExpression((String)evaluatedExpression, request, response);
    	}

        // render body
        if (renderMainBody) {
        	body.render(self, writer, context);
        } else if (elseBody != null) {
            elseBody.render(self, writer, context);
        }
    }

    @Override
    public void accept(NodeVisitor visitor) {
        visitor.visit(this);
    }

    public BodyNode getBody() {
        return body;
    }

    public BodyNode getElseBody() {
        return elseBody;
    }

}