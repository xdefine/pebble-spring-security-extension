package com.hectorlopezfernandez.pebble.springsecurity;

import java.io.IOException;
import java.io.Writer;

import javax.servlet.ServletRequest;

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

public class AuthorizeUrlNode extends AbstractRenderableNode {

    private static final String DEFAULT_METHOD = "GET";

    private final Expression<?> urlExpression;
    private final Expression<?> methodExpression;
    private final BodyNode body;
    private final BodyNode elseBody;

    public AuthorizeUrlNode(int lineNumber, Expression<?> urlExpression, Expression<?> methodExpression, BodyNode body, BodyNode elseBody) {
        super(lineNumber);
        this.urlExpression = urlExpression;
        this.methodExpression = methodExpression;
        this.body = body;
        this.elseBody = elseBody;
    }

    @Override
    public void render(PebbleTemplateImpl self, Writer writer, EvaluationContext context) throws PebbleException, IOException {
    	// decide if main body should be rendered
    	boolean renderMainBody = false;
    	if (SecurityContextHolder.getContext() != null) {
    		ScopeChain scope = context.getScopeChain();
    		// framework provided arguments
    		ServletRequest request = (ServletRequest)scope.get(PebbleView.REQUEST_VARIABLE_NAME);
    		if (request == null) {
    			throw new IllegalStateException("Configuration error. No visible ServletRequest instance could be found"
    					+ " in the evaluation context. Check if pebble-spring3 is well configured.");
    		}
    		// evaluate expressions
    		Object evaluatedUrl = urlExpression.evaluate(self, context);
    		if (!(evaluatedUrl instanceof String)) {
    			throw new IllegalArgumentException("AuthorizeUrl block only supports String urls. Actual argument was: " + (evaluatedUrl == null ? "null" : evaluatedUrl.getClass().getName()));
    		}
    		Object evaluatedMethod = methodExpression == null ? DEFAULT_METHOD : methodExpression.evaluate(self, context);
    		if (!(evaluatedMethod instanceof String)) {
    			throw new IllegalArgumentException("AuthorizeUrl block only supports String methods. Actual argument was: " + (evaluatedMethod == null ? "null" : evaluatedMethod.getClass().getName()));
    		}
    		renderMainBody = AuthorizeUtils.authorizeUsingUrlCheck((String)evaluatedUrl, (String)evaluatedMethod, request);
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