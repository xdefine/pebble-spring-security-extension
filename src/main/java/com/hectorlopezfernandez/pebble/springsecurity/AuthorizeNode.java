package com.hectorlopezfernandez.pebble.springsecurity;

import java.io.IOException;
import java.io.Writer;

import org.springframework.security.core.context.SecurityContextHolder;

import com.mitchellbosecke.pebble.error.PebbleException;
import com.mitchellbosecke.pebble.extension.NodeVisitor;
import com.mitchellbosecke.pebble.node.AbstractRenderableNode;
import com.mitchellbosecke.pebble.node.BodyNode;
import com.mitchellbosecke.pebble.node.expression.Expression;
import com.mitchellbosecke.pebble.template.EvaluationContext;
import com.mitchellbosecke.pebble.template.PebbleTemplateImpl;

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
    		// evaluate expression
    		Object evaluatedExpression = securityExpression.evaluate(self, context);
    		if (!(evaluatedExpression instanceof String)) {
    			throw new IllegalArgumentException("Authorize block only supports String expressions. Actual argument was: " + (evaluatedExpression == null ? "null" : evaluatedExpression.getClass().getName()));
    		}
    		renderMainBody = AuthorizeUtils.authorizeUsingAccessExpression((String)evaluatedExpression, null, null);
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