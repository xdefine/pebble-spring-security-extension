package com.hectorlopezfernandez.pebble.springsecurity;

import com.mitchellbosecke.pebble.error.ParserException;
import com.mitchellbosecke.pebble.lexer.Token;
import com.mitchellbosecke.pebble.lexer.TokenStream;
import com.mitchellbosecke.pebble.node.BodyNode;
import com.mitchellbosecke.pebble.node.RenderableNode;
import com.mitchellbosecke.pebble.node.expression.Expression;
import com.mitchellbosecke.pebble.parser.Parser;
import com.mitchellbosecke.pebble.parser.StoppingCondition;
import com.mitchellbosecke.pebble.tokenParser.AbstractTokenParser;

public class AuthorizeTokenParser extends AbstractTokenParser {

    private static final String START_TAG = "authorize";
    private static final String FORK_TAG = "else";
    private static final String END_TAG = "endAuthorize";

	@Override
    public RenderableNode parse(Token token, Parser parser) throws ParserException {
        TokenStream stream = parser.getStream();
        int lineNumber = token.getLineNumber();

        // parse the start token
        stream.next();
        Expression<?> securityExpression = parser.getExpressionParser().parseExpression();
        stream.expect(Token.Type.EXECUTE_END);

        // parse body
        BodyNode body = parser.subparse(decideForFork);
        BodyNode elseBody = null;

        // if there's an else token, parse it
        if (stream.current().test(Token.Type.NAME, FORK_TAG)) {
            stream.next();
            stream.expect(Token.Type.EXECUTE_END);
            
            // parse else body
            elseBody = parser.subparse(decideForEnd);
        }

        // parse the end token
        stream.next();
        stream.expect(Token.Type.EXECUTE_END);

        return new AuthorizeNode(lineNumber, securityExpression, body, elseBody);
    }

    private StoppingCondition decideForFork = new StoppingCondition() {
        @Override
        public boolean evaluate(Token token) {
            return token.test(Token.Type.NAME, FORK_TAG, END_TAG);
        }
    };

    private StoppingCondition decideForEnd = new StoppingCondition() {
        @Override
        public boolean evaluate(Token token) {
            return token.test(Token.Type.NAME, END_TAG);
        }
    };

    @Override
    public String getTag() {
        return START_TAG;
    }

}