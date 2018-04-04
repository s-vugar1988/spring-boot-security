package boot.auth;

import boot.domain.AccountCredentials;
import boot.domain.exceptions.UserDefinedException;
import boot.jwt.TokenAuthenticationService;
import boot.util.Constants;
import boot.util.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.util.Collections;


/**
 * Filter for login opeartion
 */
public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {

    public JWTLoginFilter(String url, AuthenticationManager authManager) {
        super(new AntPathRequestMatcher(url));
        setAuthenticationManager(authManager);
    }


    /**
     * Method for processing logni operation. Method gets POST json data from request, deserialize it with jackson
     * Object mapper and perform authentication operation
     * @param req Incoming request
     * @param res
     * @return
     * @throws AuthenticationException
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException, IOException, ServletException {

        //Read request input stream and read json & deserialize to AccountCredentials object.
        ServletInputStream inputStream = req.getInputStream();
        AccountCredentials accountCredentials = new ObjectMapper().readValue(inputStream, AccountCredentials.class);

        // Perform authentication operation
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(accountCredentials, Collections.emptyList());
        return getAuthenticationManager().authenticate(usernamePasswordAuthenticationToken);
    }

    /**
     * This method is called if authentication was successful. Method build token with JWT using
     * AccountCredentials class as subject. and add header to the response.
     * @param req Incoming request
     * @param res
     * @param chain
     * @param auth
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain, Authentication auth) throws IOException, ServletException {
        try{
            String token = JWT.buildToken( (AccountCredentials) auth.getPrincipal());
            res.addHeader(Constants.HEADER_STRING, Constants.TOKEN_PREFIX + " " + token);
        } catch (UserDefinedException e) {
            e.printStackTrace();
        }
    }




}
