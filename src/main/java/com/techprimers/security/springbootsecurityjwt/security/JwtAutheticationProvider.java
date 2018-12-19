package com.techprimers.security.springbootsecurityjwt.security;

import com.techprimers.security.springbootsecurityjwt.model.JwtAuthenticationToken;
import com.techprimers.security.springbootsecurityjwt.model.JwtUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class JwtAutheticationProvider extends AbstractUserDetailsAuthenticationProvider {

    @Autowired
    private JwtValidator jwtValidator;

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {

    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken) throws AuthenticationException {
       JwtAuthenticationToken jwtAuthenticationToken=(JwtAuthenticationToken) usernamePasswordAuthenticationToken;

       String token= jwtAuthenticationToken.getToken();

       JwtUser jwtUser= (JwtUser) jwtValidator.validate(token);

       if (jwtUser==null){
           throw new RuntimeException("JWT Token is incorrect");
       }


        return null;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return JwtAuthenticationToken.class.isAssignableFrom(aClass);
    }
}
