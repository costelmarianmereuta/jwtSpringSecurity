package com.techprimers.security.springbootsecurityjwt.config;

import com.techprimers.security.springbootsecurityjwt.security.JwtAuthentificationEntryPoint;
import com.techprimers.security.springbootsecurityjwt.security.JwtAuthentificationTokenFilter;
import com.techprimers.security.springbootsecurityjwt.security.JwtAutheticationProvider;
import com.techprimers.security.springbootsecurityjwt.security.JwtSuccesHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collections;

@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
@Configuration
public class JWTConfigurerSecurity extends WebSecurityConfigurerAdapter {

    private JwtAutheticationProvider authenticationProvider;
    private JwtAuthentificationEntryPoint entryPoint;

    @Bean
    public AuthenticationManager authenticationManager(){

        return new ProviderManager(Collections.singletonList(authenticationProvider));
    }

    @Bean
    public JwtAuthentificationTokenFilter authentificationTokenFilter(){

        JwtAuthentificationTokenFilter filter=new JwtAuthentificationTokenFilter();
        filter.setAuthenticationManager(authenticationManager());
        filter.setAuthenticationSuccesHandler(new JwtSuccesHandler());
        return filter;

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests().antMatchers("**/rest/").authenticated()
                .and()
                .exceptionHandling().authenticationEntryPoint(entryPoint)
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.addFilterBefore(authentificationTokenFilter(),UsernamePasswordAuthenticationFilter.class)
                ;
        http.headers().cacheControl();
    }
}
