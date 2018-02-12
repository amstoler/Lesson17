package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Controller;

@Controller
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private SSUserDetailsService userDetailsService;

    @Autowired
    private UserRepo userRepo;

    @Override
    public UserDetailsService userDetailsServiceBean() throws Exception {
        return new SSUserDetailsService(userRepo);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http
                .authorizeRequests()
                .antMatchers("/", "/h2-console/**").permitAll()
                /*.antMatchers("/").access("hasAuthority('USER') or hasAuthority('ADMIN')")
                .antMatchers("/admin").access("hasAuthority('ADMIN')")*/
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage("/login").permitAll()
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login").permitAll().permitAll()
                .and()
                .httpBasic();

                http
                        .csrf().disable();
                http
                        .headers().frameOptions().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth)
        throws Exception {

        auth
                .userDetailsService(userDetailsServiceBean());

       /* auth.inMemoryAuthentication().withUser("user").password("password").authorities("USER")
                .and()
                .withUser("ariel").password("begreat").authorities("ADMIN")*/;
    }

}
