package ir.sazehyab.auth;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.List;
import org.springframework.context.annotation.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.*;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
public class SecurityConfig {
 private record Window(long start, int count) {}
 private final java.util.Map<String,Window> attempts=new java.util.HashMap<>();
 private synchronized boolean allowed(String address) {
  long now=System.currentTimeMillis();
  attempts.entrySet().removeIf(e->now-e.getValue().start()>=60000);
  var current=attempts.get(address);
  if(current==null) {if(attempts.size()>=10000)return false; attempts.put(address,new Window(now,1));return true;}
  if(current.count()>=30)return false;
  attempts.put(address,new Window(current.start(),current.count()+1)); return true;
 }
 @Bean PasswordEncoder passwords() {return new BCryptPasswordEncoder(12);}
 @Bean SecurityFilterChain security(HttpSecurity http, AuthService service, @Value("${app.cors-origin}") String origin) throws Exception {
  var cors=new CorsConfiguration(); cors.setAllowedOrigins(List.of(origin));
  cors.setAllowedMethods(List.of("GET","POST","OPTIONS"));
  cors.setAllowedHeaders(List.of("Authorization","Content-Type"));
  var source=new UrlBasedCorsConfigurationSource();source.registerCorsConfiguration("/**",cors);
  return http.cors(c->c.configurationSource(source))
   // Credentials are accepted exclusively as explicit bearer headers, never cookies.
   .csrf(c->c.disable()).sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
   .requestCache(c->c.disable()).formLogin(c->c.disable()).httpBasic(c->c.disable())
   .authorizeHttpRequests(a->a.requestMatchers(org.springframework.http.HttpMethod.POST,"/api/v1/auth/register","/api/v1/auth/login").permitAll().requestMatchers("/error").permitAll().anyRequest().authenticated())
   .exceptionHandling(e->e.authenticationEntryPoint((req,res,ex)->res.sendError(401)).accessDeniedHandler((req,res,ex)->res.sendError(403)))
   .addFilterBefore(new OncePerRequestFilter() {
    @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain) throws ServletException,IOException {
     if(req.getMethod().equals("POST") && (req.getServletPath().equals("/api/v1/auth/login") || req.getServletPath().equals("/api/v1/auth/register")) && !allowed(req.getRemoteAddr())) {res.setHeader("Retry-After","60");res.sendError(429);return;}
     String header=req.getHeader("Authorization");
     if(header!=null && header.startsWith("Bearer ")) {
      var user=service.authenticate(header.substring(7));
      if(user.isPresent()) {
       var u=user.get(); var context=SecurityContextHolder.createEmptyContext();
       context.setAuthentication(new UsernamePasswordAuthenticationToken(u,null,List.of(new SimpleGrantedAuthority("ROLE_"+u.role().toUpperCase(java.util.Locale.ROOT)))));
       SecurityContextHolder.setContext(context);
      }
     }
     chain.doFilter(req,res);
    }
   },UsernamePasswordAuthenticationFilter.class).build();
 }
}
