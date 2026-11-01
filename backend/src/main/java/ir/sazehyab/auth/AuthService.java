package ir.sazehyab.auth;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

@Service
public class AuthService {
 public record User(String id, String name, String phone, String role) {}
 public record Session(String token, Instant expiresAt, User user) {}
 private final JdbcTemplate db; private final PasswordEncoder passwords;
 private final String dummy;
 public AuthService(JdbcTemplate db, PasswordEncoder passwords) {
  this.db=db; this.passwords=passwords; this.dummy=passwords.encode(UUID.randomUUID().toString());
 }
 @Transactional
 public Session register(AuthController.Register request) {
  var user=new User(UUID.randomUUID().toString(),request.name().trim(),request.phone(),request.role());
  try { db.update("INSERT INTO users(id,name,phone,password_hash,role) VALUES(?,?,?,?,?)",user.id(),user.name(),user.phone(),passwords.encode(request.password()),user.role()); }
  catch(org.springframework.dao.DuplicateKeyException e) { throw new ResponseStatusException(HttpStatus.CONFLICT,"Phone already registered"); }
  return issue(user);
 }
 public Session login(AuthController.Login request) {
  var rows=db.queryForList("SELECT * FROM users WHERE phone=?",request.phone());
  String hash=rows.isEmpty()?dummy:(String)rows.getFirst().get("password_hash");
  boolean matches=passwords.matches(request.password(),hash);
  if(!matches || rows.isEmpty()) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Invalid credentials");
  var row=rows.getFirst();
  return issue(new User((String)row.get("id"),(String)row.get("name"),(String)row.get("phone"),(String)row.get("role")));
 }
 private Session issue(User user) {
  byte[] bytes=new byte[32]; new SecureRandom().nextBytes(bytes);
  String token=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  Instant expiry=Instant.now().plusSeconds(3600);
  db.update("DELETE FROM auth_sessions WHERE expires_at <= ?",Timestamp.from(Instant.now()));
  db.update("INSERT INTO auth_sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",digest(token),user.id(),Timestamp.from(expiry));
  return new Session(token,expiry,user);
 }
 public Optional<User> authenticate(String token) {
  if(token.length()>100) return Optional.empty();
  return db.query("SELECT u.id,u.name,u.phone,u.role FROM users u JOIN auth_sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?",(rs,n)->new User(rs.getString(1),rs.getString(2),rs.getString(3),rs.getString(4)),digest(token),Timestamp.from(Instant.now())).stream().findFirst();
 }
 public void logout(String token) {db.update("DELETE FROM auth_sessions WHERE token_hash=?",digest(token));}
 static String digest(String token) {
  try {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));}
  catch(NoSuchAlgorithmException e) {throw new IllegalStateException(e);}
 }
}
