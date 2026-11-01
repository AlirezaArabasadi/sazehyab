package ir.sazehyab.auth;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.assertj.core.api.Assertions.*;
@SpringBootTest(properties={"spring.datasource.url=jdbc:h2:mem:auth;MODE=MySQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1","spring.datasource.username=sa","spring.datasource.password=","spring.datasource.driver-class-name=org.h2.Driver"})
@AutoConfigureMockMvc
class AuthIntegrationTest {
 @Autowired MockMvc mvc; @Autowired ObjectMapper json; @Autowired JdbcTemplate db;
 String register(String phone,String role) {return "{\"name\":\"Test User\",\"phone\":\""+phone+"\",\"password\":\"safe-password\",\"role\":\""+role+"\"}";}
 @Test void lifecycleAndSecurity() throws Exception {
  var body=register("09120000001","client");
  mvc.perform(get("/api/v1/auth/me")).andExpect(status().isUnauthorized());
  var response=mvc.perform(post("/api/v1/auth/register").contentType("application/json").content(body)).andExpect(status().isCreated()).andExpect(jsonPath("$.user.role").value("client")).andReturn().getResponse().getContentAsString();
  var token=json.readTree(response).get("token").asText();
  assertThat(db.queryForObject("SELECT password_hash FROM users WHERE phone='09120000001'",String.class)).startsWith("$2a$").isNotEqualTo("safe-password");
  assertThat(db.queryForObject("SELECT token_hash FROM auth_sessions",String.class)).isNotEqualTo(token);
  mvc.perform(get("/api/v1/auth/me").header("Authorization","Bearer "+token)).andExpect(status().isOk()).andExpect(jsonPath("$.phone").value("09120000001")).andExpect(jsonPath("$.password_hash").doesNotExist());
  mvc.perform(post("/api/v1/auth/register").contentType("application/json").content(body)).andExpect(status().isConflict());
  mvc.perform(post("/api/v1/auth/login").contentType("application/json").content("{\"phone\":\"09120000001\",\"password\":\"wrong\"}")).andExpect(status().isUnauthorized());
  var login=mvc.perform(post("/api/v1/auth/login").contentType("application/json").content("{\"phone\":\"09120000001\",\"password\":\"safe-password\"}")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
  String secondToken=json.readTree(login).get("token").asText();
  mvc.perform(post("/api/v1/auth/logout").header("Authorization","Bearer "+token)).andExpect(status().isNoContent());
  mvc.perform(get("/api/v1/auth/me").header("Authorization","Bearer "+token)).andExpect(status().isUnauthorized());
  db.update("UPDATE auth_sessions SET expires_at=?",Timestamp.from(Instant.now().minusSeconds(10)));
  assertThat(db.queryForObject("SELECT COUNT(*) FROM auth_sessions",Integer.class)).isEqualTo(1);
  mvc.perform(get("/api/v1/auth/me").header("Authorization","Bearer "+secondToken)).andExpect(status().isUnauthorized());
  String hash=db.queryForObject("SELECT token_hash FROM auth_sessions",String.class);
  assertThat(hash).hasSize(64);
 }
 @Test void rejectInvalidRegistration() throws Exception {
  mvc.perform(post("/api/v1/auth/register").contentType("application/json").content(register("09120000002","admin"))).andExpect(status().isBadRequest());
  mvc.perform(post("/api/v1/auth/register").contentType("application/json").content(register("123","client"))).andExpect(status().isBadRequest());
  mvc.perform(post("/api/v1/auth/register").contentType("application/json").content(register("09120000002","contractor").replace("safe-password","short"))).andExpect(status().isBadRequest());
 }
}
