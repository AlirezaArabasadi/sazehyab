package ir.sazehyab.auth;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
 public record Register(@NotBlank @Size(max=100) String name, @NotNull @Pattern(regexp="09[0-9]{9}") String phone, @NotNull @Size(min=8,max=64) String password, @NotNull @Pattern(regexp="client|contractor") String role) { @AssertTrue(message="Password must not exceed 72 UTF-8 bytes") public boolean isPasswordWithinByteLimit() {return password==null || password.getBytes(java.nio.charset.StandardCharsets.UTF_8).length<=72;} }
 public record Login(@NotNull @Pattern(regexp="09[0-9]{9}") String phone, @NotNull @Size(min=1,max=64) String password) { @AssertTrue(message="Password must not exceed 72 UTF-8 bytes") public boolean isPasswordWithinByteLimit() {return password==null || password.getBytes(java.nio.charset.StandardCharsets.UTF_8).length<=72;} }
 private final AuthService service;
 public AuthController(AuthService service) {this.service=service;}
 @PostMapping("/register") @ResponseStatus(HttpStatus.CREATED)
 public AuthService.Session register(@Valid @RequestBody Register body) {return service.register(body);}
 @PostMapping("/login") public AuthService.Session login(@Valid @RequestBody Login body) {return service.login(body);}
 @GetMapping("/me") public Object me(Authentication auth) {return auth.getPrincipal();}
 @PostMapping("/logout") @ResponseStatus(HttpStatus.NO_CONTENT)
 public void logout(@RequestHeader("Authorization") String authorization) {service.logout(authorization.substring(7));}
}
