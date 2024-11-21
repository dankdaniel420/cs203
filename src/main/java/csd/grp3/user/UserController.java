package csd.grp3.user;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
public class UserController {
    private UserService userService;

    @GetMapping("/user")
    public ResponseEntity<User> getUserDetails() {
        // Extract the current authentication object from the SecurityContext
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        // If the principal is an instance of UserDetails (from Spring Security), extract the username
        if (principal instanceof UserDetails) {
            String username = ((UserDetails) principal).getUsername();

            // You can now retrieve user details from the database using the username
            User currentUser = userService.findByUsername(username);

            return ResponseEntity.ok(currentUser); // Return the user details as a response
        }

        // If the user is not authenticated, return 401 Unauthorized or any other error response
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @PostMapping("/signup")
    public ResponseEntity<User> registerUser(@Valid @RequestBody User user) throws MethodArgumentNotValidException {
        User createdUser = userService.createNewUser(user.getUsername(), user.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> loginUser(@RequestBody User user) {
        String token = userService.login(user.getUsername(), user.getPassword());
        Map<String, String> response = new HashMap<>();
        response.put("token", token);  // Store the token in a map with the key "token"
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @GetMapping("/profile/{username}")
    public ResponseEntity<User> viewProfile(@PathVariable String username) {
        return ResponseEntity.status(HttpStatus.OK).body(userService.findByUsername(username));
    }

    @PutMapping("/user")
    public ResponseEntity<User> changePassword(@Valid @RequestBody User user) {
        User updatedUser = userService.changePassword(user.getUsername(), user.getPassword());
        return ResponseEntity.status(HttpStatus.OK).body(updatedUser);
    }

    @PutMapping("/user/flag")
    public ResponseEntity<HttpStatus> unflagUser(@RequestBody User user) {
        userService.updateSuspicious(user, false);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @DeleteMapping("/profile/{username}")
    public ResponseEntity<HttpStatus> deleteUser(@PathVariable String username) {
        userService.deleteByUsername(username);
        return ResponseEntity.noContent().build();
    }
}