package csd.grp3.tournament;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class UserAlreadyRegisteredException extends RuntimeException {
    
    public UserAlreadyRegisteredException() {
        super("User has already registered for this tournament.");
    }
}