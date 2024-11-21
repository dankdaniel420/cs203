package csd.grp3.exceptions;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.BindException;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import csd.grp3.exception.RestExceptionHandler;
import csd.grp3.jwt.JwtService;
import csd.grp3.match.MatchService;
import csd.grp3.tournament.InvalidTournamentStatus;
import csd.grp3.tournament.TournamentNotFoundException;
import csd.grp3.tournament.TournamentService;
import csd.grp3.tournament.UserAlreadyRegisteredException;
import csd.grp3.tournament.UserNotRegisteredException;
import csd.grp3.user.UserService;
import csd.grp3.usertournament.UserTournamentNotFoundException;

@WebMvcTest(RestExceptionHandler.class)
public class RestExceptionHandlerTest {
    @MockBean
    private MatchService matchService; // Mock the MatchService

    @MockBean
    private TournamentService tournamentService;

    @MockBean
    private UserService userService;

    @MockBean
    private JwtService jwtService;

    @InjectMocks
    private RestExceptionHandler restExceptionHandler;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testHandleMethodArgumentNotValid() throws Exception {
        // Arrange
        BindException bindException = new BindException(new Object(), "objectName");
        bindException.addError(new ObjectError("field", "Invalid value"));
        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(null, bindException);

        // Act
        ResponseEntity<Object> response = restExceptionHandler.handleMethodArgumentNotValid(ex);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Invalid value"));
    }

    @Test
    public void testHandleTypeMismatch() throws Exception {
        // Arrange
        MethodArgumentTypeMismatchException ex = new MethodArgumentTypeMismatchException(
            "value", String.class, "param", null, new IllegalArgumentException("Invalid type"));

        // Act
        ResponseEntity<Object> response = restExceptionHandler.handleTypeMismatch(ex);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Invalid type"));
    }

    @Test
    public void testHandleUserNotRegisteredException() {
        // Arrange
        UserNotRegisteredException ex = new UserNotRegisteredException();

        // Act
        ResponseEntity<Object> response = restExceptionHandler.handleUserNotRegistered(ex);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("User did not register for this tournament."));
    }

    @Test
    public void testHandleTournamentNotFoundException() {
        // Arrange
        TournamentNotFoundException ex = new TournamentNotFoundException();

        // Act
        ResponseEntity<Object> response = restExceptionHandler.handleTournamentNotFound(ex);

        // Assert
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("tournament not found"));
    }

    @Test
    public void testHandleInvalidTournamentStatus() {
        // Arrange
        InvalidTournamentStatus ex = new InvalidTournamentStatus("Invalid status.");

        // Act
        ResponseEntity<Object> response = restExceptionHandler.handleInvalidTournamentStatus(ex);

        // Assert
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Invalid status."));
    }

    @Test
    public void testHandleUsernameNotFoundException() {
        // Arrange
        UsernameNotFoundException ex = new UsernameNotFoundException("User not found");

        // Act
        ResponseEntity<Object> response = restExceptionHandler.handleUsernameNotFound(ex);

        // Assert
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("User not found"));
    }

    @Test
    public void testHandleBadCredentialsException() {
        // Arrange
        BadCredentialsException ex = new BadCredentialsException("Invalid credentials.");

        // Act
        ResponseEntity<Object> response = restExceptionHandler.handleBadCredentials(ex);

        // Assert
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Invalid credentials."));
    }

    @Test
    public void testHandleAccessDenied() {
        // Arrange
        AccessDeniedException ex = new AccessDeniedException("Access is denied");

        // Act
        ResponseEntity<Map<String, Object>> response = restExceptionHandler.handleAccessDenied(ex);

        // Assert
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("You do not have permission to access this resource"));
    }

    @Test
    public void testHandleAuthentication() {
        // Arrange
        AuthenticationException ex = new AuthenticationException("Authentication failed") {};

        // Act
        ResponseEntity<Map<String, Object>> response = restExceptionHandler.handleAuthentication(ex);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("You need to be authenticated to access this resource"));
    }

    @Test
    public void testHandleUserTournamentNotFoundException() {
        // Arrange
        UserTournamentNotFoundException ex = new UserTournamentNotFoundException();

        // Act
        ResponseEntity<Object> response = restExceptionHandler.handle(ex);

        // Assert
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("Tournament entry could not be found"));
    }

    @Test
    public void testHandleUserAlreadyRegisteredException() {
        // Arrange
        UserAlreadyRegisteredException ex = new UserAlreadyRegisteredException();

        // Act
        ResponseEntity<Object> response = restExceptionHandler.handleUserAlreadyRegistered(ex);

        // Assert
        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertTrue(response.getBody().toString().contains("User has already registered for this tournament."));
    }
}