package csd.grp3.tournament;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.test.context.support.WithMockUser;

import csd.grp3.match.Match;
import csd.grp3.round.Round;
import csd.grp3.user.User;

public class TournamentControllerTest {

    @Mock
    private TournamentRepository tournamentRepo;

    @Mock
    private TournamentService tournamentService;

    @InjectMocks
    private TournamentController tournamentController;

    private Tournament tournament;
    private User user;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        tournament = new Tournament(); // Adjust constructor or use setters to initialize properties
        user = new User("testuser", "password123");
    }

    @Test
    public void testGetAllTournaments_Success() {
        when(tournamentService.listTournaments()).thenReturn(List.of(tournament));

        ResponseEntity<List<Tournament>> response = tournamentController.getAllTournaments();

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(1, response.getBody().size());
    }

    @Test
    public void testGetTournamentById_Success() {
        when(tournamentService.getTournament(1L)).thenReturn(tournament);

        ResponseEntity<Tournament> response = tournamentController.getTournamentById(1L);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
    }

    @Test
    public void testGetTournamentById_NotFound() {
        when(tournamentService.getTournament(1L)).thenThrow(new TournamentNotFoundException());

        TournamentNotFoundException exception = assertThrows(TournamentNotFoundException.class, () -> {
            tournamentController.getTournamentById(1L);
        });

        assertEquals("tournament not found", exception.getMessage());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testAddTournament_Success() {
        when(tournamentService.addTournament(tournament)).thenReturn(tournament);

        ResponseEntity<HttpStatus> response = tournamentController.addTournament(tournament);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testUpdateTournamentById_Success() {
        when(tournamentService.updateTournament(1L, tournament)).thenReturn(tournament);

        ResponseEntity<HttpStatus> response = tournamentController.updateTournamentById(1L, tournament);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testUpdateTournamentById_NotFound() {
        when(tournamentService.updateTournament(1L, tournament)).thenThrow(new TournamentNotFoundException());

        TournamentNotFoundException exception = assertThrows(TournamentNotFoundException.class, () -> {
            tournamentController.updateTournamentById(1L, tournament);
        });

        assertEquals("tournament not found", exception.getMessage());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testDeleteTournamentById_Success() {
        doNothing().when(tournamentService).deleteTournament(1L);

        ResponseEntity<HttpStatus> response = tournamentController.deleteTournamentById(1L);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    public void testDeleteTournamentById_NotFound() {
        doThrow(new TournamentNotFoundException()).when(tournamentService).deleteTournament(1L);

        TournamentNotFoundException exception = assertThrows(TournamentNotFoundException.class, () -> {
            tournamentController.deleteTournamentById(1L);
        });

        assertEquals("tournament not found", exception.getMessage());
    }

    @Test
    public void testWithdrawUser_Success() {
        doNothing().when(tournamentService).withdrawUser(user, 1L);

        ResponseEntity<HttpStatus> response = tournamentController.withdraw(user, 1L);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
    }

    @Test
    public void testWithdrawUser_TournamentNotFound() {
        doThrow(new TournamentNotFoundException()).when(tournamentService).withdrawUser(user, 1L);

        TournamentNotFoundException exception = assertThrows(TournamentNotFoundException.class, () -> {
            tournamentController.withdraw(user, 1L);
        });

        assertEquals("tournament not found", exception.getMessage());
    }

    @Test
    public void testRegisterUser_Success() {
        doNothing().when(tournamentService).registerUser(user, 1L);

        ResponseEntity<HttpStatus> response = tournamentController.registerUser(user, 1L);

        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
    }

    @Test
    public void testRegisterUser_PlayerAlreadyRegistered() {
        doThrow(new UserAlreadyRegisteredException()).when(tournamentService).registerUser(user, 1L);

        UserAlreadyRegisteredException exception = assertThrows(UserAlreadyRegisteredException.class, () -> {
            tournamentController.registerUser(user, 1L);
        });

        assertEquals("User has already registered for this tournament.", exception.getMessage());
    }

    @Test
    public void testGetRoundData_WhenTournamentIsOver_AndNotCalculated() {
        Long tournamentId = 1L;
        Tournament mockTournament = new Tournament();
        mockTournament.setId(tournamentId);
        mockTournament.setCalculated(false);

        User user1 = new User("user1", "user1", "ROLE_PLAYER", 0);
        User user2 = new User("user2", "user2", "ROLE_PLAYER", 0);
        Round lastRound = new Round(mockTournament);
        Match match = new Match(user1, user2, lastRound);
        match.setResult(-1);
        List<Match> matches = new ArrayList<>();
        matches.add(match);
        lastRound.setMatches(matches);
        lastRound.setId(1L);
        mockTournament.setTotalRounds(1);
        mockTournament.setRounds(List.of(lastRound));

        when(tournamentService.getTournament(tournamentId)).thenReturn(mockTournament);

        // Call the endpoint
        ResponseEntity<List<Round>> response = tournamentController.getRoundData(tournamentId);

        // Verify that updateMatchResults, updateResults, and endTournament were called
        verify(tournamentService, times(1)).updateMatchResults(lastRound);
        verify(tournamentService, times(1)).updateTournamentResults(lastRound);
        verify(tournamentService, times(1)).endTournament(tournamentId);

        // Verify the response status and the body
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
    }

    @Test
    public void testGetRoundData_WhenTournamentIsOver_AndCalculated() {
        Long tournamentId = 1L;
        Tournament mockTournament = new Tournament();
        mockTournament.setId(tournamentId);
        mockTournament.setCalculated(true);

        User user1 = new User("user1", "user1", "ROLE_PLAYER", 0);
        User user2 = new User("user2", "user2", "ROLE_PLAYER", 0);
        Round lastRound = new Round(mockTournament);
        Match match = new Match(user1, user2, lastRound);
        match.setResult(-1);
        List<Match> matches = new ArrayList<>();
        matches.add(match);
        lastRound.setMatches(matches);
        lastRound.setId(1L);
        mockTournament.setTotalRounds(1);
        mockTournament.setRounds(List.of(lastRound));

        when(tournamentService.getTournament(tournamentId)).thenReturn(mockTournament);

        // Call the endpoint
        ResponseEntity<List<Round>> response = tournamentController.getRoundData(tournamentId);

        // Verify that no updates to rounds or results were called
        verify(tournamentService, never()).updateMatchResults(any());
        verify(tournamentService, never()).updateTournamentResults(any());
        verify(tournamentService, never()).endTournament(anyLong());

        // Verify the response status and the body
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
    }

    @Test
    public void testGetStandings() {
        Long tournamentId = 1L;

        List<User> tournamentUsers = List.of(new User("user1", "password1", "ROLE_PLAYER", 0),
                new User("user2", "password2", "ROLE_PLAYER", 0),
                new User("DEFAULT_BOT", "goodpassword", "ROLE_USER", -1));

        when(tournamentService.getSortedUsers(tournamentId)).thenReturn(tournamentUsers);

        // Call the endpoint
        ResponseEntity<List<User>> response = tournamentController.getStandings(tournamentId);

        // Verify the service was called correctly
        verify(tournamentService, times(1)).getSortedUsers(tournamentId);

        // Verify the response status and the body
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(tournamentUsers, response.getBody());
    }

    @Test
    public void testGetTournamentByElo() {
        int elo = 1500;
        List<Tournament> mockTournaments = List.of(new Tournament(), new Tournament());

        when(tournamentService.getUserEligibleTournament(elo)).thenReturn(mockTournaments);

        // Call the endpoint
        ResponseEntity<List<Tournament>> response = tournamentController.getTournamentByElo(elo);

        // Verify the service was called correctly
        verify(tournamentService, times(1)).getUserEligibleTournament(elo);

        // Verify the response status and the body
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(mockTournaments, response.getBody());
    }
}