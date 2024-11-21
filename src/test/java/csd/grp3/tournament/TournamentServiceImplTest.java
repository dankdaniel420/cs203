package csd.grp3.tournament;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyChar;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.time.Month;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

import csd.grp3.CheaterBugAPI.CheaterbugResponse;
import csd.grp3.CheaterBugAPI.CheaterbugService;
import csd.grp3.match.Match;
import csd.grp3.match.MatchRepository;
import csd.grp3.match.MatchServiceImpl;
import csd.grp3.round.Round;
import csd.grp3.round.RoundServiceImpl;
import csd.grp3.user.User;
import csd.grp3.user.UserServiceImpl;
import csd.grp3.usertournament.UserTournament;
import csd.grp3.usertournament.UserTournamentId;
import csd.grp3.usertournament.UserTournamentRepository;
import csd.grp3.usertournament.UserTournamentServiceImpl;

@ExtendWith(MockitoExtension.class)
public class TournamentServiceImplTest {

    @Mock
    private TournamentRepository tournamentRepository;

    @Mock
    private UserTournamentRepository utRepository;

    @Mock
    private MatchRepository matchRepository;

    @InjectMocks
    private TournamentServiceImpl tournamentService;

    @Mock
    private RoundServiceImpl roundService;

    @Mock
    private UserTournamentServiceImpl userTournamentService;

    @Mock
    private UserServiceImpl userService;

    @Mock
    private MatchServiceImpl matchService;

    @Mock
    private CheaterbugService cheaterbugService;

    private Tournament tournament;
    private User player;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        tournament = new Tournament();
        tournament.setId(1L);
        tournament.setTitle("Test Tournament");
        tournament.setSize(2);

        player = new User("testUser", "testPassword123"); // Username and password
        player.setAuthorities("ROLE_PLAYER"); // Set specific authorities
    }

    @Test
    void listTournaments_NoTournaments_ReturnEmptyList() {
        List<Tournament> tournamentsList = new ArrayList<>();

        // mock the getAllTournaments()
        when(tournamentRepository.findAll()).thenReturn(tournamentsList);

        List<Tournament> result = tournamentService.listTournaments();

        assertNotNull(result);
        assertEquals(0, result.size());
        verify(tournamentRepository).findAll();
    }

    @Test
    void listTournaments_HasTournaments_ReturnListOfTournaments() {
        // Arrange
        List<Tournament> tournamentsList = new ArrayList<>();
        tournamentsList.add(tournament);

        // mock getAllTournaments()
        when(tournamentRepository.findAll()).thenReturn(tournamentsList);

        List<Tournament> result = tournamentService.listTournaments();

        assertNotNull(result);
        assertEquals(1, result.size());
        verify(tournamentRepository).findAll();
    }

    @Test
    void getTournament_NoTournament_ReturnTournamentNotFoundException() {
        // Mock findById to return an empty Optional
        when(tournamentRepository.findById(any(Long.class))).thenReturn(Optional.empty());

        // Act & Assert: Expect TournamentNotFoundException to be thrown
        TournamentNotFoundException exception = assertThrows(TournamentNotFoundException.class, () -> {
            tournamentService.getTournament(1L);
        });

        // Verify that the exception message is correct
        assertEquals("tournament not found", exception.getMessage());

        // Verify that findById was called with the correct argument
        verify(tournamentRepository).findById(1L);
    }

    @Test
    void getTournament_TournamentFound_ReturnTournament() {
        // Mock findById to return the tournament
        when(tournamentRepository.findById(any(Long.class))).thenReturn(Optional.of(tournament));

        // Act
        Tournament foundTournament = tournamentService.getTournament(1L);

        // Assert
        assertNotNull(foundTournament);
        assertEquals(1L, foundTournament.getId());
        assertEquals("Test Tournament", foundTournament.getTitle());
        verify(tournamentRepository).findById(1L);
    }

    @Test
    void addTournament_NewTitle_ReturnSavedTournament() {

        when(tournamentRepository.save(tournament)).thenReturn(tournament);
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));
        when(userService.findByUsername("DEFAULT_BOT"))
                .thenReturn(new User("DEFAULT_BOT", "goodpassword", "ROLE_USER", 0));

        doAnswer(invocation -> {
            UserTournamentId utId = new UserTournamentId(tournament.getId(), player.getUsername());
            UserTournament userTournament = new UserTournament(utId, tournament, player, 'r', 0, 0);
            tournament.getUserTournaments().add(userTournament); // Directly add the user tournament to the tournament's
                                                                 // list
            return null; // Since add returns void
        }).when(userTournamentService).add(any(Tournament.class), any(User.class), anyChar());

        Tournament result = tournamentService.addTournament(tournament);

        assertEquals(tournament, result);
        verify(tournamentRepository).save(tournament);
    }

    @Test
    void addTournament_SameTitle_ReturnSavedTournamentWithDifferentID() {
        // Arrange
        Tournament tournament2 = tournament;
        tournament2.setId(2L);
        when(tournamentRepository.save(any(Tournament.class))).thenReturn(tournament);
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));
        when(userService.findByUsername("DEFAULT_BOT"))
                .thenReturn(new User("DEFAULT_BOT", "goodpassword", "ROLE_USER", 0));

        doAnswer(invocation -> {
            UserTournamentId utId = new UserTournamentId(tournament.getId(), player.getUsername());
            UserTournament userTournament = new UserTournament(utId, tournament, player, 'r', 0, 0);
            tournament.getUserTournaments().add(userTournament); // Directly add the user tournament to the tournament's
                                                                 // list
            return null; // Since add returns void
        }).when(userTournamentService).add(any(Tournament.class), any(User.class), anyChar());

        // Act
        tournamentService.addTournament(tournament);
        Tournament result = tournamentService.addTournament(tournament2);

        // Assert
        assertEquals(2L, result.getId());
        assertEquals("Test Tournament", result.getTitle());
        verify(tournamentRepository, times(2)).save(tournament);
    }

    @Test
    void updateTournament_NotFound_ReturnTournamentNotFoundException() {
        // Arrange
        when(tournamentRepository.findById(1L)).thenReturn(Optional.empty());

        // Act
        TournamentNotFoundException exception = assertThrows(TournamentNotFoundException.class, () -> {
            tournamentService.updateTournament(1L, tournament);
        });

        // Assert
        assertEquals("tournament not found", exception.getMessage());
        verify(tournamentRepository).findById(1L);
    }

    @Test
    void deleteTournament_DeleteSuccess_ReturnDeletedTournament() {
        // mock getById method to return a Tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));

        // mock the deleteById method to do nothing (since its a void method)
        doNothing().when(tournamentRepository).deleteById(tournament.getId());

        // act & assert
        assertDoesNotThrow(() -> tournamentService.deleteTournament(tournament.getId()));

        // verify delete called once with correct tournament ID
        verify(tournamentRepository, times(1)).deleteById(1L);
    }

    @Test
    void deleteTournament_TournamentNotFound_ReturnTournamentNotFoundException() {
        // mock deleteById method to do nothing (since its a void method)
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.empty());

        // Act & Assert: Expect TournamentNotFoundException to be thrown
        TournamentNotFoundException exception = assertThrows(TournamentNotFoundException.class, () -> {
            tournamentService.deleteTournament(tournament.getId());
        });

        // Verify that the exception message is correct
        assertEquals("tournament not found", exception.getMessage());

        // Verify that deleteById was never called with the correct argument
        verify(tournamentRepository, never()).deleteById(1L);
    }

    @Test
    void registerPlayer_RegisterToUserListSuccess_ReturnUserTournamentListSizeMoreByOne() {
        // Arrange
        List<User> userList = new ArrayList<>();
        List<User> waitingList = new ArrayList<>();
        UserTournamentId UTId = new UserTournamentId(tournament.getId(), player.getUsername());
        UserTournament userTournament = new UserTournament(UTId, tournament, player, null, 0, 0);
        tournament.setSize(10);

        // retrieve mock tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));
        when(userTournamentService.getPlayers(tournament.getId())).thenReturn(userList);
        when(userTournamentService.getWaitingList(tournament.getId())).thenReturn(waitingList);
        when(userService.findByUsername(player.getUsername())).thenReturn(player);

        doAnswer(invocation -> {
            tournament.getUserTournaments().add(userTournament); // Directly add the user tournament to the tournament's
                                                                 // list
            return null; // Since add returns void
        }).when(userTournamentService).add(any(Tournament.class), any(User.class), anyChar());

        // act
        tournamentService.registerUser(player, 1L);

        // assert
        assertEquals(1, tournament.getUserTournaments().size());
        assertEquals(userTournament, tournament.getUserTournaments().get(0));
        verify(userTournamentService, times(1)).add(tournament, player, 'r');
        verify(userTournamentService).getPlayers(tournament.getId());
        verify(userTournamentService).getWaitingList(tournament.getId());
    }

    @Test
    void registerPlayer_PlayerAlreadyRegisteredUserList_ReturnPlayerAlreadyRegisteredException() {
        // Arrange
        List<User> userList = new ArrayList<>();
        userList.add(player);

        // Retrieve empty mock tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));
        when(userTournamentService.getPlayers(tournament.getId())).thenReturn(userList);
        when(userService.findByUsername(player.getUsername())).thenReturn(player);

        // Act & Assert: Expect TournamentNotFoundException to be thrown
        UserAlreadyRegisteredException exception = assertThrows(UserAlreadyRegisteredException.class, () -> {
            tournamentService.registerUser(player, tournament.getId());
        });

        // Verify that the exception message is correct
        assertEquals("User has already registered for this tournament.", exception.getMessage());

        // Verify that deleteById was never called with the correct argument
        verify(tournamentRepository).findById(tournament.getId());
        verify(userTournamentService).getWaitingList(tournament.getId());
    }

    @Test
    void registerPlayer_PlayerAlreadyRegisteredWaitingListList_ReturnPlayerAlreadyRegisteredException() {
        // Arrange
        List<User> waitingList = new ArrayList<>();
        waitingList.add(player);

        // Retrieve empty mock tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));
        when(userTournamentService.getWaitingList(tournament.getId())).thenReturn(waitingList);
        when(userService.findByUsername(player.getUsername())).thenReturn(player);

        // Act & Assert: Expect TournamentNotFoundException to be thrown
        UserAlreadyRegisteredException exception = assertThrows(UserAlreadyRegisteredException.class, () -> {
            tournamentService.registerUser(player, tournament.getId());
        });

        // Verify that the exception message is correct
        assertEquals("User has already registered for this tournament.", exception.getMessage());

        // Verify that deleteById was never called with the correct argument
        verify(tournamentRepository).findById(tournament.getId());
        verify(userTournamentService).getWaitingList(tournament.getId());
    }

    @Test
    void registerPlayer_NoTournamentFound_ReturnTournamentNotFoundException() {
        // Retrieve empty mock tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.empty());

        // Act & Assert: Expect TournamentNotFoundException to be thrown
        TournamentNotFoundException exception = assertThrows(TournamentNotFoundException.class, () -> {
            tournamentService.registerUser(player, tournament.getId());
        });

        // Verify that the exception message is correct
        assertEquals("tournament not found", exception.getMessage());

        // Verify that deleteById was never called with the correct argument
        verify(tournamentRepository).findById(1L);
    }

    @Test
    void withdrawPlayer_UserListWithdrawSuccess_ReturnUserListSmallerByOne() {
        // Arrange
        List<User> userList = new ArrayList<>();
        List<User> waitingList = new ArrayList<>();
        LocalDateTime time = LocalDateTime.of(2014, Month.JANUARY, 1, 10, 10, 30);
        userList.add(player);
        tournament.setStartDateTime(time);
        tournament.setSize(10);

        // retrieve mock tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));
        when(userTournamentService.getPlayers(tournament.getId())).thenReturn(userList);
        when(userTournamentService.getWaitingList(tournament.getId())).thenReturn(waitingList);
        when(userService.findByUsername(player.getUsername())).thenReturn(player);

        doAnswer(invocation -> {
            userList.remove(player); // Directly add the user tournament to the tournament's list
            return null; // Since add returns void
        }).when(userTournamentService).delete(tournament, player);

        // act
        tournamentService.withdrawUser(player, tournament.getId());

        // assert
        assertEquals(0, userList.size());
        verify(userTournamentService, times(1)).getPlayers(tournament.getId());
        verify(userTournamentService, times(1)).getWaitingList(tournament.getId());
        verify(tournamentRepository, times(1)).findById(tournament.getId());
        verify(userService).findByUsername(player.getUsername());
    }

    @Test
    void withdrawPlayer_TournamentNotFound_ReturnTournamentNotFoundException() {
        // Retrieve empty mock tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.empty());

        // Act & Assert: Expect TournamentNotFoundException to be thrown
        TournamentNotFoundException exception = assertThrows(TournamentNotFoundException.class, () -> {
            tournamentService.withdrawUser(player, tournament.getId());
        });

        // Verify that the exception message is correct
        assertEquals("tournament not found", exception.getMessage());

        // Verify that deleteById was never called with the correct argument
        verify(tournamentRepository).findById(1L);
    }

    @Test
    void createPairings_FirstRound() {
        // Arrange
        tournament.setMaxElo(100);
        tournament.setSize(10);
        // tournamentService.addTournament(tournament);

        User user1 = new User("player1", "player11", "ROLE_PLAYER", 40);
        User user2 = new User("player2", "player22", "ROLE_PLAYER", 35);
        User user3 = new User("player3", "player33", "ROLE_PLAYER", 15);
        User user4 = new User("player4", "player44", "ROLE_PLAYER", 10);
        List<User> userList = new ArrayList<>(List.of(user1, user2, user3, user4));

        when(userTournamentService.getPlayers(tournament.getId())).thenReturn(userList);
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));
        when(matchService.getUserMatches(Mockito.any(User.class))).thenReturn(Collections.emptyList());
        when(matchService.getMatchesBetweenTwoUsers(Mockito.any(User.class), Mockito.any(User.class)))
                .thenReturn(Collections.emptyList());
        Round mockRound = new Round(tournament);
        tournament.getRounds().add(mockRound);
        Match match1 = new Match(user1, user2, mockRound);
        Match match2 = new Match(user3, user4, mockRound);
        when(matchService.createMatch(user1, user2, mockRound)).thenReturn(match1);
        when(matchService.createMatch(user3, user4, mockRound)).thenReturn(match2);

        tournamentService.createPairings(tournament, mockRound);
        Round returnedRound = tournament.getRounds().get(0);

        assertNotNull(returnedRound);
        assertEquals(2, returnedRound.getMatches().size());
        verify(matchService, times(2)).createMatch(Mockito.any(User.class), Mockito.any(User.class),
                Mockito.any(Round.class));
    }

    @Test
    void createPairings_SecondRound() {
        // Arrange
        tournament.setMaxElo(100);
        tournament.setSize(10);
        // tournamentService.addTournament(tournament);

        User user1 = new User("player1", "player11", "ROLE_PLAYER", 40);
        User user2 = new User("player2", "player22", "ROLE_PLAYER", 35);
        User user3 = new User("player3", "player33", "ROLE_PLAYER", 15);
        User user4 = new User("player4", "player44", "ROLE_PLAYER", 10);
        List<User> userList = new ArrayList<>(List.of(user1, user2, user3, user4));

        Round firstRound = new Round(tournament);
        Match match1 = new Match(user1, user2, firstRound);
        match1.setResult(1);
        Match match2 = new Match(user3, user4, firstRound);
        match2.setResult(1);
        List<Match> match1List = List.of(match1);
        List<Match> match2List = List.of(match2);
        when(matchService.getUserMatches(user1)).thenReturn(match1List);
        when(matchService.getUserMatches(user2)).thenReturn(match1List);
        when(matchService.getUserMatches(user3)).thenReturn(match2List);
        when(matchService.getUserMatches(user4)).thenReturn(match2List);

        // mock the sorting of users
        when(userTournamentService.getPlayers(tournament.getId())).thenReturn(userList);
        when(userTournamentService.getGamePoints(tournament.getId(), user1.getUsername())).thenReturn(1.0);
        when(userTournamentService.getGamePoints(tournament.getId(), user2.getUsername())).thenReturn(0.0);
        when(userTournamentService.getGamePoints(tournament.getId(), user3.getUsername())).thenReturn(1.0);
        when(userTournamentService.getGamePoints(tournament.getId(), user4.getUsername())).thenReturn(0.0);
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));

        when(matchService.getMatchesBetweenTwoUsers(user1, user3)).thenReturn(Collections.emptyList());
        when(matchService.getMatchesBetweenTwoUsers(user2, user4)).thenReturn(Collections.emptyList());

        Round secondRound = new Round(tournament);
        tournament.getRounds().add(secondRound);
        Match match3 = new Match(user3, user1, secondRound);
        Match match4 = new Match(user2, user4, secondRound);
        when(matchService.createMatch(user3, user1, secondRound)).thenReturn(match3);
        when(matchService.createMatch(user2, user4, secondRound)).thenReturn(match4);

        tournamentService.createPairings(tournament, secondRound);
        Round returnedRound = tournament.getRounds().get(0);

        assertNotNull(returnedRound);
        assertEquals(2, returnedRound.getMatches().size());
        verify(matchService, times(2)).createMatch(Mockito.any(User.class), Mockito.any(User.class),
                Mockito.any(Round.class));
    }

    @Test
    void endTournamentCalculateElo() {
        // arrange
        tournament.setMaxElo(100);
        tournament.setSize(10);
        // tournamentService.addTournament(tournament);

        User user1 = new User("player1", "player11", "ROLE_PLAYER", 40);
        User user2 = new User("player2", "player22", "ROLE_PLAYER", 35);
        User user3 = new User("player3", "player33", "ROLE_PLAYER", 15);
        User user4 = new User("player4", "player44", "ROLE_PLAYER", 10);
        List<User> userList = java.util.Arrays.asList(user1, user2, user3, user4);

        Round firstRound = new Round(tournament);
        Match match1 = new Match(user1, user2, firstRound);
        match1.setResult(1);
        Match match2 = new Match(user3, user4, firstRound);
        match2.setResult(1);
        firstRound.getMatches().addAll(List.of(match1, match2));

        Round secondRound = new Round(tournament);
        Match match3 = new Match(user3, user1, secondRound);
        match3.setResult(-1);
        Match match4 = new Match(user2, user4, secondRound);
        match4.setResult(-1);
        secondRound.getMatches().addAll(List.of(match3, match4));

        tournament.getRounds().addAll(List.of(firstRound, secondRound));
        // mock the get players in UT service
        when(userTournamentService.getPlayers(tournament.getId())).thenReturn(userList);

        // mock the get matches in match service
        when(matchService.getUserMatches(user1)).thenReturn(List.of(match1, match3));
        when(matchService.getUserMatches(user2)).thenReturn(List.of(match1, match4));
        when(matchService.getUserMatches(user3)).thenReturn(List.of(match2, match3));
        when(matchService.getUserMatches(user4)).thenReturn(List.of(match2, match4));

        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));

        // mock the find tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));

        // act
        tournamentService.endTournament(tournament.getId());

        // assert
        assertTrue(user1.getELO() > 40);
        assertTrue(user2.getELO() < 35);
        assertTrue(user3.getELO() > 15);
        assertTrue(user4.getELO() > 10);
    }

    @Test
    void addRound_TournamentNotFound_ReturnTournamentNotFoundException() {
        // Retrieve empty mock tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.empty());

        // Act & Assert: Expect TournamentNotFoundException to be thrown
        TournamentNotFoundException exception = assertThrows(TournamentNotFoundException.class, () -> {
            tournamentService.addRound(tournament.getId());
        });

        // Verify that the exception message is correct
        assertEquals("tournament not found", exception.getMessage());

        // Verify that deleteById was never called with the correct argument
        verify(tournamentRepository).findById(1L);
    }

    @Test
    void addRound_InvalidTournamentStatusTime_ReturnInvalidTournamentStatus() {
        // Arrange
        LocalDateTime time = LocalDateTime.of(2999, Month.JANUARY, 1, 10, 10, 30);
        tournament.setStartDateTime(time);
        tournament.setSize(3);

        // Retrieve empty mock tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));

        // Act & Assert: Expect TournamentNotFoundException to be thrown
        InvalidTournamentStatus tournamentStatus = assertThrows(InvalidTournamentStatus.class, () -> {
            tournamentService.addRound(tournament.getId());
        });

        // Verify that the exception message is correct
        assertEquals("Tournament has not started or less than 2 players", tournamentStatus.getMessage());

        // Verify that deleteById was never called with the correct argument
        verify(tournamentRepository).findById(1L);
    }

    @Test
    void addRound_InvalidTournamentStatusPlayerSize_ReturnInvalidTournamentStatus() {
        // Arrange
        LocalDateTime time = LocalDateTime.of(2014, Month.JANUARY, 1, 10, 10, 30);
        tournament.setStartDateTime(time);

        // Retrieve empty mock tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));

        // Act & Assert: Expect TournamentNotFoundException to be thrown
        InvalidTournamentStatus tournamentStatus = assertThrows(InvalidTournamentStatus.class, () -> {
            tournamentService.addRound(tournament.getId());
        });

        // Verify that the exception message is correct
        assertEquals("Tournament has not started or less than 2 players", tournamentStatus.getMessage());

        // Verify that deleteById was never called with the correct argument
        verify(tournamentRepository).findById(1L);
    }

    @Test
    public void testUpdateMatchResults() {
        // Mock data setup
        User blackPlayer = new User("blackPlayer", "black", "ROLE_PLAYER", 0);
        User whitePlayer = new User("whitePlayer", "white", "ROLE_PLAYER", 0);

        Round round = new Round(tournament);

        Match match1 = new Match(blackPlayer, whitePlayer, round); // Black wins
        Match match2 = new Match(blackPlayer, whitePlayer, round); // White wins
        Match match3 = new Match(blackPlayer, whitePlayer, round); // Draw
        match1.setResult(-1);
        match2.setResult(1);
        match3.setResult(0.5);

        List<Match> matches = List.of(match1, match2, match3);

        round.setMatches(matches);
        round.setTournament(tournament);

        // Call the updateMatchResults method
        tournamentService.updateMatchResults(round);

        // Verify that updateMatchPoints was called correctly for each match
        verify(userTournamentService, times(1)).updateMatchPoints(tournament.getId(), blackPlayer.getUsername(), 1.0); // Black
                                                                                                                       // wins
        verify(userTournamentService, times(1)).updateMatchPoints(tournament.getId(), whitePlayer.getUsername(), 0.0);

        verify(userTournamentService, times(1)).updateMatchPoints(tournament.getId(), whitePlayer.getUsername(), 1.0); // White
                                                                                                                       // wins
        verify(userTournamentService, times(1)).updateMatchPoints(tournament.getId(), blackPlayer.getUsername(), 0.0);

        verify(userTournamentService, times(1)).updateMatchPoints(tournament.getId(), blackPlayer.getUsername(), 0.5); // Draw
        verify(userTournamentService, times(1)).updateMatchPoints(tournament.getId(), whitePlayer.getUsername(), 0.5);
    }

    @Test
    public void testUpdateResults() {
        // Mock data setup
        User blackPlayer = new User("blackPlayer", "black", "ROLE_PLAYER", 0);
        User whitePlayer = new User("whitePlayer", "white", "ROLE_PLAYER", 0);

        Round round = new Round(tournament);

        Match match1 = new Match(blackPlayer, whitePlayer, round); // Some match
        Match match2 = new Match(blackPlayer, whitePlayer, round); // Some match
        match1.setResult(1);
        match2.setResult(0.5);

        List<Match> matches = new ArrayList<>();
        matches.add(match1);
        matches.add(match2);

        round.setMatches(matches);
        round.setTournament(tournament);

        // Call the updateResults method
        tournamentService.updateTournamentResults(round);

        // Verify that updateGamePoints was called correctly for each match
        verify(userTournamentService, times(2)).updateGamePoints(tournament.getId(), blackPlayer.getUsername());
        verify(userTournamentService, times(2)).updateGamePoints(tournament.getId(), whitePlayer.getUsername());
    }

    @Test
    void getTournamentAboveMin_TournamentAboveMin_ReturnListOfTournamentAboveMin() {
        // Arrange
        int elo = 100;
        Tournament testTournament = new Tournament(null, 200, 300, null, elo, 10);
        List<Tournament> tournaments = new ArrayList<>();
        tournaments.add(testTournament);

        // Mock repos
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getTournamentAboveMin(elo);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(200, result.get(0).getMinElo());
        verify(tournamentRepository).findAll();
    }

    @Test
    void getTournamentAboveMin_TournamentBelowMin_ReturnEmptyList() {
        // Arrange
        int elo = 100;
        Tournament testTournament = new Tournament(null, 50, 75, null, elo, 10);
        List<Tournament> tournaments = new ArrayList<>();
        tournaments.add(testTournament);

        // Mock repos
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getTournamentAboveMin(elo);

        // Assert
        assertNotNull(result);
        assertEquals(0, result.size());
        verify(tournamentRepository).findAll();
    }

    @Test
    void getTournamentAboveMin_TournamentIsMin_ReturnListOfTournamentAboveMin() {
        // Arrange
        int elo = 100;
        Tournament testTournament = new Tournament(null, 100, 300, null, elo, 10);
        List<Tournament> tournaments = new ArrayList<>();
        tournaments.add(testTournament);

        // Mock repos
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getTournamentAboveMin(elo);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(100, result.get(0).getMinElo());
        verify(tournamentRepository).findAll();
    }

    @Test
    void getTournamentAboveMin_NoTournaments_ReturnEmptyList() {
        // Arrange
        int elo = 100;
        List<Tournament> tournaments = new ArrayList<>();

        // Mock repos
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getTournamentAboveMin(elo);

        // Assert
        assertNotNull(result);
        assertEquals(0, result.size());
        verify(tournamentRepository).findAll();
    }

    @Test
    void getTournamentBelowMax_TournamentBelowMax_ReturnListOfTournamentBelowMax() {
        // Arrange
        int elo = 100;
        Tournament testTournament = new Tournament(null, 50, 75, null, elo, 10);
        List<Tournament> tournaments = new ArrayList<>();
        tournaments.add(testTournament);

        // Mock repos
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getTournamentBelowMax(elo);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(75, result.get(0).getMaxElo());
        verify(tournamentRepository).findAll();
    }

    @Test
    void getTournamentBelowMax_TournamentAboveMax_ReturnEmptyList() {
        // Arrange
        int elo = 100;
        Tournament testTournament = new Tournament(null, 50, 200, null, elo, 10);
        List<Tournament> tournaments = new ArrayList<>();
        tournaments.add(testTournament);

        // Mock repos
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getTournamentBelowMax(elo);

        // Assert
        assertNotNull(result);
        assertEquals(0, result.size());
        verify(tournamentRepository).findAll();
    }

    @Test
    void getTournamentBelowMax_TournamentIsMax_ReturnListOfTournamentBelowMax() {
        // Arrange
        int elo = 100;
        Tournament testTournament = new Tournament(null, 50, 100, null, elo, 10);
        List<Tournament> tournaments = new ArrayList<>();
        tournaments.add(testTournament);

        // Mock repos
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getTournamentBelowMax(elo);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(100, result.get(0).getMaxElo());
        verify(tournamentRepository).findAll();
    }

    @Test
    void getTournamentBelowMax_NoTournaments_ReturnEmptyList() {
        // Arrange
        int elo = 100;
        List<Tournament> tournaments = new ArrayList<>();

        // Mock repos
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getTournamentBelowMax(elo);

        // Assert
        assertNotNull(result);
        assertEquals(0, result.size());
        verify(tournamentRepository).findAll();
    }

    @Test
    void getTournamentAboveMinBelowMax_TournamentAboveMinNotBelowMax_ReturnEmptyList() {
        // Arrange
        int minElo = 100;
        int maxElo = 200;
        Tournament testTournament = new Tournament(null, 150, 250, null, 10, 10);
        List<Tournament> tournaments = new ArrayList<>();
        tournaments.add(testTournament);

        // Mock repos
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getTournamentAboveMinBelowMax(minElo, maxElo);

        // Assert
        assertNotNull(result);
        assertEquals(0, result.size());
        verify(tournamentRepository, times(2)).findAll();
    }

    @Test
    void getTournamentAboveMinBelowMax_TournamentNotAboveMinBelowMax_ReturnEmptyList() {
        // Arrange
        int minElo = 100;
        int maxElo = 200;
        Tournament testTournament = new Tournament(null, 50, 150, null, 10, 10);
        List<Tournament> tournaments = new ArrayList<>();
        tournaments.add(testTournament);

        // Mock repos
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getTournamentAboveMinBelowMax(minElo, maxElo);

        // Assert
        assertNotNull(result);
        assertEquals(0, result.size());
        verify(tournamentRepository, times(2)).findAll();
    }

    @Test
    void getTournamentAboveMinBelowMax_TournamentAboveMinBelowMax_ReturnListOfTournamentAboveMinBelowMax() {
        // Arrange
        int minElo = 100;
        int maxElo = 200;
        Tournament testTournament = new Tournament(null, 125, 175, null, 10, 10);
        List<Tournament> tournaments = new ArrayList<>();
        tournaments.add(testTournament);

        // Mock repos
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getTournamentAboveMinBelowMax(minElo, maxElo);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(125, result.get(0).getMinElo());
        assertEquals(175, result.get(0).getMaxElo());
        verify(tournamentRepository, times(2)).findAll();
    }

    @Test
    void getTournamentAboveMinBelowMax_NoTournament_ReturnEmptyList() {
        // Arrange
        int minElo = 100;
        int maxElo = 200;
        List<Tournament> tournaments = new ArrayList<>();

        // Mock repos
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getTournamentAboveMinBelowMax(minElo, maxElo);

        // Assert
        assertNotNull(result);
        assertEquals(0, result.size());
        verify(tournamentRepository, times(2)).findAll();
    }

    @Test
    void getUserEligibleTournament_Eligible_ReturnTournamentList() {
        // Arrange
        player.setELO(200);
        Tournament tournament = new Tournament(null, 100, 300, null, 10, 10);
        List<Tournament> tournaments = new ArrayList<>();
        tournaments.add(tournament);

        // Mock repository
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getUserEligibleTournament(player.getELO());

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        verify(tournamentRepository).findAll();
    }

    @Test
    void getUserEligibleTournament_NotEligible_ReturnTournamentList() {
        // Arrange
        player.setELO(0);
        Tournament tournament = new Tournament(null, 100, 300, null, 10, 10);
        List<Tournament> tournaments = new ArrayList<>();
        tournaments.add(tournament);

        // Mock repository
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getUserEligibleTournament(player.getELO());

        // Assert
        assertNotNull(result);
        assertEquals(0, result.size());
        verify(tournamentRepository).findAll();
    }

    @Test
    public void testHandleBYE_WhenOpponentIsDefaultBot() {
        // Mock data setup
        User user = new User("player1", "password1", "ROLE_PLAYER", 0);
        User bot = new User("DEFAULT_BOT", "password2", "ROLE_BOT", 0);
        Round round = new Round(tournament);

        Match matchWithBot = new Match(user, bot, round);
        List<Match> matches = new ArrayList<>(List.of(matchWithBot));
        round.setMatches(matches);

        // Call the handleBYE method
        tournamentService.handleBYE(round, user);

        // Verify that the match with the "DEFAULT_BOT" was removed
        assertTrue(round.getMatches().isEmpty(), "Match with DEFAULT_BOT should be removed from the round");
    }

    @Test
    public void testHandleBYE_WhenUserHasOpponent() {
        // Mock data setup
        User user = new User("player1", "password1", "ROLE_PLAYER", 0);
        User opponent = new User("player2", "password2", "ROLE_PLAYER", 0);
        Round round = new Round(tournament);

        Match matchWithOpponent = new Match(user, opponent, round);
        List<Match> matches = new ArrayList<>(List.of(matchWithOpponent));
        round.setMatches(matches);

        // Call the handleBYE method
        tournamentService.handleBYE(round, user);

        // Verify that the match result is set correctly and marked as a BYE
        assertEquals(-1, matchWithOpponent.getResult(),
                "The match result should be set to -1 (black wins) since the opponent is black");
        assertTrue(matchWithOpponent.isBYE(), "The match should be marked as a BYE");
        assertEquals(1, round.getMatches().size(),
                "The match should not be removed from the round when the opponent is not a bot");
    }

    @Test
    public void testHandleBYE_WhenUserHasNoMatch() {
        // Mock data setup
        User user = new User("player1", "password1", "ROLE_PLAYER", 0);
        Round round = new Round(tournament);

        // No matches in the round
        List<Match> matches = new ArrayList<>();
        round.setMatches(matches);

        // Call the handleBYE method
        tournamentService.handleBYE(round, user);

        // Verify that no changes occurred since there were no matches
        assertTrue(round.getMatches().isEmpty(), "There should be no changes since the user was not in any match");
    }

    @Test
    public void testIsColourSuitable_WhenLessThanTwoGamesPlayed() {
        // Mock data setup
        User user = new User("player1", "password1", "ROLE_PLAYER", 0);
        Round round = new Round(tournament);

        // User has played only one match
        Match match = new Match(user, new User("opponent", "password2", "ROLE_PLAYER", 0), round);
        match.setId(1L);

        List<Match> matches = List.of(match);

        // Mock the matchService to return the user's matches
        when(matchService.getUserMatches(user)).thenReturn(matches);

        // Call the isColourSuitable method
        boolean result = tournamentService.isColourSuitable(user, tournament, "white");

        // Verify that the result is true since fewer than 2 games were played
        assertTrue(result, "The result should be true since the user has played less than two games.");
    }

    @Test
    public void testIsColourSuitable_WhenSameColourThrice() {
        // Mock data setup
        User user = new User("player1", "password1", "ROLE_PLAYER", 0);
        Round round = new Round(tournament);

        // User has played two matches of the same color
        Match match1 = new Match(user, new User("opponent1", "password2", "ROLE_PLAYER", 0), round);
        match1.setId(1L); // Earlier match

        Match match2 = new Match(user, new User("opponent2", "password3", "ROLE_PLAYER", 0), round);
        match2.setId(2L); // More recent match

        // Set both matches where the user played as "white"
        match1.setWhite(user);
        match2.setWhite(user);

        List<Match> matches = List.of(match1, match2);

        // Mock the matchService to return the user's matches
        when(matchService.getUserMatches(user)).thenReturn(matches);

        // Call the isColourSuitable method
        boolean result = tournamentService.isColourSuitable(user, tournament, "white");

        // Verify that the result is false since the user would play the same color
        // thrice
        assertFalse(result, "The result should be false since the user would play 'white' three times in a row.");
    }

    @Test
    public void testIsColourSuitable_WhenDifferentColours() {
        // Mock data setup
        User user = new User("player1", "password1", "ROLE_PLAYER", 0);
        Round round = new Round(tournament);

        // User has played two matches with different colors
        Match match1 = new Match(user, new User("opponent1", "password2", "ROLE_PLAYER", 0), round);
        match1.setId(1L); // Earlier match

        Match match2 = new Match(new User("opponent2", "password3", "ROLE_PLAYER", 0), user, round);
        match2.setId(2L); // More recent match

        // Set one match where the user played as "white" and the other as "black"
        match1.setWhite(user); // Played as "white"
        match2.setBlack(user); // Played as "black"

        List<Match> matches = List.of(match1, match2);

        // Mock the matchService to return the user's matches
        when(matchService.getUserMatches(user)).thenReturn(matches);

        // Call the isColourSuitable method
        boolean result = tournamentService.isColourSuitable(user, tournament, "white");

        // Verify that the result is true since the user would not play the same color
        // thrice
        assertTrue(result,
                "The result should be true since the user has played different colors in the last two matches.");
    }

    @Test
    public void testUpdateTournament() {
        tournament.setTitle("Old Title");
        tournament.setStartDateTime(LocalDateTime.now());
        tournament.setMinElo(1000);
        tournament.setMaxElo(2000);
        tournament.setSize(5);
        tournament.setTotalRounds(3);

        Tournament newTournamentInfo = new Tournament();
        newTournamentInfo.setId(tournament.getId());
        newTournamentInfo.setTitle("New Title");
        newTournamentInfo.setStartDateTime(LocalDateTime.now().plusDays(1));
        newTournamentInfo.setMinElo(1200);
        newTournamentInfo.setMaxElo(1800);
        newTournamentInfo.setSize(3);
        newTournamentInfo.setTotalRounds(4);

        List<User> players = new ArrayList<>();
        User player1 = new User("player1", "player1", "ROLE_PLAYER", 1100); // Below new Elo limit
        User player2 = new User("player2", "player2", "ROLE_PLAYER", 1300); // Within new Elo limit
        User player3 = new User("player3", "player3", "ROLE_PLAYER", 1900); // Above new Elo limit
        User player4 = new User("DEFAULT_BOT", "bot", "ROLE_BOT", 1500); // Bot should be ignored

        players.add(player1);
        players.add(player2);
        players.add(player3);
        players.add(player4);

        List<User> waitingList = new ArrayList<>();
        User waitingUser1 = new User("waiting1", "waiting1", "ROLE_PLAYER", 1250); // Within new Elo limit
        User waitingUser2 = new User("waiting2", "waiting2", "ROLE_PLAYER", 2000); // Outside new Elo limit

        waitingList.add(waitingUser1);
        waitingList.add(waitingUser2);

        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));
        when(userTournamentService.getPlayers(tournament.getId())).thenReturn(players);
        when(userTournamentService.getWaitingList(tournament.getId())).thenReturn(waitingList);
        when(tournamentRepository.save(tournament)).thenReturn(newTournamentInfo);

        // Call the updateTournament method
        Tournament updatedTournament = tournamentService.updateTournament(tournament.getId(), newTournamentInfo);

        // Verify that the tournament properties were updated
        assertEquals("New Title", updatedTournament.getTitle());
        assertEquals(newTournamentInfo.getStartDateTime(), updatedTournament.getStartDateTime());
        assertEquals(1200, updatedTournament.getMinElo());
        assertEquals(1800, updatedTournament.getMaxElo());
        assertEquals(3, updatedTournament.getSize());
        assertEquals(4, updatedTournament.getTotalRounds());

        verify(tournamentRepository).findById(tournament.getId());

        // Verify that players were processed based on the new Elo limits
        verify(userTournamentService, times(1)).delete(tournament, player1); // Below new Elo limit
        verify(userTournamentService, never()).delete(tournament, player2); // Within new Elo limit
        verify(userTournamentService, times(1)).delete(tournament, player3); // Above new Elo limit
        verify(userTournamentService, never()).delete(tournament, player4); // Bot should be ignored
    }

    @Test
    public void testflagSusUserPerformance_true() {
        // Mock data setup
        User user = new User("player1", "password1", "ROLE_PLAYER", 100);
        User opp1 = new User("player2", "password2", "ROLE_PLAYER", 120);
        User opp2 = new User("player3", "password3", "ROLE_PLAYER", 220);
        User opp3 = new User("player4", "password4", "ROLE_PLAYER", 260);
        User opp4 = new User("player5", "password5", "ROLE_PLAYER", 280);
        
        List<Match> matches = List.of(
            new Match(user, opp1, new Round(tournament)), 
            new Match(user, opp3, new Round(tournament)), 
            new Match(user, opp2, new Round(tournament)), 
            new Match(user, opp4, new Round(tournament)), 
            new Match(user, opp4, new Round(tournament)),
            new Match(user, opp3, new Round(tournament))
        );
        matches.forEach(match -> match.setResult(1.0));

        when(matchService.getUserMatches(user)).thenReturn(matches);
        when(userTournamentService.getPlayers(tournament.getId())).thenReturn(List.of(user));
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));
        when(cheaterbugService.isSuspicious(null)).thenReturn(true);

        // Call the flagSusUserPerformance method
        tournamentService.flagSusUserPerformance(tournament.getId());

        // Verify that the user's performance was flagged as suspicious
        assertTrue(user.isSuspicious());
    }
}