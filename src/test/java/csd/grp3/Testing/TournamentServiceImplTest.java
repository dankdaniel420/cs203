package csd.grp3.Testing;

import java.time.LocalDateTime;
import java.time.Month;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyChar;

import org.mockito.InjectMocks;
import org.mockito.Mock;

import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

import csd.grp3.tournament.InvalidTournamentStatus;
import csd.grp3.tournament.Tournament;
import csd.grp3.tournament.TournamentNotFoundException;
import csd.grp3.tournament.TournamentRepository;
import csd.grp3.tournament.TournamentServiceImpl;
import csd.grp3.user.User;
import csd.grp3.user.UserServiceImpl;
import csd.grp3.match.MatchServiceImpl;
import csd.grp3.round.Round;
import csd.grp3.tournament.PlayerAlreadyRegisteredException;
import csd.grp3.usertournament.UserTournamentServiceImpl;
import csd.grp3.usertournament.UserTournament;
import csd.grp3.usertournament.UserTournamentId;

@ExtendWith(MockitoExtension.class)
public class TournamentServiceImplTest {

    @Mock
    private TournamentRepository tournamentRepository;

    @InjectMocks
    private TournamentServiceImpl tournamentService;

    @Mock
    private UserTournamentServiceImpl userTournamentService;

    @Mock
    private UserServiceImpl userService;

    @Mock
    private MatchServiceImpl matchService;

    private Tournament tournament;
    private User player;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        tournament = new Tournament();
        tournament.setId(1L);
        tournament.setTitle("Test Tournament");
        tournament.setSize(2);
        // tournament.setUserTournaments(new ArrayList<>());
        
        player = new User("testUser", "testPassword123");  // Username and password
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
        // assertEquals("Test Tournament", result.get(0).getTitle());
        // verify(tournamentRepository, times(1)).findAll();
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
        assertEquals("Could not find tournament 1", exception.getMessage());

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
        when(tournamentRepository.save(any(Tournament.class))).thenReturn(tournament);

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
        assertEquals("Could not find tournament 1", exception.getMessage());
        verify(tournamentRepository).findById(1L);
    }

    @Test
    void updateTournament_UpdatedTournament_ReturnUpdatedTournament() {
        // Arrange
        Tournament newTournamentInfo = new Tournament(1L, null, "Updated Tournament", 0, 0, null, 0, 10, false, null);
        when(tournamentRepository.findById(1L)).thenReturn(Optional.of(tournament));

        // Act
        Tournament updatedTournament = tournamentService.updateTournament(1L, newTournamentInfo);

        // Assert
        assertNotNull(updatedTournament);
        assertEquals("Updated Tournament", updatedTournament.getTitle());
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
        assertEquals("Could not find tournament 1", exception.getMessage());

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
            tournament.getUserTournaments().add(userTournament); // Directly add the user tournament to the tournament's list
            return null; // Since add returns void
        }).when(userTournamentService).add(any(Tournament.class), any(User.class), anyChar());
        // mock UTService
        // when(userTournamentRepository.findRegisteredUsersByTournamentId(1L)).thenReturn(userList);
        // when(userTournamentRepository.findWaitlistUsersByTournamentId(1L)).thenReturn(userList);

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
        PlayerAlreadyRegisteredException exception = assertThrows(PlayerAlreadyRegisteredException.class, () -> {
            tournamentService.registerUser(player, tournament.getId());
        });

        // Verify that the exception message is correct
        assertEquals("Player has already registered for this tournament.", exception.getMessage());

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
        PlayerAlreadyRegisteredException exception = assertThrows(PlayerAlreadyRegisteredException.class, () -> {
            tournamentService.registerUser(player, tournament.getId());
        });

        // Verify that the exception message is correct
        assertEquals("Player has already registered for this tournament.", exception.getMessage());

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
        assertEquals("Could not find tournament 1", exception.getMessage());

        // Verify that deleteById was never called with the correct argument
        verify(tournamentRepository).findById(1L);
    }

    @Test
    void withdrawPlayer_UserListWithdrawSuccess_ReturnUserListSmallerByOne() {
        // Arrange
        List<User> userList = new ArrayList<>();
        List<User> waitingList = new ArrayList<>();
        UserTournamentId UTId = new UserTournamentId(tournament.getId(), player.getUsername());
        UserTournament userTournament = new UserTournament(UTId, tournament, player, null, 0, 0);
        LocalDateTime time = LocalDateTime.of(2014, Month.JANUARY, 1, 10, 10, 30);
        userList.add(player);
        tournament.setDate(time);
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

        // mock UTService
        // when(userTournamentRepository.findRegisteredUsersByTournamentId(1L)).thenReturn(userList);
        // when(userTournamentRepository.findWaitlistUsersByTournamentId(1L)).thenReturn(userList);

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
        assertEquals("Could not find tournament 1", exception.getMessage());

        // Verify that deleteById was never called with the correct argument
        verify(tournamentRepository).findById(1L);
    }

    // @Test
    // void withdrawPlayer_PlayerNotFound_ReturnUserTournamentNotFoundException() {
        
    // }

    // @Test
    // void createPairings_PairCreated_ReturnMatch() {
    //     // Arrange
    //     List<Round> rounds = new ArrayList<>();
    //     tournament.setRounds(rounds);
    //     tournament.setMaxElo(100);
    //     tournament.setSize(10);
        
    //     // Mock users
    //     User user1 = new User("player1", "player11", "ROLE_PLAYER", 10);
    //     User user2 = new User("player1", "player11", "ROLE_PLAYER", 10);
    //     User user3 = new User("player1", "player11", "ROLE_PLAYER", 10);
    //     User user4 = new User("player1", "player11", "ROLE_PLAYER", 10);
        
    //     List<User> users = Arrays.asList(user1, user2, user3, user4);

    //     // Mock sorted users
    //     when(tournamentService.getSortedUsers(tournament.getId())).thenReturn(users);

    //     // Mock color preferences and previous matches
    //     when(tournamentService.isNextColourWhite(user1, tournament)).thenReturn(true);
    //     when(tournamentService.isNextColourWhite(user2, tournament)).thenReturn(false);
    //     when(tournamentService.hasPlayedBefore(user1, user2, tournament)).thenReturn(false);
    //     when(tournamentService.hasPlayedBefore(user3, user4, tournament)).thenReturn(false);
    //     when(tournamentService.isColourSuitable(user2, tournament, "black")).thenReturn(true);
    //     when(tournamentService.isColourSuitable(user3, tournament, "white")).thenReturn(true);

    //     // Act
    //     tournamentService.createPairings(tournament);

    //     // Assert
    //     // Verify that a new round was added to the tournament
    //     assertEquals(1, tournament.getRounds().size());
    //     Round createdRound = tournament.getRounds().get(0);
        
    //     // Verify that matches were created
    //     List<Match> matches = createdRound.getMatches();
    //     assertEquals(2, matches.size());

    //     // Verify pairing was done correctly
    //     Match match1 = matches.get(0);
    //     Match match2 = matches.get(1);

    //     assertEquals(user1, match1.getWhitePlayer());
    //     assertEquals(user2, match1.getBlackPlayer());
    //     assertEquals(user3, match2.getWhitePlayer());
    //     assertEquals(user4, match2.getBlackPlayer());

    //     // Verify the methods were called with correct parameters
    //     verify(tournamentService).getSortedUsers(tournament.getId());
    //     verify(tournamentService).isNextColourWhite(user1, tournament);
    //     verify(tournamentService).isNextColourWhite(user3, tournament);
    //     verify(tournamentService).hasPlayedBefore(user1, user2, tournament);
    //     verify(tournamentService).hasPlayedBefore(user3, user4, tournament);
    //     verify(tournamentService).isColourSuitable(user2, tournament, "black");
    //     verify(tournamentService).isColourSuitable(user3, tournament, "white");
    // }

    @Test
    void addRound_TournamentNotFound_ReturnTournamentNotFoundException() {
        // Retrieve empty mock tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.empty());

        // Act & Assert: Expect TournamentNotFoundException to be thrown
        TournamentNotFoundException exception = assertThrows(TournamentNotFoundException.class, () -> {
            tournamentService.addRound(tournament.getId());
        });

        // Verify that the exception message is correct
        assertEquals("Could not find tournament 1", exception.getMessage());

        // Verify that deleteById was never called with the correct argument
        verify(tournamentRepository).findById(1L);
    }

    @Test
    void addRound_InvalidTournamentStatusTime_ReturnInvalidTournamentStatus() {
        // Arrange
        LocalDateTime time = LocalDateTime.of(2999, Month.JANUARY, 1, 10, 10, 30);
        tournament.setDate(time);
        tournament.setSize(3);

        // Retrieve empty mock tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));

        // Act & Assert: Expect TournamentNotFoundException to be thrown
        InvalidTournamentStatus tournamentStatus = assertThrows(InvalidTournamentStatus.class, () -> {
            tournamentService.addRound(tournament.getId());
        });

        // Verify that the exception message is correct
        assertEquals("Wait for Tournament Start Date", tournamentStatus.getMessage());

        // Verify that deleteById was never called with the correct argument
        verify(tournamentRepository).findById(1L);
    }

    @Test
    void addRound_InvalidTournamentStatusPlayerSize_ReturnInvalidTournamentStatus() {
        // Arrange
        LocalDateTime time = LocalDateTime.of(2014, Month.JANUARY, 1, 10, 10, 30);
        tournament.setDate(time);

        // Retrieve empty mock tournament
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));
        when(userTournamentService.getPlayers(tournament.getId())).thenReturn(new ArrayList<>());

        // Act & Assert: Expect TournamentNotFoundException to be thrown
        InvalidTournamentStatus tournamentStatus = assertThrows(InvalidTournamentStatus.class, () -> {
            tournamentService.addRound(tournament.getId());
        });

        // Verify that the exception message is correct
        assertEquals("Need at least 2 Players registered", tournamentStatus.getMessage());

        // Verify that deleteById was never called with the correct argument
        verify(tournamentRepository).findById(1L);
    }

    @Test
    void addRound_AddSuccess_ReturnRound() {
        // Arrange 
        LocalDateTime time = LocalDateTime.of(2014, Month.JANUARY, 1, 10, 10, 30);
        tournament.setDate(time);
        tournament.setSize(10);
        tournament.setMaxElo(200);
        tournament.setMinElo(100);
        List<User> playerList = new ArrayList<>();
        User player1 = new User("player1", "player11", "ROLE_PLAYER", 100);
        User player2 = new User("player2", "player21", "ROLE_PLAYER", 200);
        playerList.add(player1);
        playerList.add(player2);

        // Mock findbyId and save
        when(tournamentRepository.findById(tournament.getId())).thenReturn(Optional.of(tournament));
        when(userTournamentService.getPlayers(tournament.getId())).thenReturn(playerList);

        // Act, add 1 round to tournament
        tournamentService.addRound(tournament.getId());

        // Assert
        assertEquals(1, tournament.getRounds().size());
        verify(tournamentRepository, times(2)).findById(tournament.getId());
    }

    // @Test
    // void updateResult_MatchNotEnded_ReturnMatchNotCompletedException() {

    // }
    
    // @Test
    // void updateResult_UpdatedResult_ReturnNothing() {

    // }

    @Test
    void getTournamentAboveMin_TournamentAboveMin_ReturnListOfTournamentAboveMin() {
        // Arrange
        int elo = 100;
        Tournament testTournament = new Tournament(1L, null, null, 200, 300, null, elo, 10, false, null);
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
        Tournament testTournament = new Tournament(1L, null, null, 50, 75, null, elo, 10, false, null);
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
        Tournament testTournament = new Tournament(1L, null, null, 100, 300, null, elo, 10, false, null);
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
        Tournament testTournament = new Tournament(1L, null, null, 50, 75, null, elo, 10, false, null);
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
        Tournament testTournament = new Tournament(1L, null, null, 50, 200, null, elo, 10, false, null);
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
        Tournament testTournament = new Tournament(1L, null, null, 50, 100, null, elo, 10, false, null);
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
        Tournament testTournament = new Tournament(1L, null, null, 150, 250, null, 10, 10, false, null);
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
        Tournament testTournament = new Tournament(1L, null, null, 50, 150, null, 10, 10, false, null);
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
        Tournament testTournament = new Tournament(1L, null, null, 125, 175, null, 10, 10, false, null);
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
        Tournament tournament = new Tournament(1L, null, null, 100, 300, null, 10, 10, false, null);
        List<Tournament> tournaments = new ArrayList<>();
        tournaments.add(tournament);

        // Mock repository
        when(tournamentRepository.findAll()).thenReturn(tournaments);

        // Act
        List<Tournament> result = tournamentService.getUserEligibleTournament(player.getELO());

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        assertEquals(1L, result.get(0).getId());
        verify(tournamentRepository).findAll();
    }

    @Test
    void getUserEligibleTournament_NotEligible_ReturnTournamentList() {
        // Arrange
        player.setELO(0);
        Tournament tournament = new Tournament(1L, null, null, 100, 300, null, 10, 10, false, null);
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

//     @Test
//     void testTournamentExists() {
//         // when(tournamentRepository.existsById(1L)).thenReturn(true);

//         // boolean exists = tournamentService.tournamentExists(1L);

//         // assertTrue(exists);
//         // verify(tournamentRepository, times(1)).existsById(1L);
//     }
}