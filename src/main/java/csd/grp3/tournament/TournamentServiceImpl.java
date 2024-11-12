package csd.grp3.tournament;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import csd.grp3.CheaterBugAPI.*;
import csd.grp3.match.Match;
import csd.grp3.match.MatchService;
import csd.grp3.round.Round;
import csd.grp3.round.RoundService;
import csd.grp3.user.User;
import csd.grp3.user.UserService;
import csd.grp3.usertournament.UserTournament;
import csd.grp3.usertournament.UserTournamentService;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;

@AllArgsConstructor
@Service
public class TournamentServiceImpl implements TournamentService {

    @Autowired
    private TournamentRepository tournaments;

    @Autowired
    private MatchService matchService;

    @Autowired
    private UserTournamentService UTService;

    @Autowired
    private UserService userService;

    @Autowired
    private RoundService roundService;

    @Autowired
    private CheaterbugService cheaterbugService;

    @Override
    public List<Tournament> listTournaments() {
        return tournaments.findAll();
    }

    /**
     * Adds a new tournmaent object to repository
     * 
     * @param newTournamentInfo Tournament object to be added
     * @return Tournament object added
     */
    @Override
    @Transactional
    public Tournament addTournament(Tournament newTournamentInfo) {
        tournaments.save(newTournamentInfo);
        registerUser(userService.findByUsername("DEFAULT_BOT"), newTournamentInfo.getId());
        return newTournamentInfo;
    }

    /**
     * Get tournament object specified by id from repository
     * 
     * @param tournamentID Long
     * @return Tournament object in repository
     */
    @Override
    public Tournament getTournament(Long tournamentID) throws TournamentNotFoundException {
        return tournaments.findById(tournamentID)
                .orElseThrow(() -> new TournamentNotFoundException(tournamentID));
    }

    /**
     * Update tournament specified by tournamentID and save it to repository
     * 
     * @param tournamentID      Long ID of tournament object to be updated
     * @param newTournamentInfo Tournament object with updated details
     * @return Tournamnet object updated
     */
    @Override
    @Transactional
    public Tournament updateTournament(Long tournamentID, Tournament newTournamentInfo) {
        Tournament tournament = getTournament(tournamentID);
        tournament.setTitle(newTournamentInfo.getTitle());
        tournament.setStartDateTime(newTournamentInfo.getStartDateTime());
        tournament.setTotalRounds(newTournamentInfo.getTotalRounds());

        // update player and waiting list based on new Elo range
        tournament.setMaxElo(newTournamentInfo.getMaxElo());
        tournament.setMinElo(newTournamentInfo.getMinElo());
        updateTournamentEloRange(tournamentID);

        // update player and waiting list based on new size
        int currentSize = tournament.getSize();
        tournament.setSize(newTournamentInfo.getSize());
        int newSize = tournament.getSize();
        if (currentSize < newSize) {
            addFromWaiting(tournamentID, newSize - currentSize);
        } else if (currentSize > newSize) {
            addToWaiting(tournamentID, currentSize - newSize);
        }

        tournaments.save(tournament);

        return tournament;
    }

    /**
     * Removes users from tournament players and waiting list to fit min max ELO
     * range
     * 
     * @param tournamentID Long
     */
    private void updateTournamentEloRange(Long tournamentID) {
        Tournament tournament = getTournament(tournamentID);
        int initialSize = tournament.getSize();
        List<User> users = UTService.getPlayers(tournamentID);

        // modify list of players based on new Elo limits and new Size limits
        for (User user : users) {
            if (isUserEloEligible(tournament, user.getELO()) == false) {
                initialSize--;
                UTService.delete(tournament, user);
            }
        }
        tournament.setSize(initialSize);

        List<User> waitingList = UTService.getWaitingList(tournamentID);

        // modify list of players based on new Elo limits and new Size limits
        for (User user : waitingList) {
            if (isUserEloEligible(tournament, user.getELO()) == false) {
                UTService.delete(tournament, user);
            }
        }
    }

    /**
     * Not to be confused with addToWaiting
     * Add from waiting list to player list when theres available positions
     * Changes player status from 'w' to 'r'.
     * 
     * @param tournamentID Long
     * @param numToAdd     int
     */
    private void addFromWaiting(Long tournamentID, int numToAdd) {
        // invite players from waiting list
        Iterator<User> waitingUsers = UTService.getWaitingList(tournamentID).iterator();

        while (numToAdd > 0 && waitingUsers.hasNext()) {
            User user = waitingUsers.next();
            UTService.updatePlayerStatus(tournamentID, user.getUsername(), 'r');
            numToAdd--;
        }
    }

    /**
     * Not to be confused with addFromWaiting.
     * Add to waiting list when tournament is full.
     * Changes player status from 'r' to 'w'
     * 
     * @param tournamentID Long
     * @param numToRemove  int
     */
    private void addToWaiting(Long tournamentID, int numToRemove) {
        // invite players from waiting list

        Iterator<User> players = UTService.getPlayers(tournamentID).iterator();

        while (numToRemove > 0 && players.hasNext()) {
            User user = players.next();
            UTService.updatePlayerStatus(tournamentID, user.getUsername(), 'w');
            numToRemove--;
        }
    }

    /**
     * Checks if user ELO is above minELO and below maxELO of tournament
     * 
     * @param tournament tournament object
     * @param userELO    int value
     * @return true if userELO is between min and max
     */
    private boolean isUserEloEligible(Tournament tournament, int userELO) {
        return userELO <= tournament.getMaxElo() &&
                userELO >= tournament.getMinElo();
    }

    /**
     * Deletes tournament object specified by ID from repository
     * 
     * @param tournamentID Long
     */
    @Override
    @Transactional
    public void deleteTournament(Long tournamentID) {
        Tournament tournament = getTournament(tournamentID);

        // Collect the UserTournament IDs to be deleted
        List<UserTournament> userTournamentsToDelete = new ArrayList<>(tournament.getUserTournaments());

        // Now iterate over the collected UserTournament list
        for (UserTournament userTournament : userTournamentsToDelete) {
            // Perform the deletion logic, which may include setting the tournament
            // reference to null
            UTService.delete(tournament, userTournament.getUser()); // Adjust according to your service
        }

        // Now delete the tournament
        tournaments.deleteById(tournamentID);
    }

    /**
     * Checks if user is in tournament already.
     * Else add user to either player list or waiting list
     * 
     * @param user         User object to be registered
     * @param tournamentID Long
     */
    @Override
    @Transactional
    public void registerUser(User tempUser, Long tournamentID) throws TournamentNotFoundException {
        Tournament tournament = getTournament(tournamentID);
        List<User> playerList = UTService.getPlayers(tournamentID);
        List<User> waitingList = UTService.getWaitingList(tournamentID);

        // check if user exists in database
        User user = userService.findByUsername(tempUser.getUsername());

        // check if tournament already has that user data
        if (playerList.contains(user) || waitingList.contains(user)) {
            throw new PlayerAlreadyRegisteredException();
        } else { // if user isn't inside tournament
            // if tournament is full, we add to waiting list instead
            if (playerList.size() == tournament.getSize()) {
                UTService.add(tournament, user, 'w');
                // else, we want to add to player list
            } else {
                UTService.add(tournament, user, 'r');
            }
        }
    }

    /**
     * Removes user from tournament player list or waiting list
     * 
     * @param tempUser     User object to be withdrawn
     * @param tournamentID Long
     */
    @Override
    @Transactional
    // TODO : Check necessity of throwing error since frontend blocks it
    public void withdrawUser(User tempUser, Long tournamentID) throws UserNotRegisteredException {
        Tournament tournament = getTournament(tournamentID);
        List<User> playerList = UTService.getPlayers(tournamentID);
        List<User> waitingList = UTService.getWaitingList(tournamentID);
        User user = userService.findByUsername(tempUser.getUsername());

        if (!playerList.contains(user) && !waitingList.contains(user)) {
            throw new UserNotRegisteredException("User has not registered for tournament");
        }

        if (tournament.getRounds().size() != 0 && playerList.contains(user)) {
            UTService.updatePlayerStatus(tournamentID, user.getUsername(), 'b');
            List<Round> rounds = tournament.getRounds();
            handleBYE(rounds.get(rounds.size() - 1), user); // give opp win for current round
            if (UTService.getPlayers(tournamentID).size() < 3) {
                endTournament(tournamentID);
            }
            return;
        }

        UTService.delete(tournament, user); // Remove player

        // handling for before tournament start
        if (tournament.getStartDateTime().isAfter(LocalDateTime.now()) && playerList.contains(user)
                && !waitingList.isEmpty()) { // Before and in player list
            addFromWaiting(tournamentID, 1);
        }
    }

    /**
     * Adds a new round to the tournament
     * 
     * @param tournamentID Long
     */
    @Override
    @Transactional
    public void addRound(Long tournamentID) throws TournamentNotFoundException, InvalidTournamentStatus {
        Tournament tournament = getTournament(tournamentID);
        List<Round> rounds = tournament.getRounds();

        if (rounds.size() > 0) {
            Round lastRound = rounds.get(rounds.size() - 1);
            updateMatchResults(lastRound); // results for this round only
            if (!lastRound.isOver()) {
                return; // return tournament data as is
            }
            updateTournamentResults(lastRound); // update tournament gamepoints
        }

        if (tournament.hasStarted()) {
            Round newRound = roundService.createRound(tournament);
            createPairings(tournament, newRound);
            rounds.add(newRound);
            tournament.setRounds(rounds);
        } else {
            throw new InvalidTournamentStatus("Tournament has not started or less than 2 players");
        }
    }

    /**
     * Updates match results for a round
     * 
     * @param round Round object to update match results
     */
    @Override
    @Transactional
    public void updateMatchResults(Round round) {
        Tournament tournament = round.getTournament();

        round.getMatches().stream()
                .filter(match -> match.getResult() != 0)
                .forEach(match -> updatePlayerPoints(tournament.getId(), match));
    }

    /**
     * Updates both player points based on match results
     * 
     * @param tournamentId Long
     * @param match        Match object to update player points
     */
    private void updatePlayerPoints(Long tournamentId, Match match) {
        // Map of results to arrays. First index is white points, second is black points
        Map<Double, double[]> resultPoints = Map.of(
                1.0, new double[] { 1.0, 0.0 }, // White wins
                -1.0, new double[] { 0.0, 1.0 }, // Black wins
                0.5, new double[] { 0.5, 0.5 } // Draw
        );

        double result = match.getResult();
        double[] points = resultPoints.get(result);

        UTService.updateMatchPoints(tournamentId, match.getWhite().getUsername(), points[0]);
        UTService.updateMatchPoints(tournamentId, match.getBlack().getUsername(), points[1]);
    }

    /**
     * Updates game points for all users based on round matches
     * 
     * @param round Round object
     */
    @Override
    @Transactional
    public void updateTournamentResults(Round round) {
        List<Match> matches = round.getMatches();
        Tournament tournament = round.getTournament();

        for (Match match : matches) {
            UTService.updateGamePoints(tournament.getId(), match.getBlack().getUsername());
            UTService.updateGamePoints(tournament.getId(), match.getWhite().getUsername());
        }
    }

    /**
     * Get list of tournaments above minELO
     * 
     * @param minELO int
     * @return List of tournaments
     */
    public List<Tournament> getTournamentAboveMin(int minELO) {
        List<Tournament> tournamentList = listTournaments();
        List<Tournament> tournamentListAboveMin = new ArrayList<>();

        for (Tournament tournament : tournamentList) {
            if (tournament.getMinElo() >= minELO) {
                tournamentListAboveMin.add(tournament);
            }
        }

        return tournamentListAboveMin;
    }

    /**
     * Get list of tournaments below maxELO
     * 
     * @param maxELO int
     * @return List of tournaments
     */
    @Override
    public List<Tournament> getTournamentBelowMax(int maxELO) {
        List<Tournament> tournamentList = listTournaments();
        List<Tournament> tournamentListBelowMax = new ArrayList<>();

        for (Tournament tournament : tournamentList) {
            if (tournament.getMaxElo() <= maxELO) {
                tournamentListBelowMax.add(tournament);
            }
        }

        return tournamentListBelowMax;
    }

    /**
     * Get list of tournaments between minELO and maxELO
     * 
     * @param minELO int
     * @param maxELO int
     * @return List of tournaments
     */
    public List<Tournament> getTournamentAboveMinBelowMax(int minELO, int maxELO) {
        List<Tournament> belowMaxList = getTournamentBelowMax(maxELO);
        List<Tournament> aboveMinList = getTournamentAboveMin(minELO);

        // remove tournaments thats are below min
        belowMaxList.retainAll(aboveMinList);

        return belowMaxList;
    }

    /**
     * Get list of tournaments that user is eligible for
     * 
     * @param userELO int
     * @return List of tournaments
     */
    public List<Tournament> getUserEligibleTournament(int userELO) {
        List<Tournament> tournamentList = listTournaments();
        List<Tournament> eligibleTournamentList = new ArrayList<>();

        for (Tournament tournament : tournamentList) {
            if (isUserEloEligible(tournament, userELO)) {
                eligibleTournamentList.add(tournament);
            }
        }

        return eligibleTournamentList;
    }

    /**
     * Checks if 2 users have played each other in the tournament before.
     * User order does not matter.
     * If no winner, returns "draw".
     * If never faced each other, returns "no direct encounter".
     * 
     * @param tournament - Tournament to check
     * @param user1      - First user
     * @param user2      - Second user
     * @return Username of winner
     */
    public String directEncounterResultInTournament(Tournament tournament, User user1, User user2) {
        List<Match> directEncounters = matchService.getMatchesBetweenTwoUsers(user1, user2)
                .stream()
                .filter(match -> match.getTournament().equals(tournament))
                .collect(Collectors.toList());

        if (directEncounters.size() == 0) {
            return "no direct encounter";
        }

        Match directEncounter = directEncounters.get(0);

        if (directEncounter.getResult() == -1) {
            return directEncounter.getBlack().getUsername();
        } else if (directEncounter.getResult() == 1) {
            return directEncounter.getWhite().getUsername();
        } else {
            return "draw";
        }
    }

    /**
     * Buchholz score is the sum of game points obtained by the opponents throughout
     * the tournament.
     * Iterate through user's matches in the tournament and sum up the game points
     * of all opponents faced.
     * 
     * @param user       User to calculate Buchholz score for
     * @param tournament Tournament object
     * @return Buchholz score of user
     */
    public double calculateBuchholzInTournament(User user, Tournament tournament) {
        List<Match> matchList = matchService.getUserMatches(user).stream()
                .filter(match -> match.getTournament().equals(tournament))
                .collect(Collectors.toList());

        double buchholzScore = 0;
        for (Match match : matchList) {
            User opponent = match.getWhite().equals(user) ? match.getBlack() : match.getWhite();
            buchholzScore += UTService.getGamePoints(tournament.getId(), opponent.getUsername());
        }
        return buchholzScore;
    }

    /**
     * Get list of users sorted in order of by game points, buchholz score, and ELO
     * 
     * @param tournamentID Long
     * @return List of sorted users
     */
    @Override
    public List<User> getSortedUsers(Long tournamentID) {
        Tournament tournament = getTournament(tournamentID);
        List<User> users = UTService.getPlayers(tournament.getId());
        users.sort(Comparator
                .comparingDouble((User user) -> UTService.getGamePoints(tournament.getId(), user.getUsername()))
                .thenComparingDouble((User user) -> calculateBuchholzInTournament(user, tournament))
                .thenComparing(User::getELO)
                .reversed());
        return users;
    }

    /**
     * Create pairings for the next round of the tournament
     * 
     * @param tournament Tournament object
     */
    @Transactional
    public void createPairings(Tournament tournament, Round round) {
        Set<User> pairedUsers = new HashSet<>();
        List<Match> matches = round.getMatches();
        List<User> users = getSortedUsers(tournament.getId());

        for (int i = 0; i < users.size(); i++) {
            User user1 = users.get(i);

            if (pairedUsers.contains(user1))
                continue;

            // Give priority to user1 (higher ranked) to get opposite colour to prev game
            // assume user1 is white
            boolean isUser1White = isNextColourWhite(user1, tournament);

            for (int j = i + 1; j < users.size(); j++) {
                User user2 = users.get(j);

                if (pairedUsers.contains(user2))
                    continue;

                // check if users have not played each other in tournament
                if (!directEncounterResultInTournament(tournament, user1, user2).equals("no direct encounter"))
                    continue;

                // check if user2 can be assigned colour
                if (!isColourSuitable(user2, tournament, isUser1White ? "black" : "white"))
                    continue;

                Match newPair = createMatchWithUserColour(user1, isUser1White ? "white" : "black", user2, round);
                matches.add(newPair);
                pairedUsers.add(user1);
                pairedUsers.add(user2);
                break;
            }
        }
    }

    /**
     * Checks previous match to determine next match colour (for colour priority)
     * 
     * @param user       - priority user
     * @param tournament - Tournament matches to consider
     * @return - true if next colour is white
     */
    private boolean isNextColourWhite(User user, Tournament tournament) {
        List<Match> matchList = matchService.getUserMatches(user).stream()
                .filter(match -> match.getTournament().equals(tournament))
                .collect(Collectors.toList());

        // Sort in order of increasing round id, since latest round will be largest
        matchList.sort(Comparator.comparing(Match::getId));

        // No games played in tournament yet, default is white
        if (matchList.size() == 0) {
            return true;
        }

        Match previousMatch = matchList.get(matchList.size() - 1);

        // if previous match user is not white, next colour is white, vice versa
        return previousMatch.getWhite().equals(user) ? false : true;
    }

    /**
     * Checks if user is able to play the nextColour
     * If user hill play same colour three time (including nextColour), returns
     * false
     * If less than 2 games played, returns true
     * 
     * @param user
     * @param tournament - Tournament matches to consider
     * @param nextColour - either "white" or "black" only
     * @return - true if not same colour for 3 times consecutively
     */
    public boolean isColourSuitable(User user, Tournament tournament, String nextColour) {
        List<Match> matchList = matchService.getUserMatches(user).stream()
                .filter(match -> match.getTournament().equals(tournament))
                .collect(Collectors.toList());

        // Sort in order of increasing round id, since most recent 2 rounds will be
        // largest
        matchList.sort(Comparator.comparing(Match::getId));

        // If less than 2 games played, can accept any colour
        if (matchList.size() < 2) {
            return true;
        }

        Match mostRecentMatch = matchList.get(matchList.size() - 1);
        Match secondRecentMatch = matchList.get(matchList.size() - 2);

        String mostRecentColour = mostRecentMatch.getWhite().equals(user) ? "white" : "black";
        String secondRecentColour = secondRecentMatch.getWhite().equals(user) ? "white" : "black";

        // If recent colours same as nextColour, user will play the same colour thrice
        boolean sameColourThrice = mostRecentColour.equals(secondRecentColour) && mostRecentColour.equals(nextColour);

        // if playing same colour thrice, it is not suitable
        return !sameColourThrice;
    }

    /**
     * Creates a match object and saves to matchRepo.
     * Assigns users to their respective colours and returns match object.
     * 
     * @param user1
     * @param user1Colour - either "white" or "black" only
     * @param user2
     * @param round
     * @return
     */
    private Match createMatchWithUserColour(User user1, String user1Colour, User user2, Round round) {
        if (user1Colour.equals("white")) {
            return matchService.createMatch(user1, user2, round);
        } else {
            return matchService.createMatch(user2, user1, round);
        }
    }

    /**
     * Iterates through players and all their matches played in tournament.
     * calls calculateELO() to calculate new ELO for each player.
     * 
     * @param tournamentID Long
     */
    @Override
public void endTournament(Long tournamentID) {
    // Retrieve the tournament and mark it as calculated
    Tournament tournament = getTournament(tournamentID);
    tournament.setCalculated(true);
    tournaments.save(tournament);

    Map<User, List<CheaterbugEntity>> userEntitiesMap = new HashMap<>();

    // Gather data for analysis and map entities to users
    for (User user : UTService.getPlayers(tournamentID)) {
        List<Match> userMatches = matchService.getUserMatches(user).stream()
                .filter(match -> match.getTournament().equals(tournament))
                .collect(Collectors.toList());

        // Calculate new ELO for the user
        Integer newELO = calculateELO(userMatches, user);
        user.setELO(newELO);
        userService.updateELO(user, newELO);

        List<CheaterbugEntity> userEntities = new ArrayList<>();
        for (Match match : userMatches) {
            User opponent = match.getWhite().equals(user) ? match.getBlack() : match.getWhite();
            double actualScore = getActualScore(match.getResult(),
                    match.getWhite().equals(user) ? "white" : "black");
            double expectedScore = calculateExpectedScore(user.getELO(), opponent.getELO());

            // Create a CheaterbugEntity for each match
            CheaterbugEntity entity = new CheaterbugEntity(expectedScore, actualScore);
            userEntities.add(entity);
        }
        userEntitiesMap.put(user, userEntities); // Link entities to the user
    }

    // Analyze each user's data individually for suspicious activity
    for (Map.Entry<User, List<CheaterbugEntity>> entry : userEntitiesMap.entrySet()) {
        User user = entry.getKey();
        List<CheaterbugEntity> userEntities = entry.getValue();

        // Analyze this user's matches using the CheaterbugService
        CheaterbugResponse response = cheaterbugService.analyze(userEntities);

        if (cheaterbugService.isSuspicious(response)) {
            System.out.println("Suspicious activity detected for user: " + user.getUsername() +
                    " in tournament ID: " + tournamentID + ", Title: " + tournament.getTitle());
        }
    }
}


    /**
     * Handles BYE case for user in round
     * 
     * @param round Round object
     * @param user  User object
     */
    @Transactional
    public void handleBYE(Round round, User user) { // color is color of worst player
        List<Match> matches = round.getMatches();
        for (Match match : matches) {
            if (match.getBlack().equals(user) || match.getWhite().equals(user)) {
                String userColour = match.getBlack().equals(user) ? "black" : "white";
                User opponent = userColour.equals("black") ? match.getWhite() : match.getBlack();
                if (opponent.getUsername().equals("DEFAULT_BOT")) {
                    matches.remove(match);
                    break;
                }
                match.setResult(userColour.equals("black") ? 1 : -1);
                match.setBYE(true);
                break;
            }
        }
    }

    /**
     * Calculate user ELO via this formula documentation
     * https://en.wikipedia.org/wiki/Chess_rating_system#Linear_approximation
     * Based on difference in expected vs actual score.
     * Uses a development coefficient, depending on the user's match history, via
     * getDevelopmentCoefficient()
     * 
     * @param matches List of matches to consider
     * @param user    User object
     * @return User's new ELO
     */
    public Integer calculateELO(List<Match> matches, User user) {
        Integer userELO = user.getELO();
        Integer developmentCoefficient = getDevelopmentCoefficient(user);
        Double changeInRating = 0.0;

        for (Match match : matches) {
            // void match results as both users didnt play tgt
            if (match.isBYE())
                continue;

            User opponent = match.getWhite().equals(user) ? match.getBlack() : match.getWhite();
            Double expectedScore = calculateExpectedScore(userELO, opponent.getELO());
            Double actualScore = getActualScore(match.getResult(), match.getWhite().equals(user) ? "white" : "black");
            changeInRating += developmentCoefficient * (actualScore - expectedScore);
        }

        return (int) (changeInRating + 0.5) + userELO;
    }

    /**
     * Calculates actual score of user via results and user colour
     * 
     * @param result     double
     * @param userColour String
     * @return Actual score wrt user
     */
    private Double getActualScore(double result, String userColour) {
        return result == 1.0 ? (userColour.equals("white") ? 1.0 : 0.0) // case if result is 1
                : result == -1 ? (userColour.equals("white") ? 0.0 : 1.0) // case if result is -1
                        : 0.5;
    }

    /**
     * Get development coefficient based on user's matches played since inception
     * THRESHOLD_ELO = 2400 to moderate pro players
     * THRESHOLD_MATCHES = 30 to moderate new players
     * 
     * @param user User object
     * @return development coefficient for ELO calculation
     */
    private Integer getDevelopmentCoefficient(User user) {
        List<Match> userMatches = matchService.getUserMatches(user);
        final int THRESHOLD_ELO = 2400;
        final int THRESHOLD_MATCHES = 30;
        final int PRO_COEFFICIENT = 5;
        final int NEWBIE_COEFFICIENT = 15;
        final int DEFAULT_COEFFICIENT = 10;

        if (user.getELO() > THRESHOLD_ELO) {
            return PRO_COEFFICIENT;
        }
        if (userMatches.size() < THRESHOLD_MATCHES) {
            return NEWBIE_COEFFICIENT;
        }
        return DEFAULT_COEFFICIENT;
    }
    /**
     * Calculate expected score of user based on ELO difference
     * 
     * @param userELO     Integer
     * @param opponentELO Integer
     * @return Double expected score
     */
    private Double calculateExpectedScore(Integer userELO, Integer opponentELO) {
        Double classInterval = 50.0;
        return 1.0 / (1 + Math.pow(10, (opponentELO - userELO) / classInterval));
    }

    /**
     * Get tournament history of user
     * 
     * @param username String
     * @return List of Tournament Objects
     */
    @Override
    public List<Tournament> getHistoryByUser(String username) {
        List<Tournament> list = new ArrayList<>();
        User user = userService.findByUsername(username);
        for (UserTournament ut : user.getUserTournaments()) {
            if (ut.getTournament().isOver()) {
                list.add(ut.getTournament());
            }
        }
        return list;
    }
}