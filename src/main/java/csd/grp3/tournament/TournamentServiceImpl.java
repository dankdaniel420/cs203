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

import csd.grp3.CheaterBugAPI.CheaterbugEntity;
import csd.grp3.CheaterBugAPI.CheaterbugService;
import csd.grp3.match.Match;
import csd.grp3.match.MatchService;
import csd.grp3.round.Round;
import csd.grp3.round.RoundService;
import csd.grp3.user.User;
import csd.grp3.user.UserService;
import csd.grp3.usertournament.UserTournament;
import csd.grp3.usertournament.UserTournamentService;
import jakarta.transaction.Transactional;

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
                .orElseThrow(() -> new TournamentNotFoundException());
    }

    /**
     * Update tournament specified by tournamentID and save it to repository
     *  
     * @param tournamentID Long ID of tournament object to be updated
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
        updateTournamentEloRange(tournament);

        // update player and waiting list based on new size
        tournament.setSize(newTournamentInfo.getSize());
        updateTournamentSize(tournament);

        return tournaments.save(tournament);
    }

    /**
     * Removes users from tournament players and waiting list to fit min max ELO range
     * 
     * @param tournament Tournament object 
     */
    private void updateTournamentEloRange(Tournament tournament) {
        List<User> users = UTService.getPlayers(tournament.getId());
        // combine waiting list with player list
        users.addAll(UTService.getWaitingList(tournament.getId()));

        // modify combined list based on new Elo limits
        for (User user : users) {
            if (isUserEloEligible(tournament, user.getELO()) == false) {
                UTService.delete(tournament, user);
            }
        }
    }

    /**
     * Updates player and waiting list based on new tournament size.
     * If new size is larger, add players from waiting list.
     * If new size is smaller, add players to waiting list.
     * 
     * @param tournament Tournament object
     */
    private void updateTournamentSize(Tournament tournament) {
        int currentSize = UTService.getPlayers(tournament.getId()).size();
        int newSize = tournament.getSize();
        if (currentSize < newSize) {
            addFromWaiting(tournament.getId(), newSize - currentSize);
        } else if (currentSize > newSize) {
            addToWaiting(tournament.getId(), currentSize - newSize);
        }
    }

    /**
     * Not to be confused with addToWaiting
     * Add from waiting list to player list when theres available positions
     * Changes player status from 'w' to 'r'.
     * 
     * @param tournamentID Long
     * @param numToAdd int
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
     * @param numToRemove int
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
     * @param userELO int value
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
     * @param tempUser User object to be registered
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
            throw new UserAlreadyRegisteredException();
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
     * @param tempUser User object to be withdrawn
     * @param tournamentID Long 
     */
    @Override
    @Transactional
    public void withdrawUser(User tempUser, Long tournamentID) throws UserNotRegisteredException {
        Tournament tournament = getTournament(tournamentID);
        List<User> playerList = UTService.getPlayers(tournamentID);
        List<User> waitingList = UTService.getWaitingList(tournamentID);
        User user = userService.findByUsername(tempUser.getUsername());

        if (!playerList.contains(user) && !waitingList.contains(user)) {
            throw new UserNotRegisteredException();
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
     * @param match Match object to update player points
     */
    private void updatePlayerPoints(Long tournamentId, Match match) {
        // Map of results to arrays. First index is white points, second is black points
        Map<Double, double[]> resultPoints = Map.of(
             1.0, new double[]{1.0, 0.0},  // White wins
            -1.0, new double[]{0.0, 1.0},  // Black wins
             0.5, new double[]{0.5, 0.5}   // Draw
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
     * Buchholz score is the sum of game points obtained by the opponents throughout the tournament.
     * Iterate through user's matches in the tournament and sum up the game points of all opponents faced.
     * 
     * @param user User to calculate Buchholz score for
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

                if (j == users.size() - 1) {
                    if (pairedUsers.contains(user2)) {
                        for (int k = i + 1; k < users.size(); k++) {
                            User desperateUser = users.get(k);
                            if (!pairedUsers.contains(desperateUser)) {
                                Match newPair = createMatchWithUserColour(user1, isUser1White ? "white" : "black", desperateUser, round);
                                matches.add(newPair);
                                pairedUsers.add(user1);
                                pairedUsers.add(desperateUser);
                                break;
                            }
                        }
                    } else {
                        Match newPair = createMatchWithUserColour(user1, isUser1White ? "white" : "black", user2, round);
                        matches.add(newPair);
                        pairedUsers.add(user1);
                        pairedUsers.add(user2);
                    }
                    break;
                }

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

        //handle odd
        users.removeAll(pairedUsers);
        if (users.size() != 0) {
            User oddUser = users.get(0);
            Match newPair = createMatchWithUserColour(oddUser, "white", userService.findByUsername("DEFAULT_BOT"), round);
            newPair.setResult(1.0);
            newPair.setBYE(true);
            matches.add(newPair);
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
        Tournament tournament = getTournament(tournamentID);
        tournament.setCalculated(true);
        tournaments.save(tournament); // set Calculated

        Map<User, Integer> eloChanges = new HashMap<>();
        for (User user : UTService.getPlayers(tournamentID)) {
            eloChanges.put(user, calculateChangeInELO(getUserExpectedActualScoreInTournament(tournament, user), getDevelopmentCoefficient(user)));
        }
        //catch cheaters
        flagSusUserPerformance(tournamentID);

        updateUserEloMap(eloChanges);

    }

    private void updateUserEloMap(Map<User, Integer> eloChanges) {
        for (Map.Entry<User, Integer> entry : eloChanges.entrySet()) {
            User user = entry.getKey();
            Integer eloChange = entry.getValue();
            user.setELO(user.getELO() + eloChange);
            userService.updateELO(user, user.getELO());
        }
    }

    /**
     * Handles BYE case for user in round
     * 
     * @param round Round object
     * @param user User object
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
     * Calculate change in user ELO based on matches played in tournament
     * Uses a development coefficient, depending on the user's match history
     * 
     * @param matches List of matches to consider
     * @param user User object
     * @return User's new ELO
     */
    public Integer calculateChangeInELO(List<Map<String, Double>> userExpectedActualScores, Integer developmentCoefficient) {
        Double changeInELO = 0.0;

        for (Map<String, Double> scoreMap : userExpectedActualScores) {
            changeInELO += developmentCoefficient * (scoreMap.get("actual") - scoreMap.get("expected"));
        }

        return (int) (changeInELO + 0.5);
    }

    /**
     * Calculates actual score of user via results and user colour
     * 
     * @param result double
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

    /**
     * Get user's expected and actual score for matches played in tournament
     * 
     * @param tournament Tournament object
     * @param user User object
     * @return List of maps of expected and actual scores
     */
    private List<Map<String, Double>> getUserExpectedActualScoreInTournament(Tournament tournament, User user) {
        List<Map<String, Double>> expectedActualScores = new ArrayList<>();
        List<Match> matches = matchService.getUserMatches(user).stream()
                .filter(match -> match.getTournament().equals(tournament))
                .collect(Collectors.toList());

        for (Match match : matches) {
            // void match results as both users didnt play tgt
            if (match.isBYE())
                continue;

            expectedActualScores.add(getUserExpectedActualScoreInMatch(match, user));
        }
        return expectedActualScores;
    }

    /**
     * Calculate expected and actual score of user in match based on this formula
     * https://en.wikipedia.org/wiki/Chess_rating_system#Linear_approximation
     * 
     * @param match Match object
     * @param user User object
     * @return Map of expected and actual score
     */
    private Map<String, Double> getUserExpectedActualScoreInMatch(Match match, User user) {
        final Double CLASS_INTERVAL = 200.0;
        Map<String, Double> expectedActualScore = new HashMap<>();
        User opponent = match.getWhite().equals(user) ? match.getBlack() : match.getWhite();
        Double expectedScore = 1.0 / (1 + Math.pow(10, (opponent.getELO() - user.getELO()) / CLASS_INTERVAL));
        Double actualScore = getActualScore(match.getResult(), match.getWhite().equals(user) ? "white" : "black");

        expectedActualScore.put("expected", expectedScore);
        expectedActualScore.put("actual", actualScore);

        return expectedActualScore;
    }

    /**
     * Flag users in tournament if suspicious performance detected
     * 
     * @param tournamentID Long
     */
    @Override
    public void flagSusUserPerformance(Long tournamentID) {
        Tournament tournament = getTournament(tournamentID);
        for (User user : UTService.getPlayers(tournamentID)) {
            if (user.getUsername().equals("DEFAULT_BOT")) {
                continue;
            }

            List<Map<String, Double>> userExpectedActualScores = getUserExpectedActualScoreInTournament(tournament, user);
            if (checkCheaterbug(userExpectedActualScores)) {
                user.setSuspicious(true);
                userService.updateSuspicious(user, true);
            }
        }
    }

    /**
     * Use Cheaterbug API to check if user's expected vs actual scores are suspicious
     * 
     * @param userExpectedActualScores List of maps of expected and actual scores
     */
    public boolean checkCheaterbug(List<Map<String, Double>> userExpectedActualScores) {
        List<CheaterbugEntity> cheaterbugEntities = new ArrayList<>();
        for (Map<String, Double> scoreMap : userExpectedActualScores) {
            cheaterbugEntities.add(new CheaterbugEntity(scoreMap.get("actual"), scoreMap.get("expected")));
        }

        System.out.println(cheaterbugEntities);
        System.out.println(cheaterbugService.analyze(cheaterbugEntities));

        return cheaterbugService.isSuspicious(cheaterbugService.analyze(cheaterbugEntities));
    }
}
