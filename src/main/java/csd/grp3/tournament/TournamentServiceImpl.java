package csd.grp3.tournament;

import csd.grp3.match.Match;
import csd.grp3.match.MatchRepository;
import csd.grp3.player.Player;
import csd.grp3.round.Round;
import csd.grp3.user.User;

import java.util.*;
import java.util.stream.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TournamentServiceImpl implements TournamentService {

    @Autowired
    private TournamentRepository tournaments;

    @Autowired
    private MatchRepository matches;

    public TournamentServiceImpl(TournamentRepository tournaments) {
        this.tournaments = tournaments;
    }

    @Override
    public List<Tournament> listTournaments() {
        return tournaments.findAll();
    }

    @Override
    public Tournament addTournament(Tournament tournament) {
        return tournaments.save(tournament);
    }

    @Override
    public Tournament updateTournament(Long id, Tournament newTournamentInfo) {
        return tournaments.findById(id).map(tournament -> {
            tournament.setTitle(newTournamentInfo.getTitle());
            return tournaments.save(tournament);
        }).orElse(null);
    }

    @Override
    public Tournament getTournament(Long id) {
        return tournaments.findById(id).orElse(null);
    }

    @Override
    public void deleteTournament(Long id) {
        tournaments.deleteById(id);
    }

    @Override
    public void registerPlayer(User player, Long id) {
        // check if got tournament
        Optional<Tournament> tournament = tournaments.findById(id);

        if (tournament.isPresent()) {
            // get tournament data & participant list from tournament
            Tournament tournamentData = tournament.get();
            List<Player> playerList = tournamentData.getPlayers();

            // if tournament is full, we add to waitingList instead
            if (playerList.size() == tournamentData.getSize()) {
                List<Player> waitingList = tournamentData.getWaitingList();
                waitingList.add((Player) player);
                tournamentData.setWaitingList(waitingList);
                // else, we want to add to normal playerList
            } else {
                playerList.add((Player) player);
                tournamentData.setPlayers(playerList);
            }

            // we save the tournament data back to database
            tournaments.save(tournamentData);
        }
    }

    @Override
    public void withdrawPlayer(User player, Long id) {
        Optional<Tournament> tournament = tournaments.findById(id);
        if (tournament.isPresent()) {
            Tournament tournamentData = tournament.get();
            List<Player> playerList = tournamentData.getPlayers();
            List<Player> waitingList = tournamentData.getWaitingList();

            // Remove from participants
            if (playerList.remove(player)) {
                // If removed from participants, check waiting list
                if (!waitingList.isEmpty()) {
                    playerList.add(waitingList.remove(0)); // Move next from waiting list to participants
                }
                tournamentData.setPlayers(playerList);
                tournamentData.setWaitingList(waitingList);
                tournaments.save(tournamentData);
            }
        }
    }

    @Override
    public boolean tournamentExists(Long tournamentId) {
        return tournamentId != null && tournaments.existsById(tournamentId);
    }

    /**
     * Checks if 2 players have played each other in the tournament before.
     * Player order does not matter.
     * If no winner, returns "draw".
     * If never faced each other, returns "no direct encounter".
     * 
     * @param tournament - Tournament to check
     * @param player1    - First player
     * @param player2    - Second player
     * @return Username of winner
     */
    public String directEncounterResultInTournament(Tournament tournament, Player player1, Player player2) {
        List<Match> directEncounters = matches.findByBlackAndWhiteOrWhiteAndBlack(player1, player2, player2, player1)
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

    // Calculate Buchholz score for a player in a specific tournament (sum of
    // opponents' match points)
    public int calculateBuchholzInTournament(Player player, Tournament tournament) {
        List<Match> matchList = matches.findByBlackOrWhite(player).stream()
                .filter(match -> match.getTournament().equals(tournament))
                .collect(Collectors.toList());

        int buchholzScore = 0;
        for (Match match : matchList) {
            Player opponent = match.getWhite().equals(player) ? match.getBlack() : match.getWhite();
            buchholzScore += opponent.getGamePoints();
        }
        return buchholzScore;
    }

    // Calculate Buchholz Cut 1 (exclude lowest opponent score) in a specific
    // tournament
    public int calculateBuchholzCut1InTournament(Player player, Tournament tournament) {
        List<Match> matchList = matches.findByBlackOrWhite(player).stream()
                .filter(match -> match.getTournament().equals(tournament))
                .collect(Collectors.toList());

        List<Integer> opponentScores = new ArrayList<>();
        for (Match match : matchList) {
            Player opponent = match.getWhite().equals(player) ? match.getBlack() : match.getWhite();
            opponentScores.add(opponent.getGamePoints());
        }

        if (!opponentScores.isEmpty()) {
            opponentScores.remove(Collections.min(opponentScores));
        }

        return opponentScores.stream().mapToInt(Integer::intValue).sum();
    }

    public Round createPairings(Tournament tournament) {
        List<Match> pairings = new ArrayList<>();
        List<Player> players = tournament.getPlayers();
        Set<Player> pairedPlayers = new HashSet<>();

        // New round
        Round nextRound = new Round();
        nextRound.setTournament(tournament);

        players.sort(Comparator.comparingInt(Player::getGamePoints).thenComparing(Player::getELO).reversed());

        for (int i = 0; i < players.size(); i++) {
            Player player1 = players.get(i);

            if (pairedPlayers.contains(player1))
                continue;

            // Give priority to player1 (higher ranked) to get opposite colour to prev game
            // assume player1 is white
            boolean isPlayer1White = isNextColourWhite(player1, tournament);

            for (int j = i + 1; j < players.size(); j++) {
                Player player2 = players.get(j);

                if (pairedPlayers.contains(player2))
                    continue;

                // check if players have not played each other in tournament
                if (hasPlayedBefore(player1, player2, tournament))
                    continue;

                // check if player2 can be assigned colour
                if (!isColourSuitable(player2, tournament, isPlayer1White ? "black" : "white"))
                    continue;

                Match newPair = createMatchWithPlayerColour(player1, isPlayer1White ? "white" : "black", player2, nextRound);
                pairings.add(newPair);
            }
        }
        // after all players are paired, assign the list to round and return it
        nextRound.setMatches(pairings);
        return nextRound;
    }

    /**
     * Checks previous match to determine next match colour (for colour priority)
     * 
     * @param player - priority player
     * @param tournament - Tournament matches to consider
     * @return - true if next colour is white
     */
    private boolean isNextColourWhite(Player player, Tournament tournament) {
        List<Match> matchList = matches.findByBlackOrWhite(player).stream()
                .filter(match -> match.getTournament().equals(tournament))
                .collect(Collectors.toList());

        // Sort in order of increasing round id, since latest round will be largest
        matchList.sort(Comparator.comparing(Match::getId));

        // No games played in tournament yet, default is white
        if (matchList.size() == 0) {
            return true;
        }

        Match previousMatch = matchList.get(matchList.size() - 1);

        // if previous match player is not white, next colour is white, vice versa
        return previousMatch.getWhite().equals(player) ? false : true;
    }

    /**
     * Similar to directEncounterResult. Order of players do not matter
     * 
     * @param player1
     * @param player2
     * @param tournament - Tournament matches to consider
     * @return true if List<match> of matches played size() != 0
     */
    private boolean hasPlayedBefore(Player player1, Player player2, Tournament tournament) {
        return matches.findByBlackAndWhiteOrWhiteAndBlack(player1, player2, player2, player1).stream()
                .filter(match -> match.getTournament().equals(tournament))
                .collect(Collectors.toList())
                .size() == 0;
    }

    /**
     * Checks if player is able to play the nextColour
     * If player hill play same colour three time (including nextColour), returns false
     * If less than 2 games played, returns true
     * 
     * @param player
     * @param tournament - Tournament matches to consider
     * @param nextColour - either "white" or "black" only
     * @return - true if not same colour for 3 times consecutively
     */
    private boolean isColourSuitable(Player player, Tournament tournament, String nextColour) {
        List<Match> matchList = matches.findByBlackOrWhite(player).stream()
                .filter(match -> match.getTournament().equals(tournament))
                .collect(Collectors.toList());

        // Sort in order of increasing round id, since most recent 2 rounds will be largest
        matchList.sort(Comparator.comparing(Match::getId));

        // If less than 2 games played, can accept any colour
        if (matchList.size() < 2) {
            return true;
        }

        Match mostRecentMatch = matchList.get(matchList.size() - 1);
        Match secondRecentMatch = matchList.get(matchList.size() - 2);

        String mostRecentColour = mostRecentMatch.getWhite().equals(player) ? "white" : "black";
        String secondRecentColour = secondRecentMatch.getWhite().equals(player) ? "white" : "black";

        // If recent colours same as nextColour, player will play the same colour thrice
        boolean sameColourThrice = mostRecentColour.equals(secondRecentColour) && mostRecentColour.equals(nextColour);

        // if playing same colour thrice, it is not suitable
        return !sameColourThrice;
    }

    /**
     * Creates a match object and saves to matchRepo.
     * Assigns players to their respective colours and returns match object.
     * 
     * @param player1
     * @param player1Colour - either "white" or "black" only
     * @param player2
     * @param round
     * @return
     */
    private Match createMatchWithPlayerColour(Player player1, String player1Colour, Player player2, Round round) {
        Match match = new Match();
        match.setRound(round);

        if (player1Colour.equals("white")) {
            match.setWhite(player1);
            match.setBlack(player2);
        } else {
            match.setBlack(player1);
            match.setWhite(player2);
        }

        matches.save(match);
        return match;
    }
}
