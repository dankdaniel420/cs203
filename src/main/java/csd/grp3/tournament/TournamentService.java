package csd.grp3.tournament;

import java.util.List;

import org.springframework.stereotype.Service;

import csd.grp3.round.Round;
import csd.grp3.user.User;

@Service
public interface TournamentService {
    List<Tournament> listTournaments();
    Tournament getTournament(Long id);
    Tournament addTournament(Tournament tournament);
    Tournament updateTournament(Long id, Tournament tournament);
    void deleteTournament(Long id);
    void registerUser(User user, Long id);
    void withdrawUser(User user, Long id);
    void addRound(Long id);
    void updateMatchResults(Round round);
    void updateTournamentResults(Round round);
    void endTournament(Long id);
    List<Tournament> getTournamentAboveMin(int ELO);
    List<Tournament> getTournamentBelowMax(int ELO);
    List<Tournament> getTournamentAboveMinBelowMax(int minELO, int maxELO);
    List<Tournament> getUserEligibleTournament(int ELO);
    double calculateBuchholzInTournament(User user, Tournament tournament);
    void createPairings(Tournament tournament, Round round);
    List<User> getSortedUsers(Long id);
    List<Tournament> getHistoryByUser(String username);
    void flagSusUserPerformance(Long id);
    void deleteForUser(User user);
}
