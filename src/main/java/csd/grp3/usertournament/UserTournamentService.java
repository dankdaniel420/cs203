package csd.grp3.usertournament;

import java.util.List;

import csd.grp3.tournament.Tournament;
import csd.grp3.user.User;  

public interface UserTournamentService {
    UserTournament findRecord(Long tourneyID, String username);
    List<User> getPlayers(Long tourneyID);
    List<User> getWaitingList(Long tourneyID);
    double getGamePoints(Long tourneyID, String username);
    void updateMatchPoints(Long tourneyID, String username, double matchPoints);
    void updateGamePoints(Long tourneyID, String username);
    UserTournament updatePlayerStatus(Long tourneyID, String username, char status);
    UserTournament add(Tournament tourneyID, User username, char status);
    void delete(Tournament tourney, User user);
}
