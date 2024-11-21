package csd.grp3.match;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import csd.grp3.round.Round;
import csd.grp3.user.User;
import jakarta.transaction.Transactional;

@Service
public class MatchServiceImpl implements MatchService{

    @Autowired
    private MatchRepository matches;

    /**
     * Creates a match object for the Round
     * 
     * @param white User object
     * @param black User object
     * @param round Round object
     * @return Match object
    */
    @Override
    public Match createMatch(User white, User black, Round round) {
        return matches.save(new Match(white, black, round));
    }

    /**
     * Get a match object via its id
     * 
     * @param id Match id
     * @return Match object
     */
    @Override
    public Match getMatch(Long id) throws MatchNotFoundException{
        return matches.findById(id)
            .orElseThrow(() -> new MatchNotFoundException());
    }

    /**
     *  Saves a match object to database
     * 
     * @param match Match object to be added
     * @return Match object added
     */
    @Override
    @Transactional
    public Match addMatch(Match match) {
        return matches.save(match);
    }

    /**
     * Update match object referenced by id
     * 
     * @param matchID target match to update
     * @param newMatch updated match details
     * @return Updated Match object
     */
    @Override 
    public Match updateMatch(Long matchID, Match newMatch) {
        Match match = getMatch(matchID);
        match.setResult(newMatch.getResult());
        match.setBYE(newMatch.isBYE());
        return matches.save(match);
    }

    /**
     * Deletes a match by id from repository 
     * 
     * @param matchID Long 
     */
    @Override 
    public void deleteMatch(Long matchID) {
        matches.deleteById(matchID);
    }

    /**
     * Get all matches in round
     * 
     * @param round Round object
     */
    @Override
    public List<Match> getRoundMatches(Round round) {
        return matches.findByRound(round);
    }

    /**
     * Get all matches played by user.
     * Across all tournaments and rounds
     * 
     * @param user User object
     * @return List of Match objects
     */
    @Override
    public List<Match> getUserMatches(User user) {
        return matches.findByBlackOrWhite(user, user);
    }

    /**
     * Get all matches played between 2 users.
     * Across all tournaments and rounds
     * 
     * @param user1 User1 object
     * @param user2 User2 object
     * @return List of Match objects
     */
    @Override
    public List<Match> getMatchesBetweenTwoUsers(User user1, User user2) {
        return matches.findByBlackAndWhiteOrWhiteAndBlack(user1,user2,user2,user1);
    }
}