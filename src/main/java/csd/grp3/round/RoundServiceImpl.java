package csd.grp3.round;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

import csd.grp3.tournament.Tournament;

@Service
public class RoundServiceImpl implements RoundService {

    @Autowired
    private RoundRepository rounds;

    /**
     * Creates a new round object for tournament
     * 
     * @param tournament Tournament object
     * @return Round object added
     */
    @Override
    public Round createRound(Tournament tournament) {
        return rounds.save(new Round(tournament));
    }

    /**
     * Get round object specified by roundID
     * 
     * @param roundID Long
     * @return Round object in repository
     */
    @Override
    public Round getRound(Long roundID) {
        return rounds.findById(roundID)
            .orElseThrow(() -> new RoundNotFoundException());
    }
}