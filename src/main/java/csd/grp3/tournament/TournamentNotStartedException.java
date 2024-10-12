package csd.grp3.tournament;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.NOT_FOUND)
public class TournamentNotStartedException extends RuntimeException{

    private static final long serialVersionUID = 1L;

    public TournamentNotStartedException(String msg) {
        super(msg);
    }
}
