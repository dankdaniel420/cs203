package csd.grp3.usertournament;

import java.io.Serializable;

import java.util.Objects;

import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Embeddable
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserTournamentId implements Serializable {
    private Long tournamentId;
    private String username;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof UserTournamentId)) return false;
        UserTournamentId that = (UserTournamentId) o;
        return tournamentId.equals(that.tournamentId) && username.equals(that.username);
    }

    @Override
    public int hashCode() {
        return Objects.hash(tournamentId, username);
    }
}