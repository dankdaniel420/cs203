package csd.grp3.round;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;

import csd.grp3.match.Match;
import csd.grp3.tournament.Tournament;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.EqualsAndHashCode;

@Entity
@Table(name="Rounds")
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode

public class Round {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "tournament_id", nullable = false)
    @JsonBackReference // Prevents infinite recursion
    private Tournament tournament;

    @OneToMany(mappedBy = "round", orphanRemoval = true, cascade = CascadeType.ALL)
    @JsonManagedReference // Prevents infinite recursion
    private List<Match> matches = new ArrayList<>();

    public Round(Tournament tournament) {
        this.tournament = tournament;
    }

    public boolean isOver() {
        boolean isOver = true;
        for (Match m : matches) {
            if (m.getResult() == 0) {
                isOver = false;
                break;
            }
        }
        return !matches.isEmpty() && isOver;
    }
    
}