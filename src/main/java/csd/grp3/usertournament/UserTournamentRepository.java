package csd.grp3.usertournament;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import csd.grp3.user.User;

@Repository
public interface UserTournamentRepository extends JpaRepository<UserTournament, UserTournamentId>{
    List<User> findUsersByTournamentId(Long tournamentId);

    Optional<UserTournament> findById_TournamentIdAndId_Username(Long tournamentId, String username);
    
    @Query("SELECT ut.user FROM UserTournament ut WHERE ut.id.tournamentId = :tournamentId AND ut.status = 'r'")
    List<User> findRegisteredUsersByTournamentId(@Param("tournamentId") Long tournamentId);
    
    @Query("SELECT ut.user FROM UserTournament ut WHERE ut.id.tournamentId = :tournamentId AND ut.status = 'w'")
    List<User> findWaitlistUsersByTournamentId(@Param("tournamentId") Long tournamentId);
    
    void deleteById_TournamentIdAndId_Username(Long tournamentId, String username);
}
