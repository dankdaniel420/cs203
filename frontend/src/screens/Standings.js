import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import ErrorMessage from '../components/ErrorMessage';
import Navbar from '../components/Navbar';
import SecondaryNavbar from '../components/SecondaryNavbar';
import StandingsTable from '../components/tournament/StandingsTable';
import { fetchUserData, handleDeleteUser, handleUnflagUser } from '../utils/UserUtils';
import { fetchTournamentData, fetchStandings, handleDeleteForUser } from '../utils/TournamentUtils';

const TournamentStandings = () => {
    const { tournamentId } = useParams();
    const [standings, setStandings] = useState([]);
    const [tournament, setTournament] = useState({});
    const [errorMessage, setErrorMessage] = useState('');
    const [user, setUser] = useState({});

    useEffect(() => {
        fetchUserData(setErrorMessage, setUser);
        fetchTournamentData(tournamentId, setErrorMessage, setTournament);
        fetchStandings(tournamentId, setErrorMessage, setStandings);
    }, [tournamentId]);

    const onDeleteUser = (user) => {
        const userData = {
            username: user.username,
            password: user.password,
        }
        handleDeleteForUser(userData, tournament.id, setErrorMessage, setStandings);
        // handleDeleteUser(userData, tournament.id, setErrorMessage, setStandings);
    };

    const onUnflagUser = (user) => {
        const userData = {
            username: user.username,
            password: user.password,
        }
        handleUnflagUser(userData, tournament.id, setErrorMessage, setStandings);
    };

    return (
        <>
            <Navbar userRole={user.userRole} />
            <SecondaryNavbar tournament={tournament} />
            <main>
                <h3>Standings</h3>
                <ErrorMessage message={errorMessage} />
                {user.userRole === 'ROLE_ADMIN' && (
                    <p style={{ color: 'red' }}>WARNING: if you unflag a user, you cannot reflag them.</p>
                )}
                <StandingsTable
                    standings={standings}
                    tournament={tournament}
                    user={user}
                    handleDeleteUser={onDeleteUser}
                    handleUnflagUser={onUnflagUser}
                />
            </main>
        </>
    );
};

export default TournamentStandings;
