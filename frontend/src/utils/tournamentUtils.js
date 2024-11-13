import { apiRequest } from './ApiUtils';
import { fetchCallback, getHomePage, successCallback } from './SuccessCallback';
import { handleDeleteUser } from './UserUtils';

export const handleAddTournament = async (tournamentData, setErrorMessage, navigate) => {
    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/tournaments`,
        method: 'POST',
        body: tournamentData,
        callback: getHomePage(`You have successfully created ${tournamentData.title}.`, navigate),
        setErrorMessage,
    });
};

export const handleUpdateTournament = async (tournamentData, tournamentId, setErrorMessage, navigate) => {
    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/tournaments/${tournamentId}`,
        method: 'PUT',
        body: tournamentData,
        callback: getHomePage(`You have successfully updated ${tournamentData.title}.`, navigate),
        setErrorMessage,
    });
};

export const handleUpdateMatchResults = async (updatedMatches, setErrorMessage, setEditing, tournamentId, setRounds, setMatches, roundNumber) => {
    const onSuccess = () => {
        fetchRoundsAndMatches(tournamentId, setErrorMessage, setRounds, setMatches, roundNumber);
        setEditing(false); // Exit edit mode
    };

    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/matches`,
        method: 'PUT',
        body: updatedMatches,
        callback: onSuccess,
        setErrorMessage,
    });
};

export const fetchTournamentData = async (tournamentId, setErrorMessage, setTournament) => {
    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/tournaments/${tournamentId}`,
        method: 'GET',
        callback: fetchCallback(setTournament),
        setErrorMessage,
    });
};

export const fetchRoundsAndMatches = async (tournamentId, setErrorMessage, setRounds, setMatches, roundNumber) => {
    const onSuccess = (roundData) => {
        console.log("Round Data:", roundData);
        setRounds(roundData);
        setMatches(roundData?.[roundNumber - 1]?.matches || []); // Set matches or empty array
    };

    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/tournaments/${tournamentId}/rounds`,
        method: 'GET',
        callback: onSuccess,
        setErrorMessage,
    });
};

export const fetchStandings = async (tournamentId, setErrorMessage, setStandings) => {
    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/tournaments/${tournamentId}/standings`,
        method: 'GET',
        callback: fetchCallback(setStandings),
        setErrorMessage,
    });
};

export const fetchEligibleTournaments = async (elo, setErrorMessage, setTournaments) => {
    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/tournaments/byElo/${elo}`,
        method: 'GET',
        callback: fetchCallback(setTournaments),
        setErrorMessage,
    });
};

export const fetchHistory = async (username, setErrorMessage, setHistory) => {
    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/tournaments/byUser/${username}`,
        method: 'GET',
        callback: fetchCallback(setHistory),
        setErrorMessage,
    });
};

export const fetchAllTournaments = async (setErrorMessage, setTournaments) => {
    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/tournaments`,
        method: 'GET',
        callback: fetchCallback(setTournaments),
        setErrorMessage,
    });
};

const registrationCallback = (message, userData, setErrorMessage, setTournaments) => () => {
    alert(message);
    fetchEligibleTournaments(userData.elo, setErrorMessage, setTournaments); // Refresh Page
};

export const handleRegister = async (title, tournamentId, userData, setErrorMessage, setTournaments) => {
    const onSuccess = registrationCallback(`${userData.username} has registered for ${title}.`, userData, setErrorMessage, setTournaments);

    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/tournaments/${tournamentId}/user`,
        method: 'POST',
        body: userData,
        callback: onSuccess,
        setErrorMessage,
    });
};

export const handleWithdraw = async (title, tournamentId, userData, setErrorMessage, setTournaments) => {
    const onSuccess = registrationCallback(`${userData.username} has withdrawn from ${title}.`, userData, setErrorMessage, setTournaments);

    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/tournaments/${tournamentId}/user`,
        method: 'DELETE',
        body: userData,
        callback: onSuccess,
        setErrorMessage,
    });
};

export const handleDeleteForUser = async (userData, tournamentId, setErrorMessage, setStandings) => {
    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/tournaments/user`,
        method: 'DELETE',
        body: userData,
        callback: successCallback(`${userData.username}'s account has been deleted.`, () => fetchStandings(tournamentId, setErrorMessage, setStandings)),
        setErrorMessage,
    });
};


export const handleDeleteTournament = async (title, tournamentId, setErrorMessage, setTournaments) => {
    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/tournaments/${tournamentId}`,
        method: 'DELETE',
        callback: successCallback(`${title} has been deleted.`, () => fetchAllTournaments(setErrorMessage, setTournaments)),
        setErrorMessage,
    });
};
