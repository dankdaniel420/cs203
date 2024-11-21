import { apiRequest } from './ApiUtils';
import { successCallback, fetchCallback } from './SuccessCallback';
import { fetchStandings } from './TournamentUtils';

export const handleSignup = async (userData, setErrorMessage, navigate) => {
    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/signup`,
        method: 'POST',
        body: userData,
        callback: successCallback(`${userData.username} has successfully created an account.`, () => navigate('/login')),
        setErrorMessage,
    });
};

export const handleLogin = async (userData, setErrorMessage, navigate) => {
    const onSuccess = (responseData) => {
        localStorage.setItem('jwtToken', responseData.token);
        console.log(responseData.token);
        navigate("/tournaments");
    };

    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/login`,
        method: 'POST',
        body: userData,
        callback: onSuccess,
        setErrorMessage,
    });
};

export const fetchUserData = async (setErrorMessage, setUser) => {
    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/user`,
        method: 'GET',
        callback: fetchCallback(setUser),
        setErrorMessage,
    });
};

export const handlePassword = async (userData, setErrorMessage, setNewPassword) => {
    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/user`,
        method: 'PUT',
        body: userData,
        callback: successCallback('Password changed successfully.', null),
        setErrorMessage,
    }).then(() => {
        setNewPassword(''); // Clear password input after successful password change
    });
};

export const handleUnflagUser = async (userData, tournamentId, setErrorMessage, setStandings) => {
    await apiRequest({
        url: `${process.env.REACT_APP_API_URL}/user/flag`,
        method: 'PUT',
        body: userData,
        callback: successCallback(`${userData.username} has been unflagged.`, () => fetchStandings(tournamentId, setErrorMessage, setStandings)),
        setErrorMessage,
    });
};
