const axios = require('axios');
const prompts = require('prompts');
require('dotenv').config()

let tryAuthentication = () => {
    var data = JSON.stringify({
        "grant_type": "http://auth0.com/oauth/grant-type/password-realm",
        "client_id": `${process.env.CLIENT_ID}`,
        "audience": `https://${process.env.AUTH0_DOMAIN}/mfa/`,
        "username": `${process.env.USER_EMAIL}`,
        "password": `${process.env.USER_PWD}`,
        "realm": `${process.env.REALM}`,
        "scope": "enroll read:authenticators remove:authenticators"
    });

    var config = {
        method: 'post',
        url: `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
        headers: {
            'Content-Type': 'application/json',
        },
        data: data
    };

    return axios(config)
        .then(response => response.data.access_token)
        .catch(error => (error.response.data.error === 'mfa_required') ?
            error.response.data.mfa_token : "");
}

let startFactorEnrollment = (mfaToken) => {
    var data = JSON.stringify({
        "client_id": `${process.env.CLIENT_ID}`,
        "authenticator_types": ["oob"],
        "oob_channels": ["sms"],
        "phone_number": `${process.env.USER_MOBILE}`
    });

    var config = {
        method: 'post',
        url: `https://${process.env.AUTH0_DOMAIN}/mfa/associate`,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${mfaToken}`,
        },
        data: data
    };

    return axios(config)
        .then(response => response.data.oob_code)
        .catch(error => (error.response.data.error === 'access_denied') ?
                'already_enrolled' : "");
}

let promptForBindingCode = async () => {
    return prompts({
        type: 'text',
        name: 'bindingCode',
        message: 'Please enter your SMS OTP'
    }).then(response => response.bindingCode);
}

let respondToMfaChallenge = (mfaToken, oobCode, bindingCode) => {
    var data = {
        "grant_type": "http://auth0.com/oauth/grant-type/mfa-oob",
        "client_id": `${process.env.CLIENT_ID}`,
        "mfa_token": `${mfaToken}`,
        "oob_code": `${oobCode}`,
        "binding_code": `${bindingCode}`
    };

    var config = {
        method: 'post',
        url: `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
        headers: {
            'Content-Type': 'application/json',
        },
        data: data
    };

    return axios(config)
        .then(response => response.data)
        .catch(error => console.log(error));
}

let startMfaChallenge = (mfaToken) => {
    var data = {
        "client_id": `${process.env.CLIENT_ID}`,
        "mfa_token": `${mfaToken}`,
        "challenge_type": "oob"
    };

    var config = {
        method: 'post',
        url: `https://${process.env.AUTH0_DOMAIN}/mfa/challenge`,
        headers: {
            'Content-Type': 'application/json',
        },
        data: data
    };

    return axios(config)
        .then(response => response.data.oob_code)
        .catch(error => console.log(error));
}

let main = async () => {
    try {
        let mfaRequiredMfaToken = await tryAuthentication();
        let oobCode = await startFactorEnrollment(mfaRequiredMfaToken);
        if (oobCode === 'already_enrolled')
            oobCode = await startMfaChallenge(mfaRequiredMfaToken);
        let bindingCode = await promptForBindingCode();
        let response = await respondToMfaChallenge(mfaRequiredMfaToken, oobCode, bindingCode);
        console.info(response);
    } catch (error) {
        console.error(error);
    }
}

main();