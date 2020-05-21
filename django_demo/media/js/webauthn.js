function b64enc(buf) {
    return base64js.fromByteArray(buf)
                   .replace(/\+/g, "-")
                   .replace(/\//g, "_")
                   .replace(/=/g, "");
}

function b64RawEnc(buf) {
    return base64js.fromByteArray(buf)
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function hexEncode(buf) {
    return Array.from(buf)
                .map(function(x) {
                    return ("0" + x.toString(16)).substr(-2);
				})
                .join("");
}

async function fetch_json(url, options) {
    options.credentials = 'include';
    const response = await fetch(url, options);
    const body = await response.json();
    if (body.fail)
        throw body.fail;
    if (response.status != 200) {
        throw body;
    }
    return body;
}

function insecure_connection() {
    if ( ! ('credentials' in navigator) ) {
        status_msg_set("Error: (hint: HTTPS connection is required)", 'visible', 'red');
        return true;
    } else {
        return false;
    }
}

function status_msg_set(msg, visible, color) {
    $('div#login-message').text(msg)
                .css('visibility',visible).attr({ 'class':color});
}

function error_handler(err_descr, err) {
    if ( typeof(err) == "string" )  // HTML code != 200, text explanation
        return status_msg_set(err, 'visible', 'red');
    else
        status_msg_set(err_descr, 'visible', 'red');
        console.error(err_descr);
        return console.error(err);
}

/**
 * REGISTRATION FUNCTIONS
 */

/**
 * Callback after the registration form is submitted.
 * @param {Event} e 
 */
const didClickRegister = async (e) => {
    e.preventDefault();

    status_msg_set('', 'hidden', 'green');
    // gather the data in the form
    const form = document.querySelector('#register-form');
    const formData = new FormData(form);

    // post the data to the server to generate the PublicKeyCredentialCreateOptions
    let credentialCreateOptionsFromServer;
    try {
        credentialCreateOptionsFromServer = await getCredentialCreateOptionsFromServer(formData);
    } catch (err) {
        return error_handler('Failed to generate credential request options:', err);
    } 
    console.table(credentialCreateOptionsFromServer);  // debug code
    // convert certain members of the PublicKeyCredentialCreateOptions into
    // byte arrays as expected by the spec.
    const publicKeyCredentialCreateOptions = transformCredentialCreateOptions(credentialCreateOptionsFromServer);
    
    // request the authenticator(s) to create a new credential keypair.
    let credential;
    if ( insecure_connection() ) 
        return;
    try {
        credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreateOptions
        });
    } catch (err) {
        return console.error("Error creating credential:", err);
    }

    // we now have a new credential! We now need to encode the byte arrays
    // in the credential into strings, for posting to our server.
    const newAssertionForServer = transformNewAssertionForServer(credential);

    // post the transformed credential data to the server for validation
    // and storing the public key
    let assertionValidationResponse;
    try {
        assertionValidationResponse = await postNewAssertionToServer(newAssertionForServer);
    } catch (err) {
        return error_handler('Server validation of credential failed:', err);
    } 
    status_msg_set(assertionValidationResponse, 'visible', 'green');
    setTimeout(function () {  
          window.location.href = '/account/login';   
    }, 1000 )  
}

/**
 * Get PublicKeyCredentialRequestOptions for this user from the server
 * formData of the registration form
 * @param {FormData} formData 
 */
const getCredentialRequestOptionsFromServer = async (formData) => {
    return await fetch_json(
        "/webauthn_begin_assertion",
        {
            method: "POST",
            body: formData
        }
    );
}

const transformCredentialRequestOptions = (credentialRequestOptionsFromServer) => {
    let {challenge, allowCredentials} = credentialRequestOptionsFromServer;

    challenge = Uint8Array.from(
        atob(challenge.replace(/\_/g, "/").replace(/\-/g, "+")), c => c.charCodeAt(0));

    allowCredentials = allowCredentials.map(credentialDescriptor => {
        let {id} = credentialDescriptor;
        id = id.replace(/\_/g, "/").replace(/\-/g, "+");
        id = Uint8Array.from(atob(id), c => c.charCodeAt(0));
        return Object.assign({}, credentialDescriptor, {id});
    });

    const transformedCredentialRequestOptions = Object.assign(
        {},
        credentialRequestOptionsFromServer,
        {challenge, allowCredentials});

    return transformedCredentialRequestOptions;
};


/**
 * Get PublicKeyCredentialRequestOptions for this user from the server
 * formData of the registration form
 * @param {FormData} formData 
 */
const getCredentialCreateOptionsFromServer = async (formData) => {
    return await fetch_json(
        "/webauthn_begin_activate",
        {
            method: "POST",
            body: formData
        }
    );
}

/**
 * Transforms items in the credentialCreateOptions generated on the server
 * into byte arrays expected by the navigator.credentials.create() call
 * @param {Object} credentialCreateOptionsFromServer 
 */
const transformCredentialCreateOptions = (credentialCreateOptionsFromServer) => {
    let {challenge, user} = credentialCreateOptionsFromServer;
    user.id = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.user.id
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
            ), 
        c => c.charCodeAt(0));

    challenge = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.challenge
            .replace(/\_/g, "/")
            .replace(/\-/g, "+")
            ),
        c => c.charCodeAt(0));
    
    const transformedCredentialCreateOptions = Object.assign(
            {}, credentialCreateOptionsFromServer,
            {challenge, user});

    return transformedCredentialCreateOptions;
}



/**
 * AUTHENTICATION FUNCTIONS
 */


/**
 * Callback executed after submitting login form
 * @param {Event} e 
 */
const didClickLogin = async (e) => {
    e.preventDefault();
    // gather the data in the form
    const form = document.querySelector('#login-form');
    const formData = new FormData(form);

    // post the login data to the server to retrieve the PublicKeyCredentialRequestOptions
    let credentialCreateOptionsFromServer;
    try {
        credentialRequestOptionsFromServer = await getCredentialRequestOptionsFromServer(formData);
    } catch (err) {
        return error_handler('Error when getting request options from server:', err);
    }

    // convert certain members of the PublicKeyCredentialRequestOptions into
    // byte arrays as expected by the spec.    
    const transformedCredentialRequestOptions = transformCredentialRequestOptions(
        credentialRequestOptionsFromServer);

    // request the authenticator to create an assertion signature using the
    // credential private key
    let assertion;
    if ( insecure_connection() ) 
        return;
    try {
        assertion = await navigator.credentials.get({
            publicKey: transformedCredentialRequestOptions,
        });
    } catch (err) {
        return error_handler('Error when creating credential', err);
    }

    // we now have an authentication assertion! encode the byte arrays contained
    // in the assertion data as strings for posting to the server
    const transformedAssertionForServer = transformAssertionForServer(assertion);

    // post the assertion to the server for verification.
    let response;
    try {
        response = await postAssertionToServer(transformedAssertionForServer);
    } catch (err) {
        return error_handler('Error when validating assertion on server:', err);
    }

    status_msg_set(response, 'visible', 'green');
    setTimeout(function () {  
          window.location.href = '/private.html';   
    }, 1000 )  
};

/**
 * Transforms the binary data in the credential into base64 strings
 * for posting to the server.
 * @param {PublicKeyCredential} newAssertion 
 */
const transformNewAssertionForServer = (newAssertion) => {
    const attObj = new Uint8Array(
        newAssertion.response.attestationObject);
    const clientDataJSON = new Uint8Array(
        newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(
        newAssertion.rawId);
    
    const registrationClientExtensions = newAssertion.getClientExtensionResults();

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        attObj: b64enc(attObj),
        clientData: b64enc(clientDataJSON),
        registrationClientExtensions: JSON.stringify(registrationClientExtensions)
    };
}

/**
 * Posts the new credential data to the server for validation and storage.
 * @param {Object} credentialDataForServer 
 */
const postNewAssertionToServer = async (credentialDataForServer) => {
    const formData = new FormData();
    credentialDataForServer.csrfmiddlewaretoken = $.cookie("csrftoken");
    Object.entries(credentialDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });
    
    return await fetch_json(
        "/verify_credential_info", {
        method: "POST",
        body: formData,
    });
}

/**
 * Encodes the binary data in the assertion into strings for posting to the server.
 * @param {PublicKeyCredential} newAssertion 
 */
const transformAssertionForServer = (newAssertion) => {
    const authData = new Uint8Array(newAssertion.response.authenticatorData);
    const clientDataJSON = new Uint8Array(newAssertion.response.clientDataJSON);
    const rawId = new Uint8Array(newAssertion.rawId);
    const sig = new Uint8Array(newAssertion.response.signature);
    const assertionClientExtensions = newAssertion.getClientExtensionResults();

    return {
        id: newAssertion.id,
        rawId: b64enc(rawId),
        type: newAssertion.type,
        authData: b64RawEnc(authData),
        clientData: b64RawEnc(clientDataJSON),
        signature: hexEncode(sig),
        assertionClientExtensions: JSON.stringify(assertionClientExtensions)
    };
};

/**
 * Post the assertion to the server for validation and logging the user in. 
 * @param {Object} assertionDataForServer 
 */
const postAssertionToServer = async (assertionDataForServer) => {
    const formData = new FormData();
    assertionDataForServer.csrfmiddlewaretoken = $.cookie("csrftoken");
    Object.entries(assertionDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    });
    
    return await fetch_json(
        "/verify_assertion", {
        method: "POST",
        body: formData
    });
}


 document.addEventListener("DOMContentLoaded", e => { 
     var bootstrapButton = $.fn.button.noConflict()
     $.fn.bootstrapBtn = bootstrapButton;
     if ( document.getElementById("register") !== null ) {
        document.querySelector('#register').addEventListener('click', didClickRegister); 
     }
     if ( document.getElementById("login") !== null ) {
        document.querySelector('#login').addEventListener('click', didClickLogin); 
     }
    $('input#id_auth-username, input#id_auth-dispname').on('keypress', function (e) { 
        if (e.which == 13) {
            $('form button[type=submit]').trigger('click')
            return false;
        }
    });
 }); 
