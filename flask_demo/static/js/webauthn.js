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

function registerNewCredential(newCredential) {
    let attObj = new Uint8Array(
        newCredential.response.attestationObject);
    let clientDataJSON = new Uint8Array(
        newCredential.response.clientDataJSON);
    let rawId = new Uint8Array(
        newCredential.rawId);
    let registrationClientExtensions = newCredential.getClientExtensionResults();
    $.post('/verify_credential_info', {
        id: newCredential.id,
        rawId: b64enc(rawId),
        type: newCredential.type,
        attObj: b64enc(attObj),
        clientData: b64enc(clientDataJSON),
        registrationClientExtensions: JSON.stringify(registrationClientExtensions)
    }).done(function(response){
        window.location = '/';
        console.log(response);
    });
}

function verifyAssertion(assertedCredential) {
    let authData = new Uint8Array(assertedCredential.response.authenticatorData);
    let clientDataJSON = new Uint8Array(assertedCredential.response.clientDataJSON);
    let rawId = new Uint8Array(assertedCredential.rawId);
    let sig = new Uint8Array(assertedCredential.response.signature);
    let assertionClientExtensions = assertedCredential.getClientExtensionResults();
    $.post('/verify_assertion', {
        id: assertedCredential.id,
        rawId: b64enc(rawId),
        type: assertedCredential.type,
        authData: b64RawEnc(authData),
        clientData: b64RawEnc(clientDataJSON),
        signature: hexEncode(sig),
        assertionClientExtensions: JSON.stringify(assertionClientExtensions)
    }).done(function(response){
        window.location = '/';
        console.log(response);
    });
}

const getCredentialCreateOptionsFromServer = async (formData) => {
    const response = await fetch(
        "/webauthn_begin_activate",
        {
            method: "POST",
            body: formData
        }
    );

    const body = await response.json();
    return body;
}

const transformCredentialCreateOptions = (credentialCreateOptionsFromServer) => {
    let {challenge, user} = credentialCreateOptionsFromServer;
    user.id = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.user.id), c => c.charCodeAt(0));

    challenge = Uint8Array.from(
        atob(credentialCreateOptionsFromServer.challenge), c => c.charCodeAt(0));
    
    const transformedCredentialCreateOptions = Object.assign(
            {}, credentialCreateOptionsFromServer,
            {challenge, user});

    return transformedCredentialCreateOptions;
}

const transformNewCredentialForServer = (newCredential) => {
    const attObj = new Uint8Array(
        newCredential.response.attestationObject);
    const clientDataJSON = new Uint8Array(
        newCredential.response.clientDataJSON);
    const rawId = new Uint8Array(
        newCredential.rawId);
    
        const registrationClientExtensions = newCredential.getClientExtensionResults();

    return {
        id: newCredential.id,
        rawId: b64enc(rawId),
        type: newCredential.type,
        attObj: b64enc(attObj),
        clientData: b64enc(clientDataJSON),
        registrationClientExtensions: JSON.stringify(registrationClientExtensions)
    }
}

const postNewCredentialToServer = async (credentialDataForServer) => {
    const formData = new FormData();
    Object.entries(credentialDataForServer).forEach(([key, value]) => {
        formData.set(key, value);
    })
    
    const response = await fetch(
        "/verify_credential_info", {
        method: "POST",
        body: formData
    });

    const body = await response.text()
    return body;
}

const didClickRegister = async (e) => {
    e.preventDefault();

    // gather the data in the form
    const form = document.querySelector('form');
    const formData = new FormData(form);

    // post the data to the server to generate the PublicKeyCredentialCreateOptions
    const credentialCreateOptionsFromServer = await getCredentialCreateOptionsFromServer(formData);

    // convert certain members of the PublicKeyCredentialCreateOptions into
    // byte arrays as expected by the spec.
    const publicKeyCredentialCreateOptions = transformCredentialCreateOptions(credentialCreateOptionsFromServer);
    
    // request the authenticator(s) to create a new credential keypair.
    let credential;
    try {
        credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreateOptions
        });
    } catch (err) {
        console.log("Error creating credential.")
        console.log(err);
    }

    // we now have a new credential! We now need to encode the byte arrays
    // in the credential into strings, for posting to our server.
    const credentialDataForServer = transformNewCredentialForServer(credential);

    const serverValidationResult = await postNewCredentialToServer(credentialDataForServer);
    debugger;
}

document.addEventListener("DOMContentLoaded", e => {
    document.querySelector('#register').addEventListener('click', didClickRegister);
})

$(document).ready(function() {
    // // if (!PublicKeyCredential) { console.log("Browser not WebAuthn compatible."); }

    // $("#register").click(function(e) {
    //     e.preventDefault();
    //     var username = $('input[name="register_username"]').val();
    //     var displayName = $('input[name="register_display_name"]').val();
    //     $.post("/webauthn_begin_activate", {
    //         username: username,
    //         displayName: displayName
    //     }).done(function(makeCredentialOptions) {
    //         // Turn the challenge back into the accepted format
    //         makeCredentialOptions.challenge = Uint8Array.from(
    //             atob(makeCredentialOptions.challenge), c => c.charCodeAt(0));
    //         // Turn the user ID back into the accepted format
    //         makeCredentialOptions.user.id = Uint8Array.from(
    //             atob(makeCredentialOptions.user.id), c => c.charCodeAt(0));
    //         navigator.credentials.create({ publicKey: makeCredentialOptions })
    //             .then(function(newCredentialInfo) {
    //                 console.log(newCredentialInfo);
    //                 // Send new credential info to server for
    //                 // verification and registration.
    //                 registerNewCredential(newCredentialInfo);
    //             }).catch(function(err) {
    //                 // No acceptable authenticator or user refused
    //                 // consent. Handle appropriately.
    //                 console.log("Error creating credential.");
    //                 console.log(err);
    //             });
    //     });
    // });

    $("#login").click(function(e) {
        e.preventDefault();
        var username = $('input[name="login_username"]').val();
        $.post("/webauthn_begin_assertion", {
            username: username
        }).done(function(assertionOptions) {
            console.log(assertionOptions);
            // Turn the challenge back into the accepted format
            assertionOptions.challenge = Uint8Array.from(
                atob(assertionOptions.challenge), c => c.charCodeAt(0));
            assertionOptions.allowCredentials.forEach(function(listItem) {
                var fixedId = listItem.id.replace(
                    /\_/g, "/").replace(/\-/g, "+");
                listItem.id = Uint8Array.from(
                    atob(fixedId), c => c.charCodeAt(0));
            });
            navigator.credentials.get({ publicKey: assertionOptions })
                .then(function(assertionInfo) {
                    console.log(assertionInfo);
                    // Send assertion to server for verification.
                    verifyAssertion(assertionInfo);
                }).catch(function(err) {
                    // No acceptable authenticator or user refused
                    // consent. Handle appropriately.
                    console.log("Error during assertion.");
                    console.log(err);
                });
        });
    });
});
