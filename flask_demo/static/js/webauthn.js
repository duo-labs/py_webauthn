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
    $.post('/verify_credential_info', {
        id: newCredential.id,
        rawId: b64enc(rawId),
        type: newCredential.type,
        attObj: b64enc(attObj),
        clientData: b64enc(clientDataJSON),
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
    $.post('/verify_assertion', {
        id: assertedCredential.id,
        rawId: b64enc(rawId),
        type: assertedCredential.type,
        authData: b64RawEnc(authData),
        clientData: b64RawEnc(clientDataJSON),
        signature: hexEncode(sig),
    }).done(function(response){
        window.location = '/';
        console.log(response);
    });
}

$(document).ready(function() {
    // if (!PublicKeyCredential) { console.log("Browser not WebAuthn compatible."); }

    $("#register").click(function(e) {
        e.preventDefault();
        var username = $('input[name="register_username"]').val();
        var displayName = $('input[name="register_display_name"]').val();
        $.post("/webauthn_begin_activate", {
            username: username,
            displayName: displayName
        }).done(function(makeCredentialOptions) {
            // Turn the challenge back into the accepted format
            makeCredentialOptions.challenge = Uint8Array.from(
                atob(makeCredentialOptions.challenge), c => c.charCodeAt(0));
            // Turn the user ID back into the accepted format
            makeCredentialOptions.user.id = Uint8Array.from(
                atob(makeCredentialOptions.user.id), c => c.charCodeAt(0));
            navigator.credentials.create({ publicKey: makeCredentialOptions })
                .then(function(newCredentialInfo) {
                    console.log(newCredentialInfo);
                    // Send new credential info to server for
                    // verification and registration.
                    registerNewCredential(newCredentialInfo);
                }).catch(function(err) {
                    // No acceptable authenticator or user refused
                    // consent. Handle appropriately.
                    console.log("Error creating credential.");
                    console.log(err);
                });
        });
    });

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
