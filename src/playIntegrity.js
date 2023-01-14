import * as jose from "jose";
import crypto from "crypto";
import { google } from "googleapis";

// module imports
import {
  count,
  validCertificateSha256Digest,
  playintegrity,
  privatekey,
  packageName,
  encodedVerificationKey,
  encodedDecryptionKey
} from "../index.js";
import { logEvent, isNonceValid, errorAndExit } from "./shared.js";

/**
 *
 * @param {String} token
 * @param {String} mode
 */
export async function decryptPlayIntegrity(token, mode, res) {
  if (mode == "server") {
    return await decryptPlayIntegrityServer(token);
  } else if (mode == "google") {
    return await decryptPlayIntegrityGoogle(token).catch((e) => {
      console.log(e);
      res
        .status(400)
        .send({ error: "A Google API error occured: " + e.message });
      return;
    });
  } else {
    logEvent(
      `WARNING`,
      `Unknown mode (Play Integrity)`,
      `unknown mode '${mode}' requested`
    );
    res.status(400).send({ Error: `Unknown mode ${mode}` });
    return;
  }
}

/**
 * decrypts the play integrity token on googles server with a google service account
 * @param {String} integrityToken
 * @returns
 */
async function decryptPlayIntegrityGoogle(integrityToken) {
  let jwtClient = new google.auth.JWT(
    privatekey.client_email,
    null,
    privatekey.private_key,
    ["https://www.googleapis.com/auth/playintegrity"]
  );

  google.options({ auth: jwtClient });

  const response = await playintegrity.v1.decodeIntegrityToken({
    packageName: packageName,
    requestBody: {
      integrityToken: integrityToken,
    },
  });
  logEvent(
    `INFO`,
    `New Client Request (${count()}) processed`,
    JSON.stringify(response.data.tokenPayloadExternal)
  );

  return response.data.tokenPayloadExternal;
}

/**
 * decrypts the play integrity token locally on the server
 * @param {String} token
 * @returns
 */
async function decryptPlayIntegrityServer(token) {
  const decryptionKey = Buffer.from(encodedDecryptionKey, "base64");
  const { plaintext, protectedHeader } = await jose.compactDecrypt(
    token,
    decryptionKey
  );
  const { payload, Header = protectedHeader } = await jose.compactVerify(
    plaintext,
    crypto.createPublicKey(
      "-----BEGIN PUBLIC KEY-----\n" +
        encodedVerificationKey +
        "\n-----END PUBLIC KEY-----"
    )
  );
  const payloadText = new TextDecoder().decode(payload);
  const payloadJson = JSON.parse(payloadText);
  logEvent(
    `INFO`,
    `(PlayIntegrity) New Client Request (${count()}) processed`,
    payloadJson
  );
  return payloadJson;
}

export async function verifyPlayIntegrity(
  decryptedToken,
  checkNonce,
  nonce_list,
  old_nonce_list,
  res
) {
  /* requestDetails */

  // check if requestDetails exists in decryptedToken
  var requestDetails = decryptedToken?.requestDetails
  if (requestDetails == null) {
    if (errorAndExit(res, `requestDetails not found in recieved token`))
      return false;
  } else {
    var error = false;
    // check if nonce is valid, otherwise send error
    var nonce = Buffer.from(requestDetails?.nonce, "base64")
      .toString()
      .replace(/\+/g, "-") // Convert '+' to '-'
      .replace(/\//g, "_") // Convert '/' to '_'
      .replace(/=+$/, ""); // Remove ending '='
    if (
      checkNonce == "server" &&
      !isNonceValid(nonce, nonce_list, old_nonce_list)
    ) {
      if (errorAndExit(res, `Invalid Nonce`)) return false;
      error = true;
    }

    // check request package name
    if (packageName != requestDetails?.requestPackageName) {
      if (errorAndExit(res, `Invalid package name`)) return false;
      error = true;
    }

    // check request isn't older than 10 seconds
    if (Date.now() - requestDetails?.timestampMs > 10000) {
      if (errorAndExit(res, `Request too old`)) return false;
      error = true;
    }

    // all checks successfull, log this in console
    if (!error) {
      logEvent(
        `INFO`,
        `Attestation`,
        `Attested Device has valid requestDetails`
      );
    }
  }

  /* appIntegrity */
  // check if appIntegrity exists in decryptedToken
  var appIntegrity = decryptedToken?.appIntegrity;
  if (appIntegrity == null) {
    if (errorAndExit(res, `appIntegrity not found in recieved token`))
      return false;
  } else {
    var error = false;
    // check if appRecognitionVerdict is UNEVALUATED
    var appRecognitionVerdict = appIntegrity?.appRecognitionVerdict;
    if (appRecognitionVerdict != "PLAY_RECOGNIZED") {
      if (
        errorAndExit(res, `appRecognitionVerdict is ${appRecognitionVerdict}.`)
      )
        return false;
      error = true;
    }

    // check package name
    if (packageName != appIntegrity?.packageName) {
      if (errorAndExit(res, `Invalid package name`)) return false;
      error = true;
    }

    // check certificateSha256Digest
    if (
      appIntegrity?.certificateSha256Digest == null ||
      appIntegrity.certificateSha256Digest.some((e) =>
        validCertificateSha256Digest.includes(e)
      )
    ) {
      if (errorAndExit(res, `Invalid certificateSha256Digest`)) return false;
      error = true;
    }
    if (!error) {
      // all checks successfull, log this in console
      logEvent(
        `INFO`,
        `Attestation`,
        `Attested Device has valid requestDetails`
      );
    }
  }

  var deviceIntegrity = decryptedToken?.deviceIntegrity;
  if (deviceIntegrity == null) {
    if (errorAndExit(res, `deviceIntegrity not found in recieved token`))
      return false;
  } else {
    // check if deviceRecognitionVerdict is UNEVALUATED
    var deviceRecognitionVerdict = deviceIntegrity?.deviceRecognitionVerdict;
    if (deviceRecognitionVerdict?.includes("MEETS_VIRTUAL_INTEGRITY")){
      if (errorAndExit(res, `Emulator got attested`)) return false;
    } else if (
      deviceRecognitionVerdict?.includes("MEETS_DEVICE_INTEGRITY") ||
      deviceRecognitionVerdict?.includes("MEETS_BASIC_INTEGRITY") ||
      deviceRecognitionVerdict?.includes("MEETS_STRONG_INTEGRITY")
    ) {
      logEvent(
        `INFO`,
        `Attestation`,
        `Attested Device has valid deviceRecognitionVerdict: ${deviceRecognitionVerdict}`
      );
    } else {
      if (
        errorAndExit(
          res,
          `Attested Device doesn't meet requirements. deviceRecognitionVerdict field is empty`
        )
      )
        return false;
    }
  }

  var accountIntegrity = decryptedToken?.accountDetails;
  if (accountIntegrity == null) {
    if (errorAndExit(res, `accountIntegrity not found in recieved token`))
      return false;
  } else {
    var appLicensingVerdict = accountIntegrity?.appLicensingVerdict;
    if (appLicensingVerdict != "LICENSED") {
      if (errorAndExit(res, `appLicensingVerdict is ${appLicensingVerdict}`))
        return false;
    } else {
      logEvent(
        `INFO`,
        `Attestation`,
        `Attested Device uses an licensed version of the Android App`
      );
    }
  }
  return true;
}
