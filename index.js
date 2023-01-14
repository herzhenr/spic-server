// Express server
import express, { json } from "express";
const app = express();
const PORT = 8080;

// local imports
import {
  decryptPlayIntegrity,
  verifyPlayIntegrity,
} from "./src/playIntegrity.js";
import { generateNonce, logEvent } from "./src/shared.js";
import { decryptSafetyNet, verifySafetyNet } from "./src/safetyNet.js";

// get environment variables
import "dotenv/config";
function dieEnv(variable) {
  console.log("Environment variable not set: " + variable);
  process.exit(1);
}
const googleCredentials = process.env.GOOGLE_APPLICATION_CREDENTIALS;
export const packageName = process.env.PACKAGE_NAME;
export const encodedDecryptionKey =
  process.env.BASE64_OF_ENCODED_DECRYPTION_KEY;
export const encodedVerificationKey =
  process.env.BASE64_OF_ENCODED_VERIFICATION_KEY;

if (!packageName) dieEnv("PACKAGE_NAME");
if (!googleCredentials) dieEnv("GOOGLE_APPLICATION_CREDENTIALS");
if (!encodedDecryptionKey) dieEnv("BASE64_OF_ENCODED_DECRYPTION_KEY");
if (!encodedVerificationKey) dieEnv("BASE64_OF_ENCODED_VERIFICATION_KEY");

export const privatekey = JSON.parse(googleCredentials);

import { google } from "googleapis";
export const playintegrity = google.playintegrity("v1");

function dieConf(variable) {
  console.log("Configuration variable not set: " + variable);
  process.exit(1);
}

// import config variables
import config from "./config.json" assert { type: "json" };
var certificates = config.validCertificateSha256Digest;
if (!certificates) {
  console.log("Configuration variable not set: validCertificateSha256Digest");
  process.exit(1);
}
if (
  !Array.isArray(certificates) ||
  !typeof certificates[0] === "string" ||
  !certificates[0] instanceof String
) {
  console.log(
    "Configuration variable validCertificateSha256Digest has to be an array of strings"
  );
  process.exit(1);
}
if (!config.errorLevel) dieConf("errorLevel");
export var validCertificateSha256Digest = certificates;

export const errorLevel = config.errorLevel;

/**
 *  Global variables: counter and nonce list
 */
var counter = 0;
export function count() {
  return counter++;
}
let nonce_list = [];
let old_nonce_list = [];

/**
 * Express JS Server
 */
app.listen(PORT, () =>
  console.log(
    "Play Integrity Server Implementation is alive on http://localhost:" + PORT
  )
);

/**
 * Playintegrity Nonce Generation Endpoint.
 */
app.get("/api/playintegrity/nonce", (req, res) => {
  const nonce = generateNonce(50);
  nonce_list.push(nonce);
  logEvent(`INFO`, `Play Integrity Generated Nonce`, nonce); // nonce.slice(0, 5)+"..."+nonce.slice(-5)
  const nonce_base64 = Buffer.from(nonce)
    .toString("base64")
    .replace(/\+/g, "-") // Convert '+' to '-'
    .replace(/\//g, "_") // Convert '/' to '_'
    .replace(/=+$/, ""); // Remove ending '='
  res.status(200).send(nonce_base64);
  return;
});

/**
 * Play Integrity check Endpoint.
 * 'token' is the token the clinet received from the PlayIntegrity Server in the previous step
 * 'mode' is optional and defaults to 'server'. Can be set to 'google' as well.
 * 'nonce' is optional and defaults to 'server'. Can be set to 'device' when nonce got generated on the device and shouldn't be evaluated on the server.
 */
app.get("/api/playintegrity/check", async (req, res) => {
  const token = req.query.token ?? "none";
  const mode = req.query.mode ?? "google";
  const checkNonce = req.query.nonce ?? "server";

  // check if token is provided
  if (token == "none") {
    res.status(400).send({ Error: "No token was provided" });
    return;
  }

  // get decrypted token
  var decryptedToken = await decryptPlayIntegrity(token, mode, res);

  // send decoded and verified token
  if (
    verifyPlayIntegrity(
      decryptedToken,
      checkNonce,
      nonce_list,
      old_nonce_list,
      res
    )
  )
    res.status(200).send(decryptedToken);
  return;
});

/**
 * Safety Net nonce generation endpoint.
 */
app.get("/api/safetynet/nonce", (req, res) => {
  const nonce = generateNonce(50);
  nonce_list.push(nonce);
  logEvent(`INFO`, `SafetyNet Generated Nonce`, nonce); // nonce.slice(0, 5)+"..."+nonce.slice(-5)
  res.status(200).send(nonce);
  return;
});

/**
 * Safetynet api endpoint. 'token' is the token the client received from playintegrity server.
 * 'nonce' is optional and defaults to 'server'. Can be set to 'device' when nonce got generated on the device and shouldn't be evaluated on the server.
 */
app.get("/api/safetynet/check", async (req, res) => {
  const token = req.query.token ?? "none";
  const checkNonce = req.query.nonce ?? "server";

  // check if token is provided
  if (token == "none") {
    res.status(400).send({ Error: "No token was provided" });
    return;
  }

  // get decrypted token
  const decryptedToken = await decryptSafetyNet(token);

  // send decoded and verified token
  if (
    verifySafetyNet(decryptedToken, checkNonce, nonce_list, old_nonce_list, res)
  )
    res.status(200).send(decryptedToken);

  return;
});
