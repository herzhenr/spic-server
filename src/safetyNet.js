import jws from "jws";

// module imports
import { count, validCertificateSha256Digest, packageName } from "../index.js";
import { logEvent, errorAndExit, isNonceValid } from "./shared.js";

export function decryptSafetyNet(token) {
  // 1. decode the jws
  const decodedJws = jws.decode(token);
  const payload = JSON.parse(decodedJws.payload);
  // verifySignature(token);
  logEvent(
    `INFO`,
    `(SafetyNet) New Client Request (${count()}) processed`,
    payload
  );
  return payload;
}

export async function verifySafetyNet(
  decryptedToken,
  checkNonce,
  nonce_list,
  old_nonce_list,
  res
) {
  var error = false;
  // verify nonce
  var nonce = Buffer.from(decryptedToken?.nonce, "base64")
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

  // verify timestamp: request isn't older than 10 seconds
  if (Date.now() - decryptedToken?.timestampMs > 10000) {
    if (errorAndExit(res, `Request too old`)) return false;
    error = true;
  }

  // verify package name
  if (packageName != decryptedToken?.apkPackageName) {
    if (errorAndExit(res, `Invalid package name`)) return false;
    error = true;
  }

  // verify basic integrity
  if (decryptedToken?.basicIntegrity == false) {
    if (errorAndExit(res, `Basic integrity check failed`)) return false;
    error = true;
  }

  // log integrity evaluation type
  logEvent(
    `INFO`,
    `Attestation`,
    `Using ${decryptedToken?.evaluationType} to evaluate device integrity.`
  );

  if (!decryptedToken?.basicIntegrity) {
    if (errorAndExit(res, `Device doesn't meet basic integrity`)) return false;
    error = true;
  }

  if (!decryptedToken?.ctsProfileMatch) {
    logEvent(
      `INFO`,
      `Attestation`,
      `(SafetyNet) Evaluation type is BASIC, skipping CTS profile check`
    );
  } else {
    if (decryptedToken?.ctsProfileMatch == false) {
      if (errorAndExit(res, `CTS profile match failed`)) return false;
      error = true;
    }

    // verify apk certificate digest
    if (
      decryptedToken?.apkCertificateDigestSha256 == null ||
      !decryptedToken?.apkCertificateDigestSha256?.some((e) =>
        validCertificateSha256Digest?.includes(e)
      )
    ) {
      if (errorAndExit(res, `Invalid apk certificate digest`)) return false;
      error = true;
    }
  }

  if (!error) {
    logEvent(`INFO`, `Attestation`, `SafetyNet Checks passed`);
    return true;
  } else {
    logEvent(`WARNING`, `Attestation`, `SafetyNet Checks failed`);
    return false;
  }
}
