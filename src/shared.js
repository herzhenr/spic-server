const maxTypeLength = 7;

import { errorLevel } from "../index.js";

/**
 * print a message to the console with the date and time
 * @param {String} type
 * @param {String} title
 * @param {String} content
 */
export function logEvent(type, title, content) {
  const date = new Date();
  const time = date.toLocaleTimeString();
  const dateString = date.toLocaleDateString();
  const placeholder = " ".repeat(Math.max(maxTypeLength - type.length, 0));
  console.log(
    `${dateString} ${time} [${type}] ${placeholder}- ${title}: ${content}`
  );
}

/**
 * generates a nonce
 * @param {Number} length length of the nonce
 * @returns {Number} generated nonce
 */
export function generateNonce(length) {
  //   const nonce = crypto.randomBytes(length).toString();
  // .replace(/\+/g, "-") // Convert '+' to '-'
  // .replace(/\//g, "_") // Convert '/' to '_'
  // .replace(/=+$/, ""); // Remove ending '='
  //   return nonce;
  var nonce = "";
  var characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    nonce += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return nonce;
}

/**
 * checks if the provided nonce is valid (if the nonce is contained in the @param nonce_list)
 * @param {String} nonce
 * @param {String[]} nonce_list
 * @param {String[]} old_nonce_list
 * @returns {Boolean}
 */
export function isNonceValid(nonce, nonce_list, old_nonce_list) {
  if (nonce_list.includes(nonce)) {
    // move nonce from nonce_list to old_nonce_list
    nonce_list.pop(nonce);
    old_nonce_list.push(nonce);
    logEvent(`INFO`, `Correct Nonce`, `Correct nonce '${nonce}' received`);
  } else {
    // nonce is not included in nonce_list error is sent
    if (old_nonce_list.includes(nonce)) {
      logEvent(
        `WARNING`,
        `Reused Nonce`,
        `duplicated use of nonce '${nonce}', potential replay attack`
      );
    } else {
      logEvent(
        `WARNING`,
        `Unknown Nonce`,
        `nonce '${nonce}' was not previously generated on the server`
      );
    }
    return false;
  }
  return true;
}

/**
 * depending on the errorLevel, either send an error to client or log it. If error is sent, function return true to indictae that server can stop processing
 * @param {*} res
 * @param {String} message
 * @returns {boolean}
 */
export function errorAndExit(res, message) {
  if (errorLevel == "error") {
    logEvent(`WARNING`, `Parsing`, message);
    res.status(400).send({ Error: message });
    return true;
  } else if (errorLevel == "log") {
    logEvent(`WARNING`, `Parsing`, message);
    return false;
  }
  return true;
}
