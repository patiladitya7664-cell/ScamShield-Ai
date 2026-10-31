"use strict";

/* =========================================================
SCAMSHIELD AI
DECOY LAB - SAFE SIMULATED CHAT ENGINE
Local-only fictional conversation
========================================================= */

document.addEventListener("DOMContentLoaded", () => {
const consent = document.getElementById("decoyConsent");
const log = document.getElementById("decoyChatLog");
const input = document.getElementById("decoyScammerInput");

const startButton = document.getElementById("decoyStartButton");
const sendButton = document.getElementById("decoySendButton");
const endButton = document.getElementById("decoyEndButton");

const status = document.getElementById("decoyChatStatus");
const extracted = document.getElementById("decoyExtracted");
const indicatorList = document.getElementById("decoyIndicatorList");

if (
!consent ||
!log ||
!input ||
!startButton ||
!sendButton ||
!endButton
) {
console.warn("Decoy Chat: Required HTML elements are missing.");
return;
}

let active = false;
let replyTimer = null;

const foundIndicators = new Set();

/* =====================================================
STATUS
===================================================== */

function updateStatus(message) {
if (status) {
status.textContent = message;
}
}

/* =====================================================
CHAT MESSAGE
===================================================== */

function addMessage(role, message) {
const bubble = document.createElement("div");


bubble.className = `decoy-chat-message ${role}`;

const label = document.createElement("small");

label.textContent =
  role === "scammer"
    ? "SIMULATED SCAMMER · FICTIONAL INPUT"
    : "DECOY AGENT · SCRIPTED SAFE RESPONSE";

const body = document.createElement("span");

body.textContent = message;

bubble.append(label, body);

log.appendChild(bubble);

log.scrollTop = log.scrollHeight;


}


/* =====================================================
   INDICATOR EXTRACTION
===================================================== */

function extractClues(text) {
  const patterns = [
    {
      type: "PHONE",
      regex: /(?:\+91[\s-]?)?[6-9]\d{9}\b/g,
    },
    {
      type: "URL",
      regex: /\bhttps?:\/\/[^\s<>'"]+/gi,
    },
    {
      type: "UPI",
      regex: /\b[a-zA-Z0-9._-]+@[a-zA-Z]{2,}\b/g,
    },
  ];

  patterns.forEach(({ type, regex }) => {
    const matches = text.match(regex) || [];

    matches.forEach((value) => {
      const cleaned = value.replace(/[.,!?;]+$/, "");
      foundIndicators.add(`${type}: ${cleaned}`);
    });
  });

  renderIndicators();
}



function renderIndicators() {
if (!indicatorList || !extracted) return;


indicatorList.replaceChildren();

foundIndicators.forEach((clue) => {
  const tag = document.createElement("span");

  tag.textContent = clue;

  indicatorList.appendChild(tag);
});

extracted.hidden = foundIndicators.size === 0;


}

/* =====================================================
SAFE SCRIPTED RESPONSE
===================================================== */

function safeReply(message) {
const text = message.toLowerCase();


if (
  /\b(police|cbi|ed|arrest|warrant|officer|case number|legal notice)\b/i.test(
    text,
  )
) {
  return (
    "I will verify this independently. Please provide a public office " +
    "contact and written case reference. I will not share personal " +
    "information or make a payment through this chat."
  );
}

if (
  /\b(upi|transfer|pay|payment|money|fee|urgent|account|blocked)\b/i.test(
    text,
  )
) {
  return (
    "I do not make urgent transfers or share OTPs, PINs, passwords, " +
    "or card details. I will verify this request through an official channel."
  );
}

if (/\bhttps?:\/\/|www\.|link\b/i.test(text)) {
  return (
    "I will not open an unexpected link. Please provide the organisation " +
    "name so I can find its official website independently."
  );
}

return (
  "I need time to check this safely. What is the official organisation " +
  "name and a public reference I can verify independently?"
);


}

/* =====================================================
BUTTON STATES
===================================================== */

function updateControls() {
startButton.disabled = active || !consent.checked;


sendButton.disabled = !active;

endButton.disabled = !active;

input.disabled = !active;


}

/* =====================================================
RESET CHAT
===================================================== */

function clearChat() {
if (replyTimer) {
window.clearTimeout(replyTimer);
replyTimer = null;
}


active = false;

log.replaceChildren();

foundIndicators.clear();

if (indicatorList) {
  indicatorList.replaceChildren();
}

if (extracted) {
  extracted.hidden = true;
}

input.value = "";

updateControls();


}

/* =====================================================
CONSENT
===================================================== */

consent.addEventListener("change", () => {
if (!consent.checked && active) {
clearChat();


  updateStatus("Consent withdrawn. The simulation has been stopped.");

  return;
}

updateControls();

if (consent.checked) {
  updateStatus("Consent accepted. You can now start the simulation.");
} else {
  updateStatus("Please accept the simulation consent before starting.");
}


});

/* =====================================================
START SIMULATION
===================================================== */

startButton.addEventListener("click", () => {
if (!consent.checked || active) {
updateStatus("Please accept consent before starting.");


  return;
}

clearChat();

active = true;

updateControls();

addMessage(
  "agent",
  "I am a fictional, cautious customer. Please explain what you are asking me to do. I will verify independently and will never share secrets or transfer money.",
);

updateStatus(
  "Simulation active. Enter a fictional scammer message to continue.",
);

input.focus();


});

/* =====================================================
SEND SIMULATED MESSAGE
===================================================== */

function sendMessage() {
if (!active || !consent.checked) {
updateStatus("Start the simulation after accepting consent.");


  return;
}

const message = input.value.trim();

if (!message) {
  updateStatus("Please enter a simulated message first.");

  input.focus();

  return;
}

if (message.length > 1000) {
  updateStatus("Message is too long. Maximum 1000 characters.");

  return;
}

addMessage("scammer", message);

extractClues(message);

input.value = "";

sendButton.disabled = true;

updateStatus("The simulated Decoy Agent is preparing a response.");

if (replyTimer) {
  window.clearTimeout(replyTimer);
}

replyTimer = window.setTimeout(() => {
  replyTimer = null;

  if (!active || !consent.checked) return;

  addMessage("agent", safeReply(message));

  sendButton.disabled = false;

  updateStatus("Response generated. You can continue the simulation.");

  input.focus();
}, 350);


}

sendButton.addEventListener("click", sendMessage);

input.addEventListener("keydown", (event) => {
if (
event.key === "Enter" &&
(event.ctrlKey || event.metaKey)
) {
event.preventDefault();


  sendMessage();
}


});

/* =====================================================
END SIMULATION
===================================================== */

endButton.addEventListener("click", () => {
if (!active) return;


if (replyTimer) {
  window.clearTimeout(replyTimer);

  replyTimer = null;
}

active = false;

updateControls();

updateStatus(
  "Simulation ended. Messages and extracted clues remain only on this page until it is cleared or reloaded.",
);

startButton.focus();


});

/* =====================================================
INITIALIZATION
===================================================== */

updateControls();

updateStatus(
"Accept the consent checkbox to begin the fictional simulation.",
);

console.log("ScamShield AI: Safe Decoy Chat initialized.");
});
