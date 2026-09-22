"use strict";

const menuToggle = document.querySelector(".menu-toggle");
const mobileNav = document.querySelector("#mobile-nav");

function closeMenu() {
  menuToggle.setAttribute("aria-expanded", "false");
  menuToggle.setAttribute("aria-label", "Open navigation");
  mobileNav.hidden = true;
}

menuToggle.addEventListener("click", () => {
  const open = menuToggle.getAttribute("aria-expanded") !== "true";
  menuToggle.setAttribute("aria-expanded", String(open));
  menuToggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
  mobileNav.hidden = !open;
});
mobileNav.addEventListener("click", (event) => {
  if (event.target.closest("a")) closeMenu();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !mobileNav.hidden) {
    closeMenu();
    menuToggle.focus();
  }
});
window.matchMedia("(min-width: 601px)").addEventListener("change", closeMenu);

const browserDemo = {
  request: {
    status: "Ready to request",
    title: "A report. Not the keys.",
    description: "A registered agent needs to read a report from your staging app. Start an example access request.",
    primary: "Request access", next: "approve", secondary: null, step: 0,
    feedback: "A local illustration of the proposed pilot."
  },
  approve: {
    status: "Awaiting your approval",
    title: "Your agent. Your decision.",
    description: "Review the workload, resource, and scope below. Approve this example task or decline it.",
    primary: "Approve this task", next: "active", secondary: "Decline", step: 1,
    feedback: "Nothing proceeds until you approve."
  },
  active: {
    status: "Example session active",
    title: "Access for the task at hand.",
    description: "In the proposed flow, the broker logs in privately and hands the agent a restricted session to read the report.",
    primary: "Complete task", next: "ended", secondary: "Revoke access", step: 2,
    feedback: "The agent can inspect its session. The source password is not handed off."
  },
  ended: {
    status: "Example session ended",
    title: "Work ends. Access ends.",
    description: "The illustration is complete. A real implementation must revoke the website session and verify that replay fails.",
    primary: "Try the flow again", next: "request", secondary: null, step: 4,
    feedback: "No real session was created or revoked. This is an interactive concept."
  },
  declined: {
    status: "Request declined",
    title: "The boundary holds.",
    description: "You declined this example request. The agent receives no session and the task does not start.",
    primary: "Try the flow again", next: "request", secondary: null, step: 1,
    feedback: "Approval is an explicit decision. A refusal never becomes permission."
  }
};

const humanDemo = {
  request: {
    status: "Ready to request", title: "Your agent needs an API key.",
    description: "A support agent needs your support API token. It asks you to provide it through a secure input page.",
    primary: "Request a secret", next: "approve", secondary: null, step: 0,
    feedback: "A local illustration. No input link is sent and no secret is requested."
  },
  approve: {
    status: "Waiting for a person", title: "Provide it through the input page.",
    description: "You review the request and open its secure input page. In the real flow, you enter the secret there for browser-side encryption.",
    primary: "Simulate secret input", next: "active", secondary: "Decline", step: 1,
    feedback: "This preview has no secret-entry field. Do not enter real credentials."
  },
  active: {
    status: "Example ciphertext ready", title: "Encrypted for the requesting runtime.",
    description: "The browser encrypts the secret to the requester’s public key. SPS coordinates ciphertext delivery; it does not need the plaintext value.",
    primary: "Simulate retrieval", next: "ended", secondary: null, step: 2,
    feedback: "The intended recipient runtime holds the private key needed to decrypt."
  },
  ended: {
    status: "Example secret delivered", title: "The runtime has what it needs.",
    description: "The recipient retrieves the ciphertext once and decrypts the secret. Its configured integration determines how the credential is consumed or stored.",
    primary: "Try the flow again", next: "request", secondary: null, step: 4,
    feedback: "One-use retrieval is a delivery limit. The API key remains valid until its provider expires or revokes it."
  },
  declined: {
    status: "Example request declined", title: "No secret was supplied.",
    description: "The person chose not to provide a value in this illustration. No secret was encrypted or delivered.",
    primary: "Try the flow again", next: "request", secondary: null, step: 1,
    feedback: "No backend action occurred. An unfulfilled real request is subject to its request expiry."
  }
};

const exchangeDemo = {
  request: {
    status: "Ready to request", title: "Another agent holds the key.",
    description: "The reporting agent requests reports.api_key from the operations agent, with a purpose attached to the exchange.",
    primary: "Request an exchange", next: "approve", secondary: null, step: 0,
    feedback: "Roles can reverse in a separate exchange. Each direction needs its own policy permission."
  },
  approve: {
    status: "Example approval required", title: "Your policy sets the decision.",
    description: "Policy can allow, deny, or require approval. This example uses an approval rule: review the requester, fulfiller, secret, and purpose.",
    primary: "Approve exchange", next: "active", secondary: "Reject exchange", step: 1,
    feedback: "Approval authorizes this exchange. It does not constrain downstream use of a copied key."
  },
  active: {
    status: "Example exchange authorized", title: "The holding agent fulfills it.",
    description: "The operations agent uses the scoped fulfillment token to reserve the exchange and encrypts the secret it holds for the requesting runtime.",
    primary: "Simulate fulfillment", next: "ready", secondary: null, step: 2,
    feedback: "SPS coordinates the encrypted payload and records exchange metadata."
  },
  ready: {
    status: "Example ciphertext ready", title: "Ready for the requester.",
    description: "The fulfiller has submitted an encrypted payload in this illustration. The reporting agent can now retrieve and decrypt it.",
    primary: "Simulate retrieval", next: "ended", secondary: null, step: 3,
    feedback: "Only metadata is shown here. No real secret or fulfillment token is created."
  },
  ended: {
    status: "Example exchange complete", title: "A handoff in either direction.",
    description: "The reporting runtime has received the secret. It can also fulfill a separate authorized request for a secret it holds; permission is not automatically reciprocal.",
    primary: "Try the flow again", next: "request", secondary: null, step: 4,
    feedback: "The recipient can access the plaintext. Exchange completion does not revoke the underlying API key."
  },
  declined: {
    status: "Example exchange rejected", title: "This request stops here.",
    description: "The example approval was rejected. The holding agent does not fulfill the exchange, and the requester receives no secret.",
    primary: "Try the flow again", next: "request", secondary: null, step: 1,
    feedback: "A separate request in the reverse direction must still pass its own policy check."
  }
};

const flows = {
  human: {
    demo: humanDemo, label: "HUMAN-TO-AGENT PROVISIONING", reference: "secret-request / example-001",
    caption: "Existing provisioning flow · A person supplies a secret requested by an agent.",
    boundary: "The recipient runtime receives the secret. One-use delivery does not expire or revoke the API key at its provider.",
    steps: [["Request", "An agent needs an API key."], ["Provide", "A person opens the input page."], ["Encrypt", "The browser encrypts the secret."], ["Retrieve", "The agent runtime decrypts it."]],
    details: [["Requester", "support-agent"], ["Provided by", "Human operator"], ["Secret name", "support.api_token"], ["Delivery", "One-use retrieval"]]
  },
  exchange: {
    demo: exchangeDemo, label: "AGENT-TO-AGENT EXCHANGE", reference: "secret-exchange / example-002",
    caption: "Existing exchange flow · Agents can request and fulfill, subject to policy in each direction.",
    boundary: "A permitted exchange delivers a secret to the requesting runtime. It does not grant unlimited sharing or enforce how a copied key is used.",
    steps: [["Request", "Name the secret and its holder."], ["Policy", "Allow, deny, or seek approval."], ["Fulfill", "The holder encrypts the secret."], ["Retrieve", "One-use ciphertext retrieval."]],
    details: [["Requester", "report-agent"], ["Fulfiller", "ops-agent"], ["Secret name", "reports.api_key"], ["Purpose", "Compile daily report"]]
  },
  browser: {
    demo: browserDemo, label: "BROWSER SESSION HANDOFF", reference: "access-request / example-003",
    caption: "Proposed pilot · Browser session handoff is planned work, not an existing secret-exchange capability.",
    boundary: "The agent receives a session it can inspect. The source password stays with the trusted login helper.",
    steps: [["Request", "An agent needs a resource."], ["Approve", "You authorize the task."], ["Work", "A bounded session is handed off."], ["End access", "Revoke the website session."]],
    details: [["Workload", "agent.browser"], ["Resource", "staging / reports"], ["Scope", "Read one report"], ["Session limit", "5 minutes · example"]]
  }
};

let flow = "human";
let state = "request";
const primary = document.querySelector("#demo-primary");
const secondary = document.querySelector("#demo-secondary");
const status = document.querySelector("#request-status");
const title = document.querySelector("#request-title");
const description = document.querySelector("#request-description");
const feedback = document.querySelector("#demo-feedback");
const steps = [...document.querySelectorAll(".workflow-steps li")];
const flowButtons = [...document.querySelectorAll("[data-flow]")];
const detailRows = [...document.querySelectorAll(".request-details > div")];

function selectFlow(nextFlow) {
  flow = nextFlow;
  const selected = flows[flow];
  document.querySelector("#flow-label").textContent = selected.label;
  document.querySelector("#flow-reference").textContent = selected.reference;
  document.querySelector("#flow-caption").textContent = selected.caption;
  document.querySelector("#flow-boundary").textContent = selected.boundary;
  flowButtons.forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.flow === flow)));
  steps.forEach((step, index) => {
    step.querySelector("strong").textContent = selected.steps[index][0];
    step.querySelector("small").textContent = selected.steps[index][1];
  });
  detailRows.forEach((row, index) => {
    row.querySelector("dt").textContent = selected.details[index][0];
    row.querySelector("dd").textContent = selected.details[index][1];
  });
  render("request");
}

function render(nextState, revoked = false) {
  state = nextState;
  const view = flows[flow].demo[state];
  status.textContent = revoked ? "Example access revoked" : view.status;
  status.dataset.state = state;
  title.textContent = revoked ? "Control stays with you." : view.title;
  description.textContent = revoked
    ? "You ended the example session early. In the pilot, server-side revocation must invalidate copied session cookies too."
    : view.description;
  primary.querySelector("span").textContent = view.primary;
  secondary.hidden = !view.secondary;
  secondary.textContent = view.secondary || "";
  feedback.textContent = view.feedback;
  steps.forEach((step, index) => {
    step.classList.toggle("is-current", index === view.step);
    step.classList.toggle("is-complete", index < view.step);
    if (index === view.step) step.setAttribute("aria-current", "step");
    else step.removeAttribute("aria-current");
  });
}

flowButtons.forEach((button) => button.addEventListener("click", () => selectFlow(button.dataset.flow)));
primary.addEventListener("click", () => render(flows[flow].demo[state].next));
secondary.addEventListener("click", () => {
  if (state === "approve") render("declined");
  else if (flow === "browser" && state === "active") render("ended", true);
  primary.focus();
});
selectFlow("human");
