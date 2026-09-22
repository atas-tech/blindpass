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

const demo = {
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
    primary: "Try the flow again", next: "request", secondary: null, step: 3,
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

let state = "request";
const primary = document.querySelector("#demo-primary");
const secondary = document.querySelector("#demo-secondary");
const status = document.querySelector("#request-status");
const title = document.querySelector("#request-title");
const description = document.querySelector("#request-description");
const feedback = document.querySelector("#demo-feedback");
const steps = [...document.querySelectorAll(".workflow-steps li")];

function render(nextState, revoked = false) {
  state = nextState;
  const view = demo[state];
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

primary.addEventListener("click", () => render(demo[state].next));
secondary.addEventListener("click", () => {
  if (state === "approve") render("declined");
  else if (state === "active") render("ended", true);
  primary.focus();
});
render("request");
