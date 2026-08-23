const SHELL_SELECTOR = ".dspy-config-shell";
const CARD_SELECTOR = ".dspy-card";
const STORAGE_PREFIX = "dspy_rlm.config.section.";
const DEFAULT_COLLAPSED = new Set([
  "Worker scheduler",
  "Quality gates",
  "Semantic evaluator",
  "Guidance delivery",
  "Worker environment",
  "Advanced Prompt Optimization Lab",
]);

function storageKey(title, sectionId = "") {
  const stable = sectionId || title.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return `${STORAGE_PREFIX}${stable}`;
}

function savedState(title, sectionId = "") {
  try {
    const saved = sessionStorage.getItem(storageKey(title, sectionId));
    if (saved === "expanded") return false;
    if (saved === "collapsed") return true;
  } catch (_error) {
    // Session storage is optional; disclosure behavior still works without it.
  }
  return DEFAULT_COLLAPSED.has(title);
}

function persistState(title, collapsed, sectionId = "") {
  try {
    sessionStorage.setItem(storageKey(title, sectionId), collapsed ? "collapsed" : "expanded");
  } catch (_error) {
    // Ignore storage restrictions in hardened browser contexts.
  }
}

function setCollapsed(card, button, title, collapsed) {
  card.classList.toggle("is-collapsed", collapsed);
  button.setAttribute("aria-expanded", String(!collapsed));
  button.setAttribute("aria-label", `${collapsed ? "Expand" : "Collapse"} ${title}`);
  const label = button.querySelector(".section-disclosure__label");
  if (label) label.textContent = collapsed ? "Show" : "Hide";
}

function enhanceCard(card) {
  if (!(card instanceof HTMLElement) || card.dataset.disclosureReady === "true") return;
  const heading = card.querySelector(":scope > h2");
  if (!(heading instanceof HTMLElement)) return;
  const title = String(heading.childNodes[0]?.textContent || heading.textContent || "Section").trim();
  const sectionId = String(card.dataset.sectionId || "");
  if (!title) return;

  const button = document.createElement("button");
  button.type = "button";
  button.className = "section-disclosure";
  button.innerHTML = '<span class="section-disclosure__label"></span><span class="section-disclosure__chevron" aria-hidden="true"></span>';
  heading.append(button);
  card.dataset.disclosureReady = "true";
  setCollapsed(card, button, title, savedState(title, sectionId));
  button.addEventListener("click", () => {
    const collapsed = !card.classList.contains("is-collapsed");
    setCollapsed(card, button, title, collapsed);
    persistState(title, collapsed, sectionId);
  });
}

function enhanceShell(shell) {
  if (!(shell instanceof HTMLElement)) return;
  shell.querySelectorAll(CARD_SELECTOR).forEach(enhanceCard);
}

function enhanceAll() {
  document.querySelectorAll(SHELL_SELECTOR).forEach(enhanceShell);
}

enhanceAll();

if (!window.__dspyRlmConfigObserver) {
  window.__dspyRlmConfigObserver = new MutationObserver(enhanceAll);
  window.__dspyRlmConfigObserver.observe(document.body, { childList: true, subtree: true });
}
