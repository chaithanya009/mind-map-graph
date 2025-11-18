const DEFAULT_SETTINGS = {
  mode: "monitor",
  idpDomains: [
    "login.microsoftonline.com",
    "login.microsoft.com",
    "accounts.google.com",
    "login.okta.com"
  ],
  webhookUrl: "",
  debug: false
};

function loadSettings() {
  chrome.runtime.sendMessage({ type: "GET_SETTINGS" }, (response) => {
    const settings = response && response.settings ? response.settings : DEFAULT_SETTINGS;

    const modeInputs = document.querySelectorAll('input[name="mode"]');
    modeInputs.forEach((input) => {
      input.checked = input.value === (settings.mode || DEFAULT_SETTINGS.mode);
    });

    const idpTextarea = document.getElementById("idpDomains");
    idpTextarea.value = (settings.idpDomains || DEFAULT_SETTINGS.idpDomains).join("\n");

    const webhookInput = document.getElementById("webhookUrl");
    webhookInput.value = settings.webhookUrl || "";

    const debugCheckbox = document.getElementById("debug");
    debugCheckbox.checked = Boolean(settings.debug);
  });
}

function saveSettings() {
  const modeInputs = document.querySelectorAll('input[name="mode"]');
  let mode = DEFAULT_SETTINGS.mode;
  modeInputs.forEach((input) => {
    if (input.checked) {
      mode = input.value;
    }
  });

  const idpTextarea = document.getElementById("idpDomains");
  const idpDomains = idpTextarea.value
    .split("\n")
    .map((d) => d.trim())
    .filter(Boolean);

  const webhookInput = document.getElementById("webhookUrl");
  const webhookUrl = webhookInput.value.trim();

  const debugCheckbox = document.getElementById("debug");
  const debug = debugCheckbox.checked;

  const status = document.getElementById("status");
  status.textContent = "Saving…";

  chrome.runtime.sendMessage(
    {
      type: "UPDATE_SETTINGS",
      settings: {
        mode,
        idpDomains,
        webhookUrl,
        debug
      }
    },
    () => {
      status.textContent = "Saved.";
      setTimeout(() => {
        status.textContent = "";
      }, 1500);
    }
  );
}

document.addEventListener("DOMContentLoaded", () => {
  loadSettings();
  const saveBtn = document.getElementById("saveBtn");
  saveBtn.addEventListener("click", saveSettings);
});


