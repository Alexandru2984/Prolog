document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector(".audit_form");
  if (!form) return;
  form.addEventListener("submit", () => {
    const button = form.querySelector("button[type='submit']");
    if (button) button.textContent = "Analyzing...";
  });
});
