document.addEventListener("DOMContentLoaded", () => {
  const profileSelect = document.querySelector("#profile_select");
  if (profileSelect) {
    profileSelect.addEventListener("change", () => {
      const target = document.querySelector("input[name='target']");
      const params = new URLSearchParams();
      params.set("profile", profileSelect.value);
      if (target && target.value.trim()) params.set("target", target.value.trim());
      window.location = `/audit?${params.toString()}`;
    });
  }

  const form = document.querySelector(".audit_form");
  if (!form) return;
  form.addEventListener("submit", () => {
    const button = form.querySelector("button[type='submit']");
    if (button) button.textContent = "Analyzing...";
  });
});
