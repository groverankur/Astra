(() => {
  const THEME_KEY = "astra-admin-theme";

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
  }

  function initTheme() {
    const saved = window.localStorage.getItem(THEME_KEY);
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(saved || (prefersDark ? "dark" : "light"));
  }

  function toggleTheme() {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    applyTheme(next);
    window.localStorage.setItem(THEME_KEY, next);
  }

  function syncSidebarLayout() {
    const layout = document.querySelector("[data-dashboard-layout]");
    const sidebar = document.getElementById("sidebar-region");
    if (!(layout instanceof HTMLElement) || !(sidebar instanceof HTMLElement)) {
      return;
    }
    const hasContent = sidebar.textContent?.trim().length;
    layout.classList.toggle("sidebar-open", Boolean(hasContent));
  }

  function setActiveNavButton(activeView) {
    document.querySelectorAll(".nav-button").forEach((button) => {
      if (!(button instanceof HTMLElement)) {
        return;
      }
      const isActive = button.dataset.navView === activeView;
      button.classList.toggle("is-active", isActive);
      button.setAttribute("aria-pressed", isActive ? "true" : "false");
    });
  }

  function scrollTargetIntoView(targetSelector) {
    const target = document.querySelector(targetSelector);
    if (target instanceof HTMLElement) {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    syncSidebarLayout();
    setActiveNavButton("/partials/dashboard/runtime");
  });

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) {
      return;
    }
    if (target.closest("[data-theme-toggle]")) {
      toggleTheme();
      return;
    }
    const navButton = target.closest(".nav-button");
    if (navButton instanceof HTMLElement) {
      const navView = navButton.dataset.navView;
      if (navView) {
        setActiveNavButton(navView);
      }
    }
  });

  document.body.addEventListener("htmx:afterRequest", (event) => {
    const source = event.detail?.requestConfig?.elt;
    if (!(source instanceof Element)) {
      return;
    }
    const navButton = source.closest(".nav-button");
    if (navButton instanceof HTMLElement && navButton.dataset.navView) {
      setActiveNavButton(navButton.dataset.navView);
      return;
    }
    const workspaceSource = source.closest("[data-workspace-view]");
    if (workspaceSource instanceof HTMLElement && workspaceSource.dataset.workspaceView) {
      setActiveNavButton(workspaceSource.dataset.workspaceView);
    }
  });

  document.body.addEventListener("htmx:afterSwap", (event) => {
    const detail = event.detail;
    const target = detail?.target;
    if (target instanceof HTMLElement) {
      syncSidebarLayout();
      if (target.id) {
        scrollTargetIntoView(`#${target.id}`);
      }
    }
  });
})();
