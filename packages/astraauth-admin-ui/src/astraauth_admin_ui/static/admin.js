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

  // Auto-dismiss status alert banner/toast after a brief period
  function dismissStatusBanners() {
    const banners = document.querySelectorAll(".banner:not(.hidden)");
    banners.forEach((banner) => {
      if (!(banner instanceof HTMLElement)) return;
      
      // Clear any existing active timeouts
      if (banner.dataset.timeoutId) {
        clearTimeout(parseInt(banner.dataset.timeoutId, 10));
      }

      banner.style.transition = "opacity 0.6s cubic-bezier(0.16, 1, 0.3, 1), transform 0.6s cubic-bezier(0.16, 1, 0.3, 1)";
      banner.style.opacity = "1";
      banner.style.transform = "translateY(0)";

      const timeoutId = setTimeout(() => {
        banner.style.opacity = "0";
        banner.style.transform = "translateY(-8px)";
        setTimeout(() => {
          banner.classList.add("hidden");
        }, 600);
      }, 3500); // Dismiss after 3.5 seconds

      banner.dataset.timeoutId = String(timeoutId);
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    syncSidebarLayout();
    setActiveNavButton("/partials/dashboard/runtime");
    dismissStatusBanners();
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
    
    // Infrastructure Tab Switcher Event Delegation
    const infraTab = target.closest(".infra-tab-btn");
    if (infraTab instanceof HTMLElement) {
      const tabId = infraTab.id.replace("btn-infra-", "");
      document.querySelectorAll(".infra-tab-btn").forEach((btn) => btn.classList.remove("active"));
      document.querySelectorAll(".tab-content-panel").forEach((panel) => panel.classList.remove("active"));
      
      infraTab.classList.add("active");
      const panel = document.getElementById(`panel-infra-${tabId}`);
      if (panel) {
        panel.classList.add("active");
      }
      return;
    }

    // Zanzibar ReBAC Snippets Tool insert event delegation
    const snippetBtn = target.closest(".btn-snippet");
    if (snippetBtn instanceof HTMLElement) {
      const type = snippetBtn.dataset.snippet;
      const textarea = document.getElementById("dsl");
      if (textarea instanceof HTMLTextAreaElement) {
        let text = "";
        if (type === "document") {
          text = "# Document collaboration model\ndefinition user {}\n\ndefinition document {\n    relation viewer: user\n    relation editor: user\n    permission view = viewer + editor\n    permission edit = editor\n}";
        } else if (type === "org") {
          text = "# Org hierarchical structures\ndefinition user {}\n\ndefinition organization {\n    relation member: user\n    relation admin: user\n}\n\ndefinition project {\n    relation parent: organization\n    relation owner: user\n    permission view = owner + parent.member\n}";
        }
        textarea.value = text;
      }
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
      dismissStatusBanners();
      if (target.id) {
        scrollTargetIntoView(`#${target.id}`);
      }
    }
  });
})();
