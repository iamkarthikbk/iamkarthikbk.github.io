(() => {
    const root = document.documentElement;
    const storageKey = 'karthik-theme';

    function applyTheme(theme) {
        root.dataset.theme = theme;
        document.querySelector('meta[name="theme-color"]').content =
            theme === 'light' ? '#f7f6fa' : '#121212';

        const toggle = document.getElementById('theme-toggle');
        if (toggle) {
            const nextTheme = theme === 'dark' ? 'light' : 'dark';
            toggle.querySelector('.theme-label').textContent = `${nextTheme} mode`;
            toggle.setAttribute('aria-label', `Switch to ${nextTheme} theme`);
        }
    }

    let theme = 'dark';
    try {
        if (localStorage.getItem(storageKey) === 'light') theme = 'light';
    } catch {
        // Theme switching still works when browser storage is unavailable.
    }
    applyTheme(theme);

    document.addEventListener('DOMContentLoaded', () => {
        const toggle = document.getElementById('theme-toggle');
        if (!toggle) return;

        applyTheme(root.dataset.theme);
        toggle.hidden = false;
        toggle.addEventListener('click', () => {
            const nextTheme = root.dataset.theme === 'dark' ? 'light' : 'dark';
            applyTheme(nextTheme);
            try {
                localStorage.setItem(storageKey, nextTheme);
            } catch {
                // Keep the chosen theme for this page when storage is blocked.
            }
        });
    });
})();
