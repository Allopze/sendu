
import os

def fix_admin_and_theme():
    index_path = r'c:\dev\sendu\frontend\index.html'
    
    with open(index_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # 1. Fix the malformed templates
    # The pattern to look for is the end of users table and the start of the broken files table header
    
    broken_pattern = """                    <tbody id="users-table-body">
                        <tr>
                            <td colspan="7" class="text-center py-4 dark:text-gray-400 light:text-gray-600">Cargando...</td>
                        </tr>
                    </tbody>
                </table>
                            <th class="text-left py-3 px-2 dark:text-gray-300 light:text-gray-700">Usuario</th>"""
                            
    fixed_pattern = """                    <tbody id="users-table-body">
                        <tr>
                            <td colspan="7" class="text-center py-4 dark:text-gray-400 light:text-gray-600">Cargando...</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </template>

    <!-- Template: Files Tab -->
    <template id="admin-files-tab">
        <div class="glass-container p-6 space-y-4">
            <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                <h3 class="text-lg font-semibold dark:text-white light:text-gray-800 flex items-center gap-2">
                    <i data-lucide="folder" style="width: 20px; height: 20px;"></i>
                    Gestión de Archivos
                </h3>
                <div class="flex gap-2">
                    <input type="text" id="search-files-input" placeholder="Buscar archivo..." class="px-3 py-1.5 rounded-lg bg-white/10 dark:bg-slate-800/50 light:bg-white border border-gray-300 dark:border-slate-700 focus:outline-none focus:ring-2 focus:ring-red-500 text-sm">
                    <button id="refresh-files-btn" class="btn-outline">
                        <i data-lucide="refresh-cw" style="width: 16px; height: 16px;"></i>
                    </button>
                </div>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b border-gray-300 dark:border-slate-700">
                            <th class="text-left py-3 px-2 dark:text-gray-300 light:text-gray-700">Nombre</th>
                            <th class="text-left py-3 px-2 dark:text-gray-300 light:text-gray-700">Usuario</th>"""
                            
    if broken_pattern in content:
        print("Found broken template pattern. Fixing...")
        content = content.replace(broken_pattern, fixed_pattern)
    else:
        print("Could not find broken template pattern. It might be slightly different.")
        # Try a smaller pattern
        broken_pattern_small = """                </table>
                            <th class="text-left py-3 px-2 dark:text-gray-300 light:text-gray-700">Usuario</th>"""
        if broken_pattern_small in content:
             print("Found smaller broken template pattern. Fixing...")
             # We need to be careful with replacement here to match the context
             # Let's try to construct the replacement
             fixed_pattern_small = """                </table>
            </div>
        </div>
    </template>

    <!-- Template: Files Tab -->
    <template id="admin-files-tab">
        <div class="glass-container p-6 space-y-4">
            <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                <h3 class="text-lg font-semibold dark:text-white light:text-gray-800 flex items-center gap-2">
                    <i data-lucide="folder" style="width: 20px; height: 20px;"></i>
                    Gestión de Archivos
                </h3>
                <div class="flex gap-2">
                    <input type="text" id="search-files-input" placeholder="Buscar archivo..." class="px-3 py-1.5 rounded-lg bg-white/10 dark:bg-slate-800/50 light:bg-white border border-gray-300 dark:border-slate-700 focus:outline-none focus:ring-2 focus:ring-red-500 text-sm">
                    <button id="refresh-files-btn" class="btn-outline">
                        <i data-lucide="refresh-cw" style="width: 16px; height: 16px;"></i>
                    </button>
                </div>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b border-gray-300 dark:border-slate-700">
                            <th class="text-left py-3 px-2 dark:text-gray-300 light:text-gray-700">Nombre</th>
                            <th class="text-left py-3 px-2 dark:text-gray-300 light:text-gray-700">Usuario</th>"""
             content = content.replace(broken_pattern_small, fixed_pattern_small)

    # 2. Add Theme Toggle Logic
    theme_logic = """
            // --- Theme Toggle Logic ---
            const themeToggle = document.getElementById('themeToggle');
            const html = document.documentElement;

            // Check local storage or system preference
            if (localStorage.theme === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
                html.classList.add('dark');
                html.classList.remove('light');
                html.setAttribute('data-theme', 'dark');
            } else {
                html.classList.remove('dark');
                html.classList.add('light');
                html.setAttribute('data-theme', 'light');
            }

            if (themeToggle) {
                themeToggle.addEventListener('click', () => {
                    if (html.classList.contains('dark')) {
                        html.classList.remove('dark');
                        html.classList.add('light');
                        html.setAttribute('data-theme', 'light');
                        localStorage.theme = 'light';
                    } else {
                        html.classList.add('dark');
                        html.classList.remove('light');
                        html.setAttribute('data-theme', 'dark');
                        localStorage.theme = 'dark';
                    }
                });
            }

            // --- Inicialización ---
            checkAuthStatus().then(() => {"""
            
    init_pattern = """            // --- Inicialización ---
            checkAuthStatus().then(() => {"""
            
    if init_pattern in content:
        print("Found initialization pattern. Adding theme logic...")
        content = content.replace(init_pattern, theme_logic)
    else:
        print("Could not find initialization pattern.")

    with open(index_path, 'w', encoding='utf-8') as f:
        f.write(content)
        
    print("Done.")

if __name__ == '__main__':
    fix_admin_and_theme()
