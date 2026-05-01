const Tools = {
    tools: [],
    categories: {
        info: [],
        vuln: []
    },
    currentTool: null,

    init() {
        this.bindEvents();
        this.loadTools();
    },

    bindEvents() {
        const filterBtns = document.querySelectorAll('.filter-btn');
        filterBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                filterBtns.forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                this.filterTools(e.target.dataset.category);
            });
        });

        const closeBtn = document.getElementById('closeExecution');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.hideExecution());
        }

        const executeBtn = document.getElementById('executeToolBtn');
        if (executeBtn) {
            executeBtn.addEventListener('click', () => this.executeCurrentTool());
        }
    },

    async loadTools() {
        const grid = document.getElementById('toolsGrid');
        grid.innerHTML = '<div class="loading">加载工具列表...</div>';

        try {
            const [toolsResult, categoriesResult] = await Promise.all([
                API.getTools(),
                API.getToolsByCategory()
            ]);

            this.tools = toolsResult.data?.tools || [];
            this.categories = {
                info: categoriesResult.data?.info_collection || [],
                vuln: categoriesResult.data?.vuln_scan || []
            };

            this.renderTools();
        } catch (error) {
            grid.innerHTML = `<div class="error">加载失败: ${error.message}</div>`;
        }
    },

    renderTools(category = 'all') {
        const grid = document.getElementById('toolsGrid');
        
        let filteredTools = this.tools;
        if (category === 'info') {
            filteredTools = this.tools.filter(t => t.category === 'info_collection' || this.categories.info.includes(t.name));
        } else if (category === 'vuln') {
            filteredTools = this.tools.filter(t => t.category === 'vuln_scan' || this.categories.vuln.includes(t.name));
        } else if (category === 'custom') {
            filteredTools = this.tools.filter(t => t.is_custom === true);
        }

        if (filteredTools.length === 0) {
            grid.innerHTML = '<div class="loading">暂无工具</div>';
            return;
        }

        grid.innerHTML = filteredTools.map(tool => `
            <div class="tool-card ${tool.is_custom ? 'custom-tool' : ''}" data-tool="${tool.name}">
                <h4>${this.formatToolName(tool.name)}</h4>
                <p>${tool.description || '安全扫描工具'}</p>
                <span class="tool-category ${tool.category}">${this.getToolCategoryLabel(tool)}</span>
            </div>
        `).join('');

        grid.querySelectorAll('.tool-card').forEach(card => {
            card.addEventListener('click', () => {
                this.showExecution(card.dataset.tool);
            });
        });
    },

    getToolCategoryLabel(tool) {
        if (tool.is_custom) return '自定义';
        if (tool.category === 'info_collection') return '信息收集';
        if (tool.category === 'vuln_scan') return '漏洞扫描';
        if (tool.category === 'poc') return 'POC验证';
        return '其他';
    },

    filterTools(category) {
        this.renderTools(category);
    },

    formatToolName(name) {
        return name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    },

    showExecution(toolName) {
        this.currentTool = toolName;
        
        const executionEl = document.getElementById('toolExecution');
        const titleEl = document.getElementById('executionTitle');
        const targetInput = document.getElementById('toolTarget');
        const resultEl = document.getElementById('executionResult');

        titleEl.textContent = `执行工具: ${this.formatToolName(toolName)}`;
        targetInput.value = '';
        resultEl.textContent = '';

        executionEl.style.display = 'block';
    },

    hideExecution() {
        document.getElementById('toolExecution').style.display = 'none';
        this.currentTool = null;
    },

    async executeCurrentTool() {
        if (!this.currentTool) return;

        const targetInput = document.getElementById('toolTarget');
        const resultEl = document.getElementById('executionResult');
        const target = targetInput.value.trim();

        if (!target) {
            App.showToast('请输入目标', 'warning');
            return;
        }

        resultEl.textContent = '执行中...';

        try {
            const result = await API.executeTool(this.currentTool, target);
            resultEl.textContent = JSON.stringify(result.data || result, null, 2);
            App.showToast('执行完成', 'success');
        } catch (error) {
            resultEl.textContent = '执行失败: ' + error.message;
            App.showToast('执行失败', 'error');
        }
    }
};

window.Tools = Tools;
