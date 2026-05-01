const App = {
    ws: null,
    sessionId: null,
    currentPage: 'console',
    settings: {
        apiUrl: 'http://localhost:8081',
        wsUrl: 'ws://localhost:8081',
        scanTimeout: 300
    },

    init() {
        this.loadSettings();
        this.initNavigation();
        this.initModal();
        this.initSettings();
        this.initModules();
        this.connectWebSocket();
    },

    loadSettings() {
        const saved = localStorage.getItem('toskill_settings');
        if (saved) {
            try {
                this.settings = { ...this.settings, ...JSON.parse(saved) };
            } catch (e) {
                console.error('Failed to load settings:', e);
            }
        }

        API.setBaseUrl(this.settings.apiUrl);
        API.setWsUrl(this.settings.wsUrl);
    },

    saveSettings() {
        localStorage.setItem('toskill_settings', JSON.stringify(this.settings));
    },

    initNavigation() {
        const navItems = document.querySelectorAll('.nav-item');
        navItems.forEach(item => {
            item.addEventListener('click', () => {
                const page = item.dataset.page;
                this.navigateTo(page);
            });
        });
    },

    navigateTo(page) {
        this.currentPage = page;

        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.page === page);
        });

        document.querySelectorAll('.page').forEach(p => {
            p.classList.toggle('active', p.id === `page-${page}`);
        });

        if (page === 'reports') {
            Reports.loadReports();
        } else if (page === 'tools') {
            Tools.loadTools();
        }
    },

    initModal() {
        const overlay = document.getElementById('modalOverlay');
        const closeBtn = document.getElementById('modalClose');
        const cancelBtn = document.getElementById('modalCancel');
        const confirmBtn = document.getElementById('modalConfirm');

        const closeModal = () => {
            overlay.classList.remove('show');
        };

        closeBtn.addEventListener('click', closeModal);
        cancelBtn.addEventListener('click', closeModal);
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) closeModal();
        });
    },

    showModal(title, body, onConfirm) {
        const overlay = document.getElementById('modalOverlay');
        const titleEl = document.getElementById('modalTitle');
        const bodyEl = document.getElementById('modalBody');
        const confirmBtn = document.getElementById('modalConfirm');

        titleEl.textContent = title;
        bodyEl.innerHTML = body;

        const newConfirmBtn = confirmBtn.cloneNode(true);
        confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);

        newConfirmBtn.addEventListener('click', () => {
            onConfirm();
            overlay.classList.remove('show');
        });

        overlay.classList.add('show');
    },

    initSettings() {
        const apiUrlInput = document.getElementById('apiUrl');
        const wsUrlInput = document.getElementById('wsUrl');
        const timeoutInput = document.getElementById('scanTimeout');
        const saveBtn = document.getElementById('saveSettings');
        const testBtn = document.getElementById('testConnection');

        if (apiUrlInput) apiUrlInput.value = this.settings.apiUrl;
        if (wsUrlInput) wsUrlInput.value = this.settings.wsUrl;
        if (timeoutInput) timeoutInput.value = this.settings.scanTimeout;

        if (saveBtn) {
            saveBtn.addEventListener('click', () => {
                this.settings.apiUrl = apiUrlInput.value;
                this.settings.wsUrl = wsUrlInput.value;
                this.settings.scanTimeout = parseInt(timeoutInput.value) || 300;

                API.setBaseUrl(this.settings.apiUrl);
                API.setWsUrl(this.settings.wsUrl);
                this.saveSettings();

                this.showToast('设置已保存', 'success');
            });
        }

        if (testBtn) {
            testBtn.addEventListener('click', () => this.testConnection());
        }
    },

    async testConnection() {
        const statusEl = document.getElementById('connectionTest');
        statusEl.innerHTML = '<div class="loading">测试中...</div>';

        try {
            await API.healthCheck();
            statusEl.innerHTML = '<div style="color: var(--success-color);">✅ 连接成功</div>';
            this.showToast('连接成功', 'success');
        } catch (error) {
            statusEl.innerHTML = `<div style="color: var(--error-color);">❌ 连接失败: ${error.message}</div>`;
            this.showToast('连接失败', 'error');
        }
    },

    initModules() {
        if (typeof Scanner !== 'undefined') Scanner.init();
        if (typeof Chat !== 'undefined') Chat.init();
        if (typeof Tools !== 'undefined') Tools.init();
        if (typeof Reports !== 'undefined') Reports.init();
    },

    connectWebSocket() {
        const wsUrl = API.getWebSocketUrl();
        this.ws = new WSManager(wsUrl);

        this.ws.onConnect(() => {
            this.updateConnectionStatus(true);
        });

        this.ws.onDisconnect(() => {
            this.updateConnectionStatus(false);
        });

        this.ws.onError((error) => {
            this.updateConnectionStatus(false);
            console.error('WebSocket error:', error);
        });

        this.ws.onReconnect((previousSessionId) => {
            console.log('WebSocket reconnected, restoring session state...');
            this.updateConnectionStatus(true);
            if (previousSessionId) {
                this.sessionId = previousSessionId;
                this.ws.send('subscribe', { session_id: previousSessionId });
            }
            if (typeof Chat !== 'undefined') {
                Chat.addMessage('🔄 已重新连接到服务器，会话已恢复', 'ai');
            }
        });

        this.ws.on('*', (data) => {
            this.handleWebSocketMessage(data);
        });

        this.ws.connect().then(sessionId => {
            this.sessionId = sessionId;
            console.log('Session ID:', sessionId);
        }).catch(error => {
            console.error('Failed to connect WebSocket:', error);
        });
    },

    updateConnectionStatus(connected) {
        const indicator = document.getElementById('connectionStatus');
        const text = document.getElementById('connectionText');

        if (connected) {
            indicator.className = 'status-indicator connected';
            text.textContent = '已连接';
        } else {
            indicator.className = 'status-indicator';
            text.textContent = '未连接';
        }
    },

    handleWebSocketMessage(data) {
        if (typeof Chat !== 'undefined') {
            Chat.handleWebSocketMessage(data);
        }
        if (typeof Scanner !== 'undefined') {
            Scanner.handleWebSocketMessage(data);
        }
    },

    getSessionId() {
        return this.sessionId || this.ws?.getSessionId();
    },

    updateCurrentTarget(target) {
        const el = document.getElementById('currentTarget');
        if (el) {
            el.textContent = target || '未设置';
        }
    },

    showToast(message, type = 'info') {
        const container = document.getElementById('toastContainer');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icon = {
            success: '✅',
            error: '❌',
            warning: '⚠️',
            info: 'ℹ️'
        }[type] || 'ℹ️';

        toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'slideIn 0.3s ease reverse';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
};

document.addEventListener('DOMContentLoaded', () => {
    App.init();
});

window.App = App;
