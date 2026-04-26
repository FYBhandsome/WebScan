const Chat = {
    messages: [],
    isTyping: false,
    waitingForChoice: false,
    currentInteraction: null,

    init() {
        this.bindEvents();
    },

    bindEvents() {
        const input = document.getElementById('chatInput');
        const sendBtn = document.getElementById('sendBtn');
        const quickActions = document.getElementById('quickActions');

        if (input) {
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    this.sendMessage();
                }
            });
        }

        if (sendBtn) {
            sendBtn.addEventListener('click', () => this.sendMessage());
        }

        if (quickActions) {
            quickActions.addEventListener('click', (e) => {
                if (e.target.classList.contains('quick-btn')) {
                    const action = e.target.dataset.action;
                    this.handleQuickAction(action);
                }
            });
        }
    },

    async sendMessage() {
        const input = document.getElementById('chatInput');
        const text = input.value.trim();

        if (!text) return;

        input.value = '';
        this.addMessage(text, 'user');

        if (this.waitingForChoice) {
            this.handleChatDuringScan(text);
            return;
        }

        if (this.isUrl(text)) {
            await this.handleScanRequest(text);
        } else {
            await this.handleChatRequest(text);
        }
    },

    isUrl(text) {
        const urlPattern = /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w-./?%&=#]*)?$/i;
        return urlPattern.test(text) || text.includes('.') && !text.includes(' ');
    },

    async handleScanRequest(target) {
        this.showTypingIndicator();
        
        try {
            if (App.ws && App.ws.isConnected()) {
                App.ws.startScan(target, 'full');
            } else {
                const result = await API.startFullScan(target);
                this.handleScanResult(result, target);
            }
        } catch (error) {
            this.hideTypingIndicator();
            this.addMessage('扫描失败: ' + error.message, 'ai');
        }
    },

    handleScanResult(result, target) {
        this.hideTypingIndicator();
        
        const data = result.data || result;
        let message = `🎯 扫描目标: ${target}\n\n`;

        if (data.completed_tasks && data.completed_tasks.length > 0) {
            message += `✅ 完成任务: ${data.completed_tasks.join(', ')}\n`;
        }

        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            message += `⚠️ 发现漏洞: ${data.vulnerabilities.length} 个\n`;
        }

        if (data.report) {
            message += `\n📄 报告已生成`;
        }

        this.addMessage(message, 'ai', true);
        App.updateCurrentTarget(target);
    },

    async handleChatRequest(text) {
        this.showTypingIndicator();

        try {
            if (App.ws && App.ws.isConnected()) {
                App.ws.sendChat(text);
            } else {
                const sessionId = App.getSessionId() || await this.createSession();
                if (sessionId) {
                    await API.sendChatMessage(sessionId, text);
                    const history = await API.getChatHistory(sessionId);
                    const lastMsg = history.data?.history?.slice(-1)[0];
                    if (lastMsg && lastMsg.role === 'assistant') {
                        this.hideTypingIndicator();
                        this.addMessage(lastMsg.content, 'ai');
                    }
                } else {
                    this.hideTypingIndicator();
                    this.addMessage(this.getFallbackResponse(text), 'ai');
                }
            }
        } catch (error) {
            this.hideTypingIndicator();
            this.addMessage(this.getFallbackResponse(text), 'ai');
        }
    },

    handleChatDuringScan(text) {
        if (text.toLowerCase() === 'stop' || text.toLowerCase() === '停止') {
            this.sendUserChoice('2');
        } else {
            if (App.ws && App.ws.isConnected()) {
                App.ws.sendChat(text);
            }
        }
    },

    async createSession() {
        try {
            const result = await API.createSession();
            return result.data?.session_id;
        } catch (error) {
            return null;
        }
    },

    getFallbackResponse(text) {
        const responses = {
            '你好': '你好！我是 TOSKill AI 安全助手，有什么可以帮助你的吗？',
            'help': '我可以帮助你进行 Web 安全扫描、漏洞检测、信息收集等工作。输入目标网址即可开始扫描。',
            '功能': '支持功能：\n1. 信息收集扫描\n2. 漏洞扫描\n3. 完整安全扫描\n4. 单独工具执行\n5. 报告生成与下载',
        };

        const key = text.toLowerCase();
        return responses[key] || '我理解你的问题。请输入目标网址开始安全扫描，或者切换到其他页面使用更多功能。';
    },

    handleQuickAction(action) {
        const input = document.getElementById('chatInput');
        const target = input.value.trim();

        if (!target) {
            App.showToast('请先输入扫描目标', 'warning');
            return;
        }

        switch (action) {
            case 'info':
                this.startQuickScan(target, 'info');
                break;
            case 'vuln':
                this.startQuickScan(target, 'vuln');
                break;
            case 'full':
                this.startQuickScan(target, 'full');
                break;
        }
    },

    async startQuickScan(target, mode) {
        this.addMessage(`开始${this.getModeName(mode)}: ${target}`, 'user');
        this.showTypingIndicator();

        try {
            let result;
            switch (mode) {
                case 'info':
                    result = await API.startInfoScan(target);
                    break;
                case 'vuln':
                    result = await API.startVulnScan(target);
                    break;
                case 'full':
                    result = await API.startFullScan(target);
                    break;
            }

            this.handleScanResult(result, target);
        } catch (error) {
            this.hideTypingIndicator();
            this.addMessage('扫描失败: ' + error.message, 'ai');
        }
    },

    getModeName(mode) {
        const names = {
            'info': '信息收集',
            'vuln': '漏洞扫描',
            'full': '完整扫描'
        };
        return names[mode] || mode;
    },

    addMessage(content, type = 'ai', hasActions = false, reportUrl = null, reportId = null) {
        const container = document.getElementById('chatMessages');
        const welcomeMsg = container.querySelector('.welcome-message');
        if (welcomeMsg) {
            welcomeMsg.remove();
        }

        const messageEl = document.createElement('div');
        messageEl.className = `message ${type}`;

        const avatar = type === 'ai' ? '🤖' : '👤';
        const avatarText = type === 'ai' ? 'AI' : '我';

        let actionsHtml = '';
        if (hasActions && type === 'ai') {
            actionsHtml = `
                <div class="message-actions">
                    <button class="action-btn" onclick="Chat.copyMessage(this)">复制</button>
                    <button class="action-btn primary" onclick="Chat.generateReport()">生成报告</button>
                </div>
            `;
        }
        
        let reportHtml = '';
        if (reportUrl && type === 'ai') {
            reportHtml = `
                <div class="report-link">
                    <a href="${API.baseUrl.replace('/api', '')}${reportUrl}" target="_blank" class="report-download-btn">
                        📥 下载报告
                    </a>
                    <span class="report-id">ID: ${reportId || ''}</span>
                </div>
            `;
        }

        messageEl.innerHTML = `
            <div class="message-avatar">${avatarText}</div>
            <div class="message-content">
                <div class="message-bubble">${this.escapeHtml(content)}</div>
                ${reportHtml}
                ${actionsHtml}
            </div>
        `;

        container.appendChild(messageEl);
        container.scrollTop = container.scrollHeight;

        this.messages.push({ type, content, timestamp: Date.now() });
    },

    addInteractionMessage(interaction) {
        const container = document.getElementById('chatMessages');
        const welcomeMsg = container.querySelector('.welcome-message');
        if (welcomeMsg) {
            welcomeMsg.remove();
        }

        const messageEl = document.createElement('div');
        messageEl.className = 'message ai interaction-required';
        messageEl.id = 'interactionMessage';

        const progress = interaction.completed_tasks?.length || 0;
        const total = interaction.options?.length > 0 ? 10 : 5;
        const progressPercent = Math.min((progress / total) * 100, 100);

        const optionsHtml = interaction.options.map(opt => `
            <button class="interaction-btn" data-choice="${opt.key}" onclick="Chat.sendUserChoice('${opt.key}')">
                <span class="choice-key">[${opt.key}]</span>
                <span class="choice-label">${opt.label}</span>
                <span class="choice-desc">${opt.description}</span>
            </button>
        `).join('');

        messageEl.innerHTML = `
            <div class="message-avatar">AI</div>
            <div class="message-content">
                <div class="message-bubble">
                    <div class="interaction-header">
                        <strong>🎯 需要您的选择</strong>
                    </div>
                    <div class="interaction-progress">
                        <div class="progress-bar" style="width: ${progressPercent}%"></div>
                        <span class="progress-text">已完成 ${progress} 个任务</span>
                    </div>
                    <div class="interaction-info">
                        <p><strong>目标:</strong> ${interaction.target}</p>
                        <p><strong>下一个任务:</strong> <code>${interaction.next_task}</code></p>
                    </div>
                </div>
                <div class="interaction-options">
                    ${optionsHtml}
                </div>
            </div>
        `;

        container.appendChild(messageEl);
        container.scrollTop = container.scrollHeight;

        this.waitingForChoice = true;
        this.currentInteraction = interaction;
    },

    sendUserChoice(choice) {
        const interactionMsg = document.getElementById('interactionMessage');
        if (interactionMsg) {
            const buttons = interactionMsg.querySelectorAll('.interaction-btn');
            buttons.forEach(btn => {
                btn.disabled = true;
                if (btn.dataset.choice === choice) {
                    btn.classList.add('selected');
                }
            });
        }

        if (App.ws && App.ws.isConnected()) {
            App.ws.send({
                type: 'user_choice',
                payload: { choice: choice }
            });
        }

        this.waitingForChoice = false;
        this.currentInteraction = null;

        const choiceLabels = {
            '1': '执行',
            '2': '停止',
            '3': '聊天'
        };
        this.addMessage(`选择了: ${choiceLabels[choice] || choice}`, 'user');
    },

    addStreamMessage(content, type = 'ai') {
        let messageEl = document.querySelector('.message.streaming');
        
        if (!messageEl) {
            const container = document.getElementById('chatMessages');
            messageEl = document.createElement('div');
            messageEl.className = `message ${type} streaming`;
            messageEl.innerHTML = `
                <div class="message-avatar">AI</div>
                <div class="message-content">
                    <div class="message-bubble"></div>
                </div>
            `;
            container.appendChild(messageEl);
        }

        const bubble = messageEl.querySelector('.message-bubble');
        bubble.textContent += content;

        const container = document.getElementById('chatMessages');
        container.scrollTop = container.scrollHeight;
    },

    finalizeStreamMessage() {
        const messageEl = document.querySelector('.message.streaming');
        if (messageEl) {
            messageEl.classList.remove('streaming');
            const content = messageEl.querySelector('.message-bubble').textContent;
            this.messages.push({ type: 'ai', content, timestamp: Date.now() });
        }
    },

    showTypingIndicator() {
        this.isTyping = true;
        const container = document.getElementById('chatMessages');
        
        const indicator = document.createElement('div');
        indicator.className = 'message ai typing';
        indicator.id = 'typingIndicator';
        indicator.innerHTML = `
            <div class="message-avatar">AI</div>
            <div class="message-content">
                <div class="typing-indicator">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
            </div>
        `;
        
        container.appendChild(indicator);
        container.scrollTop = container.scrollHeight;
    },

    hideTypingIndicator() {
        this.isTyping = false;
        const indicator = document.getElementById('typingIndicator');
        if (indicator) {
            indicator.remove();
        }
    },

    handleWebSocketMessage(data) {
        switch (data.type) {
            case 'connected':
                this.addMessage('✅ 已连接到服务器\n可用工具: ' + (data.payload.available_tools?.join(', ') || '加载中...') + '\n默认模式: ' + (data.payload.default_mode || 'full_scan'), 'ai');
                break;

            case 'ai_decision':
                this.addStreamMessage(`🤖 AI决策: 下一步执行 ${data.payload.next_task} (进度: ${data.payload.progress})`, 'ai');
                break;

            case 'ai_decision_complete':
                this.addStreamMessage(`✅ 所有扫描任务已完成，准备生成报告...`, 'ai');
                break;

            case 'task_started':
                this.addStreamMessage(`🔧 开始执行: ${data.payload.tool} -> ${data.payload.target}`, 'ai');
                break;

            case 'task_completed':
                const vulnIcon = data.payload.vulnerable ? '⚠️' : '✅';
                this.addStreamMessage(`${vulnIcon} ${data.payload.tool} 完成\n分析: ${data.payload.analysis}`, 'ai');
                break;

            case 'task_error':
                this.addStreamMessage(`❌ 任务失败: ${data.payload.tool} - ${data.payload.error}`, 'ai');
                break;

            case 'ai_chat':
                this.hideTypingIndicator();
                this.addMessage(data.payload.content, 'ai');
                break;

            case 'interaction_required':
                this.hideTypingIndicator();
                this.addInteractionMessage(data.payload);
                break;

            case 'workflow_resumed':
                const choiceLabels = { '1': '执行', '2': '停止', '3': '聊天' };
                this.addMessage(`✅ 工作流已恢复: ${choiceLabels[data.payload.choice] || data.payload.choice}`, 'ai');
                break;

            case 'scan_started':
                this.hideTypingIndicator();
                this.addMessage(`🔍 开始扫描: ${data.payload.target}\n模式: ${this.getModeName(data.payload.mode)}`, 'ai');
                break;

            case 'scan_completed':
                this.hideTypingIndicator();
                const result = data.payload;
                let scanMsg = `✅ 扫描完成\n`;
                scanMsg += `目标: ${result.target}\n`;
                scanMsg += `完成任务: ${result.completed_tasks?.length || 0} 个\n`;
                if (result.vulnerabilities_count > 0) {
                    scanMsg += `⚠️ 发现漏洞: ${result.vulnerabilities_count} 个\n`;
                }
                if (result.report_url) {
                    scanMsg += `\n📄 报告已生成`;
                }
                this.addMessage(scanMsg, 'ai', false, result.report_url, result.report_id);
                break;

            case 'scan_cancelled':
                this.hideTypingIndicator();
                this.addMessage('⏹️ 扫描已取消', 'ai');
                this.waitingForChoice = false;
                break;

            case 'report_generation_started':
                this.addStreamMessage(`📄 正在生成报告...\n工具数: ${data.payload.tool_count} | 漏洞数: ${data.payload.vulnerability_count}`, 'ai');
                break;

            case 'report_generated':
                this.addMessage('✅ 报告已生成', 'ai', false, data.payload.report_url, data.payload.report_id);
                break;

            case 'report_error':
                this.addMessage(`❌ 报告生成失败: ${data.payload.error}`, 'ai');
                break;

            case 'tool_execution_started':
                this.addMessage(`🔧 执行工具: ${data.payload.tool_name}`, 'ai');
                break;

            case 'tool_execution_completed':
                this.addMessage(`✅ 工具执行完成: ${data.payload.tool_name}`, 'ai');
                break;

            case 'error':
                this.hideTypingIndicator();
                this.addMessage('❌ 错误: ' + data.payload.error, 'ai');
                break;
        }
    },

    copyMessage(btn) {
        const bubble = btn.closest('.message-content').querySelector('.message-bubble');
        navigator.clipboard.writeText(bubble.textContent).then(() => {
            btn.textContent = '已复制';
            setTimeout(() => btn.textContent = '复制', 1500);
        });
    },

    async generateReport() {
        const sessionId = App.getSessionId();
        if (!sessionId) {
            App.showToast('请先进行扫描', 'warning');
            return;
        }

        try {
            const result = await API.generateReport(sessionId);
            this.addMessage('📄 报告已生成\n' + (result.data?.report || ''), 'ai');
        } catch (error) {
            App.showToast('报告生成失败: ' + error.message, 'error');
        }
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    clear() {
        const container = document.getElementById('chatMessages');
        container.innerHTML = `
            <div class="welcome-message">
                <div class="welcome-icon">🚀</div>
                <h2>欢迎使用 TOSKill Security Scanner</h2>
                <p>AI驱动的Web安全扫描系统，输入目标开始扫描</p>
            </div>
        `;
        this.messages = [];
        this.waitingForChoice = false;
        this.currentInteraction = null;
    }
};

window.Chat = Chat;
