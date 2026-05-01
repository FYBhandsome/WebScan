const Scanner = {
    currentScan: null,
    tasks: [],
    completedTasks: 0,
    totalTasks: 0,

    init() {
        this.bindEvents();
    },

    bindEvents() {
        const startBtn = document.getElementById('startScanBtn');
        if (startBtn) {
            startBtn.addEventListener('click', () => this.startScan());
        }
    },

    async startScan() {
        const targetInput = document.getElementById('scanTarget');
        const modeSelect = document.getElementById('scanMode');
        
        const target = targetInput.value.trim();
        const mode = modeSelect.value;

        if (!target) {
            App.showToast('请输入扫描目标', 'warning');
            return;
        }

        const startBtn = document.getElementById('startScanBtn');
        startBtn.disabled = true;
        startBtn.textContent = '扫描中...';

        this.showProgress();
        this.updateProgress(0, '正在初始化扫描...');

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

            this.handleScanResult(result);
            App.showToast('扫描完成', 'success');
            App.updateCurrentTarget(target);

        } catch (error) {
            App.showToast('扫描失败: ' + error.message, 'error');
            this.hideProgress();
        } finally {
            startBtn.disabled = false;
            startBtn.textContent = '开始扫描';
        }
    },

    showProgress() {
        const progressEl = document.getElementById('scanProgress');
        const resultsEl = document.getElementById('scanResults');
        
        progressEl.style.display = 'block';
        resultsEl.style.display = 'none';
        
        this.completedTasks = 0;
        this.totalTasks = 0;
        this.tasks = [];
    },

    hideProgress() {
        document.getElementById('scanProgress').style.display = 'none';
    },

    updateProgress(percent, status) {
        const fillEl = document.getElementById('progressFill');
        const statusEl = document.getElementById('progressStatus');
        
        fillEl.style.width = percent + '%';
        statusEl.textContent = status;
    },

    addTask(taskName, status = 'pending') {
        this.tasks.push({ name: taskName, status: status });
        this.totalTasks++;
        this.renderTasks();
    },

    updateTaskStatus(taskName, status) {
        const task = this.tasks.find(t => t.name === taskName);
        if (task) {
            task.status = status;
            if (status === 'completed' || status === 'error') {
                this.completedTasks++;
            }
            this.renderTasks();
            
            const percent = Math.round((this.completedTasks / this.totalTasks) * 100);
            this.updateProgress(percent, `已完成 ${this.completedTasks}/${this.totalTasks} 任务`);
        }
    },

    renderTasks() {
        const taskListEl = document.getElementById('taskList');
        taskListEl.innerHTML = this.tasks.map(task => `
            <div class="task-item">
                <div class="task-status ${task.status}">
                    ${this.getTaskIcon(task.status)}
                </div>
                <span class="task-name">${task.name}</span>
            </div>
        `).join('');
    },

    getTaskIcon(status) {
        switch (status) {
            case 'pending': return '○';
            case 'running': return '◐';
            case 'completed': return '✓';
            case 'error': return '✗';
            default: return '○';
        }
    },

    handleScanResult(result) {
        const resultsEl = document.getElementById('scanResults');
        const contentEl = document.getElementById('resultsContent');

        this.updateProgress(100, '扫描完成');

        const data = result.data || result;
        let html = '';

        if (data.completed_tasks && data.completed_tasks.length > 0) {
            html += `
                <div class="result-section">
                    <h4>完成的任务</h4>
                    ${data.completed_tasks.map(t => `<div class="result-item">${t}</div>`).join('')}
                </div>
            `;
        }

        if (data.tool_results) {
            html += `
                <div class="result-section">
                    <h4>工具执行结果</h4>
                    ${Object.entries(data.tool_results).map(([tool, result]) => `
                        <div class="result-item">
                            <strong>${tool}</strong>
                            <div class="code-block">${this.formatResult(result)}</div>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            html += `
                <div class="result-section">
                    <h4>发现的漏洞 (${data.vulnerabilities.length})</h4>
                    ${data.vulnerabilities.map(vuln => `
                        <div class="vulnerability-item ${vuln.severity || 'medium'}">
                            <strong>${vuln.name || vuln.type || '未知漏洞'}</strong>
                            <p>${vuln.description || vuln.details || ''}</p>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        if (data.report) {
            html += `
                <div class="result-section">
                    <h4>扫描报告</h4>
                    <div class="code-block">${data.report}</div>
                </div>
            `;
        }

        if (data.errors && data.errors.length > 0) {
            html += `
                <div class="result-section">
                    <h4>错误信息</h4>
                    ${data.errors.map(e => `<div class="result-item" style="color: var(--error-color);">${e}</div>`).join('')}
                </div>
            `;
        }

        if (!html) {
            html = '<div class="result-section"><p>扫描完成，未发现异常</p></div>';
        }

        contentEl.innerHTML = html;
        resultsEl.style.display = 'block';

        this.currentScan = data;
    },

    formatResult(result) {
        if (typeof result === 'string') {
            try {
                result = JSON.parse(result);
            } catch (e) {
                return result;
            }
        }
        
        if (typeof result === 'object') {
            return JSON.stringify(result, null, 2);
        }
        
        return String(result);
    },

    handleWebSocketMessage(data) {
        switch (data.type) {
            case 'scan_started':
                this.addTask(data.payload.task_id, 'running');
                this.updateProgress(10, '扫描已启动');
                break;

            case 'tool_execution_started':
                this.addTask(data.payload.tool_name, 'running');
                break;

            case 'tool_execution_completed':
                this.updateTaskStatus(data.payload.tool_name, 'completed');
                break;

            case 'scan_completed':
                this.updateProgress(100, '扫描完成');
                this.handleScanResult(data.payload);
                break;

            case 'scan_cancelled':
                this.updateProgress(0, '扫描已取消');
                App.showToast('扫描已取消', 'warning');
                break;

            case 'error':
                App.showToast('扫描错误: ' + data.payload.error, 'error');
                break;

            case 'task_skipped':
                this.updateTaskStatus(data.payload.tool, 'error');
                App.showToast('任务跳过: ' + data.payload.reason, 'warning');
                break;

            case 'task_error':
                this.updateTaskStatus(data.payload.tool, 'error');
                App.showToast('任务失败: ' + data.payload.error, 'error');
                break;

            case 'workflow_progress':
                const progressData = data.payload;
                if (progressData.progress_percent !== undefined) {
                    this.updateProgress(progressData.progress_percent, 
                        `${progressData.stage || '扫描中'} - ${progressData.completed}/${progressData.total}`);
                }
                break;

            case 'ai_decision':
                const decisionData = data.payload;
                this.updateProgress(
                    Math.round((decisionData.completed_tasks?.length || 0) / (decisionData.total_tasks || 1) * 100),
                    `AI决策: 下一步 ${decisionData.next_task}`
                );
                break;
        }
    }
};

window.Scanner = Scanner;
