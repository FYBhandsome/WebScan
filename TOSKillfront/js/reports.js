const Reports = {
    reports: [],
    currentReport: null,

    init() {
        this.bindEvents();
        this.loadReports();
    },

    bindEvents() {
        const refreshBtn = document.getElementById('refreshReports');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadReports());
        }

        const closeBtn = document.getElementById('closeViewer');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.hideViewer());
        }

        const downloadBtn = document.getElementById('downloadReport');
        if (downloadBtn) {
            downloadBtn.addEventListener('click', () => this.downloadCurrentReport());
        }
    },

    async loadReports() {
        const listEl = document.getElementById('reportsList');
        listEl.innerHTML = '<div class="loading">加载报告列表...</div>';

        try {
            const result = await API.getReports();
            this.reports = result.reports || [];
            this.renderReports();
        } catch (error) {
            listEl.innerHTML = `<div class="error">加载失败: ${error.message}</div>`;
        }
    },

    renderReports() {
        const listEl = document.getElementById('reportsList');

        if (this.reports.length === 0) {
            listEl.innerHTML = '<div class="loading">暂无报告</div>';
            return;
        }

        listEl.innerHTML = this.reports.map(report => `
            <div class="report-card" data-report="${report.name}">
                <div class="report-info">
                    <h4>${report.name}</h4>
                    <p>大小: ${this.formatSize(report.size)} | 修改时间: ${this.formatDate(report.modified_at)}</p>
                </div>
                <div class="report-actions">
                    <button class="action-btn" onclick="Reports.viewReport('${report.name}')">查看</button>
                    <button class="action-btn" onclick="Reports.downloadReport('${report.name}')">下载</button>
                    <button class="action-btn" onclick="Reports.deleteReport('${report.name}')">删除</button>
                </div>
            </div>
        `).join('');
    },

    async viewReport(filename) {
        const viewerEl = document.getElementById('reportViewer');
        const titleEl = document.getElementById('reportTitle');
        const contentEl = document.getElementById('viewerContent');

        titleEl.textContent = filename;
        contentEl.innerHTML = '<div class="loading">加载中...</div>';
        viewerEl.style.display = 'flex';

        this.currentReport = filename;

        try {
            const result = await API.getReportContent(filename);
            contentEl.innerHTML = `<pre style="white-space: pre-wrap; word-break: break-word;">${this.escapeHtml(result.content)}</pre>`;
        } catch (error) {
            contentEl.innerHTML = `<div class="error">加载失败: ${error.message}</div>`;
        }
    },

    hideViewer() {
        document.getElementById('reportViewer').style.display = 'none';
        this.currentReport = null;
    },

    downloadReport(filename) {
        const url = API.getReportDownloadUrl(filename);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        link.click();
        App.showToast('开始下载', 'success');
    },

    downloadCurrentReport() {
        if (this.currentReport) {
            this.downloadReport(this.currentReport);
        }
    },

    async deleteReport(filename) {
        if (!confirm(`确定要删除报告 "${filename}" 吗？`)) {
            return;
        }

        try {
            await API.deleteReport(filename);
            App.showToast('删除成功', 'success');
            this.loadReports();
        } catch (error) {
            App.showToast('删除失败: ' + error.message, 'error');
        }
    },

    formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    },

    formatDate(dateStr) {
        const date = new Date(dateStr);
        return date.toLocaleString('zh-CN', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        });
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    getReports() {
        return this.reports;
    }
};

window.Reports = Reports;
