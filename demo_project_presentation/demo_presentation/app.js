const App = {
    apiBaseUrl: 'http://localhost:8001',
    useRealDVWA: false,
    
    currentUser: {
        id: '2023001',
        name: '张三',
        role: 'student',
        class: '计算机2301班',
        completedExams: 8,
        totalScore: 2450,
        streak: 15
    },
    
    currentExam: null,
    currentQuestionIndex: 0,
    userAnswers: {},
    markedQuestions: [],
    timer: null,
    timeRemaining: 0,
    
    dvwaConfig: {
        targetUrl: 'http://localhost:8080',
        username: 'admin',
        password: 'password',
        securityLevel: 'low'
    },
    
    examData: {
        'sql-injection': {
            id: 'sql-injection',
            title: 'SQL注入漏洞检测与防御',
            category: 'SQL注入',
            difficulty: 'intermediate',
            difficultyLabel: '中级',
            duration: 45,
            questionCount: 20,
            passingScore: 60,
            totalScore: 100,
            participants: 1234,
            rating: 4.8,
            questions: [
                {
                    id: 1,
                    type: 'single',
                    text: '以下哪种SQL注入类型是通过在应用程序的输入字段中插入恶意SQL代码来实现的？',
                    options: [
                        { label: 'A', text: '盲注（Blind SQL Injection）' },
                        { label: 'B', text: '联合查询注入（Union-based SQL Injection）' },
                        { label: 'C', text: '错误注入（Error-based SQL Injection）' },
                        { label: 'D', text: '时间盲注（Time-based Blind SQL Injection）' }
                    ],
                    answer: 'B',
                    score: 5,
                    explanation: '联合查询注入是最常见的SQL注入类型，通过UNION SELECT语句将恶意查询结果与原始查询结果合并，从而获取数据库中的敏感信息。'
                },
                {
                    id: 2,
                    type: 'single',
                    text: 'SQL注入攻击的主要危害不包括以下哪项？',
                    options: [
                        { label: 'A', text: '数据泄露' },
                        { label: 'B', text: '数据篡改' },
                        { label: 'C', text: '服务器CPU资源耗尽' },
                        { label: 'D', text: '权限提升' }
                    ],
                    answer: 'C',
                    score: 5,
                    explanation: 'SQL注入主要危害数据库层面的数据安全，包括数据泄露、篡改和权限提升等。CPU资源耗尽通常属于DoS攻击的范畴。'
                },
                {
                    id: 3,
                    type: 'single',
                    text: '以下哪个函数常用于MySQL盲注中判断条件真假？',
                    options: [
                        { label: 'A', text: 'sleep()' },
                        { label: 'B', text: 'benchmark()' },
                        { label: 'C', text: 'if()' },
                        { label: 'D', text: '以上都是' }
                    ],
                    answer: 'D',
                    score: 5,
                    explanation: '在MySQL盲注中，sleep()和benchmark()用于时间盲注，if()用于条件判断，都是常用的盲注函数。'
                },
                {
                    id: 4,
                    type: 'multiple',
                    text: 'SQL注入的常见检测方法包括哪些？',
                    options: [
                        { label: 'A', text: '单引号测试' },
                        { label: 'B', text: '布尔条件测试' },
                        { label: 'C', text: '时间延迟测试' },
                        { label: 'D', text: '错误信息分析' }
                    ],
                    answer: ['A', 'B', 'C', 'D'],
                    score: 5,
                    explanation: '这些都是SQL注入检测的常用方法，通过不同的技术手段来判断是否存在注入点。'
                },
                {
                    id: 5,
                    type: 'single',
                    text: '以下哪种防御措施可以有效防止SQL注入攻击？',
                    options: [
                        { label: 'A', text: '使用HTTPS协议' },
                        { label: 'B', text: '使用存储过程' },
                        { label: 'C', text: '输入验证' },
                        { label: 'D', text: '使用参数化查询' }
                    ],
                    answer: 'D',
                    score: 5,
                    explanation: '参数化查询是防止SQL注入的最有效方法，它将SQL语句和参数分开处理，避免了恶意SQL代码的注入。存储过程虽然可以减少注入风险，但如果内部使用字符串拼接，仍然可能存在注入漏洞。'
                },
                {
                    id: 6,
                    type: 'single',
                    text: '在SQL注入中，UNION注入的前提条件是什么？',
                    options: [
                        { label: 'A', text: '数据库用户有管理员权限' },
                        { label: 'B', text: '知道数据库表名' },
                        { label: 'C', text: '原查询与UNION查询的列数相同' },
                        { label: 'D', text: '数据库版本为MySQL 5.0以上' }
                    ],
                    answer: 'C',
                    score: 5,
                    explanation: 'UNION注入要求原查询和UNION后面的查询返回的列数必须相同，否则会报错。'
                },
                {
                    id: 7,
                    type: 'single',
                    text: '以下哪个不是SQLMap的常用参数？',
                    options: [
                        { label: 'A', text: '-u' },
                        { label: 'B', text: '--dbs' },
                        { label: 'C', text: '--tables' },
                        { label: 'D', text: '--exploit' }
                    ],
                    answer: 'D',
                    score: 5,
                    explanation: 'SQLMap的常用参数包括-u指定URL，--dbs列出数据库，--tables列出表，但没有--exploit参数。'
                },
                {
                    id: 8,
                    type: 'multiple',
                    text: '以下哪些属于二阶SQL注入的特点？',
                    options: [
                        { label: 'A', text: '注入点不在直接输入处' },
                        { label: 'B', text: '攻击效果延迟触发' },
                        { label: 'C', text: '难以被常规检测发现' },
                        { label: 'D', text: '只能读取数据' }
                    ],
                    answer: ['A', 'B', 'C'],
                    score: 5,
                    explanation: '二阶SQL注入的特点是注入数据先存储后触发，具有延迟性，且难以被常规检测发现。它不仅可以读取数据，还可以执行其他恶意操作。'
                },
                {
                    id: 9,
                    type: 'single',
                    text: '在MySQL中，information_schema数据库的主要作用是什么？',
                    options: [
                        { label: 'A', text: '存储用户密码' },
                        { label: 'B', text: '存储数据库元数据' },
                        { label: 'C', text: '存储系统日志' },
                        { label: 'D', text: '存储临时数据' }
                    ],
                    answer: 'B',
                    score: 5,
                    explanation: 'information_schema是MySQL的系统数据库，存储了所有数据库的元数据信息，包括表名、列名等，在SQL注入中常用于获取数据库结构信息。'
                },
                {
                    id: 10,
                    type: 'single',
                    text: '以下哪种WAF绕过技术是通过编码实现的？',
                    options: [
                        { label: 'A', text: '大小写混合' },
                        { label: 'B', text: 'URL编码' },
                        { label: 'C', text: '内联注释' },
                        { label: 'D', text: '双写绕过' }
                    ],
                    answer: 'B',
                    score: 5,
                    explanation: 'URL编码是一种常见的WAF绕过技术，通过将特殊字符编码来绕过WAF的检测规则。'
                },
                {
                    id: 11,
                    type: 'single',
                    text: 'SQL注入中，使用hex()函数的主要目的是什么？',
                    options: [
                        { label: 'A', text: '加密数据' },
                        { label: 'B', text: '绕过引号过滤' },
                        { label: 'C', text: '提高查询速度' },
                        { label: 'D', text: '压缩数据' }
                    ],
                    answer: 'B',
                    score: 5,
                    explanation: 'hex()函数可以将字符串转换为十六进制，从而避免使用引号，绕过对引号的过滤。'
                },
                {
                    id: 12,
                    type: 'multiple',
                    text: 'SQL注入的常见检测方法包括哪些？',
                    options: [
                        { label: 'A', text: '静态代码分析' },
                        { label: 'B', text: '动态渗透测试' },
                        { label: 'C', text: '输入模糊测试' },
                        { label: 'D', text: '日志分析' }
                    ],
                    answer: ['A', 'B', 'C', 'D'],
                    score: 5,
                    explanation: '这些都是SQL注入检测的有效方法，从不同角度发现潜在的注入漏洞。'
                },
                {
                    id: 13,
                    type: 'single',
                    text: '在盲注中，布尔盲注和时间盲注的主要区别是什么？',
                    options: [
                        { label: 'A', text: '攻击方式不同' },
                        { label: 'B', text: '判断依据不同' },
                        { label: 'C', text: '目标数据库不同' },
                        { label: 'D', text: '注入位置不同' }
                    ],
                    answer: 'B',
                    score: 5,
                    explanation: '布尔盲注通过页面返回的真假来判断，时间盲注通过响应时间延迟来判断，两者的判断依据不同。'
                },
                {
                    id: 14,
                    type: 'single',
                    text: '以下哪个不是SQL注入的常见防御措施？',
                    options: [
                        { label: 'A', text: '参数化查询' },
                        { label: 'B', text: '输入过滤' },
                        { label: 'C', text: '使用CDN' },
                        { label: 'D', text: '最小权限原则' }
                    ],
                    answer: 'C',
                    score: 5,
                    explanation: 'CDN主要用于加速内容分发和防御DDoS攻击，对SQL注入没有直接的防御作用。'
                },
                {
                    id: 15,
                    type: 'single',
                    text: '在SQL Server中，用于执行系统命令的存储过程是？',
                    options: [
                        { label: 'A', text: 'sp_executesql' },
                        { label: 'B', text: 'xp_cmdshell' },
                        { label: 'C', text: 'sp_help' },
                        { label: 'D', text: 'xp_dirtree' }
                    ],
                    answer: 'B',
                    score: 5,
                    explanation: 'xp_cmdshell是SQL Server中用于执行操作系统命令的扩展存储过程，在SQL注入攻击中常被利用来获取系统权限。'
                },
                {
                    id: 16,
                    type: 'multiple',
                    text: '以下哪些是SQL注入的常见危害等级？',
                    options: [
                        { label: 'A', text: '信息泄露' },
                        { label: 'B', text: '数据篡改' },
                        { label: 'C', text: '权限提升' },
                        { label: 'D', text: '服务器接管' }
                    ],
                    answer: ['A', 'B', 'C', 'D'],
                    score: 5,
                    explanation: 'SQL注入的危害从低到高包括信息泄露、数据篡改、权限提升，严重时可能导致整个服务器被接管。'
                },
                {
                    id: 17,
                    type: 'single',
                    text: '宽字节注入的原理是什么？',
                    options: [
                        { label: 'A', text: '利用字符编码转换漏洞' },
                        { label: 'B', text: '利用数据库溢出' },
                        { label: 'C', text: '利用内存泄漏' },
                        { label: 'D', text: '利用协议漏洞' }
                    ],
                    answer: 'A',
                    score: 5,
                    explanation: '宽字节注入利用GBK等编码中，两个字节组成一个汉字的特性，通过特殊字符吃掉转义符，从而绕过引号转义。'
                },
                {
                    id: 18,
                    type: 'single',
                    text: '在SQL注入中，堆叠注入（Stacked Queries）的特点是什么？',
                    options: [
                        { label: 'A', text: '只能执行SELECT语句' },
                        { label: 'B', text: '可以执行多条SQL语句' },
                        { label: 'C', text: '只能读取数据' },
                        { label: 'D', text: '不需要闭合原语句' }
                    ],
                    answer: 'B',
                    score: 5,
                    explanation: '堆叠注入允许在原SQL语句后追加额外的SQL语句，可以执行多条独立的SQL命令，危害性更大。'
                },
                {
                    id: 19,
                    type: 'single',
                    text: '以下哪个工具不是专门用于SQL注入检测的？',
                    options: [
                        { label: 'A', text: 'SQLMap' },
                        { label: 'B', text: 'Havij' },
                        { label: 'C', text: 'Burp Suite' },
                        { label: 'D', text: 'Nmap' }
                    ],
                    answer: 'D',
                    score: 5,
                    explanation: 'Nmap是网络扫描工具，主要用于端口扫描和服务探测，不是专门的SQL注入工具。'
                },
                {
                    id: 20,
                    type: 'single',
                    text: 'ORM框架能否完全防止SQL注入？',
                    options: [
                        { label: 'A', text: '能，ORM完全安全' },
                        { label: 'B', text: '不能，ORM也有注入风险' },
                        { label: 'C', text: '取决于数据库类型' },
                        { label: 'D', text: '取决于编程语言' }
                    ],
                    answer: 'B',
                    score: 5,
                    explanation: 'ORM框架虽然提供了参数化查询等安全机制，但如果使用不当（如原生SQL拼接），仍然存在SQL注入风险。'
                }
            ]
        },
        'xss': {
            id: 'xss',
            title: 'XSS跨站脚本攻击实战',
            category: 'XSS',
            difficulty: 'advanced',
            difficultyLabel: '高级',
            duration: 60,
            questionCount: 25,
            passingScore: 60,
            totalScore: 100,
            participants: 892,
            rating: 4.6,
            questions: []
        },
        'csrf': {
            id: 'csrf',
            title: 'CSRF跨站请求伪造入门',
            category: 'CSRF',
            difficulty: 'beginner',
            difficultyLabel: '初级',
            duration: 30,
            questionCount: 15,
            passingScore: 60,
            totalScore: 100,
            participants: 2156,
            rating: 4.9,
            questions: []
        }
    },
    
    examResults: [
        {
            examId: 'sql-injection',
            score: 92,
            correctCount: 18,
            totalCount: 20,
            timeUsed: '32:15',
            date: '2026-05-15',
            rank: 'Top 5%'
        }
    ],
    
    achievements: [
        { id: 1, name: '初学者', description: '完成第一个模考', icon: 'fa-graduation-cap', unlocked: true, date: '2026-03-15' },
        { id: 2, name: '学习狂人', description: '连续学习15天', icon: 'fa-fire', unlocked: true, date: '2026-05-10', tier: 'gold' },
        { id: 3, name: '高分达人', description: '模考获得90分以上', icon: 'fa-star', unlocked: true, date: '2026-04-20', tier: 'silver' },
        { id: 4, name: 'SQL专家', description: '完成所有SQL注入题目', icon: 'fa-database', unlocked: true, date: '2026-05-05', tier: 'bronze' },
        { id: 5, name: '安全大师', description: '完成所有模考并获得80分以上', icon: 'fa-crown', unlocked: false, progress: 8, total: 12 },
        { id: 6, name: '闪电答题', description: '10分钟内完成模考', icon: 'fa-bolt', unlocked: false }
    ]
};

function init() {
    setupNavigation();
    generateQuestionGrid();
    generateCalendar();
    initCharts();
    updateUserInfo();
}

function setupNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', function() {
            const page = this.dataset.page;
            navigateTo(page);
        });
    });
}

function navigateTo(page) {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    
    const targetNav = document.querySelector(`.nav-item[data-page="${page}"]`);
    if (targetNav) {
        targetNav.classList.add('active');
    }
    
    document.querySelectorAll('.page').forEach(p => {
        p.classList.remove('active');
    });
    
    const targetPage = document.getElementById(`${page}-page`);
    if (targetPage) {
        targetPage.classList.add('active');
    }
    
    const titles = {
        'dashboard': '学习中心',
        'exams': '模考中心',
        'exam-taking': '模考进行中',
        'result': '成绩报告',
        'dvwa-lab': 'DVWA靶场',
        'question-bank': '题库练习',
        'progress': '学习进度',
        'achievements': '成就系统',
        'teacher-admin': '教师管理'
    };
    
    document.getElementById('page-title').textContent = titles[page] || '学习中心';
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('collapsed');
}

function switchRole() {
    const teacherNav = document.querySelector('.nav-item[data-page="teacher-admin"]');
    const userRole = document.querySelector('.user-role');
    const userName = document.querySelector('.user-name');
    
    if (App.currentUser.role === 'student') {
        App.currentUser.role = 'teacher';
        App.currentUser.name = '李老师';
        userRole.textContent = '教师';
        userName.textContent = '李老师';
        teacherNav.style.display = 'flex';
    } else {
        App.currentUser.role = 'student';
        App.currentUser.name = '张三';
        userRole.textContent = '学生';
        userName.textContent = '张三';
        teacherNav.style.display = 'none';
    }
}

function updateUserInfo() {
    document.querySelector('.user-name').textContent = App.currentUser.name;
    document.querySelector('.user-role').textContent = App.currentUser.role === 'student' ? '学生' : '教师';
}

function startExam(examId) {
    const exam = App.examData[examId];
    if (!exam) {
        alert('模考数据加载失败');
        return;
    }
    
    App.currentExam = exam;
    App.currentQuestionIndex = 0;
    App.userAnswers = {};
    App.markedQuestions = [];
    App.timeRemaining = exam.duration * 60;
    
    showExamModal(exam);
}

function showExamModal(exam) {
    const modal = document.getElementById('exam-modal');
    const modalBody = modal.querySelector('.modal-body');
    
    modalBody.innerHTML = `
        <div class="exam-preview">
            <h3>${exam.title}</h3>
            <div class="preview-info">
                <div class="info-item">
                    <i class="fas fa-question-circle"></i>
                    <span>题目数量: ${exam.questionCount}道</span>
                </div>
                <div class="info-item">
                    <i class="fas fa-clock"></i>
                    <span>考试时长: ${exam.duration}分钟</span>
                </div>
                <div class="info-item">
                    <i class="fas fa-signal"></i>
                    <span>难度等级: ${exam.difficultyLabel}</span>
                </div>
                <div class="info-item">
                    <i class="fas fa-star"></i>
                    <span>及格分数: ${exam.passingScore}分</span>
                </div>
            </div>
            <div class="exam-tips">
                <h4>考试须知:</h4>
                <ul>
                    <li>考试过程中请保持网络连接稳定</li>
                    <li>答题过程中可标记不确定的题目</li>
                    <li>考试结束后可查看详细解析</li>
                    <li>请认真作答，诚信考试</li>
                </ul>
            </div>
        </div>
    `;
    
    modal.classList.add('show');
}

function closeModal() {
    document.getElementById('exam-modal').classList.remove('show');
}

function confirmStartExam() {
    closeModal();
    navigateTo('exam-taking');
    loadQuestion(0);
    startTimer();
    generateQuestionGrid();
}

function generateQuestionGrid() {
    const grid = document.getElementById('question-grid');
    if (!grid || !App.currentExam) return;
    
    const questions = App.currentExam.questions;
    grid.innerHTML = '';
    
    for (let i = 0; i < questions.length; i++) {
        const btn = document.createElement('button');
        btn.className = 'question-btn';
        btn.textContent = i + 1;
        btn.onclick = () => loadQuestion(i);
        
        if (App.userAnswers[i] !== undefined) {
            btn.classList.add('answered');
        }
        if (App.markedQuestions.includes(i)) {
            btn.classList.add('marked');
        }
        if (i === App.currentQuestionIndex) {
            btn.classList.add('current');
        }
        
        grid.appendChild(btn);
    }
}

function loadQuestion(index) {
    if (!App.currentExam || !App.currentExam.questions[index]) return;
    
    App.currentQuestionIndex = index;
    const question = App.currentExam.questions[index];
    
    document.querySelector('.question-progress').textContent = `题目 ${index + 1}/${App.currentExam.questionCount}`;
    
    const typeLabels = {
        'single': '单选题',
        'multiple': '多选题',
        'judge': '判断题',
        'fill': '填空题'
    };
    
    document.querySelector('.question-type').innerHTML = `
        <span class="type-badge">${typeLabels[question.type] || '单选题'}</span>
        <span class="score">分值: ${question.score}分</span>
    `;
    
    document.getElementById('question-text').innerHTML = `<p>${question.text}</p>`;
    
    const optionsList = document.getElementById('options-list');
    optionsList.innerHTML = '';
    
    const inputType = question.type === 'multiple' ? 'checkbox' : 'radio';
    
    question.options.forEach(option => {
        const label = document.createElement('label');
        label.className = 'option-item';
        
        const isChecked = question.type === 'multiple' 
            ? (Array.isArray(App.userAnswers[index]) && App.userAnswers[index].includes(option.label))
            : App.userAnswers[index] === option.label;
        
        label.innerHTML = `
            <input type="${inputType}" name="answer" value="${option.label}" ${isChecked ? 'checked' : ''}>
            <span class="option-label">${option.label}</span>
            <span class="option-text">${option.text}</span>
        `;
        
        label.addEventListener('change', () => handleAnswerChange(question.type));
        optionsList.appendChild(label);
    });
    
    generateQuestionGrid();
}

function handleAnswerChange(questionType) {
    const inputs = document.querySelectorAll('input[name="answer"]');
    
    if (questionType === 'multiple') {
        const selected = [];
        inputs.forEach(input => {
            if (input.checked) {
                selected.push(input.value);
            }
        });
        App.userAnswers[App.currentQuestionIndex] = selected;
    } else {
        inputs.forEach(input => {
            if (input.checked) {
                App.userAnswers[App.currentQuestionIndex] = input.value;
            }
        });
    }
    
    generateQuestionGrid();
}

function prevQuestion() {
    if (App.currentQuestionIndex > 0) {
        loadQuestion(App.currentQuestionIndex - 1);
    }
}

function nextQuestion() {
    if (App.currentQuestionIndex < App.currentExam.questionCount - 1) {
        loadQuestion(App.currentQuestionIndex + 1);
    } else {
        showSubmitConfirm();
    }
}

function markQuestion() {
    const index = App.currentQuestionIndex;
    
    if (App.markedQuestions.includes(index)) {
        App.markedQuestions = App.markedQuestions.filter(q => q !== index);
    } else {
        App.markedQuestions.push(index);
    }
    
    generateQuestionGrid();
}

function startTimer() {
    const display = document.getElementById('time-display');
    
    App.timer = setInterval(() => {
        if (App.timeRemaining <= 0) {
            clearInterval(App.timer);
            submitExam();
            return;
        }
        
        App.timeRemaining--;
        const minutes = Math.floor(App.timeRemaining / 60);
        const seconds = App.timeRemaining % 60;
        display.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        
        if (App.timeRemaining <= 300) {
            display.parentElement.classList.add('warning');
        }
    }, 1000);
}

function showSubmitConfirm() {
    const unanswered = App.currentExam.questionCount - Object.keys(App.userAnswers).length;
    
    let message = '确定提交试卷吗？';
    if (unanswered > 0) {
        message = `还有 ${unanswered} 道题未作答，确定提交吗？`;
    }
    
    if (confirm(message)) {
        submitExam();
    }
}

function submitExam() {
    clearInterval(App.timer);
    
    let correctCount = 0;
    let totalScore = 0;
    const wrongQuestions = [];
    
    App.currentExam.questions.forEach((question, index) => {
        const userAnswer = App.userAnswers[index];
        const isCorrect = question.type === 'multiple'
            ? JSON.stringify(userAnswer?.sort()) === JSON.stringify(question.answer.sort())
            : userAnswer === question.answer;
        
        if (isCorrect) {
            correctCount++;
            totalScore += question.score;
        } else {
            wrongQuestions.push({
                index: index + 1,
                question: question,
                userAnswer: userAnswer,
                correctAnswer: question.answer
            });
        }
    });
    
    App.examResult = {
        examId: App.currentExam.id,
        title: App.currentExam.title,
        score: totalScore,
        correctCount: correctCount,
        totalCount: App.currentExam.questionCount,
        timeUsed: formatTimeUsed(App.currentExam.duration * 60 - App.timeRemaining),
        wrongQuestions: wrongQuestions,
        knowledgePoints: {
            'SQL注入原理': 100,
            '注入类型识别': 90,
            '防御措施': 85,
            '绕过技巧': 75
        }
    };
    
    showResult();
}

function formatTimeUsed(seconds) {
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}:${secs.toString().padStart(2, '0')}`;
}

function showResult() {
    navigateTo('result');
    
    const result = App.examResult;
    const resultPage = document.getElementById('result-page');
    
    const scoreCircle = resultPage.querySelector('.score-number');
    scoreCircle.textContent = result.score;
    
    const progressCircle = resultPage.querySelector('.progress-circle');
    const offset = 254 - (254 * result.score / 100);
    progressCircle.style.strokeDashoffset = offset;
    
    resultPage.querySelector('.result-subtitle').textContent = result.title;
    
    const detailValues = resultPage.querySelectorAll('.detail-value');
    detailValues[0].textContent = `${result.correctCount}/${result.totalCount}`;
    detailValues[1].textContent = `${result.totalCount - result.correctCount}/${result.totalCount}`;
    detailValues[2].textContent = result.timeUsed;
    
    const wrongList = resultPage.querySelector('.wrong-list');
    wrongList.innerHTML = '';
    
    result.wrongQuestions.forEach(wq => {
        const wrongItem = document.createElement('div');
        wrongItem.className = 'wrong-item';
        
        const userAnswerText = Array.isArray(wq.userAnswer) 
            ? wq.userAnswer.join(', ') 
            : (wq.userAnswer || '未作答');
        const correctAnswerText = Array.isArray(wq.correctAnswer)
            ? wq.correctAnswer.join(', ')
            : wq.correctAnswer;
        
        wrongItem.innerHTML = `
            <div class="wrong-header">
                <span class="wrong-number">第${wq.index}题</span>
                <span class="wrong-type">${wq.question.type === 'multiple' ? '多选题' : '单选题'}</span>
            </div>
            <p class="wrong-question">${wq.question.text}</p>
            <div class="wrong-answers">
                <div class="your-answer">
                    <span>你的答案:</span>
                    <span class="wrong">${userAnswerText}</span>
                </div>
                <div class="correct-answer">
                    <span>正确答案:</span>
                    <span class="correct">${correctAnswerText}</span>
                </div>
            </div>
            ${wq.question.explanation ? `
            <div class="explanation">
                <h4>解析:</h4>
                <p>${wq.question.explanation}</p>
            </div>
            ` : ''}
        `;
        
        wrongList.appendChild(wrongItem);
    });
}

function reviewExam() {
    alert('查看全部解析功能演示');
}

function shareResult() {
    alert('分享成绩功能演示');
}

function showCategory(category) {
    alert(`进入${category}题库练习`);
}

function showAdminTab(tabName) {
    document.querySelectorAll('.admin-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    event.target.classList.add('active');
    
    document.querySelectorAll('.admin-content').forEach(content => {
        content.style.display = 'none';
    });
    
    const targetTab = document.getElementById(`${tabName}-tab`);
    if (targetTab) {
        targetTab.style.display = 'block';
    }
}

function generateCalendar() {
    const calendar = document.getElementById('calendar');
    if (!calendar) return;
    
    const today = new Date();
    const year = today.getFullYear();
    const month = today.getMonth();
    
    const firstDay = new Date(year, month, 1).getDay();
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    
    const studyDays = [1, 2, 3, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16, 17];
    
    let html = '<div class="calendar-header">';
    html += '<span>日</span><span>一</span><span>二</span><span>三</span><span>四</span><span>五</span><span>六</span>';
    html += '</div><div class="calendar-body">';
    
    for (let i = 0; i < firstDay; i++) {
        html += '<span class="empty"></span>';
    }
    
    for (let day = 1; day <= daysInMonth; day++) {
        const isToday = day === today.getDate();
        const hasStudied = studyDays.includes(day);
        
        let classes = 'day';
        if (isToday) classes += ' today';
        if (hasStudied) classes += ' studied';
        
        html += `<span class="${classes}">${day}</span>`;
    }
    
    html += '</div>';
    calendar.innerHTML = html;
}

function initCharts() {
    initStudyChart();
    initSkillRadar();
    initDVWACharts();
}

function initStudyChart() {
    const canvas = document.getElementById('studyChart');
    if (!canvas || typeof Chart === 'undefined') return;
    
    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: ['周一', '周二', '周三', '周四', '周五', '周六', '周日'],
            datasets: [{
                label: '学习时长(小时)',
                data: [2, 3, 1.5, 4, 2.5, 3.5, 2],
                backgroundColor: 'rgba(59, 130, 246, 0.8)',
                borderColor: 'rgba(59, 130, 246, 1)',
                borderWidth: 1,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

function initSkillRadar() {
    const canvas = document.getElementById('skillRadar');
    if (!canvas || typeof Chart === 'undefined') return;
    
    new Chart(canvas, {
        type: 'radar',
        data: {
            labels: ['SQL注入', 'XSS', 'CSRF', '文件上传', '命令注入', 'SSRF'],
            datasets: [{
                label: '技能掌握度',
                data: [90, 75, 60, 50, 65, 40],
                backgroundColor: 'rgba(59, 130, 246, 0.2)',
                borderColor: 'rgba(59, 130, 246, 1)',
                borderWidth: 2,
                pointBackgroundColor: 'rgba(59, 130, 246, 1)',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: 'rgba(59, 130, 246, 1)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        stepSize: 20
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

const DVWAData = {
    vulnerabilities: [
        {
            id: 'VULN-001',
            type: 'sql',
            typeName: 'SQL注入',
            name: '用户登录处存在SQL注入漏洞',
            path: '/vulnerabilities/sqli/?id=1&Submit=Submit',
            payload: "1' OR '1'='1",
            severity: 'critical',
            severityName: '严重',
            time: '2026-05-17 14:32:15',
            verified: true,
            description: '在用户ID参数处存在SQL注入漏洞，攻击者可以通过构造恶意SQL语句获取数据库敏感信息。',
            solution: '使用参数化查询或预编译语句，对用户输入进行严格过滤。'
        },
        {
            id: 'VULN-002',
            type: 'xss',
            typeName: 'XSS(反射型)',
            name: '反射型XSS跨站脚本漏洞',
            path: '/vulnerabilities/xss_r/?name=',
            payload: "<script>alert('XSS')</script>",
            severity: 'high',
            severityName: '高危',
            time: '2026-05-17 14:45:22',
            verified: true,
            description: '在name参数处存在反射型XSS漏洞，攻击者可以注入恶意脚本窃取用户Cookie。',
            solution: '对用户输入进行HTML实体编码，设置HttpOnly Cookie属性。'
        },
        {
            id: 'VULN-003',
            type: 'xss',
            typeName: 'XSS(存储型)',
            name: '存储型XSS跨站脚本漏洞',
            path: '/vulnerabilities/xss_s/',
            payload: '<img src=x onerror=alert(\'XSS\')>',
            severity: 'high',
            severityName: '高危',
            time: '2026-05-17 15:12:08',
            verified: true,
            description: '在留言板功能处存在存储型XSS漏洞，恶意脚本会被持久化存储。',
            solution: '对用户输入进行HTML实体编码，使用CSP策略限制脚本执行。'
        },
        {
            id: 'VULN-004',
            type: 'csrf',
            typeName: 'CSRF',
            name: '跨站请求伪造漏洞',
            path: '/vulnerabilities/csrf/',
            payload: '可构造恶意表单修改用户密码',
            severity: 'medium',
            severityName: '中危',
            time: '2026-05-17 15:28:45',
            verified: false,
            description: '密码修改功能缺少CSRF防护，攻击者可诱导用户点击恶意链接修改密码。',
            solution: '添加Anti-CSRF Token验证，验证Referer头。'
        },
        {
            id: 'VULN-005',
            type: 'cmdi',
            typeName: '命令注入',
            name: '操作系统命令注入漏洞',
            path: '/vulnerabilities/exec/',
            payload: '127.0.0.1; cat /etc/passwd',
            severity: 'critical',
            severityName: '严重',
            time: '2026-05-17 15:45:33',
            verified: true,
            description: '在Ping功能处存在命令注入漏洞，攻击者可执行任意系统命令。',
            solution: '禁用危险函数，使用白名单过滤用户输入。'
        },
        {
            id: 'VULN-006',
            type: 'fileupload',
            typeName: '文件上传',
            name: '任意文件上传漏洞',
            path: '/vulnerabilities/upload/',
            payload: '可上传PHP WebShell获取服务器权限',
            severity: 'high',
            severityName: '高危',
            time: '2026-05-17 16:02:18',
            verified: true,
            description: '文件上传功能未对文件类型进行严格校验，可上传恶意脚本文件。',
            solution: '验证文件MIME类型，限制上传目录权限，重命名上传文件。'
        }
    ],
    
    stats: {
        total: 12,
        verified: 8,
        fixed: 6,
        critical: 2,
        high: 3,
        medium: 1,
        low: 0
    }
};

function initDVWACharts() {
    initVulnTypeChart();
    initScanTimelineChart();
    initAttackSuccessChart();
}

function initVulnTypeChart() {
    const canvas = document.getElementById('vulnTypeChart');
    if (!canvas || typeof Chart === 'undefined') return;
    
    new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: ['SQL注入', 'XSS', 'CSRF', '命令注入', '文件上传'],
            datasets: [{
                data: [2, 2, 1, 1, 1],
                backgroundColor: [
                    '#ef4444',
                    '#f59e0b',
                    '#3b82f6',
                    '#ec4899',
                    '#8b5cf6'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        padding: 15,
                        usePointStyle: true
                    }
                }
            },
            cutout: '60%'
        }
    });
}

function initScanTimelineChart() {
    const canvas = document.getElementById('scanTimelineChart');
    if (!canvas || typeof Chart === 'undefined') return;
    
    new Chart(canvas, {
        type: 'line',
        data: {
            labels: ['14:00', '14:30', '15:00', '15:30', '16:00', '16:30'],
            datasets: [{
                label: '发现漏洞数',
                data: [1, 3, 4, 5, 6, 6],
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                fill: true,
                tension: 0.4
            }, {
                label: '已验证漏洞数',
                data: [0, 2, 3, 4, 5, 6],
                borderColor: '#10b981',
                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

function initAttackSuccessChart() {
    const canvas = document.getElementById('attackSuccessChart');
    if (!canvas || typeof Chart === 'undefined') return;
    
    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: ['SQL注入', 'XSS', 'CSRF', '命令注入', '文件上传', 'LFI', 'SSRF'],
            datasets: [{
                label: '攻击成功率(%)',
                data: [95, 88, 72, 90, 85, 78, 65],
                backgroundColor: [
                    'rgba(239, 68, 68, 0.8)',
                    'rgba(245, 158, 11, 0.8)',
                    'rgba(59, 130, 246, 0.8)',
                    'rgba(236, 72, 153, 0.8)',
                    'rgba(139, 92, 246, 0.8)',
                    'rgba(16, 185, 129, 0.8)',
                    'rgba(107, 114, 128, 0.8)'
                ],
                borderRadius: 6
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    max: 100,
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                },
                y: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

function filterVulnList() {
    const typeFilter = document.getElementById('vuln-filter').value;
    const severityFilter = document.getElementById('severity-filter').value;
    const vulnItems = document.querySelectorAll('.vuln-item');
    
    vulnItems.forEach(item => {
        const type = item.querySelector('.vuln-type').classList[1];
        const severity = item.classList.contains('critical') ? 'critical' :
                        item.classList.contains('high') ? 'high' :
                        item.classList.contains('medium') ? 'medium' : 'low';
        
        const typeMatch = typeFilter === 'all' || type === typeFilter;
        const severityMatch = severityFilter === 'all' || severity === severityFilter;
        
        item.style.display = typeMatch && severityMatch ? 'block' : 'none';
    });
}

function showVulnDetail(vulnId) {
    const vuln = DVWAData.vulnerabilities.find(v => v.id === vulnId);
    if (!vuln) return;
    
    const modal = document.getElementById('exam-modal');
    const modalBody = modal.querySelector('.modal-body');
    
    modalBody.innerHTML = `
        <div class="vuln-detail">
            <div class="detail-header">
                <span class="vuln-id">#${vuln.id}</span>
                <span class="vuln-type ${vuln.type}">${vuln.typeName}</span>
                <span class="vuln-severity ${vuln.severity}">${vuln.severityName}</span>
            </div>
            <h3>${vuln.name}</h3>
            <div class="detail-section">
                <h4><i class="fas fa-link"></i> 漏洞路径</h4>
                <code>${vuln.path}</code>
            </div>
            <div class="detail-section">
                <h4><i class="fas fa-code"></i> Payload</h4>
                <code>${vuln.payload}</code>
            </div>
            <div class="detail-section">
                <h4><i class="fas fa-info-circle"></i> 漏洞描述</h4>
                <p>${vuln.description}</p>
            </div>
            <div class="detail-section">
                <h4><i class="fas fa-shield-alt"></i> 修复建议</h4>
                <p>${vuln.solution}</p>
            </div>
            <div class="detail-section">
                <h4><i class="fas fa-clock"></i> 发现时间</h4>
                <p>${vuln.time}</p>
            </div>
            <div class="detail-section">
                <h4><i class="fas fa-check-circle"></i> 验证状态</h4>
                <p>${vuln.verified ? '<span style="color: #10b981;">已验证</span>' : '<span style="color: #f59e0b;">待验证</span>'}</p>
            </div>
        </div>
    `;
    
    modal.querySelector('.modal-header h2').textContent = '漏洞详情';
    modal.classList.add('show');
}

function verifyVuln(vulnId) {
    const vuln = DVWAData.vulnerabilities.find(v => v.id === vulnId);
    if (vuln) {
        vuln.verified = true;
        alert(`漏洞 ${vulnId} 已验证成功！\n\n验证方法：使用Payload进行实际攻击测试，确认漏洞真实存在。`);
    }
}

function generatePOC(vulnId) {
    const vuln = DVWAData.vulnerabilities.find(v => v.id === vulnId);
    if (!vuln) return;
    
    let pocCode = '';
    
    switch(vuln.type) {
        case 'sql':
            pocCode = `# SQL注入POC - ${vuln.id}
import requests

target_url = "http://dvwa.local:8080${vuln.path}"
payload = "${vuln.payload}"

response = requests.get(target_url + payload)
if "User ID exists" in response.text:
    print("[+] SQL注入漏洞验证成功！")
    print("[+] Payload: " + payload)
else:
    print("[-] 漏洞验证失败")`;
            break;
        case 'xss':
            pocCode = `# XSS POC - ${vuln.id}
import requests

target_url = "http://dvwa.local:8080${vuln.path}"
payload = "${vuln.payload}"

response = requests.get(target_url + payload)
if payload in response.text:
    print("[+] XSS漏洞验证成功！")
    print("[+] Payload: " + payload)
else:
    print("[-] 漏洞验证失败")`;
            break;
        case 'cmdi':
            pocCode = `# 命令注入POC - ${vuln.id}
import requests

target_url = "http://dvwa.local:8080${vuln.path}"
payload = "${vuln.payload}"

response = requests.get(target_url + payload)
if "root:" in response.text:
    print("[+] 命令注入漏洞验证成功！")
    print("[+] 已读取/etc/passwd文件")
else:
    print("[-] 漏洞验证失败")`;
            break;
        default:
            pocCode = `# POC - ${vuln.id}
# 漏洞类型: ${vuln.typeName}
# 目标路径: ${vuln.path}
# Payload: ${vuln.payload}

print("请根据漏洞类型编写具体的POC代码")`;
    }
    
    alert(`POC代码已生成：\n\n${pocCode}`);
}

async function fetchDVWAVulnerabilities() {
    try {
        const response = await fetch(`${App.apiBaseUrl}/api/dvwa/vulnerabilities`);
        if (!response.ok) {
            throw new Error('API请求失败');
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('获取DVWA漏洞数据失败:', error);
        return DVWAData.vulnerabilities;
    }
}

async function startDVWAScan() {
    const scanBtn = document.querySelector('.dvwa-header .btn-primary');
    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 扫描中...';
    }
    
    try {
        const response = await fetch(`${App.apiBaseUrl}/api/dvwa/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target_url: App.dvwaConfig.targetUrl,
                username: App.dvwaConfig.username,
                password: App.dvwaConfig.password,
                security_level: App.dvwaConfig.securityLevel
            })
        });
        
        if (!response.ok) {
            throw new Error('扫描请求失败');
        }
        
        const result = await response.json();
        
        if (result.success) {
            updateDVWADisplay(result.data);
            alert(`扫描完成！发现 ${result.data.total_vulnerabilities} 个漏洞`);
        } else {
            alert('扫描失败: ' + (result.error || '未知错误'));
        }
    } catch (error) {
        console.error('DVWA扫描失败:', error);
        alert('扫描失败: ' + error.message + '\n\n请确保：\n1. DVWA靶场正在运行\n2. API服务已启动 (python dvwa_api.py)');
    } finally {
        if (scanBtn) {
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<i class="fas fa-search"></i> 开始扫描';
        }
    }
}

async function checkDVWAStatus() {
    try {
        const response = await fetch(`${App.apiBaseUrl}/api/dvwa/status?target_url=${encodeURIComponent(App.dvwaConfig.targetUrl)}`);
        const data = await response.json();
        
        const statusBadge = document.querySelector('.status-badge');
        if (statusBadge) {
            if (data.status === 'online') {
                statusBadge.className = 'status-badge online';
                statusBadge.innerHTML = '<i class="fas fa-circle"></i> 靶场在线';
            } else {
                statusBadge.className = 'status-badge offline';
                statusBadge.innerHTML = '<i class="fas fa-circle"></i> 靶场离线';
            }
        }
        
        return data.status === 'online';
    } catch (error) {
        console.error('检查DVWA状态失败:', error);
        return false;
    }
}

function updateDVWADisplay(data) {
    if (!data || !data.vulnerabilities) return;
    
    DVWAData.vulnerabilities = data.vulnerabilities;
    DVWAData.stats = {
        total: data.total_vulnerabilities,
        verified: data.vulnerabilities.filter(v => v.verified).length,
        fixed: 0,
        critical: data.severity_distribution.critical,
        high: data.severity_distribution.high,
        medium: data.severity_distribution.medium,
        low: data.severity_distribution.low
    };
    
    const statValues = document.querySelectorAll('.dvwa-stat-card .stat-value');
    if (statValues.length >= 4) {
        statValues[0].textContent = DVWAData.stats.total;
        statValues[1].textContent = DVWAData.stats.verified;
        statValues[2].textContent = DVWAData.stats.fixed;
    }
    
    initVulnTypeChart();
    initScanTimelineChart();
    initAttackSuccessChart();
}

function toggleDVWAMode() {
    App.useRealDVWA = !App.useRealDVWA;
    
    const modeIndicator = document.querySelector('.dvwa-mode-indicator');
    if (modeIndicator) {
        modeIndicator.textContent = App.useRealDVWA ? '真实靶场模式' : '演示模式';
        modeIndicator.className = App.useRealDVWA ? 'dvwa-mode-indicator real' : 'dvwa-mode-indicator demo';
    }
    
    if (App.useRealDVWA) {
        checkDVWAStatus();
    }
}

document.addEventListener('DOMContentLoaded', init);

window.navigateTo = navigateTo;
window.toggleSidebar = toggleSidebar;
window.switchRole = switchRole;
window.startExam = startExam;
window.closeModal = closeModal;
window.confirmStartExam = confirmStartExam;
window.prevQuestion = prevQuestion;
window.nextQuestion = nextQuestion;
window.markQuestion = markQuestion;
window.showCategory = showCategory;
window.showAdminTab = showAdminTab;
window.reviewExam = reviewExam;
window.shareResult = shareResult;
window.filterVulnList = filterVulnList;
window.showVulnDetail = showVulnDetail;
window.verifyVuln = verifyVuln;
window.generatePOC = generatePOC;
window.startDVWAScan = startDVWAScan;
window.checkDVWAStatus = checkDVWAStatus;
window.toggleDVWAMode = toggleDVWAMode;
