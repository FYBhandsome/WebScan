<template>
  <header class="app-header">

<div class="brand" style="display: flex; align-items: center; gap: 14px;">
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="flex-shrink: 0;">
    <path d="M4 10V4H10" stroke="#000000" stroke-width="2.5" stroke-linecap="square"/>
    <path d="M20 14V20H14" stroke="#000000" stroke-width="2.5" stroke-linecap="square"/>
    <circle cx="12" cy="12" r="3" fill="#10B981" />
  </svg>
  
  <div class="brand-text" style="
    /* 你可以把 font-family 换成以下三种之一来看看效果：
       1. 'Montserrat', sans-serif  (经典重工业宽体，极度平稳且霸气，最推荐)
       2. 'Orbitron', sans-serif    (纯正赛博朋克风，机甲感十足)
       3. 'Space Grotesk', sans-serif (前沿极客风，很多 AI 公司在用)
    */
    font-family: 'Montserrat', sans-serif; 
    font-weight: 900; 
    font-size: 22px; 
    letter-spacing: 0.5px;
    display: inline-block;
  ">
    <span style="color: #000000;">TOSK</span><span style="color: #10B981;">i</span><span style="color: #000000;">ll</span>
  </div>
</div>

    <div class="system-status">
      <div class="status-dot online"></div>
      <span class="status-text">已连接</span>
    </div>
  </header>
</template>

<script setup>
import { ShieldCheck } from 'lucide-vue-next'
defineProps({
  status: {
    type: String,
    default: '未连接'
  }
})
</script>

<style scoped>
@import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@900&family=Orbitron:wght@900&family=Space+Grotesk:wght@700&display=swap');
/* 顶栏容器：去除阴影，仅保留 1px 极细底边 */
.app-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  height: 64px;
  padding: 0 40px;
  background-color: #ffffff;
  border-bottom: 1px solid #eaeaea; /* 极简的灵魂在此 */
  /* box-shadow: none !important; 确保没有任何阴影 */
}

/* 品牌标识区 */
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
}

.brand-icon {
  width: 22px;
  height: 22px;
  color: #000000;
  stroke-width: 2px;
}

/* 排版对比学：TOSKill 极粗，Scanner 极细 */
.brand-text {
  font-size: 18px;
  letter-spacing: -0.5px;
  color: #000000;
}

.fw-bold {
  font-weight: 800;
}

.fw-light {
  font-weight: 400;
  color: #666666; /* 副标题稍微降噪 */
  margin-left: 6px;
}

/* 直接替换你原来的 .system-status 相关样式 */
.system-status {
  display: flex;
  align-items: center;
  gap: 8px; /* 圆点和文字的间距 */
  /* 彻底删除 background, border, padding, border-radius */
}

/* 极其精密的极小圆点 */
.status-dot {
  width: 6px; 
  height: 6px;
  border-radius: 50%;
  background-color: #10B981; /* 你的主打绿 */
  box-shadow: 0 0 8px rgba(16, 185, 129, 0.8); /* 纯净的霓虹辉光，代替原来那个脏脏的圈 */
}

/* 降噪的专业排版 */
.status-text {
  padding-left: 5px;
  font-size: 15px; /* 缩小字号 */
  font-weight: 600;
  color: #666666; /* 不要用纯黑，用中灰色让步给绿点 */
  letter-spacing: 0.5px; /* 微微拉开字间距，高级感来源 */
}


/* .system-status {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  border-radius: 20px;
  background-color: #f9f9f9; 
  border: 1px solid #eaeaea;
}

.status-text {
  font-size: 13px;
  font-weight: 500;
  color: #333333;
}


.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background-color: #10B981; 
  box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4);
  animation: pulse-green 2s infinite;
} */

@keyframes pulse-green {
  0% {
    transform: scale(0.95);
    box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
  }
  70% {
    transform: scale(1);
    box-shadow: 0 0 0 6px rgba(16, 185, 129, 0);
  }
  100% {
    transform: scale(0.95);
    box-shadow: 0 0 0 0 rgba(16, 185, 129, 0);
  }
}
</style>