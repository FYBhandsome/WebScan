"""
结果分析器.

负责分析 POC 验证结果,包括漏洞验证状态判定、漏洞等级评估、误报检测、结果置信度计算等。
"""
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from backend.ai_agents.poc_system.utils import (
    calculate_severity_distribution,
    calculate_statistics,
    get_false_positive_keywords,
    get_high_risk_targets,
    get_success_keywords
)
from backend.config import settings
from backend.models import POCExecutionLog, POCVerificationResult

logger = logging.getLogger(__name__)


class DetectionMethod(Enum):
    """误报检测方法枚举"""
    KEYWORD = "keyword"
    PATTERN = "pattern"
    ML_BASED = "ml_based"
    HYBRID = "hybrid"


class RiskLevel(Enum):
    """风险等级枚举"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExportFormat(Enum):
    """导出格式枚举"""
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    MARKDOWN = "markdown"


@dataclass
class FalsePositiveThreshold:
    """误报检测阈值配置"""
    confidence_threshold: float = 0.3
    keyword_weight: float = 0.4
    pattern_weight: float = 0.3
    ml_weight: float = 0.3
    error_penalty: float = 0.2
    timeout_penalty: float = 0.15


@dataclass
class ConfidenceWeights:
    """置信度权重配置"""
    execution_time_weight: float = 0.15
    response_pattern_weight: float = 0.25
    error_message_weight: float = 0.20
    output_quality_weight: float = 0.20
    consistency_weight: float = 0.20


@dataclass
class ConfidenceExplanation:
    """置信度解释"""
    overall_confidence: float
    factors: Dict[str, float]
    weighted_scores: Dict[str, float]
    explanation: str
    recommendations: List[str]


@dataclass
class CVSSVector:
    """CVSS向量"""
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "N"
    integrity: str = "N"
    availability: str = "N"
    
    def to_vector_string(self) -> str:
        return (
            f"AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/"
            f"I:{self.integrity}/A:{self.availability}"
        )


@dataclass
class SeverityAssessment:
    """严重程度评估结果"""
    cvss_score: float
    cvss_vector: CVSSVector
    risk_level: RiskLevel
    severity: str
    impact_score: float
    exploitability_score: float
    context_factors: Dict[str, Any]
    adjustment_history: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class CustomAnalysisRule:
    """自定义分析规则"""
    rule_id: str
    name: str
    description: str
    condition: Callable[[Any], bool]
    action: Callable[[Any], Any]
    priority: int = 0
    enabled: bool = True


@dataclass
class FalsePositiveLearningData:
    """误报学习数据"""
    result_id: int
    features: Dict[str, Any]
    is_false_positive: bool
    feedback_source: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AnalysisResult:
    """
    分析结果类
    
    用于存储单个 POC 验证结果的分析数据。
    """
    
    result_id: int
    poc_name: str
    poc_id: str
    target: str
    is_vulnerable: bool
    severity: str
    confidence: float
    cvss_score: float
    is_false_positive: bool
    risk_level: str
    recommendations: List[str]
    analysis_details: Dict[str, Any]
    confidence_explanation: Optional[ConfidenceExplanation] = None
    severity_assessment: Optional[SeverityAssessment] = None
    detection_method: Optional[DetectionMethod] = None
    false_positive_score: float = 0.0


@dataclass
class BatchAnalysisSummary:
    """
    批量分析摘要类
    
    用于存储批量 POC 验证结果的分析摘要。
    """
    
    total_results: int
    vulnerable_count: int
    not_vulnerable_count: int
    false_positive_count: int
    true_positive_count: int
    severity_distribution: Dict[str, int]
    average_confidence: float
    average_cvss_score: float
    high_risk_targets: List[str]
    recommendations: List[str]
    comparison_data: Optional[Dict[str, Any]] = None


@dataclass
class ScanComparison:
    """扫描结果比较"""
    scan_id_1: str
    scan_id_2: str
    new_vulnerabilities: List[str]
    fixed_vulnerabilities: List[str]
    persistent_vulnerabilities: List[str]
    severity_changes: Dict[str, Dict[str, str]]
    confidence_changes: Dict[str, Tuple[float, float]]


class FalsePositiveDetector:
    """
    误报检测器.

    提供多种误报检测算法:
    - 关键词检测
    - 模式检测
    - ML检测
    - 混合检测

    Attributes:
        threshold: 误报检测阈值配置.
        false_positive_keywords: 误报关键词列表.
        success_keywords: 成功关键词列表.
    """

    def __init__(self, threshold: Optional[FalsePositiveThreshold] = None):
        self.threshold = threshold or FalsePositiveThreshold()
        self.false_positive_keywords = get_false_positive_keywords()
        self.success_keywords = get_success_keywords()
        self._learned_patterns: Dict[str, float] = {}
        self._learning_data: List[FalsePositiveLearningData] = []
        
        self._error_patterns = [
            r"timeout\s*:\s*\d+\s*seconds?",
            r"connection\s+refused",
            r"connection\s+reset",
            r"network\s+unreachable",
            r"dns\s+resolution\s+failed",
            r"ssl\s+error",
            r"certificate\s+error",
            r"handshake\s+failed",
            r"socket\s+error",
            r"connection\s+timed?\s+out",
        ]
        
        self._false_positive_patterns = [
            r"4\d{2}\s+(not\s+found|forbidden|unauthorized)",
            r"5\d{2}\s+(server\s+error|gateway\s+timeout)",
            r"rate\s+limit",
            r"too\s+many\s+requests",
            r"service\s+unavailable",
            r"bad\s+gateway",
        ]
        
        self._success_patterns = [
            r"vulnerability\s+confirmed",
            r"exploit\s+successful",
            r"poc\s+verified",
            r"vulnerable\s+to\s+\w+",
            r"\[\+\].*vulnerable",
        ]
    
    def detect_by_keywords(
        self,
        result: POCVerificationResult,
        logs: List[POCExecutionLog]
    ) -> Tuple[bool, float]:
        """
        基于关键词的误报检测
        
        Args:
            result: POC验证结果
            logs: 执行日志
            
        Returns:
            Tuple[bool, float]: (是否误报, 置信度分数)
        """
        score = 0.0
        max_score = 1.0
        
        if result.output:
            output_lower = result.output.lower()
            for keyword in self.false_positive_keywords:
                if keyword in output_lower:
                    score += 0.1
            
            for keyword in self.success_keywords:
                if keyword in output_lower:
                    score -= 0.1
        
        if result.error:
            error_lower = result.error.lower()
            for keyword in self.false_positive_keywords:
                if keyword in error_lower:
                    score += 0.15
        
        for log in logs:
            if log.level.lower() == "error":
                log_lower = log.message.lower()
                for keyword in self.false_positive_keywords:
                    if keyword in log_lower:
                        score += 0.1
        
        if result.confidence < self.threshold.confidence_threshold:
            score += self.threshold.error_penalty
        
        final_score = min(max(score, 0.0), max_score)
        is_false_positive = final_score > 0.5
        
        return is_false_positive, final_score
    
    def detect_by_patterns(
        self,
        result: POCVerificationResult,
        logs: List[POCExecutionLog]
    ) -> Tuple[bool, float]:
        """
        基于正则模式的误报检测
        
        Args:
            result: POC验证结果
            logs: 执行日志
            
        Returns:
            Tuple[bool, float]: (是否误报, 置信度分数)
        """
        score = 0.0
        max_score = 1.0
        
        combined_text = ""
        if result.output:
            combined_text += result.output + " "
        if result.error:
            combined_text += result.error + " "
        
        for log in logs:
            combined_text += log.message + " "
        
        combined_text_lower = combined_text.lower()
        
        for pattern in self._error_patterns:
            if re.search(pattern, combined_text_lower, re.IGNORECASE):
                score += 0.1
        
        for pattern in self._false_positive_patterns:
            if re.search(pattern, combined_text_lower, re.IGNORECASE):
                score += 0.15
        
        for pattern in self._success_patterns:
            if re.search(pattern, combined_text_lower, re.IGNORECASE):
                score -= 0.2
        
        for pattern, weight in self._learned_patterns.items():
            if re.search(pattern, combined_text_lower, re.IGNORECASE):
                score += weight
        
        final_score = min(max(score, 0.0), max_score)
        is_false_positive = final_score > 0.5
        
        return is_false_positive, final_score
    
    def detect_by_ml(
        self,
        result: POCVerificationResult,
        logs: List[POCExecutionLog]
    ) -> Tuple[bool, float]:
        """
        基于机器学习的误报检测
        
        使用特征工程和规则评分模拟ML检测
        
        Args:
            result: POC验证结果
            logs: 执行日志
            
        Returns:
            Tuple[bool, float]: (是否误报, 置信度分数)
        """
        features = self._extract_features(result, logs)
        score = self._calculate_ml_score(features)
        
        is_false_positive = score > 0.5
        
        return is_false_positive, score
    
    def _extract_features(
        self,
        result: POCVerificationResult,
        logs: List[POCExecutionLog]
    ) -> Dict[str, float]:
        """提取ML特征"""
        features = {}
        
        features["confidence"] = result.confidence
        
        features["vulnerable"] = 1.0 if result.vulnerable else 0.0
        
        features["has_output"] = 1.0 if result.output else 0.0
        features["output_length"] = len(result.output) if result.output else 0.0
        features["output_length_normalized"] = min(features["output_length"] / 1000.0, 1.0)
        
        features["has_error"] = 1.0 if result.error else 0.0
        features["error_length"] = len(result.error) if result.error else 0.0
        
        features["log_count"] = float(len(logs))
        features["error_log_ratio"] = (
            sum(1 for log in logs if log.level.lower() == "error") / max(len(logs), 1)
        )
        
        if hasattr(result, "execution_time"):
            exec_time = result.execution_time or 0.0
            features["execution_time"] = exec_time
            features["execution_time_normalized"] = min(exec_time / 60.0, 1.0)
        else:
            features["execution_time"] = 0.0
            features["execution_time_normalized"] = 0.0
        
        return features
    
    def _calculate_ml_score(self, features: Dict[str, float]) -> float:
        """计算ML评分"""
        weights = {
            "confidence": -0.3,
            "vulnerable": -0.2,
            "has_output": -0.1,
            "output_length_normalized": -0.05,
            "has_error": 0.25,
            "error_length": 0.001,
            "error_log_ratio": 0.2,
            "execution_time_normalized": 0.1,
        }
        
        score = 0.5
        
        for feature, value in features.items():
            if feature in weights:
                score += weights[feature] * value
        
        return min(max(score, 0.0), 1.0)
    
    def detect_hybrid(
        self,
        result: POCVerificationResult,
        logs: List[POCExecutionLog]
    ) -> Tuple[bool, float, Dict[str, float]]:
        """
        混合检测方法
        
        综合使用关键词、模式和ML检测
        
        Args:
            result: POC验证结果
            logs: 执行日志
            
        Returns:
            Tuple[bool, float, Dict[str, float]]: (是否误报, 综合分数, 各方法分数)
        """
        _, keyword_score = self.detect_by_keywords(result, logs)
        _, pattern_score = self.detect_by_patterns(result, logs)
        _, ml_score = self.detect_by_ml(result, logs)
        
        combined_score = (
            keyword_score * self.threshold.keyword_weight +
            pattern_score * self.threshold.pattern_weight +
            ml_score * self.threshold.ml_weight
        )
        
        if result.error:
            combined_score += self.threshold.error_penalty
        
        scores = {
            "keyword": keyword_score,
            "pattern": pattern_score,
            "ml": ml_score,
            "combined": combined_score
        }
        
        is_false_positive = combined_score > 0.5
        
        return is_false_positive, combined_score, scores
    
    def learn_from_feedback(
        self,
        result_id: int,
        features: Dict[str, Any],
        is_false_positive: bool,
        source: str = "manual"
    ) -> None:
        """
        从反馈中学习
        
        Args:
            result_id: 结果ID
            features: 特征数据
            is_false_positive: 是否为误报
            source: 反馈来源
        """
        learning_data = FalsePositiveLearningData(
            result_id=result_id,
            features=features,
            is_false_positive=is_false_positive,
            feedback_source=source
        )
        self._learning_data.append(learning_data)
        
        if is_false_positive and "output_pattern" in features:
            pattern = features["output_pattern"]
            current_weight = self._learned_patterns.get(pattern, 0.0)
            self._learned_patterns[pattern] = min(current_weight + 0.1, 0.5)


class ConfidenceCalculator:
    """
    置信度计算器.

    提供多因素置信度计算和解释生成.

    Attributes:
        weights: 置信度权重配置.
    """

    def __init__(self, weights: Optional[ConfidenceWeights] = None):
        self.weights = weights or ConfidenceWeights()
        self._adjustment_history: List[Dict[str, Any]] = []
    
    def calculate_confidence(
        self,
        result: POCVerificationResult,
        logs: List[POCExecutionLog],
        additional_factors: Optional[Dict[str, float]] = None
    ) -> ConfidenceExplanation:
        """
        计算多因素置信度
        
        Args:
            result: POC验证结果
            logs: 执行日志
            additional_factors: 额外因素
            
        Returns:
            ConfidenceExplanation: 置信度解释
        """
        factors = {}
        weighted_scores = {}
        
        factors["execution_time"] = self._calculate_execution_time_factor(result)
        factors["response_pattern"] = self._calculate_response_pattern_factor(result, logs)
        factors["error_message"] = self._calculate_error_message_factor(result, logs)
        factors["output_quality"] = self._calculate_output_quality_factor(result)
        factors["consistency"] = self._calculate_consistency_factor(result, logs)
        
        if additional_factors:
            factors.update(additional_factors)
        
        weighted_scores["execution_time"] = (
            factors["execution_time"] * self.weights.execution_time_weight
        )
        weighted_scores["response_pattern"] = (
            factors["response_pattern"] * self.weights.response_pattern_weight
        )
        weighted_scores["error_message"] = (
            factors["error_message"] * self.weights.error_message_weight
        )
        weighted_scores["output_quality"] = (
            factors["output_quality"] * self.weights.output_quality_weight
        )
        weighted_scores["consistency"] = (
            factors["consistency"] * self.weights.consistency_weight
        )
        
        overall_confidence = sum(weighted_scores.values())
        overall_confidence = min(max(overall_confidence, 0.0), 1.0)
        
        explanation = self._generate_explanation(factors, weighted_scores, overall_confidence)
        recommendations = self._generate_confidence_recommendations(factors, overall_confidence)
        
        return ConfidenceExplanation(
            overall_confidence=overall_confidence,
            factors=factors,
            weighted_scores=weighted_scores,
            explanation=explanation,
            recommendations=recommendations
        )
    
    def _calculate_execution_time_factor(self, result: POCVerificationResult) -> float:
        """计算执行时间因素"""
        if not hasattr(result, "execution_time") or result.execution_time is None:
            return 0.5
        
        exec_time = result.execution_time
        
        if exec_time < 1.0:
            return 0.6
        elif exec_time < 5.0:
            return 0.8
        elif exec_time < 30.0:
            return 0.9
        elif exec_time < 60.0:
            return 0.7
        else:
            return 0.5
    
    def _calculate_response_pattern_factor(
        self,
        result: POCVerificationResult,
        logs: List[POCExecutionLog]
    ) -> float:
        """计算响应模式因素"""
        score = 0.5
        
        if result.vulnerable:
            score += 0.2
        
        if result.output:
            success_indicators = ["success", "vulnerable", "exploit", "confirmed"]
            output_lower = result.output.lower()
            for indicator in success_indicators:
                if indicator in output_lower:
                    score += 0.1
        
        if len(logs) > 0:
            success_logs = sum(1 for log in logs if "success" in log.message.lower())
            if success_logs > 0:
                score += min(success_logs * 0.05, 0.2)
        
        return min(max(score, 0.0), 1.0)
    
    def _calculate_error_message_factor(
        self,
        result: POCVerificationResult,
        logs: List[POCExecutionLog]
    ) -> float:
        """计算错误消息因素"""
        score = 1.0
        
        if result.error:
            score -= 0.3
            
            critical_errors = ["timeout", "connection refused", "network unreachable"]
            error_lower = result.error.lower()
            for critical_error in critical_errors:
                if critical_error in error_lower:
                    score -= 0.2
        
        error_logs = sum(1 for log in logs if log.level.lower() == "error")
        if error_logs > 0:
            score -= min(error_logs * 0.1, 0.3)
        
        return min(max(score, 0.0), 1.0)
    
    def _calculate_output_quality_factor(self, result: POCVerificationResult) -> float:
        """计算输出质量因素"""
        if not result.output:
            return 0.3
        
        score = 0.5
        output = result.output
        
        if len(output) > 100:
            score += 0.1
        if len(output) > 500:
            score += 0.1
        
        if re.search(r"\b(evidence|proof|payload|response)\b", output, re.IGNORECASE):
            score += 0.1
        
        if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", output):
            score += 0.05
        
        if re.search(r"https?://[^\s]+", output):
            score += 0.05
        
        return min(max(score, 0.0), 1.0)
    
    def _calculate_consistency_factor(
        self,
        result: POCVerificationResult,
        logs: List[POCExecutionLog]
    ) -> float:
        """计算一致性因素"""
        score = 0.5
        
        if result.vulnerable and result.confidence > 0.7:
            score += 0.3
        elif not result.vulnerable and result.confidence < 0.3:
            score += 0.3
        
        if result.vulnerable and result.output:
            score += 0.1
        
        if not result.error and result.vulnerable:
            score += 0.1
        
        return min(max(score, 0.0), 1.0)
    
    def _generate_explanation(
        self,
        factors: Dict[str, float],
        weighted_scores: Dict[str, float],
        overall: float
    ) -> str:
        """生成置信度解释"""
        explanations = []
        
        if overall >= 0.8:
            explanations.append("高置信度: 结果可信度高")
        elif overall >= 0.6:
            explanations.append("中等置信度: 结果较为可信")
        elif overall >= 0.4:
            explanations.append("低置信度: 结果需要验证")
        else:
            explanations.append("极低置信度: 结果可能不可靠")
        
        for factor, score in factors.items():
            if score >= 0.7:
                explanations.append(f"{factor}因素良好({score:.2f})")
            elif score < 0.5:
                explanations.append(f"{factor}因素较差({score:.2f})")
        
        return "; ".join(explanations)
    
    def _generate_confidence_recommendations(
        self,
        factors: Dict[str, float],
        overall: float
    ) -> List[str]:
        """生成置信度建议"""
        recommendations = []
        
        if overall < 0.5:
            recommendations.append("建议重新验证此结果")
        
        if factors.get("error_message", 1.0) < 0.5:
            recommendations.append("检查网络连接和目标可用性")
        
        if factors.get("output_quality", 0.0) < 0.5:
            recommendations.append("输出信息不足,建议增加详细日志")
        
        if factors.get("execution_time", 0.0) < 0.5:
            recommendations.append("执行时间异常,检查POC效率")
        
        return recommendations
    
    def adjust_weights(self, new_weights: Dict[str, float]) -> None:
        """
        调整置信度权重
        
        Args:
            new_weights: 新权重字典
        """
        old_weights = {
            "execution_time_weight": self.weights.execution_time_weight,
            "response_pattern_weight": self.weights.response_pattern_weight,
            "error_message_weight": self.weights.error_message_weight,
            "output_quality_weight": self.weights.output_quality_weight,
            "consistency_weight": self.weights.consistency_weight,
        }
        
        for key, value in new_weights.items():
            if hasattr(self.weights, key):
                setattr(self.weights, key, value)
        
        self._adjustment_history.append({
            "timestamp": datetime.now().isoformat(),
            "old_weights": old_weights,
            "new_weights": new_weights
        })


class SeverityAssessor:
    """
    严重程度评估器.

    提供CVSS评分计算和风险等级分类.

    Attributes:
        _adjustment_rules: 严重程度调整规则列表.
        _context_factors: 上下文因素权重字典.
    """

    def __init__(self):
        self._adjustment_rules: List[Dict[str, Any]] = []
        self._context_factors: Dict[str, float] = {
            "internet_facing": 1.2,
            "sensitive_data": 1.3,
            "critical_infrastructure": 1.5,
            "authentication_bypass": 1.4,
            "remote_code_execution": 1.5,
            "data_exfiltration": 1.3,
        }
    
    def calculate_cvss_score(
        self,
        result: POCVerificationResult,
        cvss_vector: Optional[CVSSVector] = None
    ) -> SeverityAssessment:
        """
        计算CVSS评分
        
        Args:
            result: POC验证结果
            cvss_vector: CVSS向量(可选)
            
        Returns:
            SeverityAssessment: 严重程度评估结果
        """
        if cvss_vector is None:
            cvss_vector = self._infer_cvss_vector(result)
        
        base_score = self._calculate_base_score(cvss_vector)
        impact_score = self._calculate_impact_score(cvss_vector)
        exploitability_score = self._calculate_exploitability_score(cvss_vector)
        
        risk_level = self._determine_risk_level(base_score)
        severity = risk_level.value
        
        context_factors = self._identify_context_factors(result)
        
        return SeverityAssessment(
            cvss_score=base_score,
            cvss_vector=cvss_vector,
            risk_level=risk_level,
            severity=severity,
            impact_score=impact_score,
            exploitability_score=exploitability_score,
            context_factors=context_factors
        )
    
    def _infer_cvss_vector(self, result: POCVerificationResult) -> CVSSVector:
        """从结果推断CVSS向量"""
        vector = CVSSVector()
        
        output = (result.output or "").lower()
        poc_name = (result.poc_name if hasattr(result, "poc_name") else "").lower()
        
        if any(kw in output or kw in poc_name for kw in ["rce", "remote code", "code execution"]):
            vector.confidentiality = "H"
            vector.integrity = "H"
            vector.availability = "H"
            vector.attack_vector = "N"
        elif any(kw in output or kw in poc_name for kw in ["sql injection", "sqli"]):
            vector.confidentiality = "H"
            vector.integrity = "H"
            vector.availability = "L"
        elif any(kw in output or kw in poc_name for kw in ["xss", "cross-site scripting"]):
            vector.confidentiality = "L"
            vector.integrity = "L"
            vector.availability = "N"
        elif any(kw in output or kw in poc_name for kw in ["ssrf", "server-side request"]):
            vector.confidentiality = "H"
            vector.integrity = "N"
            vector.availability = "N"
        elif any(kw in output or kw in poc_name for kw in ["lfi", "local file", "path traversal"]):
            vector.confidentiality = "H"
            vector.integrity = "N"
            vector.availability = "N"
        
        if result.vulnerable:
            vector.attack_complexity = "L"
        
        return vector
    
    def _calculate_base_score(self, vector: CVSSVector) -> float:
        """计算CVSS基础分数"""
        c_values = {"N": 0.0, "L": 0.22, "H": 0.56}
        i_values = {"N": 0.0, "L": 0.22, "H": 0.56}
        a_values = {"N": 0.0, "L": 0.22, "H": 0.56}
        
        iss = 1 - (
            (1 - c_values.get(vector.confidentiality, 0.0)) *
            (1 - i_values.get(vector.integrity, 0.0)) *
            (1 - a_values.get(vector.availability, 0.0))
        )
        
        impact = 6.42 * iss
        
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_values = {"L": 0.77, "H": 0.44}
        pr_values = {"N": 0.85, "L": 0.62, "H": 0.27}
        ui_values = {"N": 0.85, "R": 0.62}
        
        exploitability = (
            8.22 *
            av_values.get(vector.attack_vector, 0.85) *
            ac_values.get(vector.attack_complexity, 0.77) *
            pr_values.get(vector.privileges_required, 0.85) *
            ui_values.get(vector.user_interaction, 0.85)
        )
        
        if iss <= 0:
            base_score = 0.0
        elif vector.scope == "U":
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        
        return round(base_score, 1)
    
    def _calculate_impact_score(self, vector: CVSSVector) -> float:
        """计算影响分数"""
        c_values = {"N": 0.0, "L": 0.22, "H": 0.56}
        i_values = {"N": 0.0, "L": 0.22, "H": 0.56}
        a_values = {"N": 0.0, "L": 0.22, "H": 0.56}
        
        iss = 1 - (
            (1 - c_values.get(vector.confidentiality, 0.0)) *
            (1 - i_values.get(vector.integrity, 0.0)) *
            (1 - a_values.get(vector.availability, 0.0))
        )
        
        return round(6.42 * iss, 2)
    
    def _calculate_exploitability_score(self, vector: CVSSVector) -> float:
        """计算可利用性分数"""
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_values = {"L": 0.77, "H": 0.44}
        pr_values = {"N": 0.85, "L": 0.62, "H": 0.27}
        ui_values = {"N": 0.85, "R": 0.62}
        
        exploitability = (
            8.22 *
            av_values.get(vector.attack_vector, 0.85) *
            ac_values.get(vector.attack_complexity, 0.77) *
            pr_values.get(vector.privileges_required, 0.85) *
            ui_values.get(vector.user_interaction, 0.85)
        )
        
        return round(exploitability, 2)
    
    def _determine_risk_level(self, cvss_score: float) -> RiskLevel:
        """确定风险等级"""
        if cvss_score >= 9.0:
            return RiskLevel.CRITICAL
        elif cvss_score >= 7.0:
            return RiskLevel.HIGH
        elif cvss_score >= 4.0:
            return RiskLevel.MEDIUM
        elif cvss_score > 0.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def _identify_context_factors(self, result: POCVerificationResult) -> Dict[str, Any]:
        """识别上下文因素"""
        factors = {}
        output = (result.output or "").lower()
        
        if any(kw in output for kw in ["public", "internet", "external"]):
            factors["internet_facing"] = True
        
        if any(kw in output for kw in ["database", "credential", "password", "pii", "personal"]):
            factors["sensitive_data"] = True
        
        if any(kw in output for kw in ["admin", "root", "bypass", "authentication"]):
            factors["authentication_bypass"] = True
        
        if any(kw in output for kw in ["rce", "command execution", "shell"]):
            factors["remote_code_execution"] = True
        
        if any(kw in output for kw in ["exfiltrat", "leak", "dump", "export"]):
            factors["data_exfiltration"] = True
        
        return factors
    
    def update_severity_by_context(
        self,
        assessment: SeverityAssessment,
        context: Dict[str, Any]
    ) -> SeverityAssessment:
        """
        根据上下文更新严重程度
        
        Args:
            assessment: 当前评估
            context: 上下文信息
            
        Returns:
            SeverityAssessment: 更新后的评估
        """
        adjustment_factor = 1.0
        adjustments = []
        
        for factor, value in context.items():
            if factor in self._context_factors and value:
                factor_multiplier = self._context_factors[factor]
                adjustment_factor *= factor_multiplier
                adjustments.append({
                    "factor": factor,
                    "multiplier": factor_multiplier,
                    "reason": f"Context factor: {factor}"
                })
        
        new_cvss_score = min(assessment.cvss_score * adjustment_factor, 10.0)
        new_risk_level = self._determine_risk_level(new_cvss_score)
        
        adjustment_record = {
            "timestamp": datetime.now().isoformat(),
            "original_cvss": assessment.cvss_score,
            "adjusted_cvss": new_cvss_score,
            "adjustment_factor": adjustment_factor,
            "adjustments": adjustments
        }
        
        assessment.cvss_score = round(new_cvss_score, 1)
        assessment.risk_level = new_risk_level
        assessment.severity = new_risk_level.value
        assessment.adjustment_history.append(adjustment_record)
        
        return assessment
    
    def add_severity_adjustment_rule(
        self,
        condition: Callable[[Dict[str, Any]], bool],
        adjustment: float,
        description: str
    ) -> None:
        """
        添加严重程度调整规则
        
        Args:
            condition: 条件函数
            adjustment: 调整值
            description: 规则描述
        """
        rule = {
            "id": f"rule_{len(self._adjustment_rules)}",
            "condition": condition,
            "adjustment": adjustment,
            "description": description,
            "created_at": datetime.now().isoformat()
        }
        self._adjustment_rules.append(rule)
    
    def apply_adjustment_rules(
        self,
        assessment: SeverityAssessment,
        context: Dict[str, Any]
    ) -> SeverityAssessment:
        """应用调整规则"""
        for rule in self._adjustment_rules:
            try:
                if rule["condition"](context):
                    old_score = assessment.cvss_score
                    assessment.cvss_score = min(
                        max(assessment.cvss_score + rule["adjustment"], 0.0),
                        10.0
                    )
                    assessment.adjustment_history.append({
                        "rule_id": rule["id"],
                        "description": rule["description"],
                        "old_score": old_score,
                        "new_score": assessment.cvss_score,
                        "timestamp": datetime.now().isoformat()
                    })
            except Exception as e:
                logger.warning(f"应用调整规则失败: {e}")
        
        assessment.risk_level = self._determine_risk_level(assessment.cvss_score)
        assessment.severity = assessment.risk_level.value
        
        return assessment


class ResultAnalyzer:
    """
    结果分析器类.

    负责分析 POC 验证结果,包括:
    - 漏洞验证状态判定
    - 漏洞等级评估
    - 误报检测
    - 结果置信度计算
    - 风险评估
    - 修复建议生成

    Attributes:
        false_positive_keywords: 误报关键词列表.
        success_keywords: 成功关键词列表.
        fp_detector: 误报检测器实例.
        confidence_calculator: 置信度计算器实例.
        severity_assessor: 严重程度评估器实例.
    """

    def __init__(
        self,
        fp_threshold: Optional[FalsePositiveThreshold] = None,
        confidence_weights: Optional[ConfidenceWeights] = None
    ):
        """
        初始化结果分析器
        
        Args:
            fp_threshold: 误报检测阈值配置
            confidence_weights: 置信度权重配置
        """
        self.false_positive_keywords = get_false_positive_keywords()
        self.success_keywords = get_success_keywords()
        
        self.fp_detector = FalsePositiveDetector(fp_threshold)
        self.confidence_calculator = ConfidenceCalculator(confidence_weights)
        self.severity_assessor = SeverityAssessor()
        
        self._custom_rules: List[CustomAnalysisRule] = []
        self._manual_false_positives: Set[int] = set()
        self._analysis_cache: Dict[int, AnalysisResult] = {}
    
    async def analyze_single_result(
        self,
        result: POCVerificationResult,
        detection_method: DetectionMethod = DetectionMethod.HYBRID
    ) -> AnalysisResult:
        """
        分析单个 POC 验证结果
        
        Args:
            result: POC 验证结果对象
            detection_method: 误报检测方法
            
        Returns:
            AnalysisResult: 分析结果
        """
        logs = await POCExecutionLog.filter(
            task_id=str(result.verification_task_id) if hasattr(result, "verification_task_id") else str(result.id)
        ).order_by("created_at")
        
        is_false_positive, fp_score, fp_details = await self._detect_false_positive(
            result, logs, detection_method
        )
        
        if result.id in self._manual_false_positives:
            is_false_positive = True
            fp_score = 1.0
        
        confidence_explanation = self.confidence_calculator.calculate_confidence(
            result, logs
        )
        
        severity_assessment = self.severity_assessor.calculate_cvss_score(result)
        
        if not is_false_positive and result.vulnerable:
            context_factors = severity_assessment.context_factors
            severity_assessment = self.severity_assessor.update_severity_by_context(
                severity_assessment, context_factors
            )
        
        risk_level = self._calculate_risk_level(result, is_false_positive, severity_assessment)
        
        recommendations = self._generate_recommendations(result, is_false_positive, severity_assessment)
        
        analysis_details = {
            "false_positive_indicators": self._get_false_positive_indicators(result),
            "success_indicators": self._get_success_indicators(result),
            "confidence_factors": self._get_confidence_factors(result),
            "execution_logs_count": len(logs),
            "has_errors": any(log.level.lower() == "error" for log in logs),
            "false_positive_details": fp_details,
            "detection_method": detection_method.value
        }
        
        analysis_result = AnalysisResult(
            result_id=result.id if hasattr(result, "id") else 0,
            poc_name=result.poc_name if hasattr(result, "poc_name") else "unknown",
            poc_id=result.poc_id if hasattr(result, "poc_id") else "unknown",
            target=result.target if hasattr(result, "target") else "unknown",
            is_vulnerable=result.vulnerable,
            severity=severity_assessment.severity,
            confidence=confidence_explanation.overall_confidence,
            cvss_score=severity_assessment.cvss_score,
            is_false_positive=is_false_positive,
            risk_level=risk_level,
            recommendations=recommendations,
            analysis_details=analysis_details,
            confidence_explanation=confidence_explanation,
            severity_assessment=severity_assessment,
            detection_method=detection_method,
            false_positive_score=fp_score
        )
        
        self._analysis_cache[analysis_result.result_id] = analysis_result
        
        await self._apply_custom_rules(analysis_result)
        
        return analysis_result
    
    async def _detect_false_positive(
        self,
        result: POCVerificationResult,
        logs: List[POCExecutionLog],
        method: DetectionMethod
    ) -> Tuple[bool, float, Dict[str, Any]]:
        """
        检测误报
        
        Args:
            result: POC 验证结果
            logs: 执行日志
            method: 检测方法
            
        Returns:
            Tuple[bool, float, Dict]: (是否误报, 分数, 详情)
        """
        if method == DetectionMethod.KEYWORD:
            is_fp, score = self.fp_detector.detect_by_keywords(result, logs)
            details = {"method": "keyword", "score": score}
        elif method == DetectionMethod.PATTERN:
            is_fp, score = self.fp_detector.detect_by_patterns(result, logs)
            details = {"method": "pattern", "score": score}
        elif method == DetectionMethod.ML_BASED:
            is_fp, score = self.fp_detector.detect_by_ml(result, logs)
            details = {"method": "ml", "score": score}
        else:
            is_fp, score, scores = self.fp_detector.detect_hybrid(result, logs)
            details = {"method": "hybrid", "scores": scores, "combined_score": score}
        
        return is_fp, score, details
    
    async def analyze_batch_results(
        self,
        results: List[POCVerificationResult],
        detection_method: DetectionMethod = DetectionMethod.HYBRID
    ) -> BatchAnalysisSummary:
        """
        批量分析 POC 验证结果
        
        Args:
            results: POC 验证结果列表
            detection_method: 误报检测方法
            
        Returns:
            BatchAnalysisSummary: 批量分析摘要
        """
        analysis_results = []
        for result in results:
            analysis = await self.analyze_single_result(result, detection_method)
            analysis_results.append(analysis)
        
        total_results = len(results)
        vulnerable_count = sum(1 for a in analysis_results if a.is_vulnerable)
        not_vulnerable_count = total_results - vulnerable_count
        false_positive_count = sum(1 for a in analysis_results if a.is_false_positive)
        true_positive_count = vulnerable_count - false_positive_count
        
        severity_distribution = {}
        for analysis in analysis_results:
            severity = analysis.severity
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
        
        average_confidence = (
            sum(a.confidence for a in analysis_results) / total_results
            if total_results > 0 else 0.0
        )
        average_cvss_score = (
            sum(a.cvss_score for a in analysis_results) / total_results
            if total_results > 0 else 0.0
        )
        
        high_risk_targets = get_high_risk_targets(results)
        
        recommendations = self._generate_batch_recommendations(analysis_results)
        
        summary = BatchAnalysisSummary(
            total_results=total_results,
            vulnerable_count=vulnerable_count,
            not_vulnerable_count=not_vulnerable_count,
            false_positive_count=false_positive_count,
            true_positive_count=true_positive_count,
            severity_distribution=severity_distribution,
            average_confidence=average_confidence,
            average_cvss_score=average_cvss_score,
            high_risk_targets=high_risk_targets,
            recommendations=recommendations
        )
        
        return summary
    
    def _calculate_risk_level(
        self,
        result: POCVerificationResult,
        is_false_positive: bool,
        severity_assessment: SeverityAssessment
    ) -> str:
        """
        计算风险等级
        
        Args:
            result: POC 验证结果
            is_false_positive: 是否为误报
            severity_assessment: 严重程度评估
            
        Returns:
            str: 风险等级
        """
        if is_false_positive:
            return RiskLevel.INFO.value
        
        if not result.vulnerable:
            return RiskLevel.LOW.value
        
        return severity_assessment.severity
    
    def _generate_recommendations(
        self,
        result: POCVerificationResult,
        is_false_positive: bool,
        severity_assessment: SeverityAssessment
    ) -> List[str]:
        """
        生成修复建议
        
        Args:
            result: POC 验证结果
            is_false_positive: 是否为误报
            severity_assessment: 严重程度评估
            
        Returns:
            List[str]: 修复建议列表
        """
        recommendations = []
        
        if is_false_positive:
            recommendations.append("此结果可能是误报,建议进行人工验证")
            recommendations.append("检查网络连接是否正常")
            recommendations.append("确认目标服务是否正常运行")
        elif result.vulnerable:
            poc_name = result.poc_name if hasattr(result, "poc_name") else "未知POC"
            recommendations.append(f"确认漏洞存在: {poc_name}")
            recommendations.append("评估漏洞对业务的影响范围")
            recommendations.append("制定修复计划并优先处理高风险漏洞")
            
            if severity_assessment.risk_level == RiskLevel.CRITICAL:
                recommendations.append("立即修复此漏洞")
                recommendations.append("考虑临时缓解措施")
                recommendations.append("通知安全团队和管理层")
            elif severity_assessment.risk_level == RiskLevel.HIGH:
                recommendations.append("在24小时内修复此漏洞")
                recommendations.append("考虑临时缓解措施")
            elif severity_assessment.risk_level == RiskLevel.MEDIUM:
                recommendations.append("在下一个维护窗口修复")
            else:
                recommendations.append("按计划修复")
            
            if severity_assessment.context_factors:
                if severity_assessment.context_factors.get("remote_code_execution"):
                    recommendations.append("RCE漏洞: 隔离受影响系统,检查是否有入侵痕迹")
                if severity_assessment.context_factors.get("sensitive_data"):
                    recommendations.append("敏感数据泄露: 评估数据影响范围,通知相关方")
                if severity_assessment.context_factors.get("authentication_bypass"):
                    recommendations.append("认证绕过: 强制所有用户重新认证,检查异常登录")
        else:
            recommendations.append("未发现漏洞")
            recommendations.append("继续监控目标系统")
        
        return recommendations
    
    def _generate_batch_recommendations(
        self,
        analysis_results: List[AnalysisResult]
    ) -> List[str]:
        """
        生成批量修复建议
        
        Args:
            analysis_results: 分析结果列表
            
        Returns:
            List[str]: 修复建议列表
        """
        recommendations = []
        
        high_risk_targets = set(
            a.target for a in analysis_results
            if a.risk_level in [RiskLevel.CRITICAL.value, RiskLevel.HIGH.value]
        )
        
        if high_risk_targets:
            recommendations.append(f"发现 {len(high_risk_targets)} 个高风险目标,需要立即处理")
            recommendations.append("优先处理 critical 和 high 级别的漏洞")
        
        false_positive_count = sum(1 for a in analysis_results if a.is_false_positive)
        if false_positive_count > 0:
            recommendations.append(f"发现 {false_positive_count} 个可能的误报,建议人工验证")
        
        severity_distribution = {}
        for analysis in analysis_results:
            severity = analysis.severity
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
        
        if severity_distribution.get(RiskLevel.CRITICAL.value, 0) > 0:
            recommendations.append(
                f"存在 {severity_distribution[RiskLevel.CRITICAL.value]} 个严重漏洞,需要紧急修复"
            )
        
        if severity_distribution.get(RiskLevel.HIGH.value, 0) > 0:
            recommendations.append(
                f"存在 {severity_distribution[RiskLevel.HIGH.value]} 个高危漏洞,建议尽快修复"
            )
        
        avg_confidence = (
            sum(a.confidence for a in analysis_results) / len(analysis_results)
            if analysis_results else 0.0
        )
        if avg_confidence < 0.5:
            recommendations.append("整体置信度较低,建议重新验证关键结果")
        
        return recommendations
    
    def _get_false_positive_indicators(
        self,
        result: POCVerificationResult
    ) -> List[str]:
        """
        获取误报指示器
        
        Args:
            result: POC 验证结果
            
        Returns:
            List[str]: 误报指示器列表
        """
        indicators = []
        
        if result.error:
            indicators.append(f"存在错误: {result.error[:100]}")
        
        if result.confidence < 0.5:
            indicators.append(f"置信度较低: {result.confidence:.2f}")
        
        if result.output:
            output_lower = result.output.lower()
            for keyword in self.false_positive_keywords:
                if keyword in output_lower:
                    indicators.append(f"输出包含误报关键词: {keyword}")
        
        return indicators
    
    def _get_success_indicators(
        self,
        result: POCVerificationResult
    ) -> List[str]:
        """
        获取成功指示器
        
        Args:
            result: POC 验证结果
            
        Returns:
            List[str]: 成功指示器列表
        """
        indicators = []
        
        if result.vulnerable:
            indicators.append("POC 验证成功")
        
        if result.confidence > 0.8:
            indicators.append(f"置信度较高: {result.confidence:.2f}")
        
        if result.output:
            output_lower = result.output.lower()
            for keyword in self.success_keywords:
                if keyword in output_lower:
                    indicators.append(f"输出包含成功关键词: {keyword}")
        
        return indicators
    
    def _get_confidence_factors(
        self,
        result: POCVerificationResult
    ) -> Dict[str, Any]:
        """
        获取置信度因素
        
        Args:
            result: POC 验证结果
            
        Returns:
            Dict: 置信度因素字典
        """
        factors = {
            "base_confidence": result.confidence,
            "vulnerable_status": result.vulnerable,
            "has_output": bool(result.output),
            "has_error": bool(result.error),
            "output_length": len(result.output) if result.output else 0,
            "execution_time": getattr(result, "execution_time", 0)
        }
        
        adjusted_confidence = result.confidence
        
        if result.vulnerable:
            adjusted_confidence += 0.1
        elif result.error:
            adjusted_confidence -= 0.2
        
        if result.output and len(result.output) > 100:
            adjusted_confidence += 0.05
        
        factors["adjusted_confidence"] = min(max(adjusted_confidence, 0.0), 1.0)
        
        return factors
    
    async def _apply_custom_rules(self, analysis_result: AnalysisResult) -> None:
        """应用自定义分析规则"""
        for rule in sorted(self._custom_rules, key=lambda r: r.priority, reverse=True):
            if rule.enabled:
                try:
                    if rule.condition(analysis_result):
                        rule.action(analysis_result)
                except Exception as e:
                    logger.warning(f"自定义规则执行失败 [{rule.name}]: {e}")
    
    def mark_false_positive(
        self,
        result_id: int,
        is_false_positive: bool = True,
        feedback_source: str = "manual"
    ) -> None:
        """
        手动标记/取消标记误报
        
        Args:
            result_id: 结果ID
            is_false_positive: 是否为误报
            feedback_source: 反馈来源
        """
        if is_false_positive:
            self._manual_false_positives.add(result_id)
        else:
            self._manual_false_positives.discard(result_id)
        
        if result_id in self._analysis_cache:
            features = self._analysis_cache[result_id].analysis_details
            self.fp_detector.learn_from_feedback(
                result_id=result_id,
                features=features,
                is_false_positive=is_false_positive,
                source=feedback_source
            )
    
    def add_custom_analysis_rule(
        self,
        rule_id: str,
        name: str,
        description: str,
        condition: Callable[[Any], bool],
        action: Callable[[Any], Any],
        priority: int = 0,
        enabled: bool = True
    ) -> None:
        """
        添加自定义分析规则
        
        Args:
            rule_id: 规则ID
            name: 规则名称
            description: 规则描述
            condition: 条件函数
            action: 动作函数
            priority: 优先级
            enabled: 是否启用
        """
        rule = CustomAnalysisRule(
            rule_id=rule_id,
            name=name,
            description=description,
            condition=condition,
            action=action,
            priority=priority,
            enabled=enabled
        )
        self._custom_rules.append(rule)
    
    def remove_custom_rule(self, rule_id: str) -> bool:
        """
        移除自定义分析规则
        
        Args:
            rule_id: 规则ID
            
        Returns:
            bool: 是否成功移除
        """
        for i, rule in enumerate(self._custom_rules):
            if rule.rule_id == rule_id:
                self._custom_rules.pop(i)
                return True
        return False
    
    def get_custom_rules(self) -> List[Dict[str, Any]]:
        """获取所有自定义规则"""
        return [
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "priority": rule.priority,
                "enabled": rule.enabled
            }
            for rule in self._custom_rules
        ]
    
    async def compare_scans(
        self,
        results_1: List[POCVerificationResult],
        results_2: List[POCVerificationResult],
        scan_id_1: str = "scan_1",
        scan_id_2: str = "scan_2"
    ) -> ScanComparison:
        """
        比较两次扫描结果
        
        Args:
            results_1: 第一次扫描结果
            results_2: 第二次扫描结果
            scan_id_1: 第一次扫描ID
            scan_id_2: 第二次扫描ID
            
        Returns:
            ScanComparison: 比较结果
        """
        vulns_1 = {
            r.target: r for r in results_1 if r.vulnerable
        }
        vulns_2 = {
            r.target: r for r in results_2 if r.vulnerable
        }
        
        targets_1 = set(vulns_1.keys())
        targets_2 = set(vulns_2.keys())
        
        new_vulnerabilities = list(targets_2 - targets_1)
        fixed_vulnerabilities = list(targets_1 - targets_2)
        persistent_vulnerabilities = list(targets_1 & targets_2)
        
        severity_changes = {}
        confidence_changes = {}
        
        for target in persistent_vulnerabilities:
            r1 = vulns_1[target]
            r2 = vulns_2[target]
            
            s1 = r1.severity if hasattr(r1, "severity") and r1.severity else "info"
            s2 = r2.severity if hasattr(r2, "severity") and r2.severity else "info"
            
            if s1 != s2:
                severity_changes[target] = {"old": s1, "new": s2}
            
            c1 = r1.confidence if hasattr(r1, "confidence") else 0.0
            c2 = r2.confidence if hasattr(r2, "confidence") else 0.0
            
            if abs(c1 - c2) > 0.1:
                confidence_changes[target] = (c1, c2)
        
        return ScanComparison(
            scan_id_1=scan_id_1,
            scan_id_2=scan_id_2,
            new_vulnerabilities=new_vulnerabilities,
            fixed_vulnerabilities=fixed_vulnerabilities,
            persistent_vulnerabilities=persistent_vulnerabilities,
            severity_changes=severity_changes,
            confidence_changes=confidence_changes
        )
    
    async def export_results(
        self,
        analysis_results: List[AnalysisResult],
        format: ExportFormat = ExportFormat.JSON,
        file_path: Optional[str] = None
    ) -> str:
        """
        导出分析结果
        
        Args:
            analysis_results: 分析结果列表
            format: 导出格式
            file_path: 文件路径(可选)
            
        Returns:
            str: 导出内容
        """
        if format == ExportFormat.JSON:
            content = self._export_to_json(analysis_results)
        elif format == ExportFormat.CSV:
            content = self._export_to_csv(analysis_results)
        elif format == ExportFormat.HTML:
            content = self._export_to_html(analysis_results)
        elif format == ExportFormat.MARKDOWN:
            content = self._export_to_markdown(analysis_results)
        else:
            content = self._export_to_json(analysis_results)
        
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
        
        return content
    
    def _export_to_json(self, results: List[AnalysisResult]) -> str:
        """导出为JSON格式"""
        data = []
        for r in results:
            item = {
                "result_id": r.result_id,
                "poc_name": r.poc_name,
                "poc_id": r.poc_id,
                "target": r.target,
                "is_vulnerable": r.is_vulnerable,
                "severity": r.severity,
                "confidence": r.confidence,
                "cvss_score": r.cvss_score,
                "is_false_positive": r.is_false_positive,
                "risk_level": r.risk_level,
                "recommendations": r.recommendations,
                "analysis_details": r.analysis_details,
            }
            if r.confidence_explanation:
                item["confidence_explanation"] = {
                    "overall_confidence": r.confidence_explanation.overall_confidence,
                    "explanation": r.confidence_explanation.explanation,
                    "recommendations": r.confidence_explanation.recommendations
                }
            if r.severity_assessment:
                item["severity_assessment"] = {
                    "cvss_score": r.severity_assessment.cvss_score,
                    "cvss_vector": r.severity_assessment.cvss_vector.to_vector_string(),
                    "risk_level": r.severity_assessment.risk_level.value,
                    "impact_score": r.severity_assessment.impact_score,
                    "exploitability_score": r.severity_assessment.exploitability_score
                }
            data.append(item)
        return json.dumps(data, ensure_ascii=False, indent=2)
    
    def _export_to_csv(self, results: List[AnalysisResult]) -> str:
        """导出为CSV格式"""
        lines = [
            "result_id,poc_name,target,is_vulnerable,severity,confidence,cvss_score,is_false_positive,risk_level"
        ]
        for r in results:
            lines.append(
                f"{r.result_id},{r.poc_name},{r.target},{r.is_vulnerable},"
                f"{r.severity},{r.confidence:.2f},{r.cvss_score:.1f},"
                f"{r.is_false_positive},{r.risk_level}"
            )
        return "\n".join(lines)
    
    def _export_to_html(self, results: List[AnalysisResult]) -> str:
        """导出为HTML格式"""
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>POC验证结果分析报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .medium { color: #fbc02d; }
        .low { color: #388e3c; }
        .info { color: #1976d2; }
    </style>
</head>
<body>
    <h1>POC验证结果分析报告</h1>
    <p>生成时间: {timestamp}</p>
    <table>
        <tr>
            <th>POC名称</th>
            <th>目标</th>
            <th>漏洞状态</th>
            <th>严重程度</th>
            <th>置信度</th>
            <th>CVSS评分</th>
            <th>误报</th>
        </tr>
        {rows}
    </table>
</body>
</html>"""
        
        rows = []
        for r in results:
            vuln_status = "存在漏洞" if r.is_vulnerable else "安全"
            fp_status = "是" if r.is_false_positive else "否"
            severity_class = r.severity
            
            rows.append(f"""
        <tr>
            <td>{r.poc_name}</td>
            <td>{r.target}</td>
            <td>{vuln_status}</td>
            <td class="{severity_class}">{r.severity}</td>
            <td>{r.confidence:.2f}</td>
            <td>{r.cvss_score:.1f}</td>
            <td>{fp_status}</td>
        </tr>""")
        
        return html.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            rows="".join(rows)
        )
    
    def _export_to_markdown(self, results: List[AnalysisResult]) -> str:
        """导出为Markdown格式"""
        lines = [
            "# POC验证结果分析报告",
            f"\n生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
            "## 结果概览\n",
            "| POC名称 | 目标 | 漏洞状态 | 严重程度 | 置信度 | CVSS评分 | 误报 |",
            "|---------|------|----------|----------|--------|----------|------|"
        ]
        
        for r in results:
            vuln_status = "存在漏洞" if r.is_vulnerable else "安全"
            fp_status = "是" if r.is_false_positive else "否"
            lines.append(
                f"| {r.poc_name} | {r.target} | {vuln_status} | "
                f"{r.severity} | {r.confidence:.2f} | {r.cvss_score:.1f} | {fp_status} |"
            )
        
        vulnerable_results = [r for r in results if r.is_vulnerable and not r.is_false_positive]
        if vulnerable_results:
            lines.append("\n## 修复建议\n")
            for r in vulnerable_results[:10]:
                lines.append(f"\n### {r.poc_name} ({r.target})\n")
                for rec in r.recommendations:
                    lines.append(f"- {rec}")
        
        return "\n".join(lines)
    
    def generate_remediation_recommendations(
        self,
        analysis_result: AnalysisResult,
        context: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        生成详细的修复建议
        
        Args:
            analysis_result: 分析结果
            context: 额外上下文
            
        Returns:
            List[str]: 修复建议列表
        """
        recommendations = analysis_result.recommendations.copy()
        
        if context:
            if context.get("production_environment"):
                recommendations.insert(0, "生产环境: 建议先在测试环境验证修复方案")
            
            if context.get("compliance_required"):
                recommendations.append("合规要求: 记录修复过程以满足审计要求")
        
        vuln_type = self._infer_vulnerability_type(analysis_result)
        if vuln_type:
            type_recommendations = self._get_type_specific_recommendations(vuln_type)
            recommendations.extend(type_recommendations)
        
        return recommendations
    
    def _infer_vulnerability_type(self, analysis_result: AnalysisResult) -> Optional[str]:
        """推断漏洞类型"""
        poc_name = analysis_result.poc_name.lower()
        output = str(analysis_result.analysis_details.get("output", "")).lower()
        
        type_keywords = {
            "sql_injection": ["sql", "sqli", "injection"],
            "xss": ["xss", "cross-site scripting"],
            "rce": ["rce", "remote code", "command execution", "code execution"],
            "ssrf": ["ssrf", "server-side request"],
            "lfi": ["lfi", "local file", "path traversal", "directory traversal"],
            "rfi": ["rfi", "remote file"],
            "xxe": ["xxe", "xml external entity"],
            "deserialization": ["deserializ", "unserialize"],
            "authentication": ["auth", "login", "credential", "password"],
        }
        
        for vuln_type, keywords in type_keywords.items():
            if any(kw in poc_name or kw in output for kw in keywords):
                return vuln_type
        
        return None
    
    def _get_type_specific_recommendations(self, vuln_type: str) -> List[str]:
        """获取特定类型漏洞的修复建议"""
        recommendations_map = {
            "sql_injection": [
                "使用参数化查询或预编译语句",
                "对所有用户输入进行验证和过滤",
                "使用ORM框架避免直接拼接SQL",
                "限制数据库用户权限"
            ],
            "xss": [
                "对所有输出进行HTML编码",
                "使用Content-Security-Policy头",
                "设置HttpOnly和Secure Cookie标志",
                "验证和过滤用户输入"
            ],
            "rce": [
                "严格验证所有用户输入",
                "禁用危险函数(如eval, exec)",
                "使用白名单验证命令参数",
                "在沙箱环境中执行外部命令"
            ],
            "ssrf": [
                "验证和限制请求的目标URL",
                "使用白名单验证目标域名",
                "禁用不必要的协议",
                "隔离内部网络访问"
            ],
            "lfi": [
                "验证文件路径,禁止目录遍历",
                "使用白名单验证文件名",
                "禁用远程文件包含",
                "设置open_basedir限制"
            ],
            "xxe": [
                "禁用XML外部实体处理",
                "使用JSON替代XML",
                "验证XML输入格式",
                "更新XML解析库"
            ],
            "deserialization": [
                "避免反序列化不可信数据",
                "使用安全的序列化格式(如JSON)",
                "实现反序列化白名单",
                "更新依赖库版本"
            ],
            "authentication": [
                "实施多因素认证",
                "使用强密码策略",
                "实现账户锁定机制",
                "记录和监控登录尝试"
            ]
        }
        
        return recommendations_map.get(vuln_type, [])
    
    async def get_result_statistics(
        self,
        results: List[POCVerificationResult]
    ) -> Dict[str, Any]:
        """
        获取结果统计信息
        
        Args:
            results: POC 验证结果列表
            
        Returns:
            Dict: 统计信息字典
        """
        return calculate_statistics(results)
    
    def configure_false_positive_threshold(
        self,
        threshold: FalsePositiveThreshold
    ) -> None:
        """
        配置误报检测阈值
        
        Args:
            threshold: 阈值配置
        """
        self.fp_detector.threshold = threshold
    
    def configure_confidence_weights(
        self,
        weights: ConfidenceWeights
    ) -> None:
        """
        配置置信度权重
        
        Args:
            weights: 权重配置
        """
        self.confidence_calculator.weights = weights


result_analyzer = ResultAnalyzer()
