"""
POC Confidence Scoring Module
"""
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class ConfidenceScorer:
    """
    Calculates confidence scores for POC verification results
    """
    
    def __init__(self):
        self.weights = {
            "match_score": 0.3,
            "execution_score": 0.4,
            "output_score": 0.3
        }
    
    def calculate_score(
        self, 
        match_result: Optional[Any], 
        execution_result: Dict[str, Any]
    ) -> float:
        """
        Calculate overall confidence score
        
        Args:
            match_result: POC match result from matcher
            execution_result: Execution result from verification engine
            
        Returns:
            float: Confidence score (0.0 - 1.0)
        """
        try:
            match_score = self._calculate_match_score(match_result)
            execution_score = self._calculate_execution_score(execution_result)
            output_score = self._calculate_output_score(execution_result)
            
            total_score = (
                match_score * self.weights["match_score"] +
                execution_score * self.weights["execution_score"] +
                output_score * self.weights["output_score"]
            )
            
            logger.debug(
                f"Confidence scores - match: {match_score:.2f}, "
                f"execution: {execution_score:.2f}, output: {output_score:.2f}, "
                f"total: {total_score:.2f}"
            )
            
            return round(total_score, 3)
            
        except Exception as e:
            logger.error(f"Error calculating confidence score: {e}")
            return 0.0
    
    def _calculate_match_score(self, match_result: Optional[Any]) -> float:
        """Calculate score based on POC match quality"""
        if match_result is None:
            return 0.0
        
        if hasattr(match_result, 'match_score'):
            return match_result.match_score
        
        return 0.5
    
    def _calculate_execution_score(self, execution_result: Dict[str, Any]) -> float:
        """Calculate score based on execution success"""
        if not execution_result:
            return 0.0
        
        score = 0.5
        
        if execution_result.get("vulnerable"):
            score += 0.3
        
        if not execution_result.get("error"):
            score += 0.2
        
        return min(score, 1.0)
    
    def _calculate_output_score(self, execution_result: Dict[str, Any]) -> float:
        """Calculate score based on output quality"""
        if not execution_result:
            return 0.0
        
        score = 0.3
        
        output = execution_result.get("output", "")
        if output:
            score += min(len(output) / 1000, 0.4)
        
        if execution_result.get("vulnerable"):
            score += 0.3
        
        return min(score, 1.0)


confidence_scorer = ConfidenceScorer()
