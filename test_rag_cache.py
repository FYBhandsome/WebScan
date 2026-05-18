"""
测试 RAG 模型缓存功能
"""
import os
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

from TOSKill.RAG.rag_engine import get_rag_engine

def test_rag_model_cache():
    """测试 RAG 模型加载和缓存"""
    print("=" * 60)
    print("开始测试 RAG 模型缓存功能")
    print("=" * 60)
    
    # 检查缓存目录
    cache_dir = Path.home() / ".cache" / "huggingface"
    print(f"\n模型缓存目录: {cache_dir}")
    print(f"缓存目录是否存在: {cache_dir.exists()}")
    
    if cache_dir.exists():
        print("\n缓存目录内容:")
        for item in cache_dir.iterdir():
            print(f"  - {item.name}")
    
    # 初始化 RAG 引擎
    print("\n" + "=" * 60)
    print("正在初始化 RAG 引擎...")
    print("=" * 60)
    
    try:
        rag_engine = get_rag_engine()
        stats = rag_engine.get_stats()
        
        print("\nRAG 引擎状态:")
        print(f"  - 已初始化: {stats['initialized']}")
        print(f"  - 就绪状态: {stats['ready']}")
        print(f"  - 嵌入模型已加载: {stats['embed_model_loaded']}")
        
        if stats.get('model_load_error'):
            print(f"  - 模型加载错误: {stats['model_load_error']}")
        else:
            print("  - 模型加载成功!")
            
        print(f"\n文档数量: {stats['document_count']}")
        print(f"知识库目录: {stats['knowledge_dir']}")
        print(f"索引存储目录: {stats['storage_dir']}")
        
        # 再次检查缓存目录
        if cache_dir.exists():
            print("\n缓存目录内容 (模型加载后):")
            for item in cache_dir.iterdir():
                print(f"  - {item.name}")
        
        print("\n" + "=" * 60)
        print("测试完成!")
        print("=" * 60)
        
        return True
        
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_rag_model_cache()
    sys.exit(0 if success else 1)
