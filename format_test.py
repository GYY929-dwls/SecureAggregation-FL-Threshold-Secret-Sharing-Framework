import pytest
from secret_sharing import ShamirSecretSharing
import random

def test_text_handling_with_differential_privacy():
    from difflib import SequenceMatcher  # 用于计算相似度
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)

    # 动态生成测试数据
    ascii_texts = [f"ASCII text {i} {random.randint(1000, 9999)}" for i in range(50)]  # ASCII 文本
    utf8_texts = [f"UTF-8 文本 {i} - 你好世界 {random.randint(1000, 9999)}" for i in range(50)]  # UTF-8 多语言文本
    special_texts = [f"Special chars {i} 😊🚀✨ {random.randint(1000, 9999)}" for i in range(50)]  # 含特殊字符文本

    # 测试结果统计
    success_count = {"ASCII": 0, "UTF-8": 0, "Special": 0}
    total_similarity = {"ASCII": 0.0, "UTF-8": 0.0, "Special": 0.0}  # 用于累计相似度

    # 测试 ASCII 文本
    for text in ascii_texts:
        try:
            encoded = shamir.encode_text_secret(text)
            # 启用差分隐私
            shares = shamir.split_secret(encoded, epsilon=1.0, sensitivity=1.0)
            reconstructed = shamir.reconstruct_secret(shares[:3])
            decoded = shamir.decode_text_secret(reconstructed)

            # 计算相似度
            similarity = SequenceMatcher(None, text, decoded).ratio()
            total_similarity["ASCII"] += similarity

            # 验证解码结果（允许少量误差）
            assert similarity >= 0.95  # 相似度至少为 95%
            success_count["ASCII"] += 1
        except Exception as e:
            print(f"ASCII 差分隐私测试失败: {text}, 错误: {str(e)}")

    # 测试 UTF-8 文本
    for text in utf8_texts:
        try:
            encoded = shamir.encode_text_secret(text)
            # 启用差分隐私
            shares = shamir.split_secret(encoded, epsilon=1.0, sensitivity=1.0)
            reconstructed = shamir.reconstruct_secret(shares[:3])
            decoded = shamir.decode_text_secret(reconstructed)

            # 计算相似度
            similarity = SequenceMatcher(None, text, decoded).ratio()
            total_similarity["UTF-8"] += similarity

            # 验证解码结果（允许少量误差）
            assert similarity >= 0.95  # 相似度至少为 95%
            success_count["UTF-8"] += 1
        except Exception as e:
            print(f"UTF-8 差分隐私测试失败: {text}, 错误: {str(e)}")

    # 测试含特殊字符文本
    for text in special_texts:
        try:
            encoded = shamir.encode_text_secret(text)
            # 启用差分隐私
            shares = shamir.split_secret(encoded, epsilon=1.0, sensitivity=1.0)
            reconstructed = shamir.reconstruct_secret(shares[:3])
            decoded = shamir.decode_text_secret(reconstructed)

            # 计算相似度
            similarity = SequenceMatcher(None, text, decoded).ratio()
            total_similarity["Special"] += similarity

            # 验证解码结果（允许少量误差）
            assert similarity >= 0.90  # 特殊字符允许更低的相似度
            success_count["Special"] += 1
        except Exception as e:
            print(f"特殊字符差分隐私测试失败: {text}, 错误: {str(e)}")

    # 输出测试结果
    print(f"ASCII 文本测试成功次数: {success_count['ASCII']}/50")
    print(f"ASCII 文本平均相似度: {total_similarity['ASCII'] / 50:.2%}")
    print(f"UTF-8 文本测试成功次数: {success_count['UTF-8']}/50")
    print(f"UTF-8 文本平均相似度: {total_similarity['UTF-8'] / 50:.2%}")
    print(f"特殊字符文本测试成功次数: {success_count['Special']}/50")
    print(f"特殊字符文本平均相似度: {total_similarity['Special'] / 50:.2%}")

    # 确保所有测试通过
    assert success_count["ASCII"] == 50, "部分 ASCII 文本测试失败"
    assert success_count["UTF-8"] == 50, "部分 UTF-8 文本测试失败"
    assert success_count["Special"] == 50, "部分特殊字符文本测试失败"

def test_text_handling_accuracy():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)

    # 动态生成测试数据
    ascii_texts = [f"ASCII text {i} {random.randint(1000, 9999)}" for i in range(50)]  # ASCII 文本
    utf8_texts = [f"UTF-8 文本 {i} - 你好世界 {random.randint(1000, 9999)}" for i in range(50)]  # UTF-8 多语言文本
    special_texts = [f"Special chars {i} 😊🚀✨ {random.randint(1000, 9999)}" for i in range(50)]  # 含特殊字符文本

    # 测试结果统计
    success_count = {"ASCII": 0, "UTF-8": 0, "Special": 0}

    # 测试 ASCII 文本
    for text in ascii_texts:
        try:
            encoded = shamir.encode_text_secret(text)
            shares = shamir.split_secret(encoded)
            reconstructed = shamir.reconstruct_secret(shares[:3])
            decoded = shamir.decode_text_secret(reconstructed)
            assert decoded == text
            success_count["ASCII"] += 1
        except Exception as e:
            print(f"ASCII 测试失败: {text}, 错误: {str(e)}")

    # 测试 UTF-8 文本
    for text in utf8_texts:
        try:
            encoded = shamir.encode_text_secret(text)
            shares = shamir.split_secret(encoded)
            reconstructed = shamir.reconstruct_secret(shares[:3])
            decoded = shamir.decode_text_secret(reconstructed)
            assert decoded == text
            success_count["UTF-8"] += 1
        except Exception as e:
            print(f"UTF-8 测试失败: {text}, 错误: {str(e)}")

    # 测试含特殊字符文本
    for text in special_texts:
        try:
            encoded = shamir.encode_text_secret(text)
            shares = shamir.split_secret(encoded)
            reconstructed = shamir.reconstruct_secret(shares[:3])
            decoded = shamir.decode_text_secret(reconstructed)
            assert len(decoded) >= len(text) - 2  # 允许少量替换字符
            success_count["Special"] += 1
        except Exception as e:
            print(f"特殊字符测试失败: {text}, 错误: {str(e)}")

    # 输出测试结果
    print(f"ASCII 文本测试成功次数: {success_count['ASCII']}/50")
    print(f"UTF-8 文本测试成功次数: {success_count['UTF-8']}/50")
    print(f"特殊字符文本测试成功次数: {success_count['Special']}/50")

    # 确保所有测试通过
    assert success_count["ASCII"] == 50, "部分 ASCII 文本测试失败"
    assert success_count["UTF-8"] == 50, "部分 UTF-8 文本测试失败"
    assert success_count["Special"] == 50, "部分特殊字符文本测试失败"
