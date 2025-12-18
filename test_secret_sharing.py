import pytest
from secret_sharing import ShamirSecretSharing
from itertools import combinations
import os
from PIL import Image
import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

def test_secret_reconstruction():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    secret = 123456
    print(f"重构前: {secret}")
    shares = shamir.split_secret(secret)
    reconstructed = shamir.reconstruct_secret(shares[:3])
    print(f"重构结果: {reconstructed}")
    assert reconstructed == secret

def test_text_secret_roundtrip():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    text = "federated_learning_secret"
    encoded = shamir.encode_text_secret(text)
    shares = shamir.split_secret(encoded)
    reconstructed = shamir.reconstruct_secret(shares[:3])
    decoded = shamir.decode_text_secret(reconstructed)
    print(f"原始文本: {text}，解码后: {decoded}")
    assert decoded == text

#多路径恢复
def test_multiple_valid_combinations_restore_same_secret():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    secret = 2025
    shares = shamir.split_secret(secret)

    reconstructed_secrets = set()
    for subset in combinations(shares, 3):
        reconstructed = shamir.reconstruct_secret(list(subset))
        reconstructed_secrets.add(reconstructed)

    assert len(reconstructed_secrets) == 1
    assert reconstructed_secrets.pop() == secret

#多次分割随机性
def test_split_randomness():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    secret = 424242

    shares1 = shamir.split_secret(secret)
    shares2 = shamir.split_secret(secret)

    y_values1 = [y for _, y, _, _ in shares1]
    y_values2 = [y for _, y, _, _ in shares2]

    assert y_values1 != y_values2  # 多项式不同导致份额不同

def test_attack_resistance():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    shares = shamir.split_secret(42)

    # 篡改所有份额的 y 值
    tampered_shares = []
    for x, y, sig, mac in shares:
        new_y = (y + 1) % shamir.modulus
        tampered_shares.append((x, new_y, sig, mac))

    with pytest.raises(ValueError) as exc_info:
        shamir.reconstruct_secret(tampered_shares)

    assert "有效份额不足" in str(exc_info.value)

#伪造签名份额攻击
def test_forged_signature_rejection():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    shares = shamir.split_secret(999)
    x, y, _, _ = shares[0]
    fake_sig = b"invalid_signature"
    fake_mac = b"invalid_mac"
    forged_share = (x, y, fake_sig, fake_mac)

    # 混入 2 个有效份额 + 1 个伪造份额（仍不足以恢复）
    test_shares = [forged_share] + shares[1:3]
    with pytest.raises(ValueError) as exc_info:
        shamir.reconstruct_secret(test_shares)
    assert "有效份额不足" in str(exc_info.value)

#MAC 被篡改
def test_mac_tampering_detection():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    shares = shamir.split_secret(888)
    x, y, sig, mac = shares[0]
    tampered_mac = mac[:-1] + b'\x00'  # 改变最后一位
    tampered_share = (x, y, sig, tampered_mac)
    test_shares = [tampered_share] + shares[1:3]
    with pytest.raises(ValueError):
        shamir.reconstruct_secret(test_shares)

#重放攻击
def test_replay_attack_resistance():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    shares = shamir.split_secret(321)
    # 使用同一个份额三次（不应该构成有效恢复）
    duplicate_shares = [shares[0]] * 3
    with pytest.raises(ValueError):
        shamir.reconstruct_secret(duplicate_shares)

def test_differential_privacy_reconstruction_tolerance():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    original_secret = 9999
    epsilon = 0.5  # 加噪较强
    shares = shamir.split_secret(original_secret, epsilon=epsilon)

    reconstructed = shamir.reconstruct_secret(shares[:3])
    error = abs(reconstructed - original_secret)

    print(f"原始: {original_secret}, 重构: {reconstructed}, 误差: {error}")
    assert error < 50  # 允许一定误差

def test_differential_privacy_strength():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    secret = 4242

    shares_high_epsilon = shamir.split_secret(secret, epsilon=10.0)
    shares_low_epsilon = shamir.split_secret(secret, epsilon=0.1)

    recon_high = shamir.reconstruct_secret(shares_high_epsilon[:3])
    recon_low = shamir.reconstruct_secret(shares_low_epsilon[:3])

    error_high = abs(recon_high - secret)
    error_low = abs(recon_low - secret)

    print(f"ε=10重构误差: {error_high}, ε=0.1重构误差: {error_low}")
    assert error_low >= error_high  # 噪声更强导致误差更大

def test_differential_privacy_text_secret():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    text = "private_model_weights"
    encoded = shamir.encode_text_secret(text)

    shares = shamir.split_secret(encoded, epsilon=1.0)
    reconstructed = shamir.reconstruct_secret(shares[:3])
    decoded = shamir.decode_text_secret(reconstructed)

    print(f"原始: {text}, 解码后: {decoded}")
    assert isinstance(decoded, str)
    assert len(decoded) >= len(text) - 2  # 字符长度变化小


def test_modulus_validation():
    shamir = ShamirSecretSharing(threshold=2, num_parties=3)
    with pytest.raises(ValueError):
        shamir.split_secret(shamir.modulus + 1)


#空输入和非法类型输入
def test_empty_shares_list_raises_error():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    with pytest.raises(ValueError):
        shamir.reconstruct_secret([])

def test_invalid_secret_type():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    with pytest.raises(TypeError):
        shamir.split_secret("not a number")  # 非 int 类型

#莫属边界行为
def test_secret_zero_and_modulus_minus_one():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    secret_zero = 0
    secret_max = shamir.modulus - 1

    shares_zero = shamir.split_secret(secret_zero)
    shares_max = shamir.split_secret(secret_max)

    assert shamir.reconstruct_secret(shares_zero[:3]) == secret_zero
    assert shamir.reconstruct_secret(shares_max[:3]) == secret_max

#最大门限
def test_maximum_threshold_requires_all_shares():
    shamir = ShamirSecretSharing(threshold=5, num_parties=5)
    secret = 8888
    shares = shamir.split_secret(secret)
    with pytest.raises(ValueError):
        shamir.reconstruct_secret(shares[:4])


def test_image_secret_roundtrip():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)

    # 创建更简单的测试图片（使用固定值）
    test_img_path = "secret\\test.png"
    img = Image.new('L', (10, 10), color=128)  # 使用中间灰度值
    img.save(test_img_path)

    # 编码时禁用差分隐私
    secret = shamir.encode_image_secret(test_img_path, epsilon=None)

    # 分割和重构
    shares = shamir.split_secret(secret)
    reconstructed = shamir.reconstruct_secret(shares[:3])

    # 解码图片
    decoded_img = shamir.decode_image_secret(reconstructed, shape=(10, 10))

    # 验证像素值（允许±5的差异）
    decoded_pixels = np.array(decoded_img)
    assert np.all(np.abs(decoded_pixels - 128) <= 5), "像素值超出允许范围"


def test_large_image_handling():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)

    # 创建大图片
    big_img_path = "secret\\big.png"
    img = Image.new('L', (500, 500), color=200)
    img.save(big_img_path)

    # 编码应自动缩小
    secret = shamir.encode_image_secret(big_img_path)
    assert secret < (1 << (100 * 100 * 8)), "图片编码过大"


def test_image_secret_with_differential_privacy():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)

    # 创建测试图片
    test_img_path = "secret\\private.png"
    img = Image.new('L', (20, 20), color=150)
    img.save(test_img_path)

    # 测试不同隐私级别
    for epsilon in [0.5, 1.0, 5.0]:
        secret = shamir.encode_image_secret(test_img_path, epsilon=epsilon)
        shares = shamir.split_secret(secret)
        reconstructed = shamir.reconstruct_secret(shares[:3])

        # 验证结果在合理范围内
        assert 0 < reconstructed < shamir.modulus


def test_corrupted_image_secret_recovery():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)

    # 1. 准备原始秘密和份额
    secret = 12345
    shares = shamir.split_secret(secret)
    share1, share2, share3 = shares[:3]

    # 2. 创建篡改份额（修改y值但保持签名/MAC不变）
    x, y, sig, mac = share3
    tampered_share = (x, (y + 1) % shamir.modulus, sig, mac)  # 故意不更新签名

    # 3. 验证重构应失败（因为签名与数据不匹配）
    with pytest.raises(ValueError, match="有效份额不足"):
        shamir.reconstruct_secret([share1, share2, tampered_share])


# 新增：获取测试图片的绝对路径
def get_test_image_path(filename="test.png"):
    """获取测试图片路径，优先在test_images目录查找"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    paths_to_try = [
        os.path.join(base_dir, filename),  # 直接同级目录
        os.path.join(base_dir, "test_images", filename)  # test_images目录
    ]
    for path in paths_to_try:
        if os.path.exists(path):
            return path
    pytest.skip(f"测试图片 {filename} 不存在，请放置在以下位置之一:\n" + "\n".join(paths_to_try))


def test_real_image_processing():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)

    # 创建临时测试图片
    test_img_path = "secret\\test.png"
    img = Image.new('L', (100, 100), color=150)
    img.save(test_img_path)

    try:
        secret = shamir.encode_image_secret(test_img_path)
        shares = shamir.split_secret(secret)
        reconstructed = shamir.reconstruct_secret(shares[:3])

        output_path = "secret\\reconstructed.png"
        decoded_img = shamir.decode_image_secret(reconstructed,
                                                 output_path=output_path,
                                                 shape=(100, 100))

        # 验证基本属性
        assert os.path.exists(output_path)
        assert decoded_img.size == (100, 100)

    except Exception as e:
        pytest.fail(f"测试失败: {str(e)}")

