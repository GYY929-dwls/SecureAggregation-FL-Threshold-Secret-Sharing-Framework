import pytest
from secret_sharing import ShamirSecretSharing
import random

# 1. 份额丢失与容错性
def test_share_loss_tolerance():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    secret = 20240610
    shares = shamir.split_secret(secret)
    # 丢失2份，只用3份重构
    reconstructed = shamir.reconstruct_secret(shares[:3])
    assert reconstructed == secret
    # 丢失3份，只用2份重构应失败
    with pytest.raises(ValueError):
        shamir.reconstruct_secret(shares[:2])

# 2. 份额污染攻击（Byzantine攻击）
def test_byzantine_share_attack():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    secret = 424242
    attack_success = 0
    for _ in range(100):
        shares = shamir.split_secret(secret)
        # 用随机y值和x值伪造份额
        fake_share = (99, random.randint(1, shamir.modulus-1), b"fake_sig", b"fake_mac")
        test_shares = [fake_share] + shares[1:3]
        try:
            shamir.reconstruct_secret(test_shares)
        except ValueError:
            attack_success += 1
    assert attack_success == 100

# 3. 多轮攻击/持续性攻击
def test_persistent_attack():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    secret = 888888
    attack_success = 0
    for _ in range(100):
        shares = shamir.split_secret(secret)
        # 每轮都混入一个伪造份额
        fake_share = (shares[0][0], shares[0][1], b"fake_sig", b"fake_mac")
        test_shares = [fake_share] + shares[1:3]
        try:
            shamir.reconstruct_secret(test_shares)
        except ValueError:
            attack_success += 1
    assert attack_success == 100

# 4. 份额顺序打乱
def test_share_order_shuffle():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    secret = 13579
    shares = shamir.split_secret(secret)
    shuffled = shares[:3]
    random.shuffle(shuffled)
    reconstructed = shamir.reconstruct_secret(shuffled)
    assert reconstructed == secret

# 5. t-1合法+1非法份额
def test_t_minus1_valid_plus1_invalid():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    secret = 24680
    shares = shamir.split_secret(secret)
    fake_share = (shares[0][0], shares[0][1], b"fake_sig", b"fake_mac")
    test_shares = [fake_share] + shares[1:3]
    with pytest.raises(ValueError):
        shamir.reconstruct_secret(test_shares)

# 6. 不同门限和参与方数量下的安全性
def test_various_thresholds():
    for t, n in [(2,3), (3,5), (4,6)]:
        shamir = ShamirSecretSharing(threshold=t, num_parties=n)
        secret = 12345
        shares = shamir.split_secret(secret)
        reconstructed = shamir.reconstruct_secret(shares[:t])
        assert reconstructed == secret
        with pytest.raises(ValueError):
            shamir.reconstruct_secret(shares[:t-1])

# 7. 批量参数分割与重构
def test_batch_model_params():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    model_params = [random.randint(1e8, 1e10) for _ in range(10)]
    for param in model_params:
        shares = shamir.split_secret(param)
        reconstructed = shamir.reconstruct_secret(shares[:3])
        assert reconstructed == param

# 8. 抗推断攻击能力（多轮收集不足t份额）
def test_inference_attack_resistance():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    secret = 20240610
    shares = shamir.split_secret(secret)
    # 攻击者多轮收集，每轮只拿到2份
    collected = []
    for _ in range(10):
        random.shuffle(shares)
        collected.extend(shares[:2])
    # 只拿到20份（10轮，每轮2份，重复x值），但每次都不足t
    # 不能恢复秘密
    unique_xs = set(x for x,_,_,_ in collected)
    assert len(unique_xs) <= 5
    # 尝试用任意2份重构都失败
    for i in range(0, len(collected), 2):
        with pytest.raises(ValueError):
            shamir.reconstruct_secret(collected[i:i+2])

# 9. 批量重构正确性与多路径恢复

def test_massive_reconstruction_accuracy():
    # 测试参数
    test_cases = [
        (0, 3, 5),  # 边界值0
        (None, 3, 5),  # 随机大整数
        (None, 2, 3),  # 不同门限
        (None, 4, 7),  # 不同门限
        (None, 5, 8),  # 不同门限
    ]
    total = 0
    success = 0
    for case in test_cases:
        secret, t, n = case
        shamir = ShamirSecretSharing(threshold=t, num_parties=n)
        # 边界值0
        if secret == 0:
            s = 0
        # 边界值模数-1
        elif secret == -1:
            s = shamir.modulus - 1
        else:
            s = random.randint(1, shamir.modulus - 2)
        # 测试300次
        for _ in range(60):
            shares = shamir.split_secret(s)
            # 多路径恢复：任意t个合法份额组合
            from itertools import combinations
            for subset in combinations(shares, t):
                reconstructed = shamir.reconstruct_secret(list(subset))
                total += 1
                if reconstructed == s:
                    success += 1
        # 边界值模数-1
        if secret == 0:
            s = shamir.modulus - 1
            for _ in range(20):
                shares = shamir.split_secret(s)
                from itertools import combinations
                for subset in combinations(shares, t):
                    reconstructed = shamir.reconstruct_secret(list(subset))
                    total += 1
                    if reconstructed == s:
                        success += 1
    print(f"批量重构测试总次数: {total}, 成功次数: {success}, 成功率: {success/total:.2%}")
    assert success == total
