import pytest
from secret_sharing import ShamirSecretSharing
from itertools import combinations
import os
import random


def test_forged_signature_rejection_stat():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    success = 0
    for i in range(100):
        shares = shamir.split_secret(999)
        x, y, _, _ = shares[0]
        # 每次生成不同的伪造签名和MAC
        fake_sig = f"fake_sig_{i}".encode() + os.urandom(4)
        fake_mac = f"fake_mac_{i}".encode() + os.urandom(4)
        forged_share = (x, y, fake_sig, fake_mac)
        test_shares = [forged_share] + shares[1:3]
        try:
            shamir.reconstruct_secret(test_shares)
        except ValueError:
            success += 1
    print(f"签名伪造攻击检测成功次数: {success}/100, 检测成功率: {success/100:.2%}")
    
def test_mac_tampering_detection_stat():
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)
    success = 0
    for i in range(100):
        shares = shamir.split_secret(888)
        x, y, sig, mac = shares[0]
        # 生成不同的错误MAC
        tampered_mac = f"fake_mac_{i}".encode() + os.urandom(4)
        tampered_share = (x, y, sig, tampered_mac)
        test_shares = [tampered_share] + shares[1:3]
        try:
            shamir.reconstruct_secret(test_shares)
        except ValueError:
            success += 1
    print(f"MAC篡改攻击检测成功次数: {success}/100, 检测成功率: {success/100:.2%}")

def test_replay_attack_resistance_stat():
    shamir = ShamirSecretSharing(threshold=4, num_parties=7)
    # 假设模型训练后输出10个大整数参数
    model_params = [12345678901234567890 + i * 987654321 for i in range(10)]
    total = 100
    success = 0
    for i in range(total):
        # 每次随机选一个参数进行重放攻击
        param = random.choice(model_params)
        shares = shamir.split_secret(param)
        duplicate_shares = [shares[0]] * 4  # 使用门限数量的重复份额
        try:
            shamir.reconstruct_secret(duplicate_shares)
        except ValueError:
            success += 1
    print(f"重放攻击检测成功次数: {success}/{total}, 检测成功率: {success/total:.2%}")