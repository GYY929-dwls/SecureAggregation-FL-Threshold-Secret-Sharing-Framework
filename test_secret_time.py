import os
import timeit
from secret_sharing import ShamirSecretSharing

import time
import random
from secret_sharing import ShamirSecretSharing

def test_performance():
    import time
    import random
    from secret_sharing import ShamirSecretSharing

    # 测试不同参与方数量对分割时间的影响
    participant_counts = [10, 50, 100]
    for n in participant_counts:
        shamir = ShamirSecretSharing(threshold=5, num_parties=n)
        secret = random.randint(1, shamir.modulus - 1)  # 确保秘密值小于模数
        start_time = time.time()
        shamir.split_secret(secret)
        elapsed_time = time.time() - start_time
        print(f"参与方数量: {n}, 分割时间（平均）: {elapsed_time:.6f} 秒")

    # 测试不同门限值对重构时间的影响
    thresholds = [5, 10, 15]
    for t in thresholds:
        shamir = ShamirSecretSharing(threshold=t, num_parties=20)
        secret = random.randint(1, shamir.modulus - 1)  # 确保秘密值小于模数
        shares = shamir.split_secret(secret)
        start_time = time.time()
        shamir.reconstruct_secret(shares[:t])
        elapsed_time = time.time() - start_time
        print(f"门限: {t}, 重构时间（平均）: {elapsed_time:.6f} 秒")

    # 测试不同秘密大小对分割和重构时间的影响
    secret_sizes = {
        "128 位": 2**128 - 1,
        "2048 位": 2**2048 - 2,
        "接近模数的大秘密": None  # 将在运行时动态生成
    }
    for size_label, secret in secret_sizes.items():
        shamir = ShamirSecretSharing(threshold=5, num_parties=10)
        if secret is None:
            secret = shamir.modulus - 1  # 接近模数的大秘密
        else:
            secret = min(secret, shamir.modulus - 1)  # 确保秘密值小于模数

        # 测试分割时间
        start_time = time.time()
        shares = shamir.split_secret(secret)
        split_time = time.time() - start_time

        # 测试重构时间
        start_time = time.time()
        shamir.reconstruct_secret(shares[:5])
        reconstruct_time = time.time() - start_time

        print(f"秘密大小: {size_label}, 分割时间（平均）: {split_time:.6f} 秒, 重构时间（平均）: {reconstruct_time:.6f} 秒")
class TestShamirSecretSharingPerformance:
    """Shamir秘密共享性能测试套件"""

    def test_split_scalability_with_parties(self):
        """测试大量参与方时的分割性能"""
        shamir = ShamirSecretSharing(threshold=3, num_parties=100)
        secret = 123456

        # 使用timeit精确测量
        time_taken = timeit.timeit(lambda: shamir.split_secret(secret), number=10)
        avg_time = time_taken / 10

        print(f"[100参与方] 单次分割平均耗时: {avg_time:.4f}s")
        assert avg_time < 0.5, "大规模节点分割超时"

    def test_reconstruction_with_many_parties(self):
        """测试多参与方高门限重构性能"""
        shamir = ShamirSecretSharing(threshold=10, num_parties=50)
        secret = 987654321
        shares = shamir.split_secret(secret)

        # 测量10个份额的重构时间
        subset = shares[:10]
        time_taken = timeit.timeit(lambda: shamir.reconstruct_secret(subset), number=20)

        print(f"[10-of-50] 单次重构平均耗时: {time_taken / 20:.4f}s")
        assert shamir.reconstruct_secret(subset) == secret
        assert time_taken / 20 < 2.5, "高门限重构超时"

    def test_secret_size_impact(self):
        """测试不同尺寸秘密的分割性能"""
        shamir = ShamirSecretSharing(threshold=5, num_parties=10)

        # 定义测试维度：名称，字节数，生成方法
        test_cases = [
            ("small (128-bit)", 16),
            ("medium (2048-bit)", 256),
            ("large (modulus-safe)", self._calculate_max_bytes(shamir))
        ]

        for desc, size in test_cases:
            byte_size = size() if callable(size) else size
            secret = self._generate_valid_secret(shamir, byte_size)

            # 预热确保方法缓存
            shamir.split_secret(secret)

            # 精确测量100次操作
            cycles = 100
            time_taken = timeit.timeit(
                lambda: shamir.split_secret(secret),
                number=cycles
            )

            print(f"[{desc}] 平均耗时: {time_taken / cycles:.4f}s")



    # 辅助方法
    def _calculate_max_bytes(self, shamir):
        """计算模数安全字节长度"""
        bits = shamir.modulus.bit_length()
        return (bits - 1) // 8  # 保留1位安全余量

    def _generate_valid_secret(self, shamir, byte_size):
        """生成合法范围内的随机秘密"""
        max_val = min(shamir.modulus, 2 ** (byte_size * 8))
        secret = int.from_bytes(os.urandom(byte_size), 'big') % max_val
        return secret if secret != 0 else 1