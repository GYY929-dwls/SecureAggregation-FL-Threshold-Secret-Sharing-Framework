import random
import math
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.backends import default_backend
from PIL import Image
import numpy as np


class ShamirSecretSharing:
    def __init__(self, threshold: int, num_parties: int, modulus: int = None):
        self.t = threshold
        self.n = num_parties
        self.modulus = modulus or self._generate_large_prime()
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def _generate_large_prime(self, bit_length: int = 2048) -> int:
        """生成安全素数"""
        while True:
            p = secrets.randbits(bit_length)
            p |= (1 << bit_length - 1) | 1
            if self._is_probable_prime(p, k=40):
                return p

    def _is_probable_prime(self, n: int, k: int = 40) -> bool:
        """Miller-Rabin素性测试"""
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def _create_polynomial(self, secret: int, degree: int) -> callable:
        """生成t-1次多项式"""
        coefficients = [random.randrange(0, self.modulus) for _ in range(degree)]
        return lambda x: (secret + sum(
            c * pow(x, i + 1, self.modulus) for i, c in enumerate(coefficients))) % self.modulus

    def _add_laplace_noise(self, secret: int, epsilon: float, sensitivity: float) -> int:
        """添加差分隐私拉普拉斯噪声"""
        scale = sensitivity / epsilon
        u = random.uniform(-0.5, 0.5)
        noise = int(-scale * math.copysign(1, u) * math.log(1 - 2 * abs(u)))
        return (secret + noise) % self.modulus

    def split_secret(self, secret: int, epsilon: float = None, sensitivity: float = 1.0) -> list:
        """将秘密分割为n个份额，可选添加差分隐私"""
        if secret >= self.modulus:
            raise ValueError(f"秘密值必须小于模数 {self.modulus}")

        # 添加差分隐私
        if epsilon is not None and epsilon > 0:
            secret = self._add_laplace_noise(secret, epsilon, sensitivity)

        poly = self._create_polynomial(secret, self.t - 1)
        shares = []
        for i in range(1, self.n + 1):
            x = i
            y = poly(x)
            signature = self.private_key.sign(
                str(y).encode(),
                padding=rsa_padding.PSS(
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=rsa_padding.PSS.MAX_LENGTH
                ),
                algorithm=hashes.SHA256()
            )
            mac = hashes.Hash(hashes.SHA256(), backend=default_backend())
            mac.update(str(y).encode())
            shares.append((x, y, signature, mac.finalize()))
        return shares

    @staticmethod
    def _lagrange_interpolate(x: int, points: list, modulus: int) -> int:
        """拉格朗日插值"""
        result = 0
        for i in range(len(points)):
            xi, yi = points[i]
            li = 1
            for j in range(len(points)):
                if i == j:
                    continue
                xj = points[j][0]
                numerator = (x - xj) % modulus
                denominator = (xi - xj) % modulus
                inv_denominator = pow(denominator, modulus - 2, modulus)
                li = (li * numerator * inv_denominator) % modulus
            result = (result + yi * li) % modulus
        return result

    def reconstruct_secret(self, shares: list) -> int:
        """从份额中恢复秘密"""
        valid_shares = []
        seen_xs = set()
        for x, y, sig, mac in shares:
            try:
                self.public_key.verify(
                    sig,
                    str(y).encode(),
                    padding=rsa_padding.PSS(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        salt_length=rsa_padding.PSS.MAX_LENGTH
                    ),
                    algorithm=hashes.SHA256()
                )
                h = hashes.Hash(hashes.SHA256(), backend=default_backend())
                h.update(str(y).encode())
                if h.finalize() != mac or y < 0 or y >= self.modulus:
                    continue
                if x in seen_xs:
                    continue  # 重复份额，不计入有效份额
                seen_xs.add(x)
                valid_shares.append((x, y))
            except Exception:
                continue

        if len(valid_shares) < self.t:
            raise ValueError(f"有效份额不足（需要至少 {self.t} 个，有 {len(valid_shares)} 个）")
        return self._lagrange_interpolate(0, valid_shares, self.modulus)

    @staticmethod
    def encode_text_secret(text: str) -> int:
        """将文本编码为整数"""
        data_bytes = text.encode('utf-8')
        return int.from_bytes(data_bytes, byteorder='big')

    @staticmethod
    def encode_image_secret(self, image_path: str, max_pixels: int = 10000, epsilon: float = None,
                            sensitivity: float = 1.0) -> tuple:
        """将图片编码为整数（含差分隐私支持），返回编码整数、盐值、图像尺寸"""
        secret, salt, shape = self._raw_encode_image(image_path, max_pixels)

        # 差分隐私处理
        if epsilon is not None and epsilon > 0:
            secret = self._apply_differential_privacy(secret, epsilon, sensitivity)

        return secret, salt, shape

    def _raw_encode_image(self, image_path: str, max_pixels: int) -> tuple:
        """核心图片编码逻辑（不包含模数和隐私处理）"""
        try:
            img = Image.open(image_path).convert('L')

            max_dim = 100
            scale_factor = min(max_dim / img.width, max_dim / img.height, 1)
            new_width = int(img.width * scale_factor)
            new_height = int(img.height * scale_factor)
            img = img.resize((new_width, new_height))

            pixels = np.array(img).flatten()[:max_pixels]
            if len(pixels) == 0:
                raise ValueError("图片数据为空")

            # 压缩像素值到 0-127
            pixels = (pixels // 2).astype(np.uint8)

            max_pixel_value = np.max(pixels)
            if max_pixel_value == 127:
                salt = 0
            else:
                max_salt = max(1, 127 - max_pixel_value)
                salt = random.randint(1, max_salt)
            print(f"图片最大像素值: {max_pixel_value}, 盐值: {salt}")

            pixels = (pixels + salt) % 128
            pixels = np.clip(pixels, 0, 127).astype(np.uint8)

            secret = 0
            for pixel in pixels:
                secret = (secret << 8) | int(pixel)
            secret = secret % self.modulus
            secret = secret if secret != 0 else 1

            compressed_image_path = image_path.replace('.png', '_compressed.png') \
                .replace('.jpeg', '_compressed.jpeg') \
                .replace('.jpg', '_compressed.jpg')
            compressed_img_array = np.array(pixels).reshape(new_height, new_width)
            compressed_img = Image.fromarray(compressed_img_array.astype('uint8'), mode='L')
            compressed_img.save(compressed_image_path)
            print(f"压缩图保存至: {compressed_image_path}")

            return secret, salt, (new_height, new_width)

        except Exception as e:
            raise ValueError(f"图片编码失败: {str(e)}")

    def _ensure_modulus_safe(self, secret: int) -> int:
        return secret % self.modulus

    def _apply_differential_privacy(self, value: int, epsilon: float, sensitivity: float) -> int:
        noise = np.random.laplace(loc=0, scale=sensitivity / epsilon)
        return int(value + noise) % self.modulus

    @staticmethod
    def decode_compressed_image(self, secret_int: int, output_path: str = None, shape: tuple = (100, 100)) -> Image:
        """将整数解码为压缩后的图像"""
        pixels = []
        temp = secret_int
        while temp > 0 and len(pixels) < shape[0] * shape[1]:
            pixels.append(temp & 0xFF)
            temp = temp >> 8
        pixels = pixels[::-1]

        if len(pixels) < shape[0] * shape[1]:
            pixels = [0] * (shape[0] * shape[1] - len(pixels)) + pixels

        pixels = np.clip(pixels, 0, 127).astype(np.uint8)
        pixels = (pixels.astype(np.uint16) * 2).clip(0, 255).astype(np.uint8)

        img_array = np.array(pixels[:shape[0] * shape[1]]).reshape(shape)
        img = Image.fromarray(img_array.astype('uint8'), mode='L')

        if output_path:
            img.save(output_path)
        return img

    def sign_value(self, y: int):
        """为给定的y值生成签名和MAC"""
        signature = self.private_key.sign(
            str(y).encode(),
            padding=rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH
            ),
            algorithm=hashes.SHA256()
        )

        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(str(y).encode())
        mac = h.finalize()

        return signature, mac