import os
from secret_sharing import ShamirSecretSharing
from PIL import Image
import numpy as np
import time

def test_picture_folder_images():
    # 初始化 ShamirSecretSharing
    shamir = ShamirSecretSharing(threshold=3, num_parties=5)

    # 定义图片文件夹路径
    picture_folder = r"C:\Users\15360\Desktop\密码学\secret\secret\picture"

    # 遍历文件夹中的所有图片
    for filename in os.listdir(picture_folder):
        file_path = os.path.join(picture_folder, filename)

        # 检查文件是否为图片
        if not filename.lower().endswith((".png", ".jpeg", ".jpg", ".bmp", ".tiff", ".gif")):
            print(f"跳过非图片文件: {filename}")
            continue

        try:
            print(f"开始处理图片: {filename}")
            start_time = time.time()

            # 加载图片
            img = Image.open(file_path).convert("L")
            img_data = np.array(img)

            # 编码
            shares = shamir.split_secret(img_data)
            print(f"图片 {filename} 编码完成，用时: {time.time() - start_time:.2f} 秒")

            # 解码
            decoded_img = shamir.combine(shares)
            print(f"图片 {filename} 解码完成，用时: {time.time() - start_time:.2f} 秒")

            # 计算像素误差
            decoded_pixels = np.array(decoded_img)
            pixel_diff = np.abs(decoded_pixels - img_data)
            avg_error = np.mean(pixel_diff)
            print(f"图片 {filename} 平均像素误差: {avg_error}")

            # 验证误差是否在允许范围内
            assert avg_error <= 5, f"图片 {filename} 像素误差超出允许范围: {avg_error}"

            # 记录总用时
            total_time = time.time() - start_time
            print(f"图片 {filename} 测试完成，总用时: {total_time:.2f} 秒")

        except Exception as e:
            print(f"图片 {filename} 测试失败，错误: {str(e)}")

if __name__ == "__main__":
    test_picture_folder_images()