import tensorflow as tf
import numpy as np
from secret_sharing import ShamirSecretSharing

class FederatedLearningWithSecretSharing:
    def __init__(self, model: tf.keras.Model, shamir: ShamirSecretSharing):
        self.model = model
        self.shamir = shamir
        self.optimizer = tf.keras.optimizers.SGD(learning_rate=0.01)

    def client_update(self, dataset: tf.data.Dataset) -> dict:
        """客户端本地训练并分割模型参数"""
        # 模拟本地训练（简化实现）
        for batch, labels in dataset.take(10):  #
            with tf.GradientTape() as tape:
                predictions = self.model(batch, training=True)
                loss = tf.keras.losses.categorical_crossentropy(labels, predictions)
            grads = tape.gradient(loss, self.model.trainable_variables)
            self.optimizer.apply_gradients(zip(grads, self.model.trainable_variables))

        # 提取并展平所有权重参数
        params_flatten = np.concatenate([w.flatten() for w in self.model.get_weights()])
        secret = int(np.sum(params_flatten.astype(np.float64)))

        # 分割秘密并添加签名/MAC
        return self.shamir.split_secret(secret)

    @staticmethod
    def server_aggregate(self,shares_list: list) -> int:
        """服务器聚合份额并重构秘密"""
        all_shares = [share for client_shares in shares_list for share in client_shares]
        return self.shamir.reconstruct_secret(all_shares)

# 示例：构建简单联邦学习模型
def create_keras_model():
    model = tf.keras.Sequential([
        tf.keras.layers.Dense(64, activation='relu', input_shape=(784,)),
        tf.keras.layers.Dense(10, activation='softmax')
    ])
    return model

# 初始化联邦学习系统
shamir = ShamirSecretSharing(threshold=3, num_parties=5)
fl_model = FederatedLearningWithSecretSharing(create_keras_model(), shamir)
