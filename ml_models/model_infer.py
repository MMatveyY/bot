"""
Инференс-обёртка над обученной моделью XSSClassifier.

Используется:
  - для присвоения payload'у вероятности успешного срабатывания (score)
  - как вспомогательный компонент для генерации мутаций в других скриптах
"""

import os
import json
from typing import Dict, List

import torch
import torch.nn as nn

# ВАЖНО: импорт из того же пакета ml_models
# Файл train_xss_model.py лежит рядом с этим файлом (в папке ml_models)
try:
    # Пробуем относительный импорт (если запускается как модуль)
    from .train_xss_model import XSSClassifier
except ImportError:
    # Пробуем абсолютный импорт (если запускается напрямую)
    try:
        from train_xss_model import XSSClassifier
    except ImportError:
        # Последняя попытка - через sys.path
        import sys
        from pathlib import Path
        ml_dir = Path(__file__).parent
        if str(ml_dir) not in sys.path:
            sys.path.insert(0, str(ml_dir))
        from train_xss_model import XSSClassifier


def load_checkpoint(checkpoint_path: str, map_location: str = "cpu"):
    """
    Загружает чекпоинт модели и возвращает:
      - созданный и загруженный XSSClassifier
      - словарь vocab (символ -> индекс)
      - max_len
    """
    if not os.path.exists(checkpoint_path):
        raise FileNotFoundError(f"Не найден файл модели: {checkpoint_path}")

    checkpoint = torch.load(checkpoint_path, map_location=map_location)

    # Обрабатываем разные форматы сохранения
    if "vocab_itos" in checkpoint:
        # Новый формат: vocab_itos (список символов)
        vocab_itos = checkpoint["vocab_itos"]
        vocab: Dict[str, int] = {ch: i for i, ch in enumerate(vocab_itos)}
    elif "vocab" in checkpoint:
        # Старый формат: vocab (словарь)
        vocab: Dict[str, int] = checkpoint["vocab"]
    else:
        raise ValueError("В чекпоинте не найден словарь (vocab или vocab_itos)")
    
    model_state = checkpoint["model_state_dict"]
    embed_dim = checkpoint.get("embed_dim", 64)
    hidden_dim = checkpoint.get("hidden_dim", 128)
    max_len = checkpoint.get("max_len", 256)

    model = XSSClassifier(
        vocab_size=len(vocab),
        emb_dim=embed_dim,
        hidden_dim=hidden_dim,
    )
    model.load_state_dict(model_state)
    model.eval()

    return model, vocab, max_len


class XSSPayloadScorer:
    """
    Класс-инференсер для trained XSSClassifier.

    Использование:
        scorer = XSSPayloadScorer("ml_models/trained/xss_model.pt", device_preference="cuda")
        score = scorer("<img src=x onerror=alert(1)>")   # float из [0, 1]
    """

    def __init__(
        self,
        model_path: str = "ml_models/trained/xss_model.pt",
        device_preference: str = "cuda",
    ):
        """
        :param model_path: путь до чекпоинта модели (.pt)
        :param device_preference: "cuda" или "cpu" (если cuda недоступна — упадём на cpu)
        """
        # Выбор устройства
        if device_preference == "cuda" and torch.cuda.is_available():
            self.device = torch.device("cuda")
        else:
            self.device = torch.device("cpu")

        print(f"[XSSPayloadScorer] Используем устройство: {self.device}")

        # Загрузка модели
        print(f"[XSSPayloadScorer] Загружаем модель из: {model_path}")
        model, vocab, max_len = load_checkpoint(model_path, map_location=self.device)

        self.model: nn.Module = model.to(self.device)
        self.vocab: Dict[str, int] = vocab
        self.inv_vocab: Dict[int, str] = {idx: ch for ch, idx in vocab.items()}
        self.max_len: int = max_len

        print(
            f"[XSSPayloadScorer] Модель и словарь загружены. "
            f"vocab_size={len(self.vocab)}, max_len={self.max_len}"
        )

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------

    def encode_payload(self, payload: str) -> torch.Tensor:
        """
        Переводит строку payload в тензор индексов длины max_len.
        Неизвестные символы кодируются как 0.
        """
        idxs: List[int] = []
        for ch in payload:
            idxs.append(self.vocab.get(ch, 0))
            if len(idxs) >= self.max_len:
                break

        # Дополняем нулями до max_len
        if len(idxs) < self.max_len:
            idxs.extend([0] * (self.max_len - len(idxs)))

        # -> Tensor [1, max_len] на нужном устройстве
        x = torch.tensor(idxs, dtype=torch.long, device=self.device).unsqueeze(0)
        return x

    # ------------------------------------------------------------------
    # Основной интерфейс
    # ------------------------------------------------------------------

    def __call__(self, payload: str) -> float:
        """
        Возвращает score в диапазоне [0, 1] —
        вероятность того, что данный payload «похож» на рабочий.
        """
        with torch.no_grad():
            x = self.encode_payload(payload)
            logits = self.model(x)           # [1, 1] либо [1]
            if logits.ndim == 2:
                logits = logits[:, 0]
            prob = torch.sigmoid(logits).item()
        return float(prob)
    
    def predict_batch(self, payloads: List[str]) -> List[float]:
        """
        Оценивает батч пейлоадов
        
        :param payloads: список пейлоадов для оценки
        :return: список оценок (scores)
        """
        scores = []
        for payload in payloads:
            score = self(payload)
            scores.append(score)
        return scores


if __name__ == "__main__":
    # Небольшой самотест при запуске файла напрямую
    default_model_path = os.path.join(
        os.path.dirname(__file__),
        "trained",
        "xss_model.pt",
    )

    scorer = XSSPayloadScorer(model_path=default_model_path, device_preference="cpu")
    test_payload = '<img src=x onerror=alert(1)>'

    print("Test payload:", test_payload)
    print("Score:", scorer(test_payload))
