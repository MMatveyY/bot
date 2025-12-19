import re
import os
from typing import List, Dict

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader, random_split


# ==========================
# 1. Парсер файла результатов
# ==========================

def load_samples(path: str) -> List[Dict]:
    samples = []
    current = {}

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")

            if line.startswith("Пейлоад: "):
                current["payload"] = line[len("Пейлоад: "):]

            elif line.startswith("Статус: "):
                try:
                    current["status"] = int(line.split(":", 1)[1].strip())
                except ValueError:
                    current["status"] = None

            elif line.startswith("Окно: "):
                val = line.split(":", 1)[1].strip()
                current["label"] = 1 if "Сработал" in val else 0

            elif line.startswith("==="):
                if "payload" in current and "label" in current:
                    samples.append(current)
                current = {}

        if "payload" in current and "label" in current:
            samples.append(current)

    return samples


# ==========================
# 2. Символьный словарь
# ==========================

class CharVocab:
    def __init__(self, texts, min_freq: int = 1):
        counter = {}
        for t in texts:
            for ch in t:
                counter[ch] = counter.get(ch, 0) + 1

        self.pad_token = "<PAD>"
        self.unk_token = "<UNK>"

        self.itos = [self.pad_token, self.unk_token]
        for ch, freq in counter.items():
            if freq >= min_freq:
                self.itos.append(ch)

        self.stoi = {ch: i for i, ch in enumerate(self.itos)}

    def encode(self, text: str, max_len: int) -> torch.Tensor:
        ids = []
        for ch in text[:max_len]:
            ids.append(self.stoi.get(ch, self.stoi[self.unk_token]))
        while len(ids) < max_len:
            ids.append(self.stoi[self.pad_token])
        return torch.tensor(ids, dtype=torch.long)

    @property
    def vocab_size(self) -> int:
        return len(self.itos)


# ==========================
# 3. Dataset
# ==========================

class XSSPayloadDataset(Dataset):
    def __init__(self, samples: List[Dict], vocab: CharVocab, max_len: int = 256):
        self.samples = samples
        self.vocab = vocab
        self.max_len = max_len

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        s = self.samples[idx]
        payload = s["payload"]
        label = s["label"]
        x = self.vocab.encode(payload, self.max_len)
        y = torch.tensor(label, dtype=torch.float32)
        return x, y


# ==========================
# 4. Модель (char-level biLSTM)
# ==========================

class XSSClassifier(nn.Module):
    def __init__(self, vocab_size: int, emb_dim: int = 64, hidden_dim: int = 128, num_layers: int = 1):
        super().__init__()
        self.emb = nn.Embedding(vocab_size, emb_dim, padding_idx=0)
        self.lstm = nn.LSTM(
            input_size=emb_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
        )
        self.fc = nn.Linear(hidden_dim * 2, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        emb = self.emb(x)  # (batch, seq_len, emb_dim)
        out, _ = self.lstm(emb)  # (batch, seq_len, 2*hidden)
        pooled = out.mean(dim=1)  # (batch, 2*hidden)
        logits = self.fc(pooled)  # (batch, 1)
        probs = self.sigmoid(logits)  # (batch, 1)
        return probs.squeeze(1)  # (batch,)


# ==========================
# 5. Обучение с учётом дисбаланса классов
# ==========================

def train_model(
        data_path: str = None,
        max_len: int = 256,
        batch_size: int = 32,
        num_epochs: int = 15,
        lr: float = 1e-3,
        device: str = None,
):
    device = device or ("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Используем устройство: {device}")

    if data_path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        data_path = os.path.join(base_dir, "datasets", "server_response_results.txt")

    print(f"Загружаем данные из: {data_path}")
    samples = load_samples(data_path)
    print(f"Загружено примеров: {len(samples)}")

    if len(samples) < 10:
        print("Внимание: мало данных, модель будет игрушечной.")

    # Считаем дисбаланс
    num_pos = sum(s["label"] for s in samples)
    num_total = len(samples)
    num_neg = num_total - num_pos
    print(f"Положительных (1): {num_pos}, Отрицательных (0): {num_neg}")

    if num_pos == 0:
        raise RuntimeError("В данных нет положительных примеров (Окно: Сработал).")

    # Вес для положительного класса (чем больше, тем сильнее штраф за ошибку на 1)
    pos_weight = num_neg / num_pos
    neg_weight = 1.0
    print(f"Используем веса классов: pos_weight={pos_weight:.2f}, neg_weight={neg_weight:.2f}")

    all_payloads = [s["payload"] for s in samples]
    vocab = CharVocab(all_payloads, min_freq=1)
    print(f"Размер словаря (символов): {vocab.vocab_size}")

    dataset = XSSPayloadDataset(samples, vocab, max_len=max_len)
    val_size = max(1, int(0.2 * len(dataset)))
    train_size = len(dataset) - val_size
    train_ds, val_ds = random_split(dataset, [train_size, val_size])

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)

    model = XSSClassifier(vocab_size=vocab.vocab_size).to(device)
    # Берём BCE без редукции, чтобы вручную навесить веса
    bce = nn.BCELoss(reduction="none")
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    for epoch in range(1, num_epochs + 1):
        model.train()
        total_loss = 0.0

        for x, y in train_loader:
            x = x.to(device)
            y = y.to(device)

            optimizer.zero_grad()
            probs = model(x)  # (batch,)
            loss_raw = bce(probs, y)  # (batch,)

            # Веса для каждого примера
            weights = torch.where(y == 1.0,
                                  torch.tensor(pos_weight, device=device),
                                  torch.tensor(neg_weight, device=device))
            loss = (loss_raw * weights).mean()

            loss.backward()
            optimizer.step()

            total_loss += loss.item() * x.size(0)

        avg_train_loss = total_loss / len(train_ds)

        # Валидация
        model.eval()
        val_loss = 0.0
        correct = 0
        total = 0

        with torch.no_grad():
            for x, y in val_loader:
                x = x.to(device)
                y = y.to(device)
                probs = model(x)
                loss_raw = bce(probs, y)

                weights = torch.where(y == 1.0,
                                      torch.tensor(pos_weight, device=device),
                                      torch.tensor(neg_weight, device=device))
                loss = (loss_raw * weights).mean()
                val_loss += loss.item() * x.size(0)

                preds = (probs >= 0.5).float()
                correct += (preds == y).sum().item()
                total += y.size(0)

        avg_val_loss = val_loss / len(val_ds)
        val_acc = correct / total if total > 0 else 0.0

        print(
            f"Эпоха {epoch}/{num_epochs} | "
            f"train_loss={avg_train_loss:.4f} | "
            f"val_loss={avg_val_loss:.4f} | "
            f"val_acc={val_acc:.3f}"
        )

    # Сохраняем модель и словарь
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_dir, "trained")
    os.makedirs(models_dir, exist_ok=True)

    save_path = os.path.join(models_dir, "xss_model.pt")
    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "vocab_itos": vocab.itos,
            "max_len": max_len,
        },
        save_path,
    )

    print(f"Модель сохранена в {save_path}")


if __name__ == "__main__":
    train_model()
