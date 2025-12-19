"""Тест путей к ML модулям"""
from waf_tester.payload_generator import PayloadGenerator, ML_BASE_PATH, ML_MODELS_PATH, ML_DATA_PATH
from pathlib import Path

print(f"ML_BASE_PATH: {ML_BASE_PATH}")
print(f"ML_MODELS_PATH: {ML_MODELS_PATH}")
print(f"ML_DATA_PATH: {ML_DATA_PATH}")
print(f"\nМодель существует: {(ML_MODELS_PATH / 'xss_model.pt').exists()}")
print(f"Данные существуют: {(ML_DATA_PATH / 'xss-list-unique.txt').exists()}")

print("\nИнициализация PayloadGenerator...")
g = PayloadGenerator(use_ml=True)
print(f"ML доступен: {g.use_ml}")
print(f"Scorer загружен: {g.scorer is not None}")

if g.scorer:
    test_payload = '<img src=x onerror=alert(1)>'
    score = g.scorer(test_payload)
    print(f"Тестовая оценка пейлоада: {score:.4f}")

