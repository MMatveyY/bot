"""
Тестовый скрипт для проверки ML модуля
"""
import sys
import io
from pathlib import Path

# Настройка кодировки для Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

def test_ml_imports():
    """Проверяет импорты ML модулей"""
    print("Проверка импортов ML модулей...")
    try:
        from ml_models.model_infer import XSSPayloadScorer
        print("  [OK] model_infer")
        return True
    except Exception as e:
        print(f"  [FAIL] model_infer: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_model_loading():
    """Проверяет загрузку модели"""
    print("\nПроверка загрузки ML модели...")
    try:
        from ml_models.model_infer import XSSPayloadScorer
        
        model_path = Path(__file__).parent / "ml_models" / "trained" / "xss_model.pt"
        if not model_path.exists():
            print(f"  [FAIL] Модель не найдена: {model_path}")
            return False
        
        scorer = XSSPayloadScorer(model_path=str(model_path), device_preference="cpu")
        print("  [OK] Модель загружена успешно")
        
        # Тестируем оценку пейлоада
        test_payload = '<img src=x onerror=alert(1)>'
        score = scorer(test_payload)
        print(f"  [OK] Оценка пейлоада: {score:.4f}")
        
        # Тестируем batch prediction
        test_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            'normal text'
        ]
        scores = scorer.predict_batch(test_payloads)
        print(f"  [OK] Batch prediction: {len(scores)} оценок")
        for p, s in zip(test_payloads, scores):
            print(f"    {p[:30]:30} -> {s:.4f}")
        
        return True
    except Exception as e:
        print(f"  [FAIL] Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_mutator():
    """Проверяет мутатор"""
    print("\nПроверка мутатора...")
    try:
        from ml_models.mutator import simple_mutations
        
        test_payload = '<img src=x onerror=alert(1)>'
        mutations = simple_mutations(test_payload)
        print(f"  [OK] Сгенерировано {len(mutations)} мутаций")
        print(f"  [OK] Примеры мутаций:")
        for i, mut in enumerate(mutations[:5], 1):
            print(f"    {i}. {mut[:60]}")
        
        return True
    except Exception as e:
        print(f"  [FAIL] Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_payload_generator():
    """Проверяет интеграцию с payload_generator"""
    print("\nПроверка интеграции с payload_generator...")
    try:
        from waf_tester.payload_generator import PayloadGenerator
        
        generator = PayloadGenerator(use_ml=True)
        if generator.use_ml:
            print("  [OK] ML включен")
        else:
            print("  [WARN] ML не используется")
        
        payloads = generator.get_payloads(count=5, use_ml_mutation=generator.use_ml)
        print(f"  [OK] Сгенерировано {len(payloads)} пейлоадов")
        if payloads:
            print(f"  [OK] Пример: {payloads[0][:60]}")
        
        return True
    except Exception as e:
        print(f"  [FAIL] Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Главная функция тестирования"""
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ ML МОДУЛЯ")
    print("=" * 60)
    
    results = []
    
    results.append(("Импорты ML", test_ml_imports()))
    if results[-1][1]:  # Если импорты успешны
        results.append(("Загрузка модели", test_model_loading()))
        results.append(("Мутатор", test_mutator()))
        results.append(("Интеграция", test_payload_generator()))
    
    print("\n" + "=" * 60)
    print("РЕЗУЛЬТАТЫ ТЕСТИРОВАНИЯ")
    print("=" * 60)
    
    all_passed = True
    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{name}: {status}")
        if not result:
            all_passed = False
    
    print("=" * 60)
    if all_passed:
        print("Все тесты пройдены успешно!")
        return 0
    else:
        print("Некоторые тесты провалены!")
        return 1

if __name__ == "__main__":
    sys.exit(main())

