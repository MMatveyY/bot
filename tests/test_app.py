"""
Тестовый скрипт для проверки работоспособности приложения
"""
import sys
import io
from pathlib import Path

# Настройка кодировки для Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

def test_imports():
    """Проверяет импорты всех модулей"""
    print("Проверка импортов...")
    try:
        from waf_tester import payload_generator
        print("  [OK] payload_generator")
    except Exception as e:
        print(f"  [FAIL] payload_generator: {e}")
        return False
    
    try:
        from waf_tester import request_sender
        print("  [OK] request_sender")
    except Exception as e:
        print(f"  [FAIL] request_sender: {e}")
        return False
    
    try:
        from waf_tester import response_analyzer
        print("  [OK] response_analyzer")
    except Exception as e:
        print(f"  [FAIL] response_analyzer: {e}")
        return False
    
    try:
        from waf_tester import report_generator
        print("  [OK] report_generator")
    except Exception as e:
        print(f"  [FAIL] report_generator: {e}")
        return False
    
    try:
        from waf_tester import main
        print("  [OK] main")
    except Exception as e:
        print(f"  [FAIL] main: {e}")
        return False
    
    return True

def test_payload_generator():
    """Проверяет генератор пейлоадов"""
    print("\nПроверка генератора пейлоадов...")
    try:
        from waf_tester.payload_generator import PayloadGenerator
        generator = PayloadGenerator(use_ml=False)
        payloads = generator.get_payloads(count=5, use_ml_mutation=False)
        print(f"  [OK] Сгенерировано {len(payloads)} пейлоадов")
        if payloads:
            print(f"  [OK] Пример пейлоада: {payloads[0][:50]}...")
        return True
    except Exception as e:
        print(f"  [FAIL] Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_response_analyzer():
    """Проверяет анализатор ответов"""
    print("\nПроверка анализатора ответов...")
    try:
        from waf_tester.response_analyzer import ResponseAnalyzer
        import requests
        
        analyzer = ResponseAnalyzer()
        
        # Создаем фиктивный response
        class MockResponse:
            status_code = 403
            text = "Access Denied by WAF"
            headers = {}
            content = b"Access Denied"
            elapsed = None
        
        mock_response = MockResponse()
        result = analyzer.analyze_response(mock_response, "<script>alert(1)</script>")
        print(f"  [OK] Анализ выполнен: blocked={result['blocked']}")
        return True
    except Exception as e:
        print(f"  [FAIL] Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_report_generator():
    """Проверяет генератор отчетов"""
    print("\nПроверка генератора отчетов...")
    try:
        from waf_tester.report_generator import ReportGenerator
        
        generator = ReportGenerator(output_dir="../test_reports")
        generator.add_result({
            'payload': '<script>alert(1)</script>',
            'status_code': 403,
            'blocked': True,
            'waf_type': 'Test WAF'
        })
        
        summary = generator.generate_summary()
        print(f"  [OK] Сводка сгенерирована: {summary['total_tests']} тестов")
        return True
    except Exception as e:
        print(f"  [FAIL] Ошибка: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Главная функция тестирования"""
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ ПРИЛОЖЕНИЯ ДЛЯ ТЕСТИРОВАНИЯ WAF")
    print("=" * 60)
    
    results = []
    
    results.append(("Импорты", test_imports()))
    results.append(("Генератор пейлоадов", test_payload_generator()))
    results.append(("Анализатор ответов", test_response_analyzer()))
    results.append(("Генератор отчетов", test_report_generator()))
    
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

