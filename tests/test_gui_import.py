"""
Тестовый скрипт для проверки импортов GUI
"""
import sys
from pathlib import Path

# Добавляем путь к корневой директории проекта
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

print(f"Проект: {project_root}")
print(f"Python path: {sys.path[:3]}")

try:
    print("\n1. Проверка импорта payload_generator...")
    from waf_tester.payload_generator import PayloadGenerator
    print("   [OK] PayloadGenerator импортирован")
    
    print("\n2. Проверка импорта request_sender...")
    from waf_tester.request_sender import RequestSender
    print("   [OK] RequestSender импортирован")
    
    print("\n3. Проверка импорта response_analyzer...")
    from waf_tester.response_analyzer import ResponseAnalyzer
    print("   [OK] ResponseAnalyzer импортирован")
    
    print("\n4. Проверка импорта report_generator...")
    from waf_tester.report_generator import ReportGenerator
    print("   [OK] ReportGenerator импортирован")
    
    print("\n5. Проверка импорта gui...")
    from waf_tester.gui import WAFTesterGUI
    print("   [OK] WAFTesterGUI импортирован")
    
    print("\n" + "="*60)
    print("Все импорты успешны! GUI готов к запуску.")
    print("="*60)
    
except ImportError as e:
    print(f"\n[ОШИБКА] {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
except Exception as e:
    print(f"\n[ОШИБКА] {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

