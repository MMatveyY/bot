"""
Скрипт для запуска графического интерфейса WAF Tester
"""
import sys
import os
from pathlib import Path

# Добавляем путь к корневой директории проекта
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from waf_tester.gui import main
    
    if __name__ == "__main__":
        main()
except ImportError as e:
    print(f"Ошибка импорта: {e}")
    print("\nУбедитесь, что:")
    print("1. Все зависимости установлены: pip install -r requirements.txt")
    print("2. Вы запускаете скрипт из корневой директории проекта")
    print(f"3. Текущая директория: {os.getcwd()}")
    print(f"4. Путь к проекту: {project_root}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
except Exception as e:
    print(f"Ошибка запуска: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

