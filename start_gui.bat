@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Запуск WAF Tester GUI...
python run_gui.py
if errorlevel 1 (
    echo.
    echo Ошибка запуска!
    echo Убедитесь, что:
    echo 1. Python установлен
    echo 2. Все зависимости установлены: pip install -r requirements.txt
    pause
)

