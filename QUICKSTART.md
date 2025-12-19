# Быстрый старт

## Установка зависимостей

```bash
pip install -r requirements.txt
```

## Запуск графического интерфейса (GUI)

**Рекомендуемый способ использования:**

```bash
python run_gui.py
```

Или:

```bash
python -m waf_tester.gui
```

Графический интерфейс включает:
- ✅ Настройку всех параметров тестирования
- ✅ Визуальный прогресс выполнения
- ✅ Таблицу результатов с фильтрацией
- ✅ Детальную информацию о каждом тесте
- ✅ Генерацию отчетов (JSON, TXT, HTML)
- ✅ Просмотр и открытие отчетов

## Командная строка (CLI)

Базовое использование:

```bash
python waf_tester/main.py --url http://example.com
```

## Тестирование приложения

```bash
python test_app.py
```

## Примеры команд

### Тестирование с ограниченным количеством пейлоадов
```bash
python waf_tester/main.py --url http://example.com --max-payloads 50
```

### Тестирование без ML
```bash
python waf_tester/main.py --url http://example.com --no-ml_models
```

### Тестирование через POST
```bash
python waf_tester/main.py --url http://example.com --test-type post
```

### Использование собственного файла с пейлоадами
```bash
python waf_tester/main.py --url http://example.com --payloads-file A:\Diplome\ML\ml\data\xss-list-unique.txt
```

## Структура проекта

```
A:\123123123\
├── waf_tester\              # Основной пакет приложения
│   ├── __init__.py
│   ├── main.py              # Главный модуль запуска
│   ├── payload_generator.py # Генератор пейлоадов с ML
│   ├── request_sender.py    # Отправка HTTP запросов
│   ├── response_analyzer.py # Анализ ответов WAF
│   └── report_generator.py # Генерация отчетов
├── config.yaml              # Конфигурационный файл
├── requirements.txt          # Зависимости
├── README.md                # Полная документация
├── test_app.py             # Тестовый скрипт
└── QUICKSTART.md           # Этот файл
```

## Отчеты

После выполнения тестирования отчеты сохраняются в папке `reports/`:
- JSON отчет для программной обработки
- Текстовый отчет для чтения
- HTML отчет с визуализацией

## Важно

⚠️ Используйте инструмент только для тестирования собственных систем или систем с явного разрешения владельцев!

