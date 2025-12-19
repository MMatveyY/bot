#!/usr/bin/env python3
"""
Усовершенствованный инструмент тестирования WAF на устойчивость к XSS-атакам
с использованием машинного обучения для генерации адаптивных пейлоадов
"""

import yaml
import json
import time
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Optional, Any
import requests
import warnings
import sys
import os

# Добавляем путь к модулям
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from payload_generator import PayloadGenerator
from waf_detector import WAFDetector
from report_generator_enhanced import EnhancedReportGenerator

warnings.filterwarnings('ignore')


class WAFTesterEnhanced:
    def __init__(self, config_path: str = "config.yaml"):
        """Инициализация улучшенного тестера WAF"""

        print("=" * 80)
        print("УСОВЕРШЕНСТВОВАННЫЙ ИНСТРУМЕНТ ТЕСТИРОВАНИЯ WAF")
        print("Версия 2.0 с поддержкой ML и расширенной аналитикой")
        print("=" * 80)

        # Загрузка конфигурации
        self.config = self.load_config(config_path)

        # Проверка безопасности
        self.security_check()

        # Инициализация компонентов
        print("\n🔧 Инициализация компонентов...")
        self.payload_generator = PayloadGenerator(config_path)
        self.waf_detector = WAFDetector(config_path)
        self.report_generator = EnhancedReportGenerator(config_path)

        # Статистика
        self.stats = {
            'start_time': datetime.now(),
            'tests_completed': 0,
            'tests_successful': 0,
            'tests_blocked': 0,
            'tests_failed': 0,
            'payloads_generated': 0
        }

        print("✅ Инициализация завершена")

    def load_config(self, config_path: str) -> Dict:
        """Загрузка конфигурации"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # Валидация обязательных полей
            required_fields = ['target', 'payloads', 'testing']
            for field in required_fields:
                if field not in config:
                    raise ValueError(f"Отсутствует обязательное поле: {field}")

            return config

        except FileNotFoundError:
            print(f"❌ Файл конфигурации не найден: {config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"❌ Ошибка парсинга YAML: {e}")
            sys.exit(1)

    def security_check(self):
        """Проверка безопасности перед запуском"""

        print("\n🔒 Проверка безопасности...")

        target_url = self.config['target']['url']

        # Проверяем, что тестирование разрешено
        if self.config['security']['test_mode_only']:
            allowed_domains = self.config['security']['allowed_domains']

            import urllib.parse
            parsed = urllib.parse.urlparse(target_url)
            domain = parsed.netloc

            if domain not in allowed_domains:
                print(f"❌ ДОСТУП ЗАПРЕЩЕН: Домен {domain} не в списке разрешенных")
                print(f"Разрешенные домены: {', '.join(allowed_domains)}")
                sys.exit(1)

        # Проверяем публичные IP
        if self.config['security']['block_public_ips']:
            import socket
            import ipaddress

            try:
                hostname = urllib.parse.urlparse(target_url).hostname
                ip = socket.gethostbyname(hostname)

                # Проверяем, является ли IP публичным
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private:
                    if self.config['security']['require_confirmation']:
                        print(f"⚠️  ВНИМАНИЕ: Целевой IP {ip} является публичным")
                        response = input("Продолжить тестирование? (yes/no): ")
                        if response.lower() != 'yes':
                            print("Тестирование отменено")
                            sys.exit(0)
                    else:
                        print(f"❌ Тестирование публичных IP запрещено: {ip}")
                        sys.exit(1)

            except Exception as e:
                print(f"⚠️  Не удалось проверить IP: {e}")

        print("✅ Проверка безопасности пройдена")

    def detect_waf(self) -> Dict:
        """Детектирование WAF на целевой системе"""

        print("\n🔍 Детектирование WAF...")

        target_url = self.config['target']['url']

        # Базовое детектирование
        result = self.waf_detector.detect(target_url)

        if result['detected']:
            print(f"✅ Обнаружен WAF: {', '.join(result['wafs'])}")

            # Подробный фингерпринтинг
            if self.config['waf_detection'].get('detailed_fingerprint', True):
                print("🔍 Выполняем подробный фингерпринтинг...")
                fingerprint = self.waf_detector.fingerprint_waf(target_url)
                result['fingerprint'] = fingerprint

        else:
            print("⚠️  WAF не обнаружен (или используется скрытый режим)")

        return result

    def generate_test_payloads(self) -> List[Dict]:
        """Генерация тестовых пейлоадов"""

        print("\n⚙️  Генерация тестовых payloads...")

        payloads = []
        payload_config = self.config['payloads']

        # Генерация payloads по типам
        for payload_type in payload_config['types']:
            count = payload_config['count_per_type']

            print(f"  Генерация {count} {payload_type} payloads...")

            type_payloads = self.payload_generator.get_payloads_by_type(
                payload_type=payload_type,
                count=count
            )

            for p in type_payloads:
                # Добавляем метаданные
                enhanced_payload = {
                    'payload': p['payload'],
                    'type': p['type'],
                    'category': p['category'],
                    'description': p.get('description', ''),
                    'obfuscation_level': p.get('obfuscation_level', 1),
                    'bypass_techniques': p.get('bypass_techniques', []),
                    'generated_by': p.get('generated_by', 'database'),
                    'variations': []
                }

                # Генерация вариаций через ML если включено
                if payload_config.get('use_ml_variations', False):
                    variations = self.payload_generator.generate_with_ml(
                        p['payload'],
                        variations=self.config['ml_models']['variations_per_payload']
                    )

                    for var in variations:
                        if var != p['payload']:  # Не добавляем дубликаты
                            enhanced_payload['variations'].append(var)

                payloads.append(enhanced_payload)

            print(f"  ✅ Сгенерировано {len(type_payloads)} {payload_type} payloads")

        self.stats['payloads_generated'] = len(payloads)
        print(f"✅ Всего сгенерировано {len(payloads)} payloads")

        return payloads

    def send_test_request(self, payload: str, test_config: Dict) -> Dict:
        """Отправка тестового запроса с payload"""

        target_url = test_config['url']
        method = test_config['method']
        headers = test_config.get('headers', {})
        params = test_config.get('params', {})
        cookies = test_config.get('cookies', {})

        # Подготовка запроса
        if method.upper() == 'GET':
            # Встраиваем payload в параметры
            request_params = params.copy()
            for param_name, param_value in request_params.items():
                if '{payload}' in param_value:
                    request_params[param_name] = param_value.replace('{payload}', payload)

            try:
                start_time = time.time()
                response = requests.request(
                    method=method,
                    url=target_url,
                    params=request_params,
                    headers=headers,
                    cookies=cookies,
                    timeout=test_config.get('timeout', 10),
                    allow_redirects=test_config.get('follow_redirects', True)
                )
                response_time = time.time() - start_time

                # Анализ ответа
                is_bypassed = self.analyze_response(response, payload)

                result = {
                    'success': True,
                    'payload': payload,
                    'response_code': response.status_code,
                    'response_time': response_time,
                    'bypassed': is_bypassed,
                    'response_length': len(response.content),
                    'headers': dict(response.headers),
                    'error': None
                }

            except requests.exceptions.Timeout:
                result = {
                    'success': False,
                    'payload': payload,
                    'error': 'Timeout',
                    'bypassed': False
                }
            except requests.exceptions.RequestException as e:
                result = {
                    'success': False,
                    'payload': payload,
                    'error': str(e),
                    'bypassed': False
                }

        elif method.upper() == 'POST':
            # Для POST запросов
            data = test_config.get('datasets', {})

            # Заменяем payload в данных
            for key, value in data.items():
                if isinstance(value, str) and '{payload}' in value:
                    data[key] = value.replace('{payload}', payload)

            try:
                start_time = time.time()
                response = requests.request(
                    method=method,
                    url=target_url,
                    data=data,
                    headers=headers,
                    cookies=cookies,
                    timeout=test_config.get('timeout', 10)
                )
                response_time = time.time() - start_time

                is_bypassed = self.analyze_response(response, payload)

                result = {
                    'success': True,
                    'payload': payload,
                    'response_code': response.status_code,
                    'response_time': response_time,
                    'bypassed': is_bypassed,
                    'response_length': len(response.content),
                    'error': None
                }

            except requests.exceptions.RequestException as e:
                result = {
                    'success': False,
                    'payload': payload,
                    'error': str(e),
                    'bypassed': False
                }

        else:
            result = {
                'success': False,
                'payload': payload,
                'error': f'Unsupported method: {method}',
                'bypassed': False
            }

        return result

    def analyze_response(self, response, payload: str) -> bool:
        """Анализ ответа на успешность обхода WAF"""

        # Проверяем код ответа
        if response.status_code >= 400:
            return False

        # Проверяем наличие payload в ответе (для reflected XSS)
        if payload in response.text:
            return True

        # Проверяем другие признаки успешного выполнения
        success_indicators = [
            'alert(',  # JavaScript alert
            'eval(',  # JavaScript eval
            'onerror',  # Event handler
            'onload',  # Event handler
            'javascript:',  # JavaScript protocol
            '<script>',  # Script tag
        ]

        for indicator in success_indicators:
            if indicator in response.text.lower():
                return True

        # Для DOM-based XSS проверяем другие признаки
        dom_indicators = [
            'document.cookie',
            'localStorage',
            'sessionStorage',
            'XMLHttpRequest',
            'fetch('
        ]

        for indicator in dom_indicators:
            if indicator in response.text:
                return True

        return False

    def execute_test(self, payload_data: Dict, test_id: int) -> Dict:
        """Выполнение одного теста"""

        test_config = {
            'url': self.config['target']['url'],
            'method': self.config['target']['method'],
            'headers': self.config['target'].get('headers', {}),
            'params': self.config['target'].get('parameters', {}),
            'cookies': self.config['target'].get('cookies', {}),
            'timeout': self.config['testing']['timeout'],
            'follow_redirects': self.config['testing']['follow_redirects']
        }

        # Тестируем основной payload
        main_result = self.send_test_request(payload_data['payload'], test_config)

        # Тестируем вариации если есть
        variation_results = []
        for variation in payload_data.get('variations', [])[:3]:  # Ограничиваем 3 вариациями
            var_result = self.send_test_request(variation, test_config)
            variation_results.append(var_result)

        # Анализируем результаты
        bypassed = main_result.get('bypassed', False)
        bypass_techniques = []

        if bypassed:
            bypass_techniques = payload_data.get('bypass_techniques', [])
            if payload_data.get('generated_by') == 'ml_models':
                bypass_techniques.append('ml_generated')

        # Задержка между запросами
        time.sleep(self.config['testing'].get('delay_between_requests', 0.1))

        # Обновляем статистику
        with threading.Lock():
            self.stats['tests_completed'] += 1

            if bypassed:
                self.stats['tests_successful'] += 1
            elif main_result.get('success', False):
                self.stats['tests_blocked'] += 1
            else:
                self.stats['tests_failed'] += 1

            # Прогресс
            if self.stats['tests_completed'] % 10 == 0:
                self.print_progress()

        return {
            'test_id': test_id,
            'payload': payload_data['payload'],
            'payload_type': payload_data['type'],
            'payload_category': payload_data['category'],
            'bypassed': bypassed,
            'response_code': main_result.get('response_code'),
            'response_time': main_result.get('response_time', 0),
            'bypass_techniques': bypass_techniques,
            'variations_tested': len(variation_results),
            'variations_bypassed': sum(1 for v in variation_results if v.get('bypassed', False)),
            'error': main_result.get('error'),
            'timestamp': datetime.now().isoformat(),
            'request': {
                'method': test_config['method'],
                'url': test_config['url'],
                'headers': test_config['headers']
            } if self.config['reports']['include_request_response'] else {}
        }

    def print_progress(self):
        """Вывод прогресса тестирования"""
        total = self.stats['payloads_generated']
        completed = self.stats['tests_completed']
        successful = self.stats['tests_successful']

        percent = (completed / total * 100) if total > 0 else 0

        print(f"\r📊 Прогресс: {completed}/{total} ({percent:.1f}%) | "
              f"Успешно: {successful} | "
              f"Заблокировано: {self.stats['tests_blocked']}", end='')

    def run_tests(self, payloads: List[Dict]) -> List[Dict]:
        """Запуск всех тестов"""

        print(f"\n🚀 Запуск тестирования {len(payloads)} payloads...")
        print(f"⚙️  Параметры: {self.config['testing']['threads']} потоков, "
              f"задержка {self.config['testing']['delay_between_requests']}с")

        results = []
        test_configs = []

        # Подготавливаем конфигурации тестов
        for i, payload_data in enumerate(payloads):
            test_configs.append((payload_data, i))

        # Запускаем тесты в пуле потоков
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config['testing']['threads']
        ) as executor:
            # Запускаем все тесты
            future_to_test = {
                executor.submit(self.execute_test, payload, test_id): (payload, test_id)
                for payload, test_id in test_configs
            }

            # Собираем результаты
            for future in concurrent.futures.as_completed(future_to_test):
                try:
                    result = future.result(timeout=self.config['testing']['timeout'] + 5)
                    results.append(result)
                except concurrent.futures.TimeoutError:
                    print(f"\n⚠️  Таймаут теста")
                except Exception as e:
                    print(f"\n⚠️  Ошибка теста: {e}")

        print(f"\n✅ Тестирование завершено!")

        return results

    def generate_final_report(self, test_results: List[Dict], waf_info: Dict) -> Dict:
        """Генерация итогового отчета"""

        print("\n📊 Генерация отчета...")

        # Подготавливаем данные для отчета
        report_data = {
            'target_url': self.config['target']['url'],
            'tests': test_results,
            'waf_info': waf_info,
            'duration': (datetime.now() - self.stats['start_time']).total_seconds(),
            'config': self.config,
            'statistics': self.stats
        }

        # Генерируем отчет
        report_result = self.report_generator.generate_report(report_data, waf_info)

        # Выводим сводку
        self.print_summary(report_result['report_data'])

        return report_result

    def print_summary(self, report_data: Dict):
        """Вывод сводки результатов"""

        stats = report_data['statistics']
        summary = report_data['summary']

        print("\n" + "=" * 80)
        print("ИТОГОВАЯ СВОДКА")
        print("=" * 80)

        print(f"\n📈 ОБЩИЕ РЕЗУЛЬТАТЫ:")
        print(f"   Всего тестов: {stats['total_tests']}")
        print(f"   Успешных атак: {stats['successful_tests']}")
        print(f"   Заблокировано: {stats['blocked_tests']}")
        print(f"   Процент успеха: {stats['success_rate']:.1f}%")

        print(f"\n🎯 ОЦЕНКА БЕЗОПАСНОСТИ:")
        print(f"   Общий балл: {summary['overall_score']:.1f}/10")
        print(f"   Уровень риска: {summary['risk_level']}")
        print(f"   Эффективность WAF: {summary['waf_performance']['effectiveness_rating']}")

        print(f"\n📊 СТАТИСТИКА ПО ТИПАМ:")
        for ptype, data in stats['by_payload_type'].items():
            print(f"   {ptype}: {data.get('success_rate', 0):.1f}% успеха "
                  f"({data['bypassed']}/{data['total']})")

        print(f"\n🚀 РЕКОМЕНДАЦИИ ({len(report_data['recommendations'])}):")
        for i, rec in enumerate(report_data['recommendations'][:5], 1):
            print(f"   {i}. {rec}")

        if len(report_data['recommendations']) > 5:
            print(f"   ... и еще {len(report_data['recommendations']) - 5} рекомендаций")

        print(f"\n💾 ОТЧЕТЫ СОХРАНЕНЫ В:")
        for format_name, path in self.report_generator.export_paths.items():
            print(f"   {format_name.upper()}: {path}")

        print("\n" + "=" * 80)

    def run(self):
        """Основной метод запуска тестирования"""

        try:
            # 1. Детектирование WAF
            waf_info = self.detect_waf()

            # 2. Генерация payloads
            payloads = self.generate_test_payloads()

            if not payloads:
                print("❌ Не удалось сгенерировать payloads")
                return

            # 3. Запуск тестов
            test_results = self.run_tests(payloads)

            # 4. Генерация отчета
            report = self.generate_final_report(test_results, waf_info)

            # 5. Сохранение сырых данных
            self.save_raw_data(test_results, waf_info)

            print(f"\n✅ Тестирование успешно завершено за "
                  f"{(datetime.now() - self.stats['start_time']).total_seconds():.1f} секунд")

        except KeyboardInterrupt:
            print("\n\n⚠️  Тестирование прервано пользователем")
        except Exception as e:
            print(f"\n❌ Критическая ошибка: {e}")
            import traceback
            traceback.print_exc()

    def save_raw_data(self, test_results: List[Dict], waf_info: Dict):
        """Сохранение сырых данных для дальнейшего анализа"""

        raw_data_dir = os.path.join(self.report_generator.reports_dir, 'raw_data')
        os.makedirs(raw_data_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Сохраняем тестовые результаты
        results_file = os.path.join(raw_data_dir, f'test_results_{timestamp}.json')
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': timestamp,
                'config': self.config,
                'waf_info': waf_info,
                'results': test_results,
                'statistics': self.stats
            }, f, indent=2, ensure_ascii=False)

        # Сохраняем payloads
        payloads_file = os.path.join(raw_data_dir, f'payloads_{timestamp}.json')
        with open(payloads_file, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': timestamp,
                'payloads': self.payload_generator.payloads_db,
                'generation_stats': self.payload_generator.get_statistics()
            }, f, indent=2, ensure_ascii=False)


def main():
    """Точка входа"""

    import argparse

    parser = argparse.ArgumentParser(
        description='Усовершенствованный инструмент тестирования WAF на устойчивость к XSS-атакам'
    )

    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='Путь к файлу конфигурации (по умолчанию: config.yaml)'
    )

    parser.add_argument(
        '--quick',
        action='store_true',
        help='Быстрый режим (меньше payloads и тестов)'
    )

    parser.add_argument(
        '--target',
        type=str,
        help='Целевой URL для тестирования (переопределяет конфиг)'
    )

    args = parser.parse_args()

    # Запуск тестера
    tester = WAFTesterEnhanced(args.config)

    # Настройка быстрого режима
    if args.quick:
        tester.config['payloads']['count_per_type'] = 10
        tester.config['testing']['threads'] = 5

    # Переопределение цели если указано
    if args.target:
        tester.config['target']['url'] = args.target

    # Запуск тестирования
    tester.run()


if __name__ == "__main__":
    main()