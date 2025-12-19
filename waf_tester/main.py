"""
Главный модуль приложения для тестирования WAF на устойчивость к XSS-атакам
"""
import argparse
import sys
import time
from pathlib import Path
from typing import Optional

from colorama import init, Fore, Style
init(autoreset=True)

from payload_generator import PayloadGenerator
from request_sender import RequestSender
from response_analyzer import ResponseAnalyzer
from report_generator import ReportGenerator


class WAFTester:
    """Основной класс для тестирования WAF"""
    
    def __init__(
        self,
        target_url: str,
        payloads_file: Optional[str] = None,
        model_path: Optional[str] = None,
        use_ml: bool = True,
        request_delay: float = 0.5,
        max_payloads: int = 100
    ):
        """
        :param target_url: URL целевого веб-приложения
        :param payloads_file: путь к файлу с пейлоадами
        :param model_path: путь к ML модели
        :param use_ml: использовать ли ML для генерации пейлоадов
        :param request_delay: задержка между запросами
        :param max_payloads: максимальное количество пейлоадов для тестирования
        """
        self.target_url = target_url
        self.max_payloads = max_payloads
        
        print(f"{Fore.CYAN}[WAFTester] Инициализация компонентов...{Style.RESET_ALL}")
        
        # Инициализация компонентов
        self.payload_generator = PayloadGenerator(
            payloads_file=payloads_file,
            model_path=model_path,
            use_ml=use_ml
        )
        
        self.request_sender = RequestSender(
            target_url=target_url,
            request_delay=request_delay
        )
        
        self.response_analyzer = ResponseAnalyzer()
        self.report_generator = ReportGenerator()
        
        print(f"{Fore.GREEN}[WAFTester] Инициализация завершена{Style.RESET_ALL}")
    
    def run_test(self, test_type: str = "get") -> dict:
        """
        Запускает тестирование WAF
        
        :param test_type: тип теста ('get', 'post', 'header')
        :return: словарь с результатами
        """
        print(f"\n{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}НАЧАЛО ТЕСТИРОВАНИЯ WAF{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Целевой URL: {self.target_url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Тип теста: {test_type.upper()}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")
        
        # Получаем пейлоады
        print(f"{Fore.CYAN}[WAFTester] Генерация пейлоадов...{Style.RESET_ALL}")
        payloads = self.payload_generator.get_payloads(
            count=self.max_payloads,
            use_ml_mutation=self.payload_generator.use_ml
        )
        print(f"{Fore.GREEN}[WAFTester] Сгенерировано {len(payloads)} пейлоадов{Style.RESET_ALL}\n")
        
        # Тестируем каждый пейлоад
        total = len(payloads)
        for i, payload in enumerate(payloads, 1):
            print(f"{Fore.CYAN}[{i}/{total}] Тестирование пейлоада...{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Пейлоад: {payload[:80]}{'...' if len(payload) > 80 else ''}{Style.RESET_ALL}")
            
            try:
                # Отправляем запрос
                if test_type.lower() == "get":
                    response, elapsed = self.request_sender.send_get_request(payload)
                elif test_type.lower() == "post":
                    response, elapsed = self.request_sender.send_post_request(payload)
                elif test_type.lower() == "header":
                    response, elapsed = self.request_sender.send_request_in_header(payload)
                else:
                    response, elapsed = self.request_sender.send_get_request(payload)
                
                # Анализируем ответ
                analysis = self.response_analyzer.analyze_response(response, payload)
                analysis['payload'] = payload
                analysis['response_time'] = str(elapsed)
                
                # Добавляем результат
                self.report_generator.add_result(analysis)
                
                # Выводим результат
                if analysis['blocked']:
                    print(f"{Fore.RED}  ✓ Заблокирован{Style.RESET_ALL}")
                    if analysis.get('waf_type'):
                        print(f"{Fore.YELLOW}  Тип WAF: {analysis['waf_type']}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}  ✗ Пропущен (статус: {analysis['status_code']}){Style.RESET_ALL}")
                    if analysis.get('xss_executed'):
                        print(f"{Fore.RED}  ⚠ XSS выполнен!{Style.RESET_ALL}")
                
                print()
                
            except Exception as e:
                print(f"{Fore.RED}  ✗ Ошибка: {e}{Style.RESET_ALL}\n")
                error_result = {
                    'payload': payload,
                    'status_code': 0,
                    'blocked': False,
                    'error': str(e)
                }
                self.report_generator.add_result(error_result)
        
        # Генерируем отчеты
        print(f"{Fore.CYAN}[WAFTester] Генерация отчетов...{Style.RESET_ALL}")
        summary = self.report_generator.generate_summary()
        
        json_report = self.report_generator.generate_json_report()
        txt_report = self.report_generator.generate_text_report()
        html_report = self.report_generator.generate_html_report()
        
        print(f"{Fore.GREEN}[WAFTester] Отчеты сохранены:{Style.RESET_ALL}")
        print(f"  - JSON: {json_report}")
        print(f"  - TXT: {txt_report}")
        print(f"  - HTML: {html_report}")
        
        # Выводим сводку
        print(f"\n{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}СВОДКА РЕЗУЛЬТАТОВ{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"Всего тестов: {summary['total_tests']}")
        print(f"{Fore.RED}Заблокировано: {summary['blocked']} ({summary['block_rate']:.2f}%){Style.RESET_ALL}")
        print(f"{Fore.GREEN}Пропущено: {summary['passed']} ({summary['pass_rate']:.2f}%){Style.RESET_ALL}")
        print(f"Ошибки: {summary['errors']}")
        print(f"Тип WAF: {summary['waf_type']}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")
        
        return summary


def main():
    """Точка входа в приложение"""
    parser = argparse.ArgumentParser(
        description='Инструмент для тестирования WAF на устойчивость к XSS-атакам',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python main.py --url http://example.com
  python main.py --url http://example.com --max-payloads 50 --no-ml_models
  python main.py --url http://example.com --payloads-file payloads.txt --test-type post
        """
    )
    
    parser.add_argument(
        '--url',
        type=str,
        required=True,
        help='URL целевого веб-приложения за WAF'
    )
    
    parser.add_argument(
        '--payloads-file',
        type=str,
        default=None,
        help='Путь к файлу с базовыми пейлоадами'
    )
    
    parser.add_argument(
        '--model-path',
        type=str,
        default=None,
        help='Путь к обученной ML модели'
    )
    
    parser.add_argument(
        '--no-ml_models',
        action='store_true',
        help='Не использовать ML для генерации пейлоадов'
    )
    
    parser.add_argument(
        '--max-payloads',
        type=int,
        default=100,
        help='Максимальное количество пейлоадов для тестирования (по умолчанию: 100)'
    )
    
    parser.add_argument(
        '--request-delay',
        type=float,
        default=0.5,
        help='Задержка между запросами в секундах (по умолчанию: 0.5)'
    )
    
    parser.add_argument(
        '--test-type',
        type=str,
        choices=['get', 'post', 'header'],
        default='get',
        help='Тип теста: get, post или header (по умолчанию: get)'
    )
    
    args = parser.parse_args()
    
    # Проверка URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}Ошибка: URL должен начинаться с http:// или https://{Style.RESET_ALL}")
        sys.exit(1)
    
    try:
        # Создаем тестер
        tester = WAFTester(
            target_url=args.url,
            payloads_file=args.payloads_file,
            model_path=args.model_path,
            use_ml=not args.no_ml,
            request_delay=args.request_delay,
            max_payloads=args.max_payloads
        )
        
        # Запускаем тестирование
        summary = tester.run_test(test_type=args.test_type)
        
        # Код выхода зависит от результатов
        if summary['pass_rate'] > 10:  # Если пропущено более 10%
            print(f"{Fore.RED}ВНИМАНИЕ: WAF пропустил значительное количество атак!{Style.RESET_ALL}")
            sys.exit(1)
        else:
            print(f"{Fore.GREEN}Тестирование завершено успешно{Style.RESET_ALL}")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Тестирование прервано пользователем{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as e:
        print(f"{Fore.RED}Критическая ошибка: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

