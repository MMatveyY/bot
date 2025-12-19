"""
Модуль генерации отчетов о результатах тестирования WAF
"""
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path


class ReportGenerator:
    """Генератор отчетов о результатах тестирования WAF"""
    
    def __init__(self, output_dir: str = "reports"):
        """
        :param output_dir: директория для сохранения отчетов
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results: List[Dict[str, Any]] = []
    
    def add_result(self, result: Dict[str, Any]):
        """Добавляет результат тестирования"""
        self.results.append(result)
    
    def generate_summary(self) -> Dict[str, Any]:
        """Генерирует сводку по результатам тестирования"""
        total = len(self.results)
        if total == 0:
            return {
                'total_tests': 0,
                'blocked': 0,
                'passed': 0,
                'errors': 0,
                'block_rate': 0.0,
                'pass_rate': 0.0
            }
        
        blocked = sum(1 for r in self.results if r.get('blocked', False))
        passed = sum(1 for r in self.results if not r.get('blocked', False) and r.get('status_code', 0) > 0)
        errors = sum(1 for r in self.results if r.get('status_code', 0) == 0)
        
        return {
            'total_tests': total,
            'blocked': blocked,
            'passed': passed,
            'errors': errors,
            'block_rate': (blocked / total * 100) if total > 0 else 0.0,
            'pass_rate': (passed / total * 100) if total > 0 else 0.0,
            'waf_type': self._detect_waf_type(),
            'test_date': datetime.now().isoformat()
        }
    
    def _detect_waf_type(self) -> str:
        """Определяет тип WAF на основе результатов"""
        waf_types = {}
        for result in self.results:
            waf_type = result.get('waf_type')
            if waf_type:
                waf_types[waf_type] = waf_types.get(waf_type, 0) + 1
        
        if waf_types:
            return max(waf_types.items(), key=lambda x: x[1])[0]
        return "Unknown"
    
    def generate_json_report(self, filename: Optional[str] = None) -> str:
        """Генерирует JSON отчет"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"waf_test_report_{timestamp}.json"
        
        filepath = self.output_dir / filename
        
        report = {
            'summary': self.generate_summary(),
            'results': self.results,
            'generated_at': datetime.now().isoformat()
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return str(filepath)
    
    def generate_text_report(self, filename: Optional[str] = None) -> str:
        """Генерирует текстовый отчет"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"waf_test_report_{timestamp}.txt"
        
        filepath = self.output_dir / filename
        
        summary = self.generate_summary()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("ОТЧЕТ О ТЕСТИРОВАНИИ WAF НА УСТОЙЧИВОСТЬ К XSS-АТАКАМ\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Дата тестирования: {summary['test_date']}\n")
            f.write(f"Тип WAF: {summary['waf_type']}\n\n")
            
            f.write("СВОДКА:\n")
            f.write("-" * 80 + "\n")
            f.write(f"Всего тестов: {summary['total_tests']}\n")
            f.write(f"Заблокировано: {summary['blocked']} ({summary['block_rate']:.2f}%)\n")
            f.write(f"Пропущено: {summary['passed']} ({summary['pass_rate']:.2f}%)\n")
            f.write(f"Ошибки: {summary['errors']}\n\n")
            
            f.write("ДЕТАЛЬНЫЕ РЕЗУЛЬТАТЫ:\n")
            f.write("-" * 80 + "\n\n")
            
            for i, result in enumerate(self.results, 1):
                f.write(f"Тест #{i}\n")
                f.write(f"  Пейлоад: {result.get('payload', 'N/A')}\n")
                f.write(f"  Статус код: {result.get('status_code', 'N/A')}\n")
                f.write(f"  Заблокирован: {'Да' if result.get('blocked') else 'Нет'}\n")
                if result.get('waf_type'):
                    f.write(f"  Тип WAF: {result.get('waf_type')}\n")
                if result.get('block_reason'):
                    f.write(f"  Причина блокировки: {result.get('block_reason')}\n")
                if result.get('xss_executed'):
                    f.write(f"  XSS выполнен: Да\n")
                f.write(f"  Время ответа: {result.get('response_time', 'N/A')}\n")
                f.write(f"  Размер ответа: {result.get('response_size', 0)} байт\n")
                f.write("\n")
            
            # Статистика по типам пейлоадов
            f.write("СТАТИСТИКА ПО ТИПАМ ПЕЙЛОАДОВ:\n")
            f.write("-" * 80 + "\n")
            
            payload_types = {}
            for result in self.results:
                payload = result.get('payload', '')
                payload_type = self._classify_payload(payload)
                if payload_type not in payload_types:
                    payload_types[payload_type] = {'total': 0, 'blocked': 0}
                payload_types[payload_type]['total'] += 1
                if result.get('blocked'):
                    payload_types[payload_type]['blocked'] += 1
            
            for ptype, stats in payload_types.items():
                block_rate = (stats['blocked'] / stats['total'] * 100) if stats['total'] > 0 else 0
                f.write(f"{ptype}: {stats['blocked']}/{stats['total']} заблокировано ({block_rate:.2f}%)\n")
        
        return str(filepath)
    
    def _classify_payload(self, payload: str) -> str:
        """Классифицирует тип пейлоада"""
        payload_lower = payload.lower()
        if '<script' in payload_lower:
            return 'Script Tag'
        elif '<img' in payload_lower:
            return 'Image Tag'
        elif '<iframe' in payload_lower:
            return 'Iframe Tag'
        elif 'javascript:' in payload_lower:
            return 'JavaScript Protocol'
        elif 'onerror' in payload_lower or 'onload' in payload_lower:
            return 'Event Handler'
        elif '<svg' in payload_lower:
            return 'SVG Tag'
        elif '<body' in payload_lower:
            return 'Body Tag'
        else:
            return 'Other'
    
    def generate_html_report(self, filename: Optional[str] = None) -> str:
        """Генерирует HTML отчет"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"waf_test_report_{timestamp}.html"
        
        filepath = self.output_dir / filename
        
        summary = self.generate_summary()
        
        html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчет о тестировании WAF</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .summary-card {{
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #4CAF50;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #333;
        }}
        .summary-card .value {{
            font-size: 24px;
            font-weight: bold;
            color: #4CAF50;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #4CAF50;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .blocked {{
            color: #f44336;
            font-weight: bold;
        }}
        .passed {{
            color: #4CAF50;
            font-weight: bold;
        }}
        .payload {{
            font-family: monospace;
            font-size: 12px;
            word-break: break-all;
            max-width: 400px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Отчет о тестировании WAF на устойчивость к XSS-атакам</h1>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Всего тестов</h3>
                <div class="value">{summary['total_tests']}</div>
            </div>
            <div class="summary-card">
                <h3>Заблокировано</h3>
                <div class="value">{summary['blocked']}</div>
                <div>{summary['block_rate']:.2f}%</div>
            </div>
            <div class="summary-card">
                <h3>Пропущено</h3>
                <div class="value">{summary['passed']}</div>
                <div>{summary['pass_rate']:.2f}%</div>
            </div>
            <div class="summary-card">
                <h3>Ошибки</h3>
                <div class="value">{summary['errors']}</div>
            </div>
        </div>
        
        <h2>Информация о тестировании</h2>
        <p><strong>Дата:</strong> {summary['test_date']}</p>
        <p><strong>Тип WAF:</strong> {summary['waf_type']}</p>
        
        <h2>Детальные результаты</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Пейлоад</th>
                    <th>Статус</th>
                    <th>Результат</th>
                    <th>WAF Тип</th>
                    <th>Время ответа</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for i, result in enumerate(self.results, 1):
            status_class = 'blocked' if result.get('blocked') else 'passed'
            status_text = 'Заблокирован' if result.get('blocked') else 'Пропущен'
            payload = result.get('payload', 'N/A')
            # Экранируем HTML в пейлоаде
            payload_escaped = payload.replace('<', '&lt;').replace('>', '&gt;')
            
            html += f"""
                <tr>
                    <td>{i}</td>
                    <td class="payload">{payload_escaped}</td>
                    <td>{result.get('status_code', 'N/A')}</td>
                    <td class="{status_class}">{status_text}</td>
                    <td>{result.get('waf_type', 'N/A')}</td>
                    <td>{result.get('response_time', 'N/A')}</td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return str(filepath)

