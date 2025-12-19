import json
import yaml
import csv
from datetime import datetime
from typing import Dict, List, Any, Optional
import os
from jinja2 import Template
import matplotlib.pyplot as plt
import seaborn as sns
from fpdf import FPDF
import plotly.graph_objects as go
import plotly.io as pio


class EnhancedReportGenerator:
    def __init__(self, config_path: str = "config.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        self.reports_dir = self.config['reports']['output_dir']
        os.makedirs(self.reports_dir, exist_ok=True)

        self.timestamp = datetime.now().strftime(
            self.config['reports']['timestamp_format']
        )

        self.report_data = {
            'metadata': {},
            'summary': {},
            'details': {},
            'statistics': {},
            'recommendations': []
        }

    def generate_report(self, test_results: Dict, waf_info: Dict = None) -> Dict:
        """Генерация комплексного отчета"""

        # Собираем метаданные
        self.report_data['metadata'] = {
            'generated_at': datetime.now().isoformat(),
            'tool_version': '1.0.0',
            'target_url': test_results.get('target_url', 'unknown'),
            'test_duration': test_results.get('duration', 0),
            'waf_detected': waf_info.get('detected', False) if waf_info else False,
            'detected_wafs': waf_info.get('wafs', []) if waf_info else []
        }

        # Собираем статистику
        self.report_data['statistics'] = self.calculate_statistics(test_results)

        # Собираем детали
        self.report_data['details'] = self.collect_details(test_results)

        # Генерируем сводку
        self.report_data['summary'] = self.generate_summary()

        # Генерируем рекомендации
        self.report_data['recommendations'] = self.generate_recommendations(
            test_results, waf_info
        )

        # Экспорт в различные форматы
        export_paths = {}

        if 'txt' in self.config['reports']['formats']:
            export_paths['txt'] = self.export_txt()

        if 'json' in self.config['reports']['formats']:
            export_paths['json'] = self.export_json()

        if 'html' in self.config['reports']['formats']:
            export_paths['html'] = self.export_html()

        if 'pdf' in self.config['reports']['formats']:
            export_paths['pdf'] = self.export_pdf()

        if 'csv' in self.config['reports']['formats']:
            export_paths['csv'] = self.export_csv()

        # Генерируем визуализации
        if self.config['reports'].get('generate_charts', True):
            self.generate_charts()

        return {
            'report_data': self.report_data,
            'export_paths': export_paths
        }

    def calculate_statistics(self, test_results: Dict) -> Dict:
        """Расчет статистики тестирования"""

        tests = test_results.get('tests', [])

        total_tests = len(tests)
        successful_tests = sum(1 for t in tests if t.get('bypassed', False))
        blocked_tests = total_tests - successful_tests

        # Группировка по типам payloads
        payload_types = {}
        for test in tests:
            ptype = test.get('payload_type', 'unknown')
            if ptype not in payload_types:
                payload_types[ptype] = {'total': 0, 'bypassed': 0}

            payload_types[ptype]['total'] += 1
            if test.get('bypassed', False):
                payload_types[ptype]['bypassed'] += 1

        # Эффективность по типам обхода
        bypass_techniques = {}
        for test in tests:
            if test.get('bypassed', False):
                techniques = test.get('bypass_techniques', [])
                for tech in techniques:
                    bypass_techniques[tech] = bypass_techniques.get(tech, 0) + 1

        # Время ответа
        response_times = [t.get('response_time', 0) for t in tests]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0

        return {
            'total_tests': total_tests,
            'successful_tests': successful_tests,
            'blocked_tests': blocked_tests,
            'success_rate': (successful_tests / total_tests * 100) if total_tests > 0 else 0,
            'block_rate': (blocked_tests / total_tests * 100) if total_tests > 0 else 0,
            'by_payload_type': payload_types,
            'bypass_techniques': bypass_techniques,
            'response_time': {
                'average': avg_response_time,
                'min': min(response_times) if response_times else 0,
                'max': max(response_times) if response_times else 0
            },
            'waf_effectiveness': {
                'detection_rate': (blocked_tests / total_tests * 100) if total_tests > 0 else 0,
                'false_negatives': successful_tests,
                'false_positives': 0  # Нужно рассчитывать отдельно
            }
        }

    def collect_details(self, test_results: Dict) -> Dict:
        """Сбор детальной информации о тестах"""

        details = {
            'successful_tests': [],
            'blocked_tests': [],
            'errors': [],
            'payload_analysis': {}
        }

        for test in test_results.get('tests', []):
            test_detail = {
                'payload': test.get('payload', ''),
                'payload_type': test.get('payload_type', 'unknown'),
                'bypassed': test.get('bypassed', False),
                'response_code': test.get('response_code', 0),
                'response_time': test.get('response_time', 0),
                'bypass_techniques': test.get('bypass_techniques', []),
                'timestamp': test.get('timestamp', ''),
                'request_details': test.get('request', {}),
                'response_details': test.get('response', {}) if self.config['reports'][
                    'include_request_response'] else {}
            }

            if test.get('bypassed', False):
                details['successful_tests'].append(test_detail)
            else:
                details['blocked_tests'].append(test_detail)

            if test.get('error'):
                details['errors'].append({
                    'payload': test.get('payload', ''),
                    'error': test.get('error', ''),
                    'timestamp': test.get('timestamp', '')
                })

        # Анализ payloads
        details['payload_analysis'] = self.analyze_payloads(test_results)

        return details

    def analyze_payloads(self, test_results: Dict) -> Dict:
        """Анализ эффективности payloads"""

        payload_groups = {}

        for test in test_results.get('tests', []):
            payload = test.get('payload', '')
            ptype = test.get('payload_type', 'unknown')
            bypassed = test.get('bypassed', False)

            if ptype not in payload_groups:
                payload_groups[ptype] = {
                    'total': 0,
                    'bypassed': 0,
                    'payloads': []
                }

            payload_groups[ptype]['total'] += 1
            if bypassed:
                payload_groups[ptype]['bypassed'] += 1

            payload_groups[ptype]['payloads'].append({
                'payload': payload[:100],  # Обрезаем для читаемости
                'bypassed': bypassed,
                'techniques': test.get('bypass_techniques', [])
            })

        # Расчет эффективности
        for ptype, data in payload_groups.items():
            data['success_rate'] = (data['bypassed'] / data['total'] * 100) if data['total'] > 0 else 0
            data['most_effective_techniques'] = self.get_top_techniques(data['payloads'])

        return payload_groups

    def get_top_techniques(self, payloads: List) -> List:
        """Получение наиболее эффективных техник обхода"""

        technique_counts = {}
        for payload in payloads:
            if payload['bypassed']:
                for tech in payload.get('techniques', []):
                    technique_counts[tech] = technique_counts.get(tech, 0) + 1

        # Сортируем по убыванию
        sorted_techniques = sorted(
            technique_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [{'technique': tech, 'count': count}
                for tech, count in sorted_techniques[:5]]

    def generate_summary(self) -> Dict:
        """Генерация сводки отчета"""

        stats = self.report_data['statistics']

        summary = {
            'overall_score': self.calculate_security_score(stats),
            'risk_level': self.determine_risk_level(stats),
            'key_findings': [],
            'critical_issues': [],
            'waf_performance': {}
        }

        # Ключевые находки
        if stats['successful_tests'] > 0:
            summary['key_findings'].append(
                f"Найдено {stats['successful_tests']} уязвимостей XSS"
            )

            # Наиболее уязвимые типы payloads
            vulnerable_types = []
            for ptype, data in stats['by_payload_type'].items():
                if data['bypassed'] > 0:
                    rate = (data['bypassed'] / data['total'] * 100)
                    vulnerable_types.append(f"{ptype}: {rate:.1f}% успеха")

            if vulnerable_types:
                summary['key_findings'].append(
                    f"Наиболее уязвимые типы: {', '.join(vulnerabled_types[:3])}"
                )

        # Критические проблемы
        if stats['success_rate'] > 50:
            summary['critical_issues'].append(
                f"Высокий уровень успешных атак: {stats['success_rate']:.1f}%"
            )

        # Производительность WAF
        summary['waf_performance'] = {
            'detection_rate': f"{stats['waf_effectiveness']['detection_rate']:.1f}%",
            'average_response_time': f"{stats['response_time']['average']:.2f}с",
            'effectiveness_rating': self.rate_waf_effectiveness(stats)
        }

        return summary

    def calculate_security_score(self, stats: Dict) -> float:
        """Расчет общего балла безопасности"""

        # Весовые коэффициенты
        weights = {
            'success_rate': 0.4,
            'critical_bypasses': 0.3,
            'response_time': 0.2,
            'coverage': 0.1
        }

        # Нормализованные значения (0-1)
        success_rate_norm = 1 - (stats['success_rate'] / 100)

        # Критические обходы (DOM-based более критичны)
        critical_score = 1.0
        if 'dom-based' in stats['by_payload_type']:
            dom_stats = stats['by_payload_type']['dom-based']
            if dom_stats['total'] > 0:
                dom_success = dom_stats['bypassed'] / dom_stats['total']
                critical_score = 1 - dom_success

        # Время ответа (меньше лучше)
        response_norm = 1.0
        if stats['response_time']['average'] > 1.0:
            response_norm = 1.0 / stats['response_time']['average']

        # Покрытие тестами
        coverage_norm = min(stats['total_tests'] / 1000, 1.0)

        # Итоговый балл
        total_score = (
                weights['success_rate'] * success_rate_norm +
                weights['critical_bypasses'] * critical_score +
                weights['response_time'] * response_norm +
                weights['coverage'] * coverage_norm
        )

        return total_score * 10  # Масштабируем до 10 баллов

    def determine_risk_level(self, stats: Dict) -> str:
        """Определение уровня риска"""

        score = self.calculate_security_score(stats)

        if score >= 8.0:
            return "НИЗКИЙ"
        elif score >= 5.0:
            return "СРЕДНИЙ"
        elif score >= 3.0:
            return "ВЫСОКИЙ"
        else:
            return "КРИТИЧЕСКИЙ"

    def rate_waf_effectiveness(self, stats: Dict) -> str:
        """Оценка эффективности WAF"""

        detection_rate = stats['waf_effectiveness']['detection_rate']

        if detection_rate >= 95:
            return "ОТЛИЧНО"
        elif detection_rate >= 85:
            return "ХОРОШО"
        elif detection_rate >= 70:
            return "УДОВЛЕТВОРИТЕЛЬНО"
        else:
            return "НЕДОСТАТОЧНО"

    def generate_recommendations(self, test_results: Dict, waf_info: Dict) -> List[str]:
        """Генерация рекомендаций по улучшению безопасности"""

        recommendations = []
        stats = self.report_data['statistics']

        # Рекомендации на основе статистики
        if stats['success_rate'] > 30:
            recommendations.append(
                "Увеличьте строгость правил фильтрации для XSS атак"
            )

        # Рекомендации по типам payloads
        for ptype, data in stats['by_payload_type'].items():
            if data.get('success_rate', 0) > 50:
                recommendations.append(
                    f"Усильте защиту от {ptype} XSS атак"
                )

        # Рекомендации на основе WAF
        if waf_info and waf_info.get('detected', False):
            wafs = waf_info.get('wafs', [])

            if 'Cloudflare' in wafs:
                recommendations.extend([
                    "Настройте правила WAF для блокировки сложных обфускаций",
                    "Включите анализ JavaScript в реальном времени",
                    "Настройте лимиты запросов для предотвращения брутфорса"
                ])

            if 'ModSecurity' in wafs:
                recommendations.extend([
                    "Обновите OWASP CRS до последней версии",
                    "Настройте правила для DOM-based XSS",
                    "Включите парсинг JavaScript для обнаружения скрытых угроз"
                ])

        # Общие рекомендации
        general_recommendations = [
            "Регулярно обновляйте правила WAF",
            "Проводите периодические тесты на проникновение",
            "Внедрите Content Security Policy (CSP)",
            "Используйте HTTPOnly и Secure флаги для cookies",
            "Внедрите валидацию ввода на стороне сервера"
        ]

        recommendations.extend(general_recommendations)

        # Уникальные рекомендации
        return list(set(recommendations))[:10]  # Ограничиваем 10 рекомендациями

    def export_txt(self) -> str:
        """Экспорт отчета в TXT формате"""

        filename = f"report_{self.timestamp}.txt"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("ОТЧЕТ О ТЕСТИРОВАНИИ WAF НА УСТОЙЧИВОСТЬ К XSS-АТАКАМ\n")
            f.write("=" * 80 + "\n\n")

            # Метаданные
            f.write("МЕТАДАННЫЕ:\n")
            f.write("-" * 40 + "\n")
            for key, value in self.report_data['metadata'].items():
                f.write(f"{key}: {value}\n")
            f.write("\n")

            # Сводка
            f.write("СВОДКА:\n")
            f.write("-" * 40 + "\n")
            summary = self.report_data['summary']
            f.write(f"Общий балл безопасности: {summary['overall_score']:.1f}/10\n")
            f.write(f"Уровень риска: {summary['risk_level']}\n")
            f.write(f"Оценка эффективности WAF: {summary['waf_performance']['effectiveness_rating']}\n")
            f.write("\n")

            # Ключевые находки
            if summary['key_findings']:
                f.write("КЛЮЧЕВЫЕ НАХОДКИ:\n")
                f.write("-" * 40 + "\n")
                for finding in summary['key_findings']:
                    f.write(f"• {finding}\n")
                f.write("\n")

            # Статистика
            f.write("СТАТИСТИКА:\n")
            f.write("-" * 40 + "\n")
            stats = self.report_data['statistics']
            f.write(f"Всего тестов: {stats['total_tests']}\n")
            f.write(f"Успешных атак: {stats['successful_tests']}\n")
            f.write(f"Заблокировано: {stats['blocked_tests']}\n")
            f.write(f"Процент успеха: {stats['success_rate']:.1f}%\n")
            f.write(f"Процент блокировки: {stats['block_rate']:.1f}%\n")
            f.write("\n")

            # Рекомендации
            f.write("РЕКОМЕНДАЦИИ:\n")
            f.write("-" * 40 + "\n")
            for i, rec in enumerate(self.report_data['recommendations'], 1):
                f.write(f"{i}. {rec}\n")

        return filepath

    def export_json(self) -> str:
        """Экспорт отчета в JSON формате"""

        filename = f"report_{self.timestamp}.json"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.report_data, f, indent=2, ensure_ascii=False)

        return filepath

    def export_html(self) -> str:
        """Экспорт отчета в HTML формате"""

        # HTML шаблон
        html_template = """
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Отчет тестирования WAF - {{ metadata.target_url }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .section { margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
                .risk-critical { color: #e74c3c; font-weight: bold; }
                .risk-high { color: #e67e22; }
                .risk-medium { color: #f1c40f; }
                .risk-low { color: #27ae60; }
                table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background-color: #f2f2f2; }
                .success { background-color: #d4edda; }
                .danger { background-color: #f8d7da; }
                .chart-container { margin: 20px 0; }
            </style>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        </head>
        <body>
            <div class="header">
                <h1>📊 Отчет тестирования WAF</h1>
                <p>Цель: {{ metadata.target_url }}</p>
                <p>Дата: {{ metadata.generated_at }}</p>
            </div>

            <div class="section">
                <h2>📈 Сводка</h2>
                <p><strong>Общий балл безопасности:</strong> {{ summary.overall_score|round(1) }}/10</p>
                <p><strong>Уровень риска:</strong> 
                    <span class="risk-{{ summary.risk_level|lower }}">{{ summary.risk_level }}</span>
                </p>
                <p><strong>Эффективность WAF:</strong> {{ summary.waf_performance.effectiveness_rating }}</p>
            </div>

            <div class="section">
                <h2>📊 Статистика</h2>
                <table>
                    <tr>
                        <th>Метрика</th>
                        <th>Значение</th>
                    </tr>
                    <tr>
                        <td>Всего тестов</td>
                        <td>{{ statistics.total_tests }}</td>
                    </tr>
                    <tr class="{{ 'danger' if statistics.successful_tests > 0 else '' }}">
                        <td>Успешных атак</td>
                        <td>{{ statistics.successful_tests }}</td>
                    </tr>
                    <tr>
                        <td>Заблокировано</td>
                        <td>{{ statistics.blocked_tests }}</td>
                    </tr>
                    <tr class="{{ 'danger' if statistics.success_rate > 30 else '' }}">
                        <td>Процент успеха атак</td>
                        <td>{{ statistics.success_rate|round(1) }}%</td>
                    </tr>
                </table>

                <div class="chart-container">
                    <div id="chart1"></div>
                </div>
            </div>

            <div class="section">
                <h2>🎯 Рекомендации</h2>
                <ol>
                    {% for rec in recommendations %}
                    <li>{{ rec }}</li>
                    {% endfor %}
                </ol>
            </div>

            <script>
                // График успешности по типам payloads
                var types = {{ statistics.by_payload_type|tojson }};
                var typeNames = Object.keys(types);
                var successRates = typeNames.map(function(type) {
                    return types[type].success_rate || 0;
                });

                var trace1 = {
                    x: typeNames,
                    y: successRates,
                    type: 'bar',
                    name: 'Процент успеха',
                    marker: {
                        color: successRates.map(function(rate) {
                            return rate > 50 ? '#e74c3c' : 
                                   rate > 30 ? '#e67e22' : 
                                   rate > 10 ? '#f1c40f' : '#27ae60';
                        })
                    }
                };

                var layout1 = {
                    title: 'Успешность атак по типам payloads',
                    xaxis: { title: 'Тип payload' },
                    yaxis: { title: 'Процент успеха (%)', range: [0, 100] }
                };

                Plotly.newPlot('chart1', [trace1], layout1);
            </script>
        </body>
        </html>
        """

        filename = f"report_{self.timestamp}.html"
        filepath = os.path.join(self.reports_dir, filename)

        template = Template(html_template)
        html_content = template.render(**self.report_data)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return filepath

    def export_pdf(self) -> str:
        """Экспорт отчета в PDF формате"""

        filename = f"report_{self.timestamp}.pdf"
        filepath = os.path.join(self.reports_dir, filename)

        class PDFReport(FPDF):
            def header(self):
                self.set_font('Arial', 'B', 16)
                self.cell(0, 10, 'Отчет тестирования WAF', 0, 1, 'C')
                self.set_font('Arial', '', 10)
                self.cell(0, 10, f"Цель: {self.target_url}", 0, 1, 'C')
                self.ln(5)

            def footer(self):
                self.set_y(-15)
                self.set_font('Arial', 'I', 8)
                self.cell(0, 10, f'Страница {self.page_no()}', 0, 0, 'C')

        pdf = PDFReport()
        pdf.target_url = self.report_data['metadata']['target_url']

        pdf.add_page()
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Сводка результатов', 0, 1)

        pdf.set_font('Arial', '', 12)
        summary = self.report_data['summary']
        pdf.cell(0, 10, f"Общий балл безопасности: {summary['overall_score']:.1f}/10", 0, 1)
        pdf.cell(0, 10, f"Уровень риска: {summary['risk_level']}", 0, 1)

        # Добавляем таблицу со статистикой
        pdf.add_page()
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Статистика тестирования', 0, 1)

        pdf.set_font('Arial', '', 12)
        stats = self.report_data['statistics']

        data = [
            ['Метрика', 'Значение'],
            ['Всего тестов', str(stats['total_tests'])],
            ['Успешных атак', str(stats['successful_tests'])],
            ['Заблокировано', str(stats['blocked_tests'])],
            ['Процент успеха', f"{stats['success_rate']:.1f}%"]
        ]

        col_width = pdf.w / 2.5
        row_height = 10

        for row in data:
            for item in row:
                pdf.cell(col_width, row_height, str(item), border=1)
            pdf.ln(row_height)

        pdf.output(filepath)

        return filepath

    def export_csv(self) -> str:
        """Экспорт детальных результатов в CSV"""

        filename = f"detailed_results_{self.timestamp}.csv"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Заголовки
            writer.writerow([
                'Payload', 'Type', 'Bypassed', 'Response Code',
                'Response Time', 'Techniques', 'Timestamp'
            ])

            # Данные
            for test in self.report_data['details'].get('successful_tests', []):
                writer.writerow([
                    test['payload'][:100],
                    test['payload_type'],
                    test['bypassed'],
                    test['response_code'],
                    test['response_time'],
                    ';'.join(test['bypass_techniques']),
                    test['timestamp']
                ])

            for test in self.report_data['details'].get('blocked_tests', []):
                writer.writerow([
                    test['payload'][:100],
                    test['payload_type'],
                    test['bypassed'],
                    test['response_code'],
                    test['response_time'],
                    ';'.join(test['bypass_techniques']),
                    test['timestamp']
                ])

        return filepath

    def generate_charts(self):
        """Генерация графиков и диаграмм"""

        charts_dir = os.path.join(self.reports_dir, 'charts')
        os.makedirs(charts_dir, exist_ok=True)

        stats = self.report_data['statistics']

        # 1. Круговая диаграмма: успешные vs заблокированные
        plt.figure(figsize=(8, 6))
        labels = ['Успешные', 'Заблокированные']
        sizes = [stats['successful_tests'], stats['blocked_tests']]
        colors = ['#ff6b6b', '#51cf66']

        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.axis('equal')
        plt.title('Соотношение успешных и заблокированных атак')
        plt.savefig(os.path.join(charts_dir, 'success_vs_blocked.png'), dpi=150, bbox_inches='tight')
        plt.close()

        # 2. Столбчатая диаграмма: эффективность по типам payloads
        plt.figure(figsize=(10, 6))

        types = []
        success_rates = []

        for ptype, data in stats['by_payload_type'].items():
            types.append(ptype)
            success_rates.append(data.get('success_rate', 0))

        bars = plt.bar(types, success_rates, color=['#3498db', '#9b59b6', '#e74c3c'])

        # Цвета по уровню успеха
        for i, rate in enumerate(success_rates):
            if rate > 50:
                bars[i].set_color('#e74c3c')
            elif rate > 30:
                bars[i].set_color('#e67e22')
            elif rate > 10:
                bars[i].set_color('#f1c40f')
            else:
                bars[i].set_color('#27ae60')

        plt.xlabel('Тип payload')
        plt.ylabel('Процент успеха (%)')
        plt.title('Эффективность атак по типам payloads')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(charts_dir, 'by_payload_type.png'), dpi=150)
        plt.close()

        # 3. График времени ответа
        if 'response_time' in stats:
            plt.figure(figsize=(10, 6))

            response_data = stats['response_time']
            metrics = ['Среднее', 'Минимум', 'Максимум']
            values = [
                response_data.get('average', 0),
                response_data.get('min', 0),
                response_data.get('max', 0)
            ]

            bars = plt.bar(metrics, values, color=['#3498db', '#2ecc71', '#e74c3c'])
            plt.ylabel('Время (секунды)')
            plt.title('Время ответа WAF')

            # Добавляем значения на столбцы
            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width() / 2., height + 0.01,
                         f'{height:.3f}', ha='center', va='bottom')

            plt.tight_layout()
            plt.savefig(os.path.join(charts_dir, 'response_time.png'), dpi=150)
            plt.close()

        # 4. Heatmap эффективности техник обхода
        if stats.get('bypass_techniques'):
            plt.figure(figsize=(12, 8))

            techniques = list(stats['bypass_techniques'].keys())[:10]  # Топ-10
            counts = list(stats['bypass_techniques'].values())[:10]

            # Нормализуем для heatmap
            max_count = max(counts) if counts else 1
            normalized = [c / max_count for c in counts]

            # Создаем heatmap
            import numpy as np
            heatmap_data = np.array(normalized).reshape(1, -1)

            sns.heatmap(heatmap_data,
                        xticklabels=techniques,
                        yticklabels=['Эффективность'],
                        cmap='YlOrRd',
                        annot=True,
                        fmt='.2f',
                        cbar_kws={'label': 'Нормализованная эффективность'})

            plt.title('Топ-10 наиболее эффективных техник обхода')
            plt.tight_layout()
            plt.savefig(os.path.join(charts_dir, 'bypass_techniques_heatmap.png'), dpi=150)
            plt.close()