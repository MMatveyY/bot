"""
Графический интерфейс для тестирования WAF на устойчивость к XSS-атакам
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import queue
import os
import sys
from pathlib import Path
from datetime import datetime
import webbrowser

# Добавляем путь к родительской директории для импорта модулей
sys.path.insert(0, str(Path(__file__).parent.parent))

from waf_tester.payload_generator import PayloadGenerator
from waf_tester.request_sender import RequestSender
from waf_tester.response_analyzer import ResponseAnalyzer
from waf_tester.report_generator import ReportGenerator


class WAFTesterGUI:
    """Графический интерфейс для тестирования WAF"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("WAF Tester - Тестирование на устойчивость к XSS-атакам")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Переменные
        self.testing = False
        self.test_thread = None
        self.message_queue = queue.Queue()
        self.results = []
        
        # Компоненты
        self.payload_generator = None
        self.request_sender = None
        self.response_analyzer = ResponseAnalyzer()
        self.report_generator = ReportGenerator()
        
        self.create_widgets()
        self.check_queue()
        
    def create_widgets(self):
        """Создает виджеты интерфейса"""
        # Создаем notebook для вкладок
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Вкладка настроек
        self.settings_frame = ttk.Frame(notebook)
        notebook.add(self.settings_frame, text="Настройки")
        self.create_settings_tab()
        
        # Вкладка тестирования
        self.test_frame = ttk.Frame(notebook)
        notebook.add(self.test_frame, text="Тестирование")
        self.create_test_tab()
        
        # Вкладка результатов
        self.results_frame = ttk.Frame(notebook)
        notebook.add(self.results_frame, text="Результаты")
        self.create_results_tab()
        
        # Вкладка отчетов
        self.reports_frame = ttk.Frame(notebook)
        notebook.add(self.reports_frame, text="Отчеты")
        self.create_reports_tab()
    
    def create_settings_tab(self):
        """Создает вкладку настроек"""
        # Основные настройки
        main_group = ttk.LabelFrame(self.settings_frame, text="Основные настройки", padding=10)
        main_group.pack(fill=tk.X, padx=10, pady=5)
        
        # URL целевого приложения
        ttk.Label(main_group, text="URL целевого приложения:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_var = tk.StringVar(value="http://example.com")
        url_entry = ttk.Entry(main_group, textvariable=self.url_var, width=50)
        url_entry.grid(row=0, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        main_group.columnconfigure(1, weight=1)
        
        # Тип теста
        ttk.Label(main_group, text="Тип теста:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.test_type_var = tk.StringVar(value="get")
        test_type_combo = ttk.Combobox(main_group, textvariable=self.test_type_var, 
                                       values=["get", "post", "header"], state="readonly", width=20)
        test_type_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Количество пейлоадов (общее)
        ttk.Label(main_group, text="Количество пейлоадов (всего):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.max_payloads_var = tk.IntVar(value=100)
        max_payloads_spin = ttk.Spinbox(
            main_group, from_=1, to=2000, textvariable=self.max_payloads_var, width=20
        )
        max_payloads_spin.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Задержка между запросами
        ttk.Label(main_group, text="Задержка между запросами (сек):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.delay_var = tk.DoubleVar(value=0.5)
        delay_spin = ttk.Spinbox(main_group, from_=0.1, to=10.0, increment=0.1, 
                                textvariable=self.delay_var, width=20, format="%.1f")
        delay_spin.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Настройки генератора пейлоадов
        payload_group = ttk.LabelFrame(self.settings_frame, text="Генератор пейлоадов", padding=10)
        payload_group.pack(fill=tk.X, padx=10, pady=5)
        
        # Использование ML
        self.use_ml_var = tk.BooleanVar(value=True)
        ml_check = ttk.Checkbutton(payload_group, text="Использовать ML для генерации пейлоадов", 
                                   variable=self.use_ml_var)
        ml_check.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Количество пейлоадов через ML-мутатор
        ttk.Label(payload_group, text="Пейлоадов через ML-мутатор:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ml_payloads_var = tk.IntVar(value=50)
        ml_payloads_spin = ttk.Spinbox(
            payload_group, from_=0, to=2000, textvariable=self.ml_payloads_var, width=20
        )
        ml_payloads_spin.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Файл с пейлоадами
        ttk.Label(payload_group, text="Файл с пейлоадами:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.payloads_file_var = tk.StringVar()
        payloads_file_frame = ttk.Frame(payload_group)
        payloads_file_frame.grid(row=2, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        payload_group.columnconfigure(1, weight=1)
        
        payloads_file_entry = ttk.Entry(payloads_file_frame, textvariable=self.payloads_file_var, width=40)
        payloads_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        def browse_payloads_file():
            filename = filedialog.askopenfilename(
                title="Выберите файл с пейлоадами",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                self.payloads_file_var.set(filename)
        
        ttk.Button(payloads_file_frame, text="Обзор...", command=browse_payloads_file).pack(side=tk.LEFT, padx=5)
        
        # Путь к ML модели
        ttk.Label(payload_group, text="Путь к ML модели:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.model_path_var = tk.StringVar()
        model_path_frame = ttk.Frame(payload_group)
        model_path_frame.grid(row=3, column=1, sticky=tk.W+tk.E, padx=5, pady=5)
        payload_group.columnconfigure(1, weight=1)
        
        model_path_entry = ttk.Entry(model_path_frame, textvariable=self.model_path_var, width=40)
        model_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        def browse_model_path():
            filename = filedialog.askopenfilename(
                title="Выберите файл модели",
                filetypes=[("PyTorch trained", "*.pt"), ("All files", "*.*")]
            )
            if filename:
                self.model_path_var.set(filename)
        
        ttk.Button(model_path_frame, text="Обзор...", command=browse_model_path).pack(side=tk.LEFT, padx=5)
        
        # Кнопка сохранения настроек
        ttk.Button(self.settings_frame, text="Сохранить настройки", 
                  command=self.save_settings).pack(pady=10)
    
    def create_test_tab(self):
        """Создает вкладку тестирования"""
        # Кнопки управления
        control_frame = ttk.Frame(self.test_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.start_button = ttk.Button(control_frame, text="Начать тестирование", 
                                       command=self.start_testing, state=tk.NORMAL)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="Остановить", 
                                      command=self.stop_testing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Прогресс
        progress_frame = ttk.LabelFrame(self.test_frame, text="Прогресс", padding=10)
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_var = tk.StringVar(value="Готов к тестированию")
        ttk.Label(progress_frame, textvariable=self.progress_var).pack(anchor=tk.W)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # Лог тестирования
        log_frame = ttk.LabelFrame(self.test_frame, text="Лог тестирования", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Статистика
        stats_frame = ttk.LabelFrame(self.test_frame, text="Статистика", padding=10)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        stats_inner = ttk.Frame(stats_frame)
        stats_inner.pack(fill=tk.X)
        
        self.stats_labels = {}
        stats = [
            ("Всего тестов", "total"),
            ("Заблокировано", "blocked"),
            ("Пропущено", "passed"),
            ("Ошибки", "errors"),
            ("Процент блокировки", "block_rate")
        ]
        
        for i, (label, key) in enumerate(stats):
            row = i // 3
            col = (i % 3) * 2
            ttk.Label(stats_inner, text=f"{label}:").grid(row=row, column=col, sticky=tk.W, padx=5)
            var = tk.StringVar(value="0")
            self.stats_labels[key] = var
            ttk.Label(stats_inner, textvariable=var, font=("Arial", 10, "bold")).grid(
                row=row, column=col+1, sticky=tk.W, padx=5)
    
    def create_results_tab(self):
        """Создает вкладку результатов"""
        # Фильтры
        filter_frame = ttk.Frame(self.results_frame)
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(filter_frame, text="Фильтр:").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar()
        filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var,
                                   values=["Все", "Заблокировано", "Пропущено", "Ошибки"],
                                   state="readonly", width=15)
        filter_combo.pack(side=tk.LEFT, padx=5)
        filter_combo.set("Все")
        filter_combo.bind("<<ComboboxSelected>>", self.filter_results)
        
        # Таблица результатов
        results_inner = ttk.Frame(self.results_frame)
        results_inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Создаем Treeview
        columns = ("#", "Пейлоад", "Статус", "Результат", "WAF Тип", "Время")
        self.results_tree = ttk.Treeview(results_inner, columns=columns, show="headings", height=20)
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=150)
        
        self.results_tree.column("#", width=50)
        self.results_tree.column("Пейлоад", width=300)
        self.results_tree.column("Статус", width=80)
        self.results_tree.column("Результат", width=120)
        self.results_tree.column("WAF Тип", width=150)
        self.results_tree.column("Время", width=100)
        
        scrollbar = ttk.Scrollbar(results_inner, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Детали результата
        details_frame = ttk.LabelFrame(self.results_frame, text="Детали результата", padding=10)
        details_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, height=5, wrap=tk.WORD)
        self.details_text.pack(fill=tk.X)
        
        self.results_tree.bind("<<TreeviewSelect>>", self.on_result_select)
    
    def create_reports_tab(self):
        """Создает вкладку отчетов"""
        # Информация
        info_frame = ttk.LabelFrame(self.reports_frame, text="Информация", padding=10)
        info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        info_text = """
После завершения тестирования отчеты автоматически сохраняются в папке 'reports/'.
Вы можете сгенерировать отчеты вручную, используя кнопки ниже.
        """
        ttk.Label(info_frame, text=info_text, justify=tk.LEFT).pack(anchor=tk.W)
        
        # Кнопки генерации отчетов
        buttons_frame = ttk.Frame(self.reports_frame)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(buttons_frame, text="Генерировать JSON отчет", 
                  command=lambda: self.generate_report("json")).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Генерировать TXT отчет", 
                  command=lambda: self.generate_report("txt")).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Генерировать HTML отчет", 
                  command=lambda: self.generate_report("html")).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Открыть папку с отчетами", 
                  command=self.open_reports_folder).pack(side=tk.LEFT, padx=5)
        
        # Список отчетов
        reports_list_frame = ttk.LabelFrame(self.reports_frame, text="Последние отчеты", padding=10)
        reports_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.reports_listbox = tk.Listbox(reports_list_frame, height=10)
        self.reports_listbox.pack(fill=tk.BOTH, expand=True)
        self.reports_listbox.bind("<Double-Button-1>", self.open_report)
    
    def save_settings(self):
        """Сохраняет настройки"""
        messagebox.showinfo("Настройки", "Настройки сохранены!")
    
    def log_message(self, message):
        """Добавляет сообщение в лог"""
        self.message_queue.put(("log", message))
    
    def update_progress(self, current, total, message=""):
        """Обновляет прогресс"""
        self.message_queue.put(("progress", current, total, message))
    
    def update_stats(self, stats):
        """Обновляет статистику"""
        self.message_queue.put(("stats", stats))
    
    def add_result(self, result):
        """Добавляет результат"""
        self.message_queue.put(("result", result))
    
    def check_queue(self):
        """Проверяет очередь сообщений"""
        try:
            while True:
                msg_type, *args = self.message_queue.get_nowait()
                
                if msg_type == "log":
                    self.log_text.insert(tk.END, args[0] + "\n")
                    self.log_text.see(tk.END)
                elif msg_type == "progress":
                    current, total, message = args
                    if total > 0:
                        self.progress_bar['maximum'] = total
                        self.progress_bar['value'] = current
                        self.progress_var.set(f"{message} ({current}/{total})")
                    else:
                        self.progress_var.set(message)
                elif msg_type == "stats":
                    stats = args[0]
                    for key, var in self.stats_labels.items():
                        if key in stats:
                            var.set(str(stats[key]))
                elif msg_type == "result":
                    result = args[0]
                    self.results.append(result)
                    self.add_result_to_tree(result)
                    self.report_generator.add_result(result)
        except queue.Empty:
            pass
        
        self.root.after(100, self.check_queue)
    
    def add_result_to_tree(self, result):
        """Добавляет результат в дерево"""
        payload = result.get('payload', 'N/A')
        status = result.get('status_code', 'N/A')
        blocked = "Заблокирован" if result.get('blocked') else "Пропущен"
        waf_type = result.get('waf_type', 'N/A')
        response_time = result.get('response_time', 'N/A')
        
        item = self.results_tree.insert("", tk.END, values=(
            len(self.results),
            payload[:50] + "..." if len(payload) > 50 else payload,
            status,
            blocked,
            waf_type,
            response_time
        ))
        
        # Цветовая индикация
        if result.get('blocked'):
            self.results_tree.set(item, "Результат", "Заблокирован")
        else:
            self.results_tree.set(item, "Результат", "Пропущен")
    
    def filter_results(self, event=None):
        """Фильтрует результаты"""
        filter_value = self.filter_var.get()
        
        # Очищаем дерево
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Добавляем отфильтрованные результаты
        for result in self.results:
            if filter_value == "Все":
                self.add_result_to_tree(result)
            elif filter_value == "Заблокировано" and result.get('blocked'):
                self.add_result_to_tree(result)
            elif filter_value == "Пропущено" and not result.get('blocked') and result.get('status_code', 0) > 0:
                self.add_result_to_tree(result)
            elif filter_value == "Ошибки" and result.get('status_code', 0) == 0:
                self.add_result_to_tree(result)
    
    def on_result_select(self, event):
        """Обработчик выбора результата"""
        selection = self.results_tree.selection()
        if not selection:
            return
        
        item = self.results_tree.item(selection[0])
        index = int(item['values'][0]) - 1
        
        if 0 <= index < len(self.results):
            result = self.results[index]
            details = f"Пейлоад: {result.get('payload', 'N/A')}\n"
            details += f"Статус код: {result.get('status_code', 'N/A')}\n"
            details += f"Заблокирован: {'Да' if result.get('blocked') else 'Нет'}\n"
            if result.get('waf_type'):
                details += f"Тип WAF: {result.get('waf_type')}\n"
            if result.get('block_reason'):
                details += f"Причина блокировки: {result.get('block_reason')}\n"
            if result.get('xss_executed'):
                details += f"XSS выполнен: Да\n"
            details += f"Время ответа: {result.get('response_time', 'N/A')}\n"
            details += f"Размер ответа: {result.get('response_size', 0)} байт\n"
            
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(1.0, details)
    
    def start_testing(self):
        """Запускает тестирование"""
        if self.testing:
            return
        
        url = self.url_var.get().strip()
        if not url or not url.startswith(('http://', 'https://')):
            messagebox.showerror("Ошибка", "Введите корректный URL (начинается с http:// или https://)")
            return
        
        # Очищаем предыдущие результаты
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.results.clear()
        self.report_generator = ReportGenerator()
        self.log_text.delete(1.0, tk.END)
        
        # Инициализируем компоненты
        try:
            payloads_file = self.payloads_file_var.get().strip() or None
            model_path = self.model_path_var.get().strip() or None
            ml_top_k = self.ml_payloads_var.get()
            
            self.payload_generator = PayloadGenerator(
                payloads_file=payloads_file,
                model_path=model_path,
                use_ml=self.use_ml_var.get(),
                ml_top_k=ml_top_k,
            )
            
            self.request_sender = RequestSender(
                target_url=url,
                request_delay=self.delay_var.get()
            )
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка инициализации: {e}")
            return
        
        # Запускаем тестирование в отдельном потоке
        self.testing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        self.test_thread = threading.Thread(target=self.run_test, daemon=True)
        self.test_thread.start()
    
    def run_test(self):
        """Выполняет тестирование"""
        try:
            test_type = self.test_type_var.get()
            max_payloads = self.max_payloads_var.get()
            
            self.log_message(f"Начало тестирования WAF")
            self.log_message(f"URL: {self.url_var.get()}")
            self.log_message(f"Тип теста: {test_type.upper()}")
            self.log_message(f"Количество пейлоадов: {max_payloads}")
            self.log_message("=" * 60)
            
            # Получаем пейлоады
            self.update_progress(0, 0, "Генерация пейлоадов...")
            payloads = self.payload_generator.get_payloads(
                count=max_payloads,
                use_ml_mutation=self.payload_generator.use_ml
            )
            self.log_message(f"Сгенерировано {len(payloads)} пейлоадов")
            
            # Тестируем каждый пейлоад
            total = len(payloads)
            blocked_count = 0
            passed_count = 0
            error_count = 0
            
            for i, payload in enumerate(payloads, 1):
                if not self.testing:
                    break
                
                self.log_message(f"[{i}/{total}] Тестирование пейлоада...")
                self.log_message(f"Пейлоад: {payload[:80]}{'...' if len(payload) > 80 else ''}")
                
                try:
                    # Отправляем запрос
                    if test_type == "get":
                        response, elapsed = self.request_sender.send_get_request(payload)
                    elif test_type == "post":
                        response, elapsed = self.request_sender.send_post_request(payload)
                    else:
                        response, elapsed = self.request_sender.send_request_in_header(payload)
                    
                    # Анализируем ответ
                    analysis = self.response_analyzer.analyze_response(response, payload)
                    analysis['payload'] = payload
                    analysis['response_time'] = f"{elapsed:.3f}"
                    
                    # Обновляем статистику
                    if analysis['blocked']:
                        blocked_count += 1
                        self.log_message(f"  [ЗАБЛОКИРОВАН]")
                    else:
                        if analysis['status_code'] > 0:
                            passed_count += 1
                            self.log_message(f"  [ПРОПУЩЕН] (статус: {analysis['status_code']})")
                        else:
                            error_count += 1
                            self.log_message(f"  [ОШИБКА]")
                    
                    if analysis.get('waf_type'):
                        self.log_message(f"  Тип WAF: {analysis['waf_type']}")
                    
                    # Добавляем результат
                    self.add_result(analysis)
                    
                except Exception as e:
                    error_count += 1
                    self.log_message(f"  [ОШИБКА] {e}")
                    error_result = {
                        'payload': payload,
                        'status_code': 0,
                        'blocked': False,
                        'error': str(e)
                    }
                    self.add_result(error_result)
                
                # Обновляем прогресс
                self.update_progress(i, total, f"Тестирование...")
                
                # Обновляем статистику
                total_tests = i
                block_rate = (blocked_count / total_tests * 100) if total_tests > 0 else 0
                pass_rate = (passed_count / total_tests * 100) if total_tests > 0 else 0
                
                self.update_stats({
                    'total': total_tests,
                    'blocked': blocked_count,
                    'passed': passed_count,
                    'errors': error_count,
                    'block_rate': f"{block_rate:.2f}%"
                })
            
            # Генерируем отчеты
            if self.testing:
                self.log_message("=" * 60)
                self.log_message("Генерация отчетов...")
                
                json_report = self.report_generator.generate_json_report()
                txt_report = self.report_generator.generate_text_report()
                html_report = self.report_generator.generate_html_report()
                
                self.log_message(f"JSON отчет: {json_report}")
                self.log_message(f"TXT отчет: {txt_report}")
                self.log_message(f"HTML отчет: {html_report}")
                
                # Обновляем список отчетов
                self.update_reports_list()
            
            self.log_message("=" * 60)
            self.log_message("Тестирование завершено!")
            
        except Exception as e:
            self.log_message(f"Критическая ошибка: {e}")
            import traceback
            self.log_message(traceback.format_exc())
        finally:
            self.testing = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.update_progress(0, 0, "Готов к тестированию")
    
    def stop_testing(self):
        """Останавливает тестирование"""
        self.testing = False
        self.log_message("Остановка тестирования...")
    
    def filter_results(self, event=None):
        """Фильтрует результаты"""
        filter_value = self.filter_var.get()
        
        # Очищаем дерево
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Добавляем отфильтрованные результаты
        for result in self.results:
            if filter_value == "Все":
                self.add_result_to_tree(result)
            elif filter_value == "Заблокировано" and result.get('blocked'):
                self.add_result_to_tree(result)
            elif filter_value == "Пропущено" and not result.get('blocked') and result.get('status_code', 0) > 0:
                self.add_result_to_tree(result)
            elif filter_value == "Ошибки" and result.get('status_code', 0) == 0:
                self.add_result_to_tree(result)
    
    def generate_report(self, report_type):
        """Генерирует отчет"""
        if not self.results:
            messagebox.showwarning("Предупреждение", "Нет результатов для генерации отчета")
            return
        
        try:
            if report_type == "json":
                report_path = self.report_generator.generate_json_report()
            elif report_type == "txt":
                report_path = self.report_generator.generate_text_report()
            else:
                report_path = self.report_generator.generate_html_report()
            
            messagebox.showinfo("Успех", f"Отчет сохранен:\n{report_path}")
            self.update_reports_list()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка генерации отчета: {e}")
    
    def update_reports_list(self):
        """Обновляет список отчетов"""
        self.reports_listbox.delete(0, tk.END)
        reports_dir = Path("reports")
        if reports_dir.exists():
            reports = sorted(reports_dir.glob("waf_test_report_*.{json,txt,html}"), 
                           key=lambda p: p.stat().st_mtime, reverse=True)
            for report in reports[:10]:  # Последние 10 отчетов
                self.reports_listbox.insert(0, report.name)
    
    def open_report(self, event):
        """Открывает выбранный отчет"""
        selection = self.reports_listbox.curselection()
        if not selection:
            return
        
        filename = self.reports_listbox.get(selection[0])
        report_path = Path("reports") / filename
        
        if report_path.exists():
            if report_path.suffix == ".html":
                webbrowser.open(f"file://{report_path.absolute()}")
            else:
                os.startfile(report_path.absolute())
    
    def open_reports_folder(self):
        """Открывает папку с отчетами"""
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        os.startfile(reports_dir.absolute())


def main():
    """Точка входа для GUI"""
    root = tk.Tk()
    app = WAFTesterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

