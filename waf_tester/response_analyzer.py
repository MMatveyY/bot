"""
Модуль анализа ответов WAF для определения блокировки/пропуска атак
"""
import re
from typing import Dict, Optional, Tuple
from bs4 import BeautifulSoup
import requests


class ResponseAnalyzer:
    """Анализатор ответов WAF для определения результата тестирования"""
    
    def __init__(self):
        # Паттерны для определения блокировки WAF
        self.block_patterns = [
            r'blocked',
            r'forbidden',
            r'access denied',
            r'security.*violation',
            r'waf',
            r'firewall',
            r'403',
            r'406',
            r'not acceptable',
            r'request.*rejected',
            r'security.*alert',
            r'malicious.*request',
            r'suspicious.*activity',
            r'modsecurity',
            r'cloudflare',
            r'akamai',
            r'incapsula',
            r'barracuda',
            r'f5',
            r'fortinet',
            r'palo.*alto',
        ]
        
        # Паттерны для определения успешного выполнения XSS
        self.xss_patterns = [
            r'<script[^>]*>.*alert',
            r'javascript:.*alert',
            r'onerror.*alert',
            r'onload.*alert',
            r'eval\(.*alert',
        ]
    
    def analyze_response(
        self,
        response: requests.Response,
        payload: str,
        check_xss_execution: bool = True
    ) -> Dict[str, any]:
        """
        Анализирует ответ WAF и определяет результат
        
        :param response: объект ответа requests
        :param payload: отправленный пейлоад
        :param check_xss_execution: проверять ли выполнение XSS в ответе
        :return: словарь с результатами анализа
        """
        result = {
            'status_code': response.status_code if response else 0,
            'blocked': False,
            'xss_executed': False,
            'waf_detected': False,
            'response_time': getattr(response, 'elapsed', None),
            'response_size': len(response.content) if response else 0,
            'waf_type': None,
            'block_reason': None,
            'details': {}
        }
        
        if not response or response.status_code == 0:
            result['blocked'] = True
            result['block_reason'] = 'Connection error'
            return result
        
        # Анализ статус кода
        if response.status_code in [403, 406, 429]:
            result['blocked'] = True
            result['block_reason'] = f'HTTP {response.status_code}'
        
        # Анализ содержимого ответа
        try:
            content = response.text.lower()
            headers_text = str(response.headers).lower()
            full_text = content + ' ' + headers_text
            
            # Проверка на блокировку WAF
            for pattern in self.block_patterns:
                if re.search(pattern, full_text, re.IGNORECASE):
                    result['blocked'] = True
                    result['waf_detected'] = True
                    
                    # Определение типа WAF
                    if 'modsecurity' in full_text:
                        result['waf_type'] = 'ModSecurity'
                    elif 'cloudflare' in full_text:
                        result['waf_type'] = 'Cloudflare'
                    elif 'akamai' in full_text:
                        result['waf_type'] = 'Akamai'
                    elif 'incapsula' in full_text:
                        result['waf_type'] = 'Incapsula'
                    elif 'barracuda' in full_text:
                        result['waf_type'] = 'Barracuda'
                    elif 'f5' in full_text:
                        result['waf_type'] = 'F5'
                    elif 'fortinet' in full_text:
                        result['waf_type'] = 'Fortinet'
                    elif 'palo' in full_text or 'alto' in full_text:
                        result['waf_type'] = 'Palo Alto'
                    else:
                        result['waf_type'] = 'Unknown WAF'
                    
                    result['block_reason'] = f'Matched pattern: {pattern}'
                    break
            
            # Проверка на выполнение XSS
            if check_xss_execution and not result['blocked']:
                # Проверяем, есть ли пейлоад в ответе
                if payload.lower() in content:
                    # Проверяем паттерны выполнения XSS
                    for pattern in self.xss_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            result['xss_executed'] = True
                            break
                    
                    # Дополнительная проверка через BeautifulSoup
                    try:
                        soup = BeautifulSoup(content, 'html.parser')
                        scripts = soup.find_all('script')
                        for script in scripts:
                            if payload.lower() in str(script).lower():
                                result['xss_executed'] = True
                                break
                    except:
                        pass
            
            # Анализ заголовков
            result['details']['headers'] = dict(response.headers)
            
            # Проверка на редирект
            if response.status_code in [301, 302, 303, 307, 308]:
                result['details']['redirect'] = response.headers.get('Location', '')
            
        except Exception as e:
            result['details']['error'] = str(e)
        
        return result
    
    def is_blocked(self, response: requests.Response) -> bool:
        """Быстрая проверка на блокировку"""
        if not response or response.status_code == 0:
            return True
        
        if response.status_code in [403, 406, 429]:
            return True
        
        try:
            content = response.text.lower()
            headers_text = str(response.headers).lower()
            full_text = content + ' ' + headers_text
            
            for pattern in self.block_patterns:
                if re.search(pattern, full_text, re.IGNORECASE):
                    return True
        except:
            pass
        
        return False
    
    def detect_waf_type(self, response: requests.Response) -> Optional[str]:
        """Определяет тип WAF по ответу"""
        if not response:
            return None
        
        try:
            content = response.text.lower()
            headers_text = str(response.headers).lower()
            full_text = content + ' ' + headers_text
            
            waf_indicators = {
                'ModSecurity': ['modsecurity', 'owasp'],
                'Cloudflare': ['cloudflare', 'cf-ray'],
                'Akamai': ['akamai', 'ak-'],
                'Incapsula': ['incapsula', 'incap'],
                'Barracuda': ['barracuda'],
                'F5': ['f5', 'bigip'],
                'Fortinet': ['fortinet', 'fortigate'],
                'Palo Alto': ['palo', 'alto'],
            }
            
            for waf_type, indicators in waf_indicators.items():
                for indicator in indicators:
                    if indicator in full_text:
                        return waf_type
            
        except:
            pass
        
        return None

