"""
Модуль отправки HTTP-запросов к WAF
"""
import time
import requests
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode, quote
import urllib3

# Отключаем предупреждения о небезопасных SSL соединениях
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RequestSender:
    """Класс для отправки HTTP-запросов к WAF"""
    
    def __init__(
        self,
        target_url: str,
        request_delay: float = 0.5,
        timeout: int = 10,
        verify_ssl: bool = False,
        headers: Optional[Dict[str, str]] = None
    ):
        """
        :param target_url: URL целевого веб-приложения за WAF
        :param request_delay: задержка между запросами (секунды)
        :param timeout: таймаут запроса (секунды)
        :param verify_ssl: проверять ли SSL сертификат
        :param headers: дополнительные HTTP заголовки
        """
        self.target_url = target_url
        self.request_delay = request_delay
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        if headers:
            self.default_headers.update(headers)
    
    def send_get_request(
        self,
        payload: str,
        param_name: str = "q",
        path: Optional[str] = None
    ) -> Tuple[requests.Response, float]:
        """
        Отправляет GET запрос с пейлоадом в параметре URL
        
        :param payload: XSS пейлоад
        :param param_name: имя параметра для пейлоада
        :param path: дополнительный путь к URL
        :return: кортеж (response, время выполнения)
        """
        url = self.target_url
        if path:
            url = f"{url.rstrip('/')}/{path.lstrip('/')}"
        
        # Добавляем пейлоад в параметры
        params = {param_name: payload}
        full_url = f"{url}?{urlencode(params, quote_via=quote)}"
        
        start_time = time.time()
        try:
            response = requests.get(
                full_url,
                headers=self.default_headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            elapsed = time.time() - start_time
            time.sleep(self.request_delay)
            return response, elapsed
        except requests.exceptions.RequestException as e:
            elapsed = time.time() - start_time
            print(f"[RequestSender] Ошибка при отправке GET запроса: {e}")
            # Создаем фиктивный response для обработки ошибки
            response = requests.Response()
            response.status_code = 0
            response._content = b''
            response.elapsed = time.time() - start_time
            return response, elapsed
    
    def send_post_request(
        self,
        payload: str,
        param_name: str = "q",
        path: Optional[str] = None,
        data: Optional[Dict] = None
    ) -> Tuple[requests.Response, float]:
        """
        Отправляет POST запрос с пейлоадом в теле запроса
        
        :param payload: XSS пейлоад
        :param param_name: имя параметра для пейлоада
        :param path: дополнительный путь к URL
        :param data: дополнительные данные для POST
        :return: кортеж (response, время выполнения)
        """
        url = self.target_url
        if path:
            url = f"{url.rstrip('/')}/{path.lstrip('/')}"
        
        post_data = data.copy() if data else {}
        post_data[param_name] = payload
        
        start_time = time.time()
        try:
            response = requests.post(
                url,
                data=post_data,
                headers=self.default_headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            elapsed = time.time() - start_time
            time.sleep(self.request_delay)
            return response, elapsed
        except requests.exceptions.RequestException as e:
            elapsed = time.time() - start_time
            print(f"[RequestSender] Ошибка при отправке POST запроса: {e}")
            response = requests.Response()
            response.status_code = 0
            response._content = b''
            response.elapsed = time.time() - start_time
            return response, elapsed
    
    def send_request_in_header(
        self,
        payload: str,
        header_name: str = "User-Agent",
        path: Optional[str] = None
    ) -> Tuple[requests.Response, float]:
        """
        Отправляет запрос с пейлоадом в HTTP заголовке
        
        :param payload: XSS пейлоад
        :param header_name: имя заголовка для пейлоада
        :param path: дополнительный путь к URL
        :return: кортеж (response, время выполнения)
        """
        url = self.target_url
        if path:
            url = f"{url.rstrip('/')}/{path.lstrip('/')}"
        
        headers = self.default_headers.copy()
        headers[header_name] = payload
        
        start_time = time.time()
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            elapsed = time.time() - start_time
            time.sleep(self.request_delay)
            return response, elapsed
        except requests.exceptions.RequestException as e:
            elapsed = time.time() - start_time
            print(f"[RequestSender] Ошибка при отправке запроса с заголовком: {e}")
            response = requests.Response()
            response.status_code = 0
            response._content = b''
            response.elapsed = time.time() - start_time
            return response, elapsed

