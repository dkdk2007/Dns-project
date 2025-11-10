from flask import Flask
import threading, time

app = Flask('')

@app.route('/')
def home():
    return "البوت شغال ✅"

def run():
    app.run(host='0.0.0.0', port=8080)

t = threading.Thread(target=run)
t.start()


#!/usr/bin/env python3
"""
nextdns_manager.py
NextDNS Custom Denylist Monitor - full CLI tool
Enhanced with better UI and persistent data
"""

import os
import json
import time
import threading
from datetime import datetime
from typing import Dict, Set, Any
import sys

import requests

# Files
ACCOUNTS_FILE = "nextdns_accounts.json"
BOT_SETTINGS_FILE = "bot_settings.json"
STATE_FILE = "state.json"

# Network timeouts
HTTP_TIMEOUT = 10


class NextDNSManager:
    def __init__(self):
        self.accounts_file = ACCOUNTS_FILE
        self.bot_file = BOT_SETTINGS_FILE
        self.state_file = STATE_FILE

        # إنشاء الملفات إذا لم تكن موجودة
        self.ensure_files_exist()
        
        self.accounts: Dict[str, Dict[str, Any]] = self.load_accounts()
        self.bot_settings: Dict[str, str] = self.load_bot_settings()
        self.state: Dict[str, Any] = self.load_state()

        # processed requests: profile_id -> set of request_ids
        self.processed_requests: Dict[str, Set[str]] = {
            k: set(v) for k, v in self.state.get("processed_requests", {}).items()
        }
        # denylist cache: profile_id -> list of domains
        self.denylist_cache: Dict[str, list] = self.state.get("denylist_cache", {})

        # thread control
        self.monitor_threads: Dict[str, threading.Thread] = {}
        self.monitoring = False

    def ensure_files_exist(self):
        """تأكد من وجود جميع الملفات اللازمة"""
        for file_path in [self.accounts_file, self.bot_file, self.state_file]:
            if not os.path.exists(file_path):
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump({}, f, indent=4)

    def clear_screen(self):
        """Clear terminal screen"""
        os.system("cls" if os.name == "nt" else "clear")

    def print_header(self, title):
        """طباعة عنوان منمق"""
        self.clear_screen()
        print("╔" + "═" * 78 + "╗")
        print("║ {:^78} ║".format(title))
        print("╚" + "═" * 78 + "╝")

    def print_success(self, message):
        """طباعة رسالة نجاح"""
        print(f"✅ {message}")

    def print_error(self, message):
        """طباعة رسالة خطأ"""
        print(f"❌ {message}")

    def print_warning(self, message):
        """طباعة رسالة تحذير"""
        print(f"⚠️  {message}")

    def print_info(self, message):
        """طباعة رسالة معلومات"""
        print(f"ℹ️  {message}")

    def wait_for_enter(self):
        """انتظار ضغط Enter مع رسالة منمقة"""
        print("\n" + "─" * 80)
        input("📥 Press Enter to continue...")

    # -------------------- Persistence --------------------
    def load_accounts(self) -> Dict[str, Dict[str, Any]]:
        try:
            with open(self.accounts_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.print_info(f"Loaded {len(data)} accounts from storage")
                return data
        except Exception as e:
            self.print_error(f"Error loading accounts: {e}")
            return {}

    def save_accounts(self):
        try:
            with open(self.accounts_file, "w", encoding="utf-8") as f:
                json.dump(self.accounts, f, indent=4, ensure_ascii=False)
            self.print_info("Accounts saved successfully")
        except Exception as e:
            self.print_error(f"Error saving accounts: {e}")

    def load_bot_settings(self) -> Dict[str, str]:
        try:
            with open(self.bot_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                bot_configured = bool(data.get("bot_token") and data.get("chat_id"))
                if bot_configured:
                    self.print_info("Telegram bot settings loaded")
                return data
        except Exception as e:
            self.print_error(f"Error loading bot settings: {e}")
            return {"bot_token": "", "chat_id": ""}

    def save_bot_settings(self):
        try:
            with open(self.bot_file, "w", encoding="utf-8") as f:
                json.dump(self.bot_settings, f, indent=4, ensure_ascii=False)
            self.print_info("Bot settings saved successfully")
        except Exception as e:
            self.print_error(f"Error saving bot settings: {e}")

    def load_state(self) -> Dict[str, Any]:
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                processed_count = sum(len(v) for v in data.get("processed_requests", {}).values())
                self.print_info(f"Loaded state with {processed_count} processed requests")
                return data
        except Exception as e:
            self.print_error(f"Error loading state: {e}")
            return {}

    def save_state(self):
        try:
            state_out = {
                "processed_requests": {k: list(v) for k, v in self.processed_requests.items()},
                "denylist_cache": self.denylist_cache,
                "last_saved": datetime.now().isoformat()
            }
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(state_out, f, indent=4, ensure_ascii=False)
        except Exception as e:
            self.print_error(f"Error saving state: {e}")

    # -------------------- NextDNS API helpers --------------------
    def validate_api_key(self, api_key: str) -> Dict[str, Any]:
        """
        Validate API key and return first profile id + name.
        """
        try:
            self.print_info("Validating API key...")
            headers = {"X-Api-Key": api_key}
            resp = requests.get("https://api.nextdns.io/profiles", headers=headers, timeout=HTTP_TIMEOUT)
            if resp.status_code != 200:
                return {"success": False, "error": "HTTP {}".format(resp.status_code)}
            data = resp.json()
            profiles = data.get("data", [])
            if not profiles:
                return {"success": False, "error": "No profiles found"}
            profile = profiles[0]
            return {"success": True, "profile_id": profile.get("id"), "profile_name": profile.get("name", "")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def fetch_denylist(self, profile_id: str, api_key: str, force_refresh: bool = False) -> list:
        """
        Fetch custom denylist entries for a profile using NextDNS API denylist endpoint.
        Cache results in memory.
        """
        try:
            # Use cache if present and not forcing refresh
            if profile_id in self.denylist_cache and not force_refresh:
                return self.denylist_cache[profile_id]

            headers = {"X-Api-Key": api_key}
            url = "https://api.nextdns.io/profiles/{}/denylist".format(profile_id)
            resp = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT)
            if resp.status_code != 200:
                return []
            data = resp.json()
            entries = data.get("data", [])
            domains = []
            for e in entries:
                # entries sometimes have 'id' which is domain
                dom = e.get("id") or e.get("domain") or e.get("name")
                if dom:
                    domains.append(dom.strip().lower())
            # cache
            self.denylist_cache[profile_id] = domains
            return domains
        except Exception:
            return []

    def fetch_logs(self, profile_id: str, api_key: str, since_seconds: int = 60) -> list:
        """
        Fetch recent logs (default last 1 minute) for a profile.
        """
        try:
            headers = {"X-Api-Key": api_key}
            url = "https://api.nextdns.io/profiles/{}/logs".format(profile_id)
            params = {"limit": 100, "from": int((time.time() - since_seconds) * 1000)}
            resp = requests.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
            if resp.status_code != 200:
                return []
            data = resp.json()
            return data.get("data", [])
        except Exception:
            return []

    # -------------------- Telegram helpers --------------------
    def send_telegram(self, text: str, parse_mode: str = None) -> bool:
        token = self.bot_settings.get("bot_token")
        chat_id = self.bot_settings.get("chat_id")
        if not token or not chat_id:
            return False
        try:
            url = "https://api.telegram.org/bot{}/sendMessage".format(token)
            data = {"chat_id": chat_id, "text": text}
            if parse_mode:
                data["parse_mode"] = parse_mode
            resp = requests.post(url, data=data, timeout=HTTP_TIMEOUT)
            return resp.status_code == 200
        except Exception:
            return False

    def send_telegram_alert(self, account_name: str, domain: str, reason: str, client_ip: str = "") -> bool:
        token = self.bot_settings.get("bot_token")
        chat_id = self.bot_settings.get("chat_id")
        if not token or not chat_id:
            # print locally when no bot configured
            print("🔔 Alert (no bot): {} blocked {} - {}".format(account_name, domain, reason))
            return False
        try:
            message = "🚨 *NextDNS Alert*\n\n"
            message += "• *Account*: {}\n".format(account_name)
            message += "• *Domain*: `{}`\n".format(domain)
            message += "• *Reason*: {}\n".format(reason)
            if client_ip:
                message += "• *Client IP*: `{}`\n".format(client_ip)
            message += "• *Time*: {}".format(datetime.now().strftime('%Y-%m-%d %I:%M:%S %p'))
            return self.send_telegram(message, parse_mode="Markdown")
        except Exception:
            return False

    # -------------------- Account management --------------------
    def add_account(self):
        self.print_header("Add New Account")
        print("📝 You will need your NextDNS API Key")
        print("   Get it from: https://my.nextdns.io/account")
        print()
        
        name = input("🏷️  Account name: ").strip()
        if not name:
            self.print_error("Account name is required")
            self.wait_for_enter()
            return
            
        api_key = input("🔑 API Key: ").strip()
        if not api_key:
            self.print_error("API Key is required")
            self.wait_for_enter()
            return
            
        self.print_info("Validating API Key...")
        res = self.validate_api_key(api_key)
        if not res.get("success"):
            self.print_error("Failed to validate API Key: {}".format(res.get('error')))
            self.wait_for_enter()
            return
            
        profile_id = res["profile_id"]
        profile_name = res.get("profile_name", "")
        
        self.accounts[profile_id] = {
            "name": name,
            "profile_name": profile_name,
            "api_key": api_key,
            "added_at": datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"),
            "active": True,
        }
        
        # clear caches for this profile if any
        if profile_id in self.denylist_cache:
            del self.denylist_cache[profile_id]
            
        self.save_accounts()
        self.print_success("Account '{}' added with profile {}".format(name, profile_id))
        
        # offer test alert
        if self.bot_settings.get("bot_token") and self.bot_settings.get("chat_id"):
            choice = input("\n📤 Send a test alert for this account to Telegram now? (y/n): ").strip().lower()
            if choice == "y":
                ok = self.test_account_alert(profile_id)
                if ok:
                    self.print_success("Test alert sent")
                else:
                    self.print_error("Test alert failed")
        else:
            self.print_warning("Telegram bot not configured. Set it up from main menu to receive alerts")
            
        self.wait_for_enter()

    def list_accounts(self):
        self.print_header("Saved Accounts")
        if not self.accounts:
            self.print_warning("No accounts saved")
            self.wait_for_enter()
            return
            
        for i, (pid, acc) in enumerate(self.accounts.items(), start=1):
            status = "🟢 Active" if acc.get("active", False) else "🔴 Inactive"
            print(f"{i}. {acc.get('name','N/A')}")
            print(f"   📋 Profile: {pid}")
            print(f"   📊 Status: {status}")
            print(f"   ⏰ Added: {acc.get('added_at','N/A')}")
            print()
            
        self.wait_for_enter()

    def manage_account(self):
        self.print_header("Manage Account")
        if not self.accounts:
            self.print_warning("No accounts available")
            self.wait_for_enter()
            return
            
        print("📋 Accounts:")
        for i, (pid, acc) in enumerate(self.accounts.items(), start=1):
            status = "🟢" if acc.get("active", False) else "🔴"
            print(f"{i}. {status} {acc.get('name','N/A')} (Profile {pid})")
            
        try:
            idx = int(input("\n🎯 Select account number to manage (0 to cancel): ").strip())
        except ValueError:
            self.print_error("Invalid input")
            self.wait_for_enter()
            return
            
        if idx == 0:
            return
        if idx < 1 or idx > len(self.accounts):
            self.print_error("Invalid selection")
            self.wait_for_enter()
            return
            
        profile_id = list(self.accounts.keys())[idx - 1]
        account = self.accounts[profile_id]
        
        while True:
            self.print_header(f"Manage Account: {account.get('name','N/A')}")
            print(f"📋 Profile ID: {profile_id}")
            print(f"🏷️  Profile name: {account.get('profile_name','N/A')}")
            print(f"📊 Status: {'🟢 Active' if account.get('active', False) else '🔴 Inactive'}")
            print(f"⏰ Added: {account.get('added_at','N/A')}")
            print()
            print("🔧 Management Options:")
            print("1. 🔄 Toggle Enable/Disable")
            print("2. 📤 Send Test Alert to Telegram")
            print("3. 🗑️  Delete Account")
            print("4. ↩️  Back to Main Menu")
            
            sub = input("\n🎯 Choose option: ").strip()
            if sub == "1":
                account["active"] = not account.get("active", False)
                self.save_accounts()
                status = "enabled" if account["active"] else "disabled"
                self.print_success(f"Account {status} successfully")
                self.wait_for_enter()
            elif sub == "2":
                ok = self.test_account_alert(profile_id)
                if ok:
                    self.print_success("Test alert sent successfully")
                else:
                    self.print_error("Failed to send test alert (check bot settings)")
                self.wait_for_enter()
            elif sub == "3":
                confirm = input("❓ Are you sure you want to delete this account? (y/n): ").strip().lower()
                if confirm == "y":
                    # remove caches
                    if profile_id in self.denylist_cache:
                        del self.denylist_cache[profile_id]
                    if profile_id in self.processed_requests:
                        del self.processed_requests[profile_id]
                    del self.accounts[profile_id]
                    self.save_accounts()
                    self.save_state()
                    self.print_success("Account deleted successfully")
                    self.wait_for_enter()
                    break
            elif sub == "4":
                break
            else:
                self.print_error("Invalid option")
                self.wait_for_enter()

    def quick_toggle_account(self):
        self.print_header("Quick Toggle Account")
        if not self.accounts:
            self.print_warning("No accounts available")
            self.wait_for_enter()
            return
            
        for i, (pid, acc) in enumerate(self.accounts.items(), start=1):
            status = '🟢 Active' if acc.get('active', False) else '🔴 Inactive'
            print(f"{i}. {acc.get('name','N/A')} | {status}")
            
        try:
            idx = int(input("\n🎯 Select account number to toggle: ").strip())
        except ValueError:
            self.print_error("Invalid input")
            self.wait_for_enter()
            return
            
        if idx < 1 or idx > len(self.accounts):
            self.print_error("Invalid selection")
            self.wait_for_enter()
            return
            
        profile_id = list(self.accounts.keys())[idx - 1]
        acc = self.accounts[profile_id]
        acc["active"] = not acc.get("active", False)
        self.save_accounts()
        status = '🟢 Active' if acc['active'] else '🔴 Inactive'
        self.print_success(f"Account '{acc.get('name')}' is now {status}")
        self.wait_for_enter()

    def delete_account(self):
        self.print_header("Delete Account")
        if not self.accounts:
            self.print_warning("No accounts available")
            self.wait_for_enter()
            return
            
        for i, (pid, acc) in enumerate(self.accounts.items(), start=1):
            print(f"{i}. {acc.get('name','N/A')} (Profile {pid})")
            
        try:
            idx = int(input("\n🎯 Select account number to delete: ").strip())
        except ValueError:
            self.print_error("Invalid input")
            self.wait_for_enter()
            return
            
        if idx < 1 or idx > len(self.accounts):
            self.print_error("Invalid selection")
            self.wait_for_enter()
            return
            
        profile_id = list(self.accounts.keys())[idx - 1]
        name = self.accounts[profile_id].get("name", "N/A")
        
        confirm = input(f"❓ Confirm delete account '{name}'? (y/n): ").strip().lower()
        if confirm == "y":
            if profile_id in self.denylist_cache:
                del self.denylist_cache[profile_id]
            if profile_id in self.processed_requests:
                del self.processed_requests[profile_id]
            del self.accounts[profile_id]
            self.save_accounts()
            self.save_state()
            self.print_success("Account deleted successfully")
        else:
            self.print_info("Deletion cancelled")
            
        self.wait_for_enter()

    # -------------------- Telegram Bot --------------------
    def setup_bot(self):
        self.print_header("Telegram Bot Setup")
        print("🤖 To create a Telegram bot:")
        print("   1. Start a chat with @BotFather")
        print("   2. Use /newbot command")
        print("   3. Follow instructions to get bot token")
        print("   4. Start your bot and send a message")
        print("   5. Get your chat ID from @userinfobot")
        print()
        
        token = input("🔑 Bot Token: ").strip()
        chat_id = input("💬 Chat ID: ").strip()
        
        self.bot_settings["bot_token"] = token
        self.bot_settings["chat_id"] = chat_id
        self.save_bot_settings()
        
        self.print_success("Bot settings saved successfully")
        
        if token and chat_id:
            ask = input("\n📤 Send test message now? (y/n): ").strip().lower()
            if ask == "y":
                ok = self.test_telegram_bot()
                if ok:
                    self.print_success("Test message sent successfully")
                else:
                    self.print_error("Test failed - check token and chat ID")
                    
        self.wait_for_enter()

    def test_telegram_bot(self) -> bool:
        token = self.bot_settings.get("bot_token")
        chat_id = self.bot_settings.get("chat_id")
        if not token or not chat_id:
            self.print_error("Telegram bot not configured")
            return False
        try:
            text = "✅ Test message from NextDNS Manager\nTime: {}".format(
                datetime.now().strftime('%Y-%m-%d %I:%M:%S %p'))
            return self.send_telegram(text)
        except Exception:
            return False

    def test_account_alert(self, profile_id: str) -> bool:
        acc = self.accounts.get(profile_id)
        if not acc:
            self.print_error("Account not found")
            return False
        return self.send_telegram_alert(acc.get("name", "Account"), "test.example.com", "Test alert from account")

    # -------------------- Dashboard --------------------
    def show_dashboard(self):
        self.clear_screen()
        now = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
        total = len(self.accounts)
        active = sum(1 for a in self.accounts.values() if a.get("active", False))
        bot_status = "🤖 Configured" if self.bot_settings.get("bot_token") else "❌ Not Configured"
        
        print("╔" + "═" * 78 + "╗")
        print("║ {:^78} ║".format("NextDNS Manager Dashboard"))
        print("╠" + "═" * 78 + "╣")
        print("║ {:<40} {:>36} ║".format("📊 Monitoring Statistics", f"🕐 {now}"))
        print("╠" + "─" * 78 + "╣")
        print("║ {:<30} {:>46} ║".format("• Total Accounts", f"{total}"))
        print("║ {:<30} {:>46} ║".format("• Active Accounts", f"{active}"))
        print("║ {:<30} {:>46} ║".format("• Telegram Bot", bot_status))
        print("╠" + "═" * 78 + "╣")
        
        if not self.accounts:
            self.print_warning("No accounts added yet")
            print("╚" + "═" * 78 + "╝")
            return
            
        print("║ {:<78} ║".format("📋 Account Details:"))
        print("╠" + "─" * 78 + "╣")
        
        for i, (pid, acc) in enumerate(self.accounts.items(), start=1):
            name = acc.get("name", "N/A")
            status = "🟢 Active" if acc.get("active", False) else "🔴 Inactive"
            profile_name = acc.get("profile_name", "N/A")
            denylist = self.fetch_denylist(pid, acc.get("api_key", ""))
            recent_logs = self.fetch_logs(pid, acc.get("api_key", ""))
            recent_custom_blocks = [l for l in recent_logs if l.get("action") == "blocked" and l.get("domain") in denylist]
            
            print(f"║ {i}. {name:<20} {status:<15} ║")
            print(f"║    📍 Profile: {profile_name:<64} ║")
            print(f"║    📊 Denylist: {len(denylist):<3} domains | Recent blocks: {len(recent_custom_blocks):<3} ║")
            print("║" + " " * 78 + "║")
            
        print("╚" + "═" * 78 + "╝")

    # -------------------- Monitoring --------------------
    def is_domain_in_denylist(self, domain: str, denylist: set) -> bool:
        """
        Check if domain matches any entry in denylist.
        Supports exact match and wildcard patterns (*.example.com)
        """
        domain = domain.lower().strip()
        
        # Exact match
        if domain in denylist:
            return True
        
        # Check wildcard patterns (*.example.com should match sub.example.com)
        for denylist_entry in denylist:
            if denylist_entry.startswith("*."):
                # Remove *. and check if domain ends with the pattern
                pattern = denylist_entry[2:]  # Remove *.
                if domain.endswith(pattern) or domain.endswith("." + pattern):
                    return True
            # Check if domain is subdomain of denylist entry
            elif "." in domain:
                parts = domain.split(".")
                for i in range(len(parts)):
                    parent = ".".join(parts[i:])
                    if parent in denylist:
                        return True
        
        return False

    def monitor_worker(self, profile_id: str, account: Dict[str, Any]):
        """
        Thread worker that monitors logs for a single account/profile and sends alerts only
        when domain is in custom denylist.
        """
        if profile_id not in self.processed_requests:
            self.processed_requests[profile_id] = set()
        
        acc_name = account.get('name')
        self.print_info(f"Started monitoring: {acc_name} (Profile: {profile_id})")
        
        # Load denylist
        denylist_raw = self.fetch_denylist(profile_id, account.get("api_key", ""), force_refresh=True)
        denylist = set(d.lower().strip() for d in denylist_raw)
        self.print_info(f"Loaded {len(denylist)} domains in denylist")
        
        check_interval = 10  # Check every 10 seconds
        iteration = 0
        
        while account.get("active", False) and self.monitoring:
            try:
                iteration += 1
                
                # Refresh denylist every 5 minutes (30 iterations)
                if iteration % 30 == 0:
                    denylist_raw = self.fetch_denylist(profile_id, account.get("api_key", ""), force_refresh=True)
                    denylist = set(d.lower().strip() for d in denylist_raw)
                    self.print_info(f"Refreshed denylist: {len(denylist)} domains")
                
                # Fetch logs from last minute
                logs = self.fetch_logs(profile_id, account.get("api_key", ""), since_seconds=60)
                
                blocked_logs = [l for l in logs if l.get("status") == 2 or l.get("status") == "blocked"]
                
                if len(logs) > 0:
                    current_time = datetime.now().strftime('%H:%M:%S')
                    print(f"[{current_time}] 📡 {acc_name}: Checked {len(logs)} logs, {len(blocked_logs)} blocked")
                
                for log in blocked_logs:
                    domain = (log.get("name") or log.get("domain") or "").lower().strip()
                    
                    if not domain:
                        continue
                    
                    # Check if domain is in denylist
                    if not self.is_domain_in_denylist(domain, denylist):
                        continue
                    
                    # Create unique ID for this request
                    timestamp = log.get("timestamp", int(time.time() * 1000))
                    req_id = "{}_{}".format(domain, timestamp)
                    
                    # Skip if already processed
                    if req_id in self.processed_requests.get(profile_id, set()):
                        continue
                    
                    # Record this alert
                    self.processed_requests.setdefault(profile_id, set()).add(req_id)
                    
                    # Extract client info
                    client_ip = log.get("clientIp") or log.get("device", {}).get("id", "") or ""
                    device_name = log.get("device", {}).get("name", "")
                    reason = "Blocked by custom denylist"
                    if device_name:
                        reason += f" (Device: {device_name})"
                    
                    # Send alert
                    alert_time = datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')
                    print(f"[{alert_time}] 🚨 ALERT: {acc_name} blocked {domain}")
                    self.send_telegram_alert(account.get("name", "Account"), domain, reason, client_ip)
                    
                    # Save state immediately after sending alert
                    self.save_state()
                    
                    # Limit memory usage
                    if len(self.processed_requests[profile_id]) > 2000:
                        self.processed_requests[profile_id] = set(list(self.processed_requests[profile_id])[-1000:])
                
                # Save state periodically
                if iteration % 6 == 0:  # Every minute
                    self.save_state()
                
                time.sleep(check_interval)
                
            except Exception as e:
                self.print_error(f"Monitor error for {profile_id}: {str(e)}")
                import traceback
                traceback.print_exc()
                time.sleep(10)

    def start_live_monitoring(self):
        # start threaded monitoring for all active accounts
        active_accounts = [acc for acc in self.accounts.values() if acc.get("active", False)]
        if not active_accounts:
            self.print_error("No active accounts to monitor")
            self.wait_for_enter()
            return
            
        if self.monitoring:
            self.print_warning("Monitoring already running")
            self.wait_for_enter()
            return
            
        self.monitoring = True
        threads = []
        
        self.print_header("Starting Live Monitoring")
        print(f"🔍 Starting monitoring for {len(active_accounts)} active account(s)")
        print("📝 Press Ctrl+C to stop monitoring")
        print()
        
        for pid, acc in self.accounts.items():
            if acc.get("active", False):
                t = threading.Thread(target=self.monitor_worker, args=(pid, acc), daemon=True)
                threads.append(t)
                t.start()
                
        try:
            while self.monitoring:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping monitoring...")
            self.monitoring = False
            # wait briefly for threads to finish gracefully
            time.sleep(2)
            self.save_state()
            self.print_success("Monitoring stopped and state saved")
            self.wait_for_enter()

    # -------------------- Main Menu --------------------
    def main_menu(self):
        while True:
            self.show_dashboard()
            print("\n📋 Main Menu:")
            print("1. ➕ Add New Account")
            print("2. 📜 List Accounts")
            print("3. ⚙️  Manage Account")
            print("4. 🔄 Quick Toggle Enable/Disable Account")
            print("5. 🤖 Setup Telegram Bot")
            print("6. 📤 Test Telegram Bot")
            print("7. 🚨 Test Account Alert")
            print("8. 🗑️  Delete Account")
            print("9. 🔍 Start Live Custom Denylist Monitoring")
            print("0. 🚪 Exit")
            print()
            choice = input("🎯 Choose option: ").strip()
            if choice == "1":
                self.add_account()
            elif choice == "2":
                self.list_accounts()
            elif choice == "3":
                self.manage_account()
            elif choice == "4":
                self.quick_toggle_account()
            elif choice == "5":
                self.setup_bot()
            elif choice == "6":
                ok = self.test_telegram_bot()
                if ok:
                    self.print_success("Telegram test message sent successfully")
                else:
                    self.print_error("Telegram test failed")
                self.wait_for_enter()
            elif choice == "7":
                # Choose account to test
                if not self.accounts:
                    self.print_error("No accounts to test")
                    self.wait_for_enter()
                else:
                    self.print_header("Test Account Alert")
                    print("📋 Select account to test:")
                    for i, (pid, acc) in enumerate(self.accounts.items(), start=1):
                        print(f"{i}. {acc.get('name','N/A')} (Profile {pid})")
                    try:
                        idx = int(input("\n🎯 Select account number: ").strip())
                        if 1 <= idx <= len(self.accounts):
                            profile_id = list(self.accounts.keys())[idx - 1]
                            sent = self.test_account_alert(profile_id)
                            if sent:
                                self.print_success("Test alert sent successfully")
                            else:
                                self.print_error("Test alert failed (check bot settings)")
                        else:
                            self.print_error("Invalid selection")
                    except ValueError:
                        self.print_error("Invalid input. Enter a number")
                    self.wait_for_enter()
            elif choice == "8":
                self.delete_account()
            elif choice == "9":
                self.start_live_monitoring()
            elif choice == "0":
                print("\n👋 Goodbye!")
                # Save state before exiting
                self.save_state()
                time.sleep(1)
                break
            else:
                self.print_error("Invalid choice")
                self.wait_for_enter()


def main():
    try:
        manager = NextDNSManager()
        manager.clear_screen()
        print("🚀 NextDNS Manager Starting...")
        time.sleep(1)
        manager.main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Program interrupted by user. Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
