import streamlit as st
import requests
import ipaddress
import json
import datetime
import re

# Set page configuration
st.set_page_config(
    page_title="Cloudflare DNS Updater",
    page_icon="🌐",
    layout="wide",
)

# Custom CSS for styling
st.markdown("""
<style>
    .main-header {
        font-size: 2rem !important;
        font-weight: bold;
        margin-bottom: 1rem;
        color: #0082FF;
    }
    .section-header {
        font-size: 1.3rem !important;
        font-weight: bold;
        margin-top: 1rem;
        margin-bottom: 0.5rem;
        color: #0082FF;
    }
    .success-message {
        padding: 1rem;
        background-color: #d4edda;
        color: #155724;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .error-message {
        padding: 1rem;
        background-color: #f8d7da;
        color: #721c24;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .info-message {
        padding: 1rem;
        background-color: #cce5ff;
        color: #004085;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .log-container {
        height: 300px;
        overflow-y: auto;
        background-color: #2E2E2E;
        color: #FFFFFF;
        padding: 1rem;
        border-radius: 0.5rem;
        font-family: monospace;
    }
    .log-entry {
        margin-bottom: 0.5rem;
        line-height: 1.2;
    }
    .log-timestamp {
        color: #888888;
    }
    .log-error {
        color: #FF6B6B;
    }
    .small-info {
        font-size: 0.8rem;
        color: #6c757d;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state for logs
if 'logs' not in st.session_state:
    st.session_state.logs = []
    
if 'update_status' not in st.session_state:
    st.session_state.update_status = None

# Function to add log entries
def add_log(message, is_error=False):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    st.session_state.logs.append({
        "timestamp": timestamp,
        "message": message,
        "is_error": is_error
    })

# Function to get external IP
def get_external_ip():
    try:
        add_log("Fetching external IP...")
        response = requests.get("https://checkip.amazonaws.com", timeout=10)
        if response.status_code == 200:
            ip = response.text.strip()
            add_log(f"External IP: {ip}")
            return ip
        else:
            add_log(f"Error fetching external IP: HTTP {response.status_code}", True)
            return None
    except Exception as e:
        add_log(f"Error fetching external IP: {str(e)}", True)
        return None

# Function to validate IP address
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Function to get DNS record info from Cloudflare
def get_dns_record_info(zone_id, dns_record, api_token):
    try:
        add_log(f"Fetching DNS record info for {dns_record}...")
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={dns_record}"
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(url, headers=headers)
        data = response.json()
        
        if not data.get("success"):
            error_msg = "Unknown error"
            if data.get("errors") and len(data["errors"]) > 0:
                error_msg = data["errors"][0].get("message", "Unknown error")
            add_log(f"Error fetching DNS record info: {error_msg}", True)
            return None
        
        if len(data.get("result", [])) == 0:
            add_log("DNS record not found", True)
            return None
        
        record_info = data["result"][0]
        add_log(f"Current DNS record IP: {record_info['content']}")
        add_log(f"Current proxied status: {record_info['proxied']}")
        
        return record_info
    except Exception as e:
        add_log(f"Error fetching DNS record info: {str(e)}", True)
        return None

# Function to update DNS record
def update_dns_record(zone_id, record_id, dns_record, ip, ttl, proxied, api_token):
    try:
        add_log(f"Updating DNS record to {ip}...")
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        
        body = {
            "type": "A",
            "name": dns_record,
            "content": ip,
            "ttl": int(ttl),
            "proxied": proxied
        }
        
        response = requests.put(url, headers=headers, json=body)
        data = response.json()
        
        if not data.get("success"):
            error_msg = "Unknown error"
            if data.get("errors") and len(data["errors"]) > 0:
                error_msg = data["errors"][0].get("message", "Unknown error")
            add_log(f"Error updating DNS record: {error_msg}", True)
            return False
        
        add_log(f"Successfully updated {dns_record} to {ip}")
        add_log(f"TTL: {ttl}, Proxied: {proxied}")
        return True
    except Exception as e:
        add_log(f"Error updating DNS record: {str(e)}", True)
        return False

# Function to send Telegram notification
def send_telegram_notification(bot_token, chat_id, dns_record, ip, old_ip):
    if not bot_token or not chat_id:
        return
    
    try:
        add_log("Sending Telegram notification...")
        message = f"{dns_record} DNS Record Updated To: {ip} (was {old_ip})"
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage?chat_id={chat_id}&text={message}"
        
        response = requests.get(url)
        data = response.json()
        
        if not data.get("ok"):
            add_log("Telegram notification failed", True)
            return
        
        add_log("Telegram notification sent successfully")
    except Exception as e:
        add_log(f"Error sending Telegram notification: {str(e)}", True)

# Function to send Discord notification
def send_discord_notification(webhook_url, dns_record, ip, old_ip):
    if not webhook_url:
        return
    
    try:
        add_log("Sending Discord notification...")
        message = f"{dns_record} DNS Record Updated To: {ip} (was {old_ip})"
        
        payload = {
            "content": message
        }
        
        response = requests.post(webhook_url, json=payload)
        
        if not response.ok:
            add_log("Discord notification failed", True)
            return
        
        add_log("Discord notification sent successfully")
    except Exception as e:
        add_log(f"Error sending Discord notification: {str(e)}", True)

# Function to update DNS
def update_dns():
    # Reset logs for new update
    st.session_state.logs = []
    st.session_state.update_status = None
    
    # Get form values
    ip_source = st.session_state.ip_source
    custom_ip = st.session_state.custom_ip if ip_source == "custom" else ""
    dns_record = st.session_state.dns_record
    zone_id = st.session_state.zone_id
    api_token = st.session_state.api_token
    ttl = st.session_state.ttl
    proxied = st.session_state.proxied
    notify_telegram = st.session_state.notify_telegram
    telegram_bot_token = st.session_state.telegram_bot_token if notify_telegram else ""
    telegram_chat_id = st.session_state.telegram_chat_id if notify_telegram else ""
    notify_discord = st.session_state.notify_discord
    discord_webhook_url = st.session_state.discord_webhook_url if notify_discord else ""
    
    # Validate inputs
    if not dns_record or not zone_id or not api_token:
        add_log("Error: DNS Record, Zone ID, and API Token are required", True)
        st.session_state.update_status = "error"
        return
    
    # Validate TTL
    try:
        ttl_int = int(ttl)
        if (ttl_int < 120 or ttl_int > 7200) and ttl_int != 1:
            add_log("Error! TTL out of range (120-7200) or not set to 1", True)
            st.session_state.update_status = "error"
            return
    except ValueError:
        add_log("Error! TTL must be a number", True)
        st.session_state.update_status = "error"
        return
    
    # Check custom IP and proxied settings
    if ip_source == "custom" and proxied:
        add_log("Error! Custom IP cannot be Proxied", True)
        st.session_state.update_status = "error"
        return
    
    # Get current IP based on selection
    if ip_source == "external":
        current_ip = get_external_ip()
    else:  # custom
        if not is_valid_ip(custom_ip):
            add_log("Error! Invalid IP address format", True)
            st.session_state.update_status = "error"
            return
        current_ip = custom_ip
        add_log(f"Using custom IP: {current_ip}")
    
    if not current_ip:
        st.session_state.update_status = "error"
        return
    
    # Get DNS record info
    record_info = get_dns_record_info(zone_id, dns_record, api_token)
    
    if not record_info:
        st.session_state.update_status = "error"
        return
    
    # Check if update is needed
    if record_info["content"] == current_ip and record_info["proxied"] == proxied:
        add_log(f"DNS record IP of {dns_record} is already {current_ip}, no changes needed.")
        st.session_state.update_status = "unchanged"
        return
    
    # Update DNS record
    update_success = update_dns_record(
        zone_id, 
        record_info["id"], 
        dns_record, 
        current_ip, 
        ttl, 
        proxied, 
        api_token
    )
    
    if not update_success:
        st.session_state.update_status = "error"
        return
    
    # Send notifications
    if notify_telegram and telegram_bot_token and telegram_chat_id:
        send_telegram_notification(
            telegram_bot_token,
            telegram_chat_id,
            dns_record,
            current_ip,
            record_info["content"]
        )
    
    if notify_discord and discord_webhook_url:
        send_discord_notification(
            discord_webhook_url,
            dns_record,
            current_ip,
            record_info["content"]
        )
    
    st.session_state.update_status = "success"

# Function to load sample data
def load_sample_data():
    st.session_state.ip_source = "external"
    st.session_state.custom_ip = "192.168.1.100"
    st.session_state.dns_record = "home.example.com"
    st.session_state.zone_id = "346d3eba30e4a4d282f23fef3b4add60"
    st.session_state.api_token = "5bcFxQiRsNq5L48bnMcxtn5pIxW-ILueXt_p0Eq0"
    st.session_state.ttl = 120
    st.session_state.proxied = True
    st.session_state.notify_telegram = False
    st.session_state.telegram_bot_token = ""
    st.session_state.telegram_chat_id = ""
    st.session_state.notify_discord = True
    st.session_state.discord_webhook_url = "https://discord.com/api/webhooks/123456789/example"

# Main app layout
st.markdown("<h1 class='main-header'>Cloudflare DNS Updater</h1>", unsafe_allow_html=True)

# Create two columns for the layout
col1, col2 = st.columns([2, 1])

with col1:
    # DNS Configuration Form
    st.markdown("<h2 class='section-header'>DNS Configuration</h2>", unsafe_allow_html=True)
    
    # IP Source Selection
    st.radio(
        "IP Source", 
        options=["external", "custom"],
        index=0, 
        key="ip_source",
        format_func=lambda x: "External IP (Auto-detected)" if x == "external" else "Custom IP"
    )
    
    # Custom IP input (shown only when custom IP is selected)
    if st.session_state.ip_source == "custom":
        st.text_input(
            "Custom IP Address", 
            placeholder="e.g., 192.168.1.100",
            help="Enter a valid IPv4 address",
            key="custom_ip"
        )
    else:
        # Ensure the custom_ip exists in session state
        if "custom_ip" not in st.session_state:
            st.session_state.custom_ip = ""
    
    # DNS Record Input
    st.text_input(
        "DNS Record", 
        placeholder="e.g., home.example.com",
        help="The DNS record you want to update",
        key="dns_record"
    )
    
    # Split the next row into two columns
    cf_col1, cf_col2 = st.columns(2)
    
    with cf_col1:
        st.text_input(
            "Cloudflare Zone ID", 
            placeholder="e.g., 346d3eba30e4a4d282f23fef3b4add60",
            help="Found in your Cloudflare dashboard",
            key="zone_id"
        )
    
    with cf_col2:
        st.text_input(
            "Cloudflare API Token", 
            placeholder="Your API token with DNS edit permissions",
            type="password",
            help="Create a token with DNS:Edit permissions",
            key="api_token"
        )
    
    # TTL and Proxied options
    ttl_proxy_col1, ttl_proxy_col2 = st.columns(2)
    
    with ttl_proxy_col1:
        st.number_input(
            "TTL (seconds)", 
            min_value=1, 
            max_value=7200, 
            value=120,
            help="Time To Live: 120-7200 seconds, or 1 for Auto",
            key="ttl"
        )
    
    with ttl_proxy_col2:
        st.checkbox(
            "Use Cloudflare Proxy", 
            value=True,
            help="Enable Cloudflare's proxy features (not available with custom IPs)",
            key="proxied"
        )
    
    # Notification Settings
    st.markdown("<h2 class='section-header'>Notification Settings</h2>", unsafe_allow_html=True)
    
    # Telegram Notifications
    st.checkbox(
        "Enable Telegram Notifications", 
        value=False,
        key="notify_telegram"
    )
    
    if st.session_state.notify_telegram:
        telegram_col1, telegram_col2 = st.columns(2)
        
        with telegram_col1:
            st.text_input(
                "Telegram Chat ID", 
                placeholder="Your Telegram chat ID",
                key="telegram_chat_id"
            )
        
        with telegram_col2:
            st.text_input(
                "Telegram Bot API Token", 
                placeholder="Your bot API token",
                type="password",
                key="telegram_bot_token"
            )
    else:
        # Ensure these exist in session state
        if "telegram_chat_id" not in st.session_state:
            st.session_state.telegram_chat_id = ""
        if "telegram_bot_token" not in st.session_state:
            st.session_state.telegram_bot_token = ""
    
    # Discord Notifications
    st.checkbox(
        "Enable Discord Notifications", 
        value=False,
        key="notify_discord"
    )
    
    if st.session_state.notify_discord:
        st.text_input(
            "Discord Webhook URL", 
            placeholder="Your Discord webhook URL",
            key="discord_webhook_url"
        )
    else:
        # Ensure this exists in session state
        if "discord_webhook_url" not in st.session_state:
            st.session_state.discord_webhook_url = ""
    
    # Action buttons
    button_col1, button_col2 = st.columns([1, 2])
    
    with button_col1:
        st.button("Load Sample Data", on_click=load_sample_data)
    
    with button_col2:
        st.button("Update DNS Record", on_click=update_dns, type="primary")

with col2:
    # Status Section
    st.markdown("<h2 class='section-header'>Status</h2>", unsafe_allow_html=True)
    
    status_container = st.container()
    
    with status_container:
        if st.session_state.update_status == "success":
            st.markdown(
                "<div class='success-message'>DNS record updated successfully!</div>", 
                unsafe_allow_html=True
            )
        elif st.session_state.update_status == "error":
            st.markdown(
                "<div class='error-message'>Error updating DNS record</div>", 
                unsafe_allow_html=True
            )
        elif st.session_state.update_status == "unchanged":
            st.markdown(
                "<div class='info-message'>No changes needed</div>", 
                unsafe_allow_html=True
            )
    
    # Display current settings
    st.markdown("#### Current Settings")
    
    settings_container = st.container()
    
    with settings_container:
        st.markdown(f"**DNS Record:** {st.session_state.dns_record or 'Not set'}")
        
        # Get current external IP for display (if using external IP)
        current_ip_display = "Unknown"
        if st.session_state.ip_source == "external":
            try:
                current_ip_display = requests.get("https://checkip.amazonaws.com", timeout=5).text.strip()
            except:
                current_ip_display = "Could not detect"
        else:
            current_ip_display = st.session_state.custom_ip or "Not set"
        
        st.markdown(f"**Current IP:** {current_ip_display}")
        
        ttl_display = st.session_state.ttl
        if ttl_display == 1:
            ttl_display = "Auto (1)"
        st.markdown(f"**TTL:** {ttl_display} seconds")
        
        st.markdown(f"**Proxied:** {'Yes' if st.session_state.proxied else 'No'}")
        
        notifications = []
        if st.session_state.notify_telegram:
            notifications.append("Telegram")
        if st.session_state.notify_discord:
            notifications.append("Discord")
        
        notifications_display = ", ".join(notifications) if notifications else "None"
        st.markdown(f"**Notifications:** {notifications_display}")
    
    # Logs Section
    st.markdown("<h2 class='section-header'>Logs</h2>", unsafe_allow_html=True)
    
    log_container = st.container()
    
    with log_container:
        st.markdown("<div class='log-container'>", unsafe_allow_html=True)
        
        if len(st.session_state.logs) == 0:
            st.markdown("<div class='log-entry' style='color: #888;'>No logs yet. Start an update to see activity logs.</div>", unsafe_allow_html=True)
        else:
            for log in st.session_state.logs:
                css_class = "log-error" if log["is_error"] else ""
                st.markdown(
                    f"<div class='log-entry {css_class}'>"
                    f"<span class='log-timestamp'>[{log['timestamp']}]</span> {log['message']}"
                    f"</div>", 
                    unsafe_allow_html=True
                )
        
        st.markdown("</div>", unsafe_allow_html=True)

# Footer
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<p class='small-info'>Cloudflare DNS Updater • Inspired by PowerShell Scripts</p>", unsafe_allow_html=True)
