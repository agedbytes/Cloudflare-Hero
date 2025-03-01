import streamlit as st
import requests
import ipaddress
import datetime
import traceback
import json

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

# Initialize session state
if 'logs' not in st.session_state:
    st.session_state.logs = []

# Function to add log entries
def add_log(message, is_error=False):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    entry = {
        "timestamp": timestamp,
        "message": message,
        "is_error": is_error
    }
    st.session_state.logs.append(entry)

# Function to validate IP address
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Function to get user's public IP address with multiple fallbacks
def get_public_ip():
    ip_services = [
        {
            "url": "https://api.ipify.org?format=json",
            "parser": lambda resp: resp.json().get("ip")
        },
        {
            "url": "https://api.myip.com",
            "parser": lambda resp: resp.json().get("ip")
        },
        {
            "url": "https://ipinfo.io/json",
            "parser": lambda resp: resp.json().get("ip")
        },
        {
            "url": "https://checkip.amazonaws.com",
            "parser": lambda resp: resp.text.strip()
        },
        {
            "url": "https://icanhazip.com",
            "parser": lambda resp: resp.text.strip()
        },
        {
            "url": "https://ifconfig.me/ip",
            "parser": lambda resp: resp.text.strip()
        }
    ]
    
    for service in ip_services:
        try:
            response = requests.get(service["url"], timeout=3)
            if response.status_code == 200:
                ip = service["parser"](response)
                if ip and is_valid_ip(ip):
                    return ip
        except:
            continue
    
    return None

# Function to get DNS record info from Cloudflare
def get_dns_record_info(zone_id, dns_record, api_token):
    try:
        add_log(f"Getting DNS record info for {dns_record}...")
        add_log(f"Fetching DNS record info for {dns_record}...")
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={dns_record}"
        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(url, headers=headers)
        data = response.json()
        
        add_log(f"Response from Cloudflare: {data}")
        
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
        add_log(f"Exception when fetching DNS record info: {str(e)}", True)
        add_log(traceback.format_exc(), True)
        return None

# Function to update DNS record
def update_dns_record(zone_id, record_id, dns_record, ip, ttl, proxied, api_token):
    try:
        add_log(f"Updating DNS record {dns_record} to {ip}...")
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
        
        add_log(f"Sending update request with body: {body}")
        
        response = requests.put(url, headers=headers, json=body)
        data = response.json()
        
        add_log(f"Response from Cloudflare: {data}")
        
        if not data.get("success"):
            error_msg = "Unknown error"
            if data.get("errors") and len(data["errors"]) > 0:
                error_msg = data["errors"][0].get("message", "Unknown error")
            add_log(f"Error updating DNS record: {error_msg}", True)
            return False
        
        add_log(f"Successfully updated {dns_record} to {ip}")
        return True
    except Exception as e:
        add_log(f"Exception when updating DNS record: {str(e)}", True)
        add_log(traceback.format_exc(), True)
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

# Function to perform the DNS update
def update_dns():
    # Get form values
    ip_address = st.session_state.ip_address
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
    
    # Clear logs
    st.session_state.logs = []
    st.session_state.update_status = None
    
    # Validate inputs
    if not dns_record or not zone_id or not api_token:
        add_log("Error: DNS Record, Zone ID, and API Token are required", True)
        st.session_state.update_status = "error"
        return
    
    if not ip_address:
        add_log("Error: IP Address is required", True)
        st.session_state.update_status = "error"
        return
    
    if not is_valid_ip(ip_address):
        add_log(f"Error: '{ip_address}' is not a valid IP address", True)
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
    
    # Get DNS record info
    record_info = get_dns_record_info(zone_id, dns_record, api_token)
    
    if not record_info:
        add_log(f"Failed to get DNS record info for {dns_record}", True)
        st.session_state.update_status = "error"
        return
    
    # Check if update is needed
    if record_info["content"] == ip_address and record_info["proxied"] == proxied:
        add_log(f"DNS record IP of {dns_record} is already {ip_address} with proxied={proxied}, no changes needed.")
        st.session_state.update_status = "unchanged"
        return
    
    # Update DNS record
    update_success = update_dns_record(
        zone_id, 
        record_info["id"], 
        dns_record, 
        ip_address, 
        ttl, 
        proxied, 
        api_token
    )
    
    if not update_success:
        add_log("Failed to update DNS record", True)
        st.session_state.update_status = "error"
        return
    
    # Send notifications
    if notify_telegram and telegram_bot_token and telegram_chat_id:
        send_telegram_notification(
            telegram_bot_token,
            telegram_chat_id,
            dns_record,
            ip_address,
            record_info["content"]
        )
    
    if notify_discord and discord_webhook_url:
        send_discord_notification(
            discord_webhook_url,
            dns_record,
            ip_address,
            record_info["content"]
        )
    
    st.session_state.update_status = "success"

# Function to load sample data
def load_sample_data():
    st.session_state.ip_address = "192.0.2.1"  # Example IP
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

# Function to copy logs to clipboard
def get_logs_text():
    logs_text = ""
    for log in st.session_state.logs:
        prefix = "ERROR: " if log["is_error"] else ""
        logs_text += f"[{log['timestamp']}] {prefix}{log['message']}\n"
    return logs_text

# Attempt to get the user's IP at the start (this happens server-side)
server_detected_ip = get_public_ip()

# Main app layout
st.markdown("<h1 class='main-header'>Cloudflare DNS Updater</h1>", unsafe_allow_html=True)

# Create two columns for the layout
col1, col2 = st.columns([2, 1])

with col1:
    # DNS Configuration Form
    st.markdown("<h2 class='section-header'>DNS Configuration</h2>", unsafe_allow_html=True)
    
    # IP Address Section
    ip_col1, ip_col2 = st.columns([3, 1])
    
    with ip_col1:
        # IP Address Input field
        if server_detected_ip:
            ip_placeholder = server_detected_ip
            ip_help = f"Detected IP: {server_detected_ip} (server-side detection)"
        else:
            ip_placeholder = "Enter your IP address"
            ip_help = "Enter the IP address you want to use for the DNS record"
            
        st.text_input(
            "IP Address",
            placeholder=ip_placeholder,
            help=ip_help,
            key="ip_address"
        )
    
    with ip_col2:
        # Only show the button if we actually detected an IP
        if server_detected_ip:
            if st.button("Use Detected IP"):
                st.session_state.ip_address = server_detected_ip
                st.rerun()
    
    # Client-side IP detection with JavaScript
    st.markdown("### Detect Your IP Address (Client-side)")
    st.markdown("""
    <div id="ip-display">Loading your IP address...</div>
    <script>
        async function getIp() {
            try {
                // Try multiple services
                const services = [
                    'https://api.ipify.org?format=json',
                    'https://api.my-ip.io/ip.json',
                    'https://api.db-ip.com/v2/free/self'
                ];
                
                for (const service of services) {
                    try {
                        const response = await fetch(service);
                        const data = await response.json();
                        // Different APIs return IP in different fields
                        return data.ip || data.ipAddress;
                    } catch (e) {
                        console.error("Error with service:", service, e);
                    }
                }
                return "Could not detect your IP";
            } catch (error) {
                return "Error detecting IP: " + error.message;
            }
        }
        
        // Update the display with IP address
        getIp().then(ip => {
            document.getElementById('ip-display').innerHTML = 
                'Your browser detected IP: <strong>' + ip + '</strong> ' +
                '<button onclick="useThisIp(\'' + ip + '\')">Use This IP</button>';
        });
        
        // Function to use the detected IP
        function useThisIp(ip) {
            // Find the IP input field and set its value
            const inputs = document.querySelectorAll('input');
            for (const input of inputs) {
                if (input.placeholder.includes("IP address")) {
                    input.value = ip;
                    // Trigger an input event to update Streamlit
                    const event = new Event('input', { bubbles: true });
                    input.dispatchEvent(event);
                    break;
                }
            }
        }
    </script>
    """, unsafe_allow_html=True)
    
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
            help="Enable Cloudflare's proxy features (not available for private IPs)",
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
        if 'update_status' in st.session_state:
            if st.session_state.update_status == "success":
                st.success("DNS record updated successfully!")
            elif st.session_state.update_status == "error":
                st.error("Error updating DNS record")
            elif st.session_state.update_status == "unchanged":
                st.info("No changes needed")
    
    # Display current settings
    st.markdown("#### Current Settings")
    
    settings_container = st.container()
    
    with settings_container:
        st.markdown(f"**DNS Record:** {st.session_state.get('dns_record', 'Not set')}")
        st.markdown(f"**IP Address:** {st.session_state.get('ip_address', 'Not set')}")
        
        ttl_display = st.session_state.get('ttl', 'Not set')
        if ttl_display == 1:
            ttl_display = "Auto (1)"
        st.markdown(f"**TTL:** {ttl_display} seconds")
        
        proxied_display = "Yes" if st.session_state.get('proxied', False) else "No"
        st.markdown(f"**Proxied:** {proxied_display}")
        
        notifications = []
        if st.session_state.get('notify_telegram', False):
            notifications.append("Telegram")
        if st.session_state.get('notify_discord', False):
            notifications.append("Discord")
        
        notifications_display = ", ".join(notifications) if notifications else "None"
        st.markdown(f"**Notifications:** {notifications_display}")
    
    # Logs Section
    st.markdown("<h2 class='section-header'>Logs</h2>", unsafe_allow_html=True)
    
    # Add a copy button for logs
    if st.button("Copy Logs to Clipboard"):
        logs_text = get_logs_text()
        st.code(logs_text, language=None)
        st.toast("Logs copied to clipboard (use the code block above)")
    
    log_container = st.container()
    
    with log_container:
        log_panel = st.empty()
        
        log_html = "<div class='log-container'>"
        
        if len(st.session_state.logs) == 0:
            log_html += "<div class='log-entry' style='color: #888;'>No logs yet. Start an update to see activity logs.</div>"
        else:
            for log in st.session_state.logs:
                css_class = "log-error" if log["is_error"] else ""
                log_html += f"<div class='log-entry {css_class}'><span class='log-timestamp'>[{log['timestamp']}]</span> {log['message']}</div>"
        
        log_html += "</div>"
        log_panel.markdown(log_html, unsafe_allow_html=True)

# Add helpful information in the sidebar
st.sidebar.title("Help & Information")

st.sidebar.markdown("### About This App")
st.sidebar.markdown("""
This app helps you update your Cloudflare DNS records with your current IP address.

It's perfect for maintaining access to home servers or services when your ISP changes your IP address.
""")

st.sidebar.markdown("---")
st.sidebar.markdown("### Troubleshooting")
st.sidebar.markdown("""
If you're experiencing issues:

1. Make sure your Cloudflare API token has the correct permissions (Zone:DNS:Edit)
2. Verify that the DNS record already exists in your Cloudflare account
3. Check that your Zone ID is correct
4. If you're using Cloudflare proxy, make sure the IP is publicly accessible
""")

# Footer
st.markdown("<hr>", unsafe_allow_html=True)
st.markdown("<p class='small-info'>Cloudflare DNS Updater • Inspired by PowerShell Scripts</p>", unsafe_allow_html=True)
