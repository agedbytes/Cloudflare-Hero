import streamlit as st
import requests
import ipaddress
import datetime
import json

# Set page configuration
st.set_page_config(
    page_title="Cloudflare DNS Updater",
    page_icon="🌐",
    layout="wide",
)

# Initialize session state for logs and update status
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
        add_log(f"Getting DNS record info for {dns_record}...")
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
        add_log(f"Exception when fetching DNS record info: {str(e)}", True)
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

# Function to format logs
def format_logs():
    logs_text = ""
    for log in st.session_state.logs:
        prefix = "ERROR: " if log["is_error"] else ""
        logs_text += f"[{log['timestamp']}] {prefix}{log['message']}\n"
    return logs_text

# Main app layout
st.title("Cloudflare DNS Updater")

# Create two columns for the layout
col1, col2 = st.columns([2, 1])

with col1:
    # Check your IP section
    st.subheader("Check Your Public IP")
    st.markdown("""
    To find your current public IP address, visit one of these sites:
    - [ipify.org](https://api.ipify.org)
    - [WhatIsMyIP.com](https://www.whatismyip.com/)
    - [icanhazip.com](https://icanhazip.com)
    """)
    
    # DNS Configuration Form
    st.subheader("DNS Configuration")
    
    # IP Address Input field
    st.text_input(
        "IP Address",
        placeholder="Enter your IP address",
        help="Enter the IP address you want to use for the DNS record",
        key="ip_address"
    )
    
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
    st.subheader("Notification Settings")
    
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
    st.subheader("Status")
    
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
    st.subheader("Current Settings")
    
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
    st.subheader("Logs")
    
    # Copy Logs button
    if st.button("Copy Logs"):
        st.session_state.copy_logs_requested = True
    
    # Execute clipboard copy when requested
    if st.session_state.get("copy_logs_requested", False):
        logs_text = format_logs()
        # Escape the text to safely pass it to JavaScript
        logs_text_escaped = json.dumps(logs_text)
        st.components.v1.html(
            f"""
            <script>
                navigator.clipboard.writeText({logs_text_escaped}).then(function() {{
                    console.log('Logs copied to clipboard');
                }}, function(err) {{
                    console.error('Could not copy logs: ', err);
                }});
            </script>
            """,
            height=0  # Hide the component visually
        )
        st.session_state.copy_logs_requested = False
        st.toast("Logs copied to clipboard!")
    
    # Logs display
    logs_placeholder = st.empty()
    
    # Update logs in the text area
    log_content = format_logs()
    if not log_content:
        log_content = "No logs yet. Start an update to see activity logs."
    
    logs_placeholder.text_area(
        label="",
        value=log_content,
        height=300,
        key="logs_display",
        disabled=True
    )

# Add helpful information in the sidebar
st.sidebar.title("Help & Information")

st.sidebar.subheader("About This App")
st.sidebar.markdown("""
This app helps you update your Cloudflare DNS records with your current IP address.

It's perfect for maintaining access to home servers or services when your ISP changes your IP address.
""")

st.sidebar.subheader("How to Find Your IP")
st.sidebar.markdown("""
Visit one of these sites to find your current public IP address:
- [ipify.org](https://api.ipify.org)
- [WhatIsMyIP.com](https://www.whatismyip.com/)
- [icanhazip.com](https://icanhazip.com)
""")

st.sidebar.subheader("Cloudflare Information")
st.sidebar.markdown("""
1. Log in to your Cloudflare dashboard
2. Go to your domain settings
3. Find your Zone ID at the bottom right
4. Create an API token with DNS:Edit permissions
""")
