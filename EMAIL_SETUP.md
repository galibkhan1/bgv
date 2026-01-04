# Free Email Service Setup Guide

## Option 1: Brevo (Recommended - 300 emails/day FREE)

### Steps to Setup:

1. **Sign up for free account:**
   - Go to: https://www.brevo.com/
   - Click "Sign up free"
   - Complete registration with your email

2. **Get your API Key:**
   - After login, go to: https://app.brevo.com/settings/keys/api
   - Click "Generate a new API key"
   - Give it a name (e.g., "Verification Portal")
   - Copy the API key

3. **Configure in .env file:**
   ```
   BREVO_API_KEY=your-api-key-here
   SENDER_EMAIL=your-email@example.com
   SENDER_NAME=Verification Portal
   ```

4. **Verify sender email:**
   - Go to: https://app.brevo.com/senders
   - Add and verify your sender email address
   - Follow the verification link sent to your email

### Features:
- ✅ 300 emails per day FREE forever
- ✅ No credit card required
- ✅ Professional email delivery
- ✅ Easy to setup (5 minutes)

---

## Option 2: Without Email Service (Console/Terminal Only)

If you don't want to setup email service right now:

1. **Keep default configuration:**
   ```
   BREVO_API_KEY=your-brevo-api-key-here
   ```

2. **How it works:**
   - User enters email and clicks "Generate OTP"
   - OTP is displayed in the console/terminal window
   - User copies OTP from console and enters it
   - Works for testing and development

---

## Current Setup Status

Your application will work immediately in **console mode** without any email configuration.

To enable real email delivery, just follow Option 1 above.

---

## Testing

1. Run the application:
   ```bash
   python app.py
   ```

2. Open browser: http://127.0.0.1:1000/login

3. Enter ANY valid email address

4. Check console for OTP (or email if configured)

5. Enter OTP and access portal

---

## Security Notes

- OTPs are valid for 5 minutes
- Maximum 3 attempts per OTP
- Any valid email can access (add restrictions if needed)
- For production, consider:
  - Rate limiting
  - Email whitelist/blacklist
  - Database for OTP storage
  - Redis for better performance
