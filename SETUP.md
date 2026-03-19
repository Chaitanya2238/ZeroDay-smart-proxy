# Setup Guide - API Keys & Environment Variables

## Getting Started with Gemini API

### 1. Get Your API Key

- Visit [Google AI Studio](https://aistudio.google.com/)
- Click "Get API Key" in the top menu
- Create a new API key
- Copy the key

### 2. Set Environment Variable (Choose One Method)

#### Method A: PowerShell (Temporary)

```powershell
$env:GOOGLE_API_KEY = 'your-api-key-here'
```

#### Method B: PowerShell (Permanent)

```powershell
[Environment]::SetEnvironmentVariable('GOOGLE_API_KEY', 'your-api-key-here', 'User')
```

#### Method C: Create .env file (Recommended for Development)

1. Copy `.env.example` to `.env`:

   ```powershell
   Copy-Item .env.example .env
   ```

2. Edit `.env` and add your API key:

   ```
   GOOGLE_API_KEY=your-api-key-here
   ```

3. Load environment from .env using python-dotenv:
   ```python
   from dotenv import load_dotenv
   load_dotenv()
   ```

### 3. Verify Setup

```bash
python tests/test_api_key.py
```

Expected output:

```
✅ API Key is valid!
   Available models:
   - models/gemini-2.5-flash
   - models/gemini-2.0-flash
   ...
```

## Running Tests

All tests are in the `tests/` folder:

```bash
# Make sure GOOGLE_API_KEY is set first

# Test Tier 1 Rules
python tests/test_tier1_rules.py

# Test Tier 2 AI Engine (mock mode)
python tests/test_tier2_ai_engine.py

# Test full analyzer pipeline
python tests/test_analyzer_full.py

# Verify API key validity
python tests/test_api_key.py

# Test Gemini integration
python tests/test_gemini_integration.py
```

## Security Notes

⚠️ **IMPORTANT**:

- **Never** commit API keys to GitHub
- **Never** share your API keys in messages or pull requests
- Always use environment variables or `.env` files (which are gitignored)
- If you accidentally expose a key, regenerate it immediately
- Use `.env.example` to show what variables are needed

## File Structure

```
smart-proxy/
├── .env                 ← Your API keys (IGNORED by git)
├── .env.example         ← Template showing what keys you need
├── .gitignore          ← Prevents .env from being committed
├── phase2/
│   ├── ai_engine.py
│   ├── rules.py
│   ├── analyzer.py
│   └── requirements.txt
└── tests/
    ├── test_tier1_rules.py
    ├── test_tier2_ai_engine.py
    ├── test_analyzer_full.py
    ├── test_api_key.py
    └── test_gemini_integration.py
```

## Troubleshooting

### "GOOGLE_API_KEY not found" error

- Make sure environment variable is set: `$env:GOOGLE_API_KEY`
- Or create `.env` file with the key
- Restart your terminal/IDE after setting environment variables

### "API key is invalid" error

- Verify API key is correct
- Check it hasn't been regenerated in Google AI Studio
- Ensure there are no extra spaces in the key

### Rate limit error (429)

- Free tier has 60 requests/minute limit
- Wait a minute before running tests again
- Consider upgrading to paid tier if you need higher limits

## Additional Resources

- [Google Generative AI API Docs](https://ai.google.dev/)
- [Gemini Models](https://ai.google.dev/models/)
- [Free Tier Limits](https://ai.google.dev/pricing)
