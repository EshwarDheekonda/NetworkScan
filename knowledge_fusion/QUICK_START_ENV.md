# Quick Start: Setting Up .env File

## Step 1: Create .env File

The `.env` file has been created in your project root. It contains placeholder values that you need to replace.

## Step 2: Required Values to Replace

### **CRITICAL: OpenAI API Key (Required for LLM features)**

1. Get your API key from: https://platform.openai.com/api-keys
2. Open the `.env` file
3. Find this line:
   ```
   OPENAI_API_KEY=sk-your-openai-api-key-here
   ```
4. Replace `sk-your-openai-api-key-here` with your actual API key:
   ```
   OPENAI_API_KEY=sk-proj-abc123xyz...
   ```

### **Optional: Neo4j Configuration**

If you're NOT using `cred.json` for Neo4j credentials, update:
```
NEO4J_PASSWORD=your_neo4j_password_here
```

## Step 3: Verify Configuration

Run the test script:
```bash
python test_openai_setup.py
```

This will verify your API key is configured correctly.

## What Gets Loaded

The module automatically loads these environment variables:
- `OPENAI_API_KEY` - **REQUIRED** for LLM features
- `LLM_PROVIDER` - Default: openai
- `LLM_MODEL` - Default: gpt-3.5-turbo
- `LLM_TEMPERATURE` - Default: 0.3
- `LLM_MAX_TOKENS` - Default: 1000
- `NEO4J_URI` - Default: bolt://localhost:7687

## Security Note

✅ The `.env` file is already in `.gitignore` - your API key will NOT be committed to git.

⚠️ **Never commit your actual API key to version control!**



