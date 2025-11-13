# OpenAI API Key Integration Guide

This guide shows you how to integrate your OpenAI API key with the Knowledge Fusion module.

## Method 1: Environment Variable (Recommended for Production)

### Windows (PowerShell)
```powershell
# Set for current session
$env:OPENAI_API_KEY = "sk-your-api-key-here"

# Set permanently (User-level)
[System.Environment]::SetEnvironmentVariable('OPENAI_API_KEY', 'sk-your-api-key-here', 'User')
```

### Windows (Command Prompt)
```cmd
# Set for current session
set OPENAI_API_KEY=sk-your-api-key-here

# Set permanently (requires admin or use GUI)
setx OPENAI_API_KEY "sk-your-api-key-here"
```

### Linux/Mac (Bash)
```bash
# Set for current session
export OPENAI_API_KEY="sk-your-api-key-here"

# Set permanently (add to ~/.bashrc or ~/.zshrc)
echo 'export OPENAI_API_KEY="sk-your-api-key-here"' >> ~/.bashrc
source ~/.bashrc
```

## Method 2: .env File (Recommended for Development)

1. Create a `.env` file in the project root:

```bash
# .env file
OPENAI_API_KEY=sk-your-api-key-here
LLM_PROVIDER=openai
LLM_MODEL=gpt-3.5-turbo
LLM_TEMPERATURE=0.3
LLM_MAX_TOKENS=1000
```

2. The module automatically loads `.env` files using `python-dotenv` (already in requirements.txt).

**Note**: Add `.env` to your `.gitignore` to keep your API key secure!

## Method 3: Direct Configuration in Code

You can also configure it directly in your code:

```python
from knowledge_fusion.config import LLMConfig
from knowledge_fusion.rag_pipeline import LLMProvider, RAGPipeline

# Create custom LLM config
llm_config = LLMConfig(
    provider="openai",
    model_name="gpt-3.5-turbo",
    api_key="sk-your-api-key-here",
    temperature=0.3,
    max_tokens=1000
)

# Use it in RAG pipeline
llm_provider = LLMProvider(config=llm_config)
rag_pipeline = RAGPipeline(llm_provider=llm_provider)
```

## Method 4: Configuration File (Alternative)

You could also create a config file (not recommended for API keys, but shown for completeness):

```python
# config.json (DO NOT COMMIT THIS FILE!)
{
    "llm": {
        "provider": "openai",
        "model_name": "gpt-3.5-turbo",
        "api_key": "sk-your-api-key-here",
        "temperature": 0.3,
        "max_tokens": 1000
    }
}
```

## Verification

Test that your API key is configured correctly:

```python
# test_openai_key.py
import os
from knowledge_fusion.rag_pipeline import LLMProvider

# Check if API key is set
api_key = os.getenv("OPENAI_API_KEY")
if api_key:
    print(f"[OK] OpenAI API key found: {api_key[:10]}...")
    
    # Test initialization
    try:
        llm_provider = LLMProvider()
        print("[OK] LLM Provider initialized successfully!")
    except Exception as e:
        print(f"[ERROR] Failed to initialize: {e}")
else:
    print("[ERROR] OPENAI_API_KEY not set!")
```

## Quick Start Example

```python
from knowledge_fusion.fusion_core import KnowledgeFusion
from knowledge_fusion.rag_pipeline import RAGPipeline
from knowledge_fusion.agent_interface import AgentInterface
from datetime import datetime

# Your API key should be set via environment variable or .env file
# The module will automatically use it

# Create agent output
agent_interface = AgentInterface()
agent_data = {
    "agent_id": "router",
    "timestamp": datetime.now(),
    "observations": [{
        "type": "network",
        "description": "Suspicious connection detected",
        "indicators": ["192.168.1.100"],
        "severity": "high"
    }],
    "confidence": 0.85
}

agent_output = agent_interface.normalize_agent_output(agent_data)

# Run fusion (will use OpenAI if API key is set)
knowledge_fusion = KnowledgeFusion()
enriched = knowledge_fusion.fuse([agent_output])

# Enhance with RAG (requires OpenAI API key)
rag_pipeline = RAGPipeline()
enhanced = rag_pipeline.enhance_with_rag(enriched)

print(enhanced.threat_context)
```

## Troubleshooting

### "OpenAI API key not found"
- Verify the environment variable is set: `echo $OPENAI_API_KEY` (Linux/Mac) or `echo %OPENAI_API_KEY%` (Windows)
- Check your `.env` file is in the project root
- Restart your terminal/IDE after setting environment variables

### "API key invalid"
- Verify your API key starts with `sk-`
- Check your OpenAI account has credits/billing set up
- Ensure the API key hasn't been revoked

### Fallback Mode
If the API key is not found or LLM fails, the module automatically uses a structured fallback summary. Check the `attribution["rag_generated"]` field to see if LLM was used.

## Security Best Practices

1. **Never commit API keys to git**
   - Add `.env` to `.gitignore`
   - Use environment variables in production
   - Use secrets management tools for deployment

2. **Rotate keys regularly**
   - Generate new keys in OpenAI dashboard
   - Update environment variables
   - Revoke old keys

3. **Use least privilege**
   - Only grant necessary permissions to API keys
   - Monitor API usage in OpenAI dashboard


