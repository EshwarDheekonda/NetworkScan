"""
Test script to verify OpenAI API key configuration.
Run this after setting up your API key to verify it works.
"""

import os
from knowledge_fusion.rag_pipeline import LLMProvider, RAGPipeline
from knowledge_fusion.config import get_config

print("=" * 60)
print("OpenAI API Key Configuration Test")
print("=" * 60)

# Check environment variable
api_key = os.getenv("OPENAI_API_KEY")
if api_key:
    masked_key = api_key[:7] + "..." + api_key[-4:] if len(api_key) > 11 else "***"
    print(f"\n[OK] OPENAI_API_KEY found: {masked_key}")
else:
    print("\n[WARNING] OPENAI_API_KEY environment variable not set")
    print("  Set it using one of these methods:")
    print("  1. Environment variable: set OPENAI_API_KEY=sk-your-key")
    print("  2. .env file: Create .env in project root with OPENAI_API_KEY=sk-your-key")
    print("  3. Direct config: Pass api_key to LLMConfig")
    print("\n  See knowledge_fusion/SETUP_OPENAI.md for detailed instructions")

# Check config
try:
    config = get_config()
    llm_config = config.llm
    
    print(f"\n[Config] LLM Provider: {llm_config.provider}")
    print(f"[Config] Model: {llm_config.model_name}")
    print(f"[Config] Temperature: {llm_config.temperature}")
    
    if llm_config.api_key:
        masked = llm_config.api_key[:7] + "..." + llm_config.api_key[-4:] if len(llm_config.api_key) > 11 else "***"
        print(f"[Config] API Key: {masked} (from config)")
    elif api_key:
        print(f"[Config] API Key: Will use environment variable")
    else:
        print(f"[Config] API Key: NOT SET")
    
except Exception as e:
    print(f"\n[ERROR] Failed to load config: {e}")

# Test LLM Provider initialization
print("\n" + "-" * 60)
print("Testing LLM Provider Initialization...")
print("-" * 60)

try:
    llm_provider = LLMProvider()
    print("[OK] LLM Provider initialized successfully!")
    print(f"[OK] Provider: {llm_provider.config.provider}")
    print(f"[OK] Model: {llm_provider.config.model_name}")
    
    # Test a simple generation
    print("\nTesting LLM generation...")
    try:
        response = llm_provider.generate(
            "Say 'OpenAI integration successful' in one sentence.",
            system_message="You are a helpful assistant.",
            max_retries=1
        )
        print(f"[OK] LLM response received: {response[:100]}...")
        print("\n[SUCCESS] OpenAI API key is working correctly!")
    except Exception as e:
        print(f"[WARNING] LLM generation test failed: {e}")
        print("  This might be due to:")
        print("  - Invalid API key")
        print("  - Network issues")
        print("  - API rate limits")
        print("  - Account billing issues")
        
except ValueError as e:
    if "API key not found" in str(e):
        print(f"[ERROR] {e}")
        print("\nTo fix this:")
        print("  1. Get your API key from: https://platform.openai.com/api-keys")
        print("  2. Set it as environment variable:")
        print("     Windows: set OPENAI_API_KEY=sk-your-key")
        print("     Linux/Mac: export OPENAI_API_KEY=sk-your-key")
        print("  3. Or create a .env file with: OPENAI_API_KEY=sk-your-key")
    else:
        print(f"[ERROR] Initialization failed: {e}")
except Exception as e:
    print(f"[ERROR] Unexpected error: {e}")

print("\n" + "=" * 60)
print("Test Complete")
print("=" * 60)



