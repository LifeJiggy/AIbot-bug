import os
import asyncio
import json
import requests
import google.generativeai as genai
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
import colorama
from colorama import Fore, Style

# Initialize colorama
colorama.init()

load_dotenv()

class AIProvider:
    def __init__(self, api_key: str, model_name: str):
        self.api_key = api_key
        self.model_name = model_name
    async def generate_content(self, prompt: str, context: Optional[str] = None) -> str:
        raise NotImplementedError

class GeminiProvider(AIProvider):
    def __init__(self, api_key: str, model_name: str = 'gemini-2.0-flash-exp'):
        super().__init__(api_key, model_name)
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model_name)
    async def generate_content(self, prompt: str, context: Optional[str] = None) -> str:
        full_prompt = f"{context}\n\n{prompt}" if context else prompt
        try:
            response = await asyncio.to_thread(self.model.generate_content, full_prompt)
            return response.text
        except Exception as e: return f"Gemini Error: {e}"

class OpenAICompatibleProvider(AIProvider):
    def __init__(self, api_key: str, model_name: str, url: str):
        super().__init__(api_key, model_name)
        self.url = url
    async def generate_content(self, prompt: str, context: Optional[str] = None) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        messages = [{"role": "system", "content": context}] if context else []
        messages.append({"role": "user", "content": prompt})
        data = {"model": self.model_name, "messages": messages, "max_tokens": 2048}
        try:
            response = await asyncio.to_thread(requests.post, self.url, headers=headers, json=data)
            res_json = response.json()
            if 'choices' in res_json:
                return res_json['choices'][0]['message']['content']
            return f"API Error: {res_json}"
        except Exception as e: return f"Error: {e}"

class ClaudeProvider(AIProvider):
    def __init__(self, api_key: str, model_name: str = 'claude-3-5-sonnet-20241022'):
        super().__init__(api_key, model_name)
        self.url = "https://api.anthropic.com/v1/messages"
    async def generate_content(self, prompt: str, context: Optional[str] = None) -> str:
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"}
        data = {"model": self.model_name, "system": context if context else "", "messages": [{"role": "user", "content": prompt}], "max_tokens": 2048}
        try:
            response = await asyncio.to_thread(requests.post, self.url, headers=headers, json=data)
            return response.json()['content'][0]['text']
        except Exception as e: return f"Claude Error: {e}"

class AIManager:
    def __init__(self):
        self.providers = {}
        self.current_provider = 'gemini'
        self.available_models = {
            'gemini': [
                'gemini-2.0-flash-exp', 'gemini-1.5-pro-002', 'gemini-1.5-flash-002', 
                'gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-1.0-pro', 
                'gemini-pro-vision', 'gemini-2.0-pro-exp', 'gemini-ultra'
            ],
            'openai': [
                'o1-preview', 'o1-mini', 'gpt-4o', 'gpt-4o-2024-08-06', 
                'gpt-4-turbo', 'gpt-4', 'gpt-3.5-turbo', 'gpt-3.5-turbo-16k', 'gpt-4o-mini'
            ],
            'claude': [
                'claude-3-5-sonnet-20241022', 'claude-3-5-haiku-20241022', 'claude-3-opus-20240229', 
                'claude-3-sonnet-20240229', 'claude-3-haiku-20240307', 'claude-2.1', 
                'claude-2.0', 'claude-instant-1.2', 'claude-3-5-sonnet-latest'
            ],
            'xai': [
                'grok-2', 'grok-2-mini', 'grok-2-1212', 'grok-beta', 
                'grok-1', 'grok-1.5', 'grok-1.5-vision', 'grok-2-preview', 'grok-mini'
            ],
            'groq': [
                'llama-3.3-70b-versatile', 'llama-3.1-70b-versatile', 'llama-3.1-8b-instant', 
                'mixtral-8x7b-32768', 'gemma2-9b-it', 'llama3-70b-8192', 
                'llama3-8b-8192', 'distil-whisper-large-v3-en', 'llama-guard-3-8b'
            ],
            'deepseek': [
                'deepseek-v3', 'deepseek-chat', 'deepseek-coder', 'deepseek-reasoner',
                'deepseek-v2', 'deepseek-v2.5', 'deepseek-moe', 'deepseek-llm-67b', 'deepseek-coder-33b'
            ],
            'mistral': [
                'pixtral-large-latest', 'mistral-large-latest', 'mistral-medium-latest', 
                'mistral-small-latest', 'codestral-latest', 'open-mistral-7b', 
                'open-mixtral-8x7b', 'open-mixtral-8x22b', 'mistral-embed'
            ],
            'huggingface': [
                'meta-llama/Llama-3.3-70B-Instruct', 'Qwen/Qwen2.5-72B-Instruct', 'mistralai/Mistral-7B-Instruct-v0.3',
                'microsoft/phi-4', 'google/gemma-2-27b-it', '01-ai/Yi-1.5-34B-Chat',
                'meta-llama/Llama-3.2-11B-Vision-Instruct', 'deepseek-ai/DeepSeek-V2.5', 'HuggingFaceH4/zephyr-7b-beta'
            ],
            'qwen': [
                'qwen-max-2024-11-19', 'qwen-plus', 'qwen-turbo', 'qwen-long', 
                'qwen-vl-max', 'qwen-vl-plus', 'qwen-audio-turbo', 'qwen-math-max', 'qwen-coder-plus'
            ],
            'moonshot': [
                'moonshot-v1-8k', 'moonshot-v1-32k', 'moonshot-v1-128k', 'moonshot-v1-auto', 
                'moonshot-v1-8k-vision', 'moonshot-v1-32k-vision', 'moonshot-v1-128k-vision', 
                'moonshot-v1-deep-insight', 'moonshot-v1-ultra'
            ],
            'perplexity': [
                'llama-3.1-sonar-huge-128k-online', 'llama-3.1-sonar-large-128k-online', 'llama-3.1-sonar-small-128k-online', 
                'llama-3.1-sonar-huge-128k-chat', 'llama-3.1-sonar-large-128k-chat', 'llama-3.1-sonar-small-128k-chat',
                'mixtral-8x7b-instruct', 'llama-3-8b-instruct', 'llama-3-70b-instruct'
            ],
            'openrouter': [
                'anthropic/claude-3.5-sonnet', 'google/gemini-pro-1.5', 'openai/gpt-4o', 
                'meta-llama/llama-3.1-405b', 'mistralai/mistral-large', 'google/palm-2-chat-bison',
                'gryphe/mythomax-l2-13b', 'nousresearch/nous-hermes-2-mixtral-8x7b-dpo', 'openrouter/auto'
            ],
            'cohere': [
                'command-r-plus-08-2024', 'command-r-08-2024', 'command-light', 
                'command-nightly', 'command-r-plus', 'command-r', 'embed-english-v3.0', 
                'embed-multilingual-v3.0', 'rerank-english-v3.0'
            ]
        }

        self.env_map = {
            'gemini': ('GEMINI_API_KEY', lambda k, m: GeminiProvider(k, m)),
            'openai': ('OPENAI_API_KEY', lambda k, m: OpenAICompatibleProvider(k, m, "https://api.openai.com/v1/chat/completions")),
            'claude': ('ANTHROPIC_API_KEY', lambda k, m: ClaudeProvider(k, m)),
            'xai': ('XAI_API_KEY', lambda k, m: OpenAICompatibleProvider(k, m, "https://api.x.ai/v1/chat/completions")),
            'groq': ('GROQ_API_KEY', lambda k, m: OpenAICompatibleProvider(k, m, "https://api.groq.com/openai/v1/chat/completions")),
            'deepseek': ('DEEPSEEK_API_KEY', lambda k, m: OpenAICompatibleProvider(k, m, "https://api.deepseek.com/v1/chat/completions")),
            'mistral': ('MISTRAL_API_KEY', lambda k, m: OpenAICompatibleProvider(k, m, "https://api.mistral.ai/v1/chat/completions")),
            'huggingface': ('HUGGINGFACE_API_KEY', lambda k, m: OpenAICompatibleProvider(k, m, "https://api-inference.huggingface.co/v1/chat/completions")),
            'qwen': ('QWEN_API_KEY', lambda k, m: OpenAICompatibleProvider(k, m, "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions")),
            'moonshot': ('MOONSHOT_API_KEY', lambda k, m: OpenAICompatibleProvider(k, m, "https://api.moonshot.cn/v1/chat/completions")),
            'perplexity': ('PERPLEXITY_API_KEY', lambda k, m: OpenAICompatibleProvider(k, m, "https://api.perplexity.ai/chat/completions")),
            'openrouter': ('OPENROUTER_API_KEY', lambda k, m: OpenAICompatibleProvider(k, m, "https://openrouter.ai/api/v1/chat/completions")),
            'cohere': ('COHERE_API_KEY', lambda k, m: OpenAICompatibleProvider(k, m, "https://api.cohere.ai/v1/chat"))
        }
        self._initialize_providers()

    def _initialize_providers(self):
        for name, (env_var, init_fn) in self.env_map.items():
            key = os.environ.get(env_var)
            if key:
                self.providers[name] = init_fn(key, self.available_models[name][0])

    def get_all_provider_names(self) -> List[str]:
        return list(self.available_models.keys())
    def get_available_providers(self) -> List[str]:
        return list(self.providers.keys())
    def setup_provider_manually(self, name: str, api_key: str):
        if name in self.env_map:
            init_fn = self.env_map[name][1]
            self.providers[name] = init_fn(api_key, self.available_models[name][0])
            self.current_provider = name
            return True
        return False
    def get_models_for_provider(self, provider: str) -> List[str]:
        return self.available_models.get(provider, [])
    def set_provider(self, name: str, model_name: Optional[str] = None):
        if name in self.providers:
            self.current_provider = name
            if model_name:
                self.providers[name].model_name = model_name
                if name == 'gemini':
                    self.providers[name].model = genai.GenerativeModel(model_name)
            return True
        return False
    async def analyze(self, prompt: str, provider_name: Optional[str] = None, context: Optional[str] = None) -> str:
        name = provider_name or self.current_provider
        available = self.get_available_providers()
        
        if not available:
            return "Error: No AI providers configured (Check .env or manual setup)."

        # Try the selected/current provider first
        providers_to_try = [name] + [p for p in available if p != name]
        
        for p_name in providers_to_try:
            provider = self.providers.get(p_name)
            if not provider: continue
            
            try:
                response = await provider.generate_content(prompt, context)
                if any(k in response for k in ["Quota exceeded", "429", "402", "credits"]):
                    print(Fore.YELLOW + f"[AI Monitor] {p_name.capitalize()} quota or credit issue. Rotating provider..." + Style.RESET_ALL)
                    continue
                return response
            except Exception as e:
                if "429" in str(e):
                    print(Fore.YELLOW + f"[AI Monitor] {p_name.capitalize()} ratelimit hit. Rotating..." + Style.RESET_ALL)
                    continue
                return f"AI Error ({p_name}): {e}"
        
        return "Critical Error: All AI providers hit quota or failed. Please wait or check keys."

