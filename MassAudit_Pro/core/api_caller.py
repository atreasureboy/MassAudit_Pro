
import os
import logging
from openai import OpenAI, APIStatusError, APIConnectionError, APITimeoutError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# Import constants from the config file
from MassAudit_Pro.config import (
    API_KEY,
    API_BASE,
    MAX_API_ERROR_COUNT,
    PROJECT_API_CALL_COUNTS
)

class APICaller:
    """
    封装DeepSeek API调用逻辑，集成tenacity进行指数退避重试，处理API错误和全局熔断。
    """
    _consecutive_api_errors = 0
    _circuit_breaker_tripped = False

    def __init__(self, api_key: str, api_base: str):
        """
        初始化APICaller，设置DeepSeek API客户端。
        :param api_key: DeepSeek API Key
        :param api_base: DeepSeek API Base URL
        """
        self.client = OpenAI(
            api_key=api_key,
            base_url=api_base
        )
        self.api_key = api_key
        self.api_base = api_base
        logging.info("APICaller initialized with DeepSeek API.")

    @retry(
        wait=wait_exponential(multiplier=1, min=4, max=10), # 指数退避，等待时间从4秒开始，最大10秒
        stop=stop_after_attempt(5), # 最多重试5次
        retry=retry_if_exception_type((APIConnectionError, APITimeoutError, APIStatusError)), # 仅对连接、超时或状态错误重试
        before_sleep=lambda retry_state: logging.warning(
            f"API call failed ({retry_state.outcome.exception()}), retrying... (attempt {retry_state.attempt_number})"
        )
    )
    def _call_deepseek_api(self, messages: list, model: str = "deepseek-chat", max_tokens: int = 2048, response_format: dict = {"type": "json_object"}):
        """
        实际调用DeepSeek Chat Completion API的方法，受tenacity装饰器保护。
        """
        if APICaller._circuit_breaker_tripped:
            logging.error("Circuit breaker tripped. Skipping API call.")
            raise RuntimeError("API Circuit Breaker Tripped")

        logging.debug(f"Calling DeepSeek API with model: {model}, messages: {messages[:1]}")
        try:
            response = self.client.chat.completions.create(
                model=model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=0.7,
                response_format=response_format
            )
            # 如果成功，重置连续错误计数
            APICaller._consecutive_api_errors = 0
            return response.choices[0].message.content
        except (APIConnectionError, APITimeoutError, APIStatusError) as e:
            APICaller._consecutive_api_errors += 1
            logging.error(f"DeepSeek API error: {e}. Consecutive errors: {APICaller._consecutive_api_errors}")
            if APICaller._consecutive_api_errors >= MAX_API_ERROR_COUNT:
                APICaller._circuit_breaker_tripped = True
                logging.critical(f"Consecutive API errors reached {MAX_API_ERROR_COUNT}. Circuit breaker tripped. Terminating further API calls.")
            raise # 重新抛出异常，让tenacity捕获并重试
        except Exception as e:
            logging.error(f"An unexpected error occurred during API call: {e}")
            APICaller._consecutive_api_errors += 1
            if APICaller._consecutive_api_errors >= MAX_API_ERROR_COUNT:
                APICaller._circuit_breaker_tripped = True
                logging.critical(f"Consecutive API errors reached {MAX_API_ERROR_COUNT}. Circuit breaker tripped. Terminating further API calls.")
            raise

    def call_llm(self, messages: list, model: str = "deepseek-chat", max_tokens: int = 2048, response_format: dict = {"type": "json_object"}):
        """
        公共方法，用于调用LLM，会触发重试和熔断逻辑。
        :param messages: 聊天消息列表
        :param model: 使用的LLM模型
        :param max_tokens: 最大生成tokens
        :param response_format: 响应格式，默认为JSON对象
        :return: LLM的响应内容
        :raises RuntimeError: 如果熔断器被触发
        """
        if APICaller._circuit_breaker_tripped:
            logging.error("Attempted to call LLM while circuit breaker is tripped.")
            raise RuntimeError("API Circuit Breaker Tripped: Cannot make further API calls.")

        try:
            return self._call_deepseek_api(messages, model, max_tokens, response_format)
        except Exception as e:
            logging.error(f"Failed to call LLM after retries or due to critical error: {e}")
            raise
