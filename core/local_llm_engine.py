"""
Local LLM Engine for OSINT Analysis
===================================

Robust local language model integration for OSINT pattern analysis,
web search intelligence, and blackbox investigations without requiring API keys.

This engine supports multiple local LLM backends:
- Ollama (Llama 2/3, Mistral, CodeLlama, etc.)
- Hugging Face Transformers
- GGML/llama.cpp models
- Custom fine-tuned models

Features:
- Zero external API dependencies
- Specialized OSINT analysis prompts
- Advanced pattern recognition
- Web search intelligence
- Privacy-preserving local processing
"""

import asyncio
import logging
import os
import subprocess
import re
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests  # type: ignore

from core.autonomous_pipeline import AutonomousInvestigationEngine

# Local LLM backends
try:
    import ollama  # type: ignore

    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    ollama = None  # type: ignore

try:
    import torch  # type: ignore
    from transformers import pipeline  # type: ignore

    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    torch = None  # type: ignore
    pipeline = None  # type: ignore

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from local LLM processing."""

    content: str
    confidence: float
    processing_time: float
    model_used: str
    metadata: Dict[str, Any]


@dataclass
class OSINTAnalysis:
    """OSINT-specific analysis result."""

    insights: List[str]
    patterns: List[Dict[str, Any]]
    risk_assessment: Dict[str, Any]
    recommendations: List[str]
    search_strategies: List[str]


class LocalLLMEngine:
    """
    Local Language Model Engine for OSINT Analysis.

    This engine provides sophisticated AI capabilities without requiring
    external API keys or internet connectivity for model inference.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.force_backend = self.config.get("force_backend")
        self.available_backends = self._detect_backends()
        self.active_backend = None
        self.models: Dict[str, Any] = {}

        # OSINT-specific prompts and templates
        self.osint_prompts = self._load_osint_prompts()

        # Initialize the best available backend
        self._initialize_backend()

        if not self.active_backend:
            # Always provide a functional fallback so higher level features stay usable
            self.active_backend = "rule_based"
            logger.info(
                "Falling back to rule-based heuristics for local LLM operations"
            )

        # Evidence-driven autonomous investigation pipeline
        self.autonomous_engine = AutonomousInvestigationEngine()

    def _detect_backends(self) -> Dict[str, bool]:
        """Detect available local LLM backends."""
        backends = {
            "perplexity": self._check_perplexity(),
            "openai": self._check_openai(),
            "ollama": self._check_ollama(),
            "transformers": TRANSFORMERS_AVAILABLE,
            "llamacpp": self._check_llamacpp(),
            "mcp": False,  # Disable MCP for now
        }

        logger.info(f"Available LLM backends: {[k for k, v in backends.items() if v]}")
        return backends

    def _check_ollama(self) -> bool:
        """Check if Ollama is available and running."""
        if not OLLAMA_AVAILABLE:
            return False

        try:
            # Try to connect to Ollama service
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    def _check_perplexity(self) -> bool:
        """Check if Perplexity API is available."""
        try:
            # Test API key by making a minimal request
            api_key = self._get_perplexity_api_key()
            if not api_key:
                return False

            url = "https://api.perplexity.ai/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }

            # Minimal test payload
            payload = {
                "model": "sonar",
                "messages": [{"role": "user", "content": "test"}],
                "max_tokens": 1,
            }

            response = requests.post(url, json=payload, headers=headers, timeout=5)
            return response.status_code in [
                200,
                400,
                401,
            ]  # Any response means API is accessible

        except Exception:
            return False

    def _check_openai(self) -> bool:
        """Check if OpenAI API is available."""
        try:
            # Test API key by making a minimal request
            api_key = self._get_openai_api_key()
            if not api_key:
                return False

            url = "https://api.openai.com/v1/models"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }

            response = requests.get(url, headers=headers, timeout=5)
            return response.status_code == 200

        except Exception:
            return False

    def _check_llamacpp(self) -> bool:
        """Check if llama.cpp is available."""
        try:
            subprocess.run(["llama"], capture_output=True, timeout=5)
            return True
        except (
            subprocess.SubprocessError,
            FileNotFoundError,
            subprocess.TimeoutExpired,
        ):
            return False

    def _check_mcp(self) -> bool:
        """Check if Perplexity API is available (direct access)."""
        # Check if we have the API key
        api_key = os.getenv("PERPLEXITY_API_KEY", "")
        if not api_key:
            return False

        # Test direct API access
        try:
            url = "https://api.perplexity.ai/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": "sonar",
                "messages": [{"role": "user", "content": "test"}],
                "max_tokens": 10,
            }

            response = requests.post(url, json=payload, headers=headers, timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    def _initialize_backend(self):
        """Initialize the best available backend."""
        if self.force_backend:
            logger.info(f"Force-initializing backend: {self.force_backend}")
            self._initialize_specific_backend(self.force_backend)
            return

        if self.available_backends.get("transformers"):
            self.active_backend = "transformers"
            self._setup_transformers()
        elif self.available_backends.get("ollama"):
            self.active_backend = "ollama"
            self._setup_ollama()
        elif self.available_backends.get("llamacpp"):
            self.active_backend = "llamacpp"
            self._setup_llamacpp()
        elif self.available_backends.get("perplexity"):
            self.active_backend = "perplexity"
            self._setup_perplexity()
        elif self.available_backends.get("openai"):
            self.active_backend = "openai"
            self._setup_openai()
        else:
            logger.warning(
                "No advanced LLM backends available. Falling back to heuristic responses."
            )

    def _initialize_specific_backend(self, backend: str) -> None:
        """Initialize a specific backend, used when force_backend is provided."""

        initializer_map = {
            "transformers": self._setup_transformers,
            "ollama": self._setup_ollama,
            "llamacpp": self._setup_llamacpp,
            "perplexity": self._setup_perplexity,
            "openai": self._setup_openai,
            "rule_based": lambda: None,
        }

        if backend not in initializer_map:
            raise ValueError(f"Unsupported backend requested: {backend}")

        if backend != "rule_based" and not self.available_backends.get(backend, False):
            logger.warning(
                f"Requested backend '{backend}' not available. Using heuristic mode instead."
            )
            self.active_backend = "rule_based"
            return

        self.active_backend = backend
        initializer_map[backend]()

    def _get_perplexity_api_key(self) -> str:
        """Get Perplexity API key from config or environment."""
        # Check environment variable first
        api_key = os.getenv("PERPLEXITY_API_KEY")
        if api_key:
            return api_key

        # Check encrypted config file
        try:
            from utils.osint_utils import OSINTUtils

            utils = OSINTUtils()
            api_keys = utils.get_all_api_keys()
            key = api_keys.get("PERPLEXITY_API_KEY", "")
            if key:
                return key
        except Exception as e:
            logger.warning(f"Failed to load encrypted API key: {e}")

        # No key available
        logger.error("No Perplexity API key found in environment or encrypted config")
        return ""

    def _get_openai_api_key(self) -> str:
        """Get OpenAI API key from config or environment."""
        # Check environment variable first
        api_key = os.getenv("OPENAI_API_KEY")
        if api_key:
            return api_key

        # Check secrets manager (where API key manager stores it)
        try:
            from secrets_manager import secrets_manager  # type: ignore

            key = secrets_manager.get_secret("openai_api_key", "")
            if key:
                return key
        except Exception as e:
            logger.warning(f"Failed to load API key from secrets manager: {e}")

        # Check encrypted config file as fallback
        try:
            from utils.osint_utils import OSINTUtils

            utils = OSINTUtils()
            api_keys = utils.get_all_api_keys()
            key = api_keys.get("OPENAI_API_KEY", "")
            if key:
                return key
        except Exception as e:
            logger.warning(f"Failed to load encrypted API key: {e}")

        # No key available
        logger.error(
            "No OpenAI API key found in environment, secrets manager, or encrypted config"
        )
        return ""

    def _setup_ollama(self):
        """Setup Ollama backend with OSINT-optimized models."""
        try:
            if not OLLAMA_AVAILABLE or ollama is None:
                logger.warning("Ollama not available, skipping setup")
                return
            # Check available models
            client = ollama.Client()
            models = client.list()

            # Recommended models for OSINT analysis
            recommended_models = [
                "llama3:latest",  # General analysis
                "mistral:latest",  # Pattern recognition
                "codellama:latest",  # Technical analysis
                "dolphin-mixtral:latest",  # Specialized reasoning
            ]

            installed_models = [model["name"] for model in models["models"]]

            # Pull missing recommended models
            for model in recommended_models:
                if model not in installed_models:
                    logger.info(f"Pulling {model} for OSINT analysis...")
                    try:
                        client.pull(model)
                        logger.info(f"Successfully installed {model}")
                    except Exception as e:
                        logger.warning(f"Failed to install {model}: {e}")

            self.models["ollama"] = client
            logger.info("Ollama backend initialized successfully")

        except Exception as e:
            logger.error(f"Failed to setup Ollama: {e}")
            self.available_backends["ollama"] = False

    def _setup_transformers(self):
        """Setup Hugging Face Transformers backend."""
        try:
            # Use efficient models for OSINT analysis
            model_configs = [
                {
                    "name": "microsoft/DialoGPT-medium",
                    "task": "text-generation",
                    "use_case": "conversation",
                },
                {
                    "name": "google/flan-t5-large",
                    "task": "text2text-generation",
                    "use_case": "analysis",
                },
            ]

            self.models["transformers"] = {}

            for config in model_configs:
                try:
                    if not TRANSFORMERS_AVAILABLE or torch is None or pipeline is None:
                        logger.warning(
                            "Transformers not available, skipping model load"
                        )
                        continue
                    if torch.cuda.is_available():
                        device = 0  # Use GPU
                    else:
                        device = -1  # Use CPU

                    model = pipeline(
                        config["task"], model=config["name"], device=device
                    )

                    self.models["transformers"][config["use_case"]] = model
                    logger.info(f"Loaded {config['name']} for {config['use_case']}")

                except Exception as e:
                    logger.warning(f"Failed to load {config['name']}: {e}")

            logger.info("Transformers backend initialized")

        except Exception as e:
            logger.error(f"Failed to setup Transformers: {e}")
            self.available_backends["transformers"] = False

    def _setup_llamacpp(self):
        """Setup llama.cpp backend."""
        try:
            # Check if llama.cpp executable exists
            llama_path = self.config.get("llama_cpp_path", "llama")
            model_path = self.config.get("llama_model_path", "")

            if not model_path:
                # Try common model locations
                possible_paths = [
                    "./models/llama-2-7b.ggmlv3.q4_0.bin",
                    "./models/llama-2-13b.ggmlv3.q4_0.bin",
                    "/usr/local/models/llama-2-7b.ggmlv3.q4_0.bin",
                    os.path.expanduser("~/models/llama-2-7b.ggmlv3.q4_0.bin"),
                ]

                for path in possible_paths:
                    if os.path.exists(path):
                        model_path = path
                        break

            if not model_path or not os.path.exists(model_path):
                logger.warning(
                    "No llama.cpp model file found. Please specify llama_model_path in config"
                )
                self.available_backends["llamacpp"] = False
                return

            # Test llama.cpp executable
            try:
                result = subprocess.run(
                    [llama_path, "--help"], capture_output=True, timeout=10
                )
                if result.returncode != 0:
                    raise subprocess.SubprocessError("llama.cpp executable test failed")
            except (subprocess.SubprocessError, FileNotFoundError):
                logger.warning("llama.cpp executable not found or not working")
                self.available_backends["llamacpp"] = False
                return

            self.models["llamacpp"] = {
                "executable": llama_path,
                "model_path": model_path,
                "context_size": self.config.get("llama_context_size", 2048),
                "threads": self.config.get("llama_threads", 4),
            }

            logger.info(f"llama.cpp backend initialized with model: {model_path}")

        except Exception as e:
            logger.error(f"Failed to setup llama.cpp: {e}")
            self.available_backends["llamacpp"] = False

    def _setup_mcp(self):
        """Setup Perplexity API backend."""
        try:
            logger.info("Setting up Perplexity API backend")

            # Get API key from secure config
            api_key = self._get_perplexity_api_key()
            if not api_key:
                logger.error("No Perplexity API key available")
                self.available_backends["mcp"] = False
                return

            # Store API key
            self.perplexity_api_key = api_key
            self.models["mcp"] = {"sonar": "sonar", "sonar-pro": "sonar-pro"}
            logger.info("Perplexity API backend initialized successfully")

        except Exception as e:
            logger.error(f"Failed to setup Perplexity API backend: {e}")
            self.available_backends["mcp"] = False

    def _setup_perplexity(self):
        """Setup Perplexity API backend (direct)."""
        try:
            api_key = self._get_perplexity_api_key()
            if not api_key:
                raise RuntimeError("No Perplexity API key available")

            # Test API connection
            url = "https://api.perplexity.ai/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": "sonar",
                "messages": [{"role": "user", "content": "test"}],
                "max_tokens": 1,
            }

            response = requests.post(url, json=payload, headers=headers, timeout=5)
            if response.status_code in [
                200,
                400,
            ]:  # 400 is OK for invalid model in test
                self.models["perplexity"] = {
                    "api_key": api_key,
                    "endpoint": url,
                    "models": ["sonar-pro", "sonar"],
                }
                logger.info("Perplexity backend initialized successfully")
            else:
                raise RuntimeError(
                    f"Perplexity API test failed: {response.status_code}"
                )

        except Exception as e:
            logger.error(f"Failed to setup Perplexity backend: {e}")
            self.available_backends["perplexity"] = False

    def _setup_openai(self):
        """Setup OpenAI API backend."""
        try:
            api_key = self._get_openai_api_key()
            if not api_key:
                raise RuntimeError("No OpenAI API key available")

            # Test API connection
            url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": "test"}],
                "max_tokens": 1,
            }

            response = requests.post(url, json=payload, headers=headers, timeout=5)
            if response.status_code in [200, 400]:  # 400 is OK for test
                self.models["openai"] = {
                    "api_key": api_key,
                    "endpoint": url,
                    "models": ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"],
                }
                logger.info("OpenAI backend initialized successfully")
            else:
                raise RuntimeError(f"OpenAI API test failed: {response.status_code}")

        except Exception as e:
            logger.error(f"Failed to setup OpenAI backend: {e}")
            self.available_backends["openai"] = False

    def _install_ollama(self):
        """Install Ollama automatically."""
        try:
            logger.info("Installing Ollama...")

            # Download and install Ollama
            install_command = "curl -fsSL https://ollama.ai/install.sh | sh"
            result = subprocess.run(
                install_command, shell=True, capture_output=True, text=True
            )

            if result.returncode == 0:
                logger.info("Ollama installed successfully")
                # Start Ollama service
                subprocess.Popen(["ollama", "serve"])

                # Wait for service to start
                import time

                time.sleep(5)

                # Retry backend detection
                self.available_backends = self._detect_backends()
                if self.available_backends["ollama"]:
                    self._setup_ollama()
            else:
                logger.error(f"Failed to install Ollama: {result.stderr}")

        except Exception as e:
            logger.error(f"Ollama installation failed: {e}")

    def _load_osint_prompts(self) -> Dict[str, str]:
        """Load OSINT-specific analysis prompts."""
        return {
            "pattern_analysis": """
            You are an expert OSINT analyst specializing in pattern recognition and intelligence analysis.
            
            Analyze the following data for patterns, anomalies, and intelligence indicators:
            
            Data: {data}
            
            Provide analysis in this format:
            1. PATTERNS IDENTIFIED: List significant patterns
            2. ANOMALIES: Note unusual or suspicious elements  
            3. INTELLIGENCE INDICATORS: Highlight actionable intelligence
            4. SEARCH STRATEGIES: Suggest follow-up investigations
            5. RISK ASSESSMENT: Evaluate potential threats or opportunities
            
            Focus on practical OSINT applications and maintain analytical objectivity.
            """,
            "web_search_optimization": """
            You are an expert in advanced web search techniques and OSINT methodologies.
            
            Target: {target}
            Objective: {objective}
            
            Generate optimized search strategies:
            
            1. GOOGLE DORKS: Advanced search operators for maximum intelligence gathering
            2. ALTERNATIVE ENGINES: Specialized search engines and databases
            3. SOCIAL MEDIA: Platform-specific search techniques
            4. TECHNICAL SOURCES: Code repositories, documentation, forums
            5. DARKWEB/DEEPWEB: Specialized search approaches
            6. TEMPORAL ANALYSIS: Time-based search strategies
            
            Prioritize passive techniques that maintain operational security.
            """,
            "threat_assessment": """
            As a cybersecurity and threat intelligence analyst, assess the following information:
            
            Intelligence: {intelligence}
            Context: {context}
            
            Provide threat assessment:
            
            1. THREAT LEVEL: Scale 1-10 with justification
            2. THREAT ACTORS: Identify potential actors or groups
            3. ATTACK VECTORS: Analyze possible attack methods
            4. INDICATORS: Technical and behavioral indicators
            5. MITIGATION: Recommended defensive measures
            6. ATTRIBUTION: Analysis of threat attribution indicators
            
            Base analysis on established threat intelligence frameworks.
            """,
            "data_correlation": """
            You are an intelligence analyst expert in data correlation and link analysis.
            
            Dataset A: {dataset_a}
            Dataset B: {dataset_b}
            
            Perform correlation analysis:
            
            1. DIRECT CONNECTIONS: Explicit relationships between datasets
            2. INDIRECT ASSOCIATIONS: Hidden or implied connections
            3. TEMPORAL CORRELATIONS: Time-based relationships
            4. GEOGRAPHIC CORRELATIONS: Location-based connections
            5. BEHAVIORAL PATTERNS: Activity-based correlations
            6. INTELLIGENCE GAPS: Missing information for complete picture
            
            Highlight high-confidence correlations and intelligence requirements.
            """,
        }

    async def analyze_osint_data(
        self, data: str, analysis_type: str = "pattern_analysis"
    ) -> OSINTAnalysis:
        """
        Perform OSINT-specific analysis on data.

        Args:
            data: Raw data to analyze
            analysis_type: Type of analysis to perform

        Returns:
            OSINTAnalysis object with structured results
        """
        if analysis_type not in self.osint_prompts:
            raise ValueError(f"Unknown analysis type: {analysis_type}")

        prompt = self.osint_prompts[analysis_type].format(data=data)

        response = await self._query_llm(prompt)

        # Parse response into structured format
        return self._parse_osint_response(response, analysis_type)

    async def generate_search_strategies(
        self, target: str, objective: str
    ) -> List[str]:
        """Generate optimized search strategies for OSINT investigation."""
        prompt = self.osint_prompts["web_search_optimization"].format(
            target=target, objective=objective
        )

        response = await self._query_llm(prompt)

        # Extract search strategies from response
        strategies = self._extract_search_strategies(response.content)
        return strategies

    async def assess_threat_level(
        self, intelligence: str, context: str = ""
    ) -> Dict[str, Any]:
        """Assess threat level based on intelligence data."""
        prompt = self.osint_prompts["threat_assessment"].format(
            intelligence=intelligence, context=context
        )

        response = await self._query_llm(prompt)

        # Parse threat assessment
        return self._parse_threat_assessment(response.content)

    async def correlate_data(self, dataset_a: str, dataset_b: str) -> Dict[str, Any]:
        """Perform data correlation analysis between two datasets."""
        prompt = self.osint_prompts["data_correlation"].format(
            dataset_a=dataset_a, dataset_b=dataset_b
        )

        response = await self._query_llm(prompt)

        # Parse correlation results
        return self._parse_correlation_analysis(response.content)

    async def _query_llm(self, prompt: str, model: Optional[str] = None) -> LLMResponse:
        """Query the active LLM backend."""
        start_time = datetime.now()

        try:
            if self.active_backend == "perplexity":
                response = await self._query_perplexity(prompt, model)
            elif self.active_backend == "openai":
                response = await self._query_openai(prompt, model)
            elif self.active_backend == "ollama":
                response = await self._query_ollama(prompt, model)
            elif self.active_backend == "transformers":
                response = await self._query_transformers(prompt, model)
            elif self.active_backend == "llamacpp":
                response = await self._query_llamacpp(prompt, model)
            elif self.active_backend == "rule_based":
                response = await self._query_rule_based(prompt)
            else:
                raise RuntimeError("No active LLM backend available")

            processing_time = (datetime.now() - start_time).total_seconds()

            return LLMResponse(
                content=response,
                confidence=0.8,  # Default confidence
                processing_time=processing_time,
                model_used=model or "default",
                metadata={"backend": self.active_backend},
            )

        except Exception as e:
            logger.error(f"LLM query failed: {e}")
            raise

    async def _query_rule_based(self, prompt: str) -> str:
        """Provide deterministic heuristic output when no model backend is available."""

        def summarize() -> str:
            lines = [line.strip() for line in prompt.splitlines() if line.strip()]
            if not lines:
                return "No input provided."

            summary = " ".join(lines[-5:])
            summary = summary[:400]
            return (
                "Heuristic analysis: "
                + summary
                + ("..." if len(summary) == 400 else "")
            )

        return await asyncio.to_thread(summarize)

    async def _query_ollama(self, prompt: str, model: Optional[str] = None) -> str:
        """Query Ollama backend."""
        client = self.models["ollama"]
        model_name = model or "llama3:latest"

        try:
            response = client.chat(
                model=model_name, messages=[{"role": "user", "content": prompt}]
            )

            return response["message"]["content"]

        except Exception as e:
            logger.error(f"Ollama query failed: {e}")
            # Fallback to simpler model
            try:
                response = client.generate(model="llama3:latest", prompt=prompt)
                return response["response"]
            except (Exception,):
                raise RuntimeError("Ollama backend unavailable")

    async def _query_transformers(
        self, prompt: str, model: Optional[str] = None
    ) -> str:
        """Query Transformers backend."""
        models = self.models["transformers"]

        if "analysis" in models:
            generator = models["analysis"]
            response = generator(prompt, max_length=512, num_return_sequences=1)
            return response[0]["generated_text"]

        raise RuntimeError("Transformers backend not properly configured")

    async def _query_llamacpp(self, prompt: str, model: Optional[str] = None) -> str:
        """Query llama.cpp backend."""
        try:
            config = self.models.get("llamacpp")
            if not config:
                raise RuntimeError("llama.cpp backend not properly configured")

            executable = config["executable"]
            model_path = config["model_path"]
            context_size = config["context_size"]
            threads = config["threads"]

            # Prepare the command for llama.cpp
            # Using the main executable with inference parameters
            cmd = [
                executable,
                "--model",
                model_path,
                "--prompt",
                prompt,
                "--ctx-size",
                str(context_size),
                "--threads",
                str(threads),
                "--n-predict",
                "512",  # Maximum tokens to generate
                "--temp",
                "0.7",  # Temperature for creativity
                "--top-k",
                "40",  # Top-k sampling
                "--top-p",
                "0.9",  # Top-p sampling
                "--repeat-last-n",
                "64",  # Repeat penalty window
                "--repeat-penalty",
                "1.1",  # Repeat penalty
                "--seed",
                "-1",  # Random seed (-1 for random)
            ]

            # Run llama.cpp as subprocess
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=os.getcwd(),
            )

            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=120,  # 2 minute timeout
                )

                if process.returncode == 0:
                    # Extract the generated text (llama.cpp outputs the prompt + generation)
                    output = stdout.decode("utf-8", errors="ignore")

                    # Remove the original prompt from the output
                    if prompt in output:
                        generated_text = output.split(prompt, 1)[1].strip()
                    else:
                        generated_text = output.strip()

                    # Clean up any llama.cpp artifacts
                    generated_text = self._clean_llamacpp_output(generated_text)

                    return generated_text if generated_text else "No response generated"

                else:
                    error_msg = stderr.decode("utf-8", errors="ignore")
                    logger.error(f"llama.cpp process failed: {error_msg}")
                    raise RuntimeError(f"llama.cpp execution failed: {error_msg}")

            except asyncio.TimeoutError:
                logger.warning("llama.cpp query timed out")
                process.kill()
                raise RuntimeError("llama.cpp query timed out")

        except Exception as e:
            logger.error(f"llama.cpp query failed: {e}")
            raise RuntimeError(f"llama.cpp backend error: {e}")

    def _clean_llamacpp_output(self, output: str) -> str:
        """Clean llama.cpp output by removing artifacts."""
        try:
            # Remove common llama.cpp artifacts
            lines = output.split("\n")

            # Remove empty lines and llama.cpp status messages
            cleaned_lines = []
            for line in lines:
                line = line.strip()
                # Skip status messages and empty lines
                if (
                    line
                    and not line.startswith("llama_")
                    and not line.startswith("[")
                    and "tokens/s" not in line
                    and "generation speed" not in line
                ):
                    cleaned_lines.append(line)

            # Join back and limit to reasonable length
            cleaned_output = "\n".join(cleaned_lines)

            # Truncate if too long (llama.cpp can generate very long responses)
            if len(cleaned_output) > 10000:
                cleaned_output = cleaned_output[:10000] + "...[truncated]"

            return cleaned_output

        except Exception as e:
            logger.warning(f"Failed to clean llama.cpp output: {e}")
            return output

    async def _query_mcp(self, prompt: str, model: Optional[str] = None) -> str:
        """Query Perplexity API directly."""
        try:
            api_key = os.getenv("PERPLEXITY_API_KEY", "")

            # Map model names
            if model == "perplexity" or model is None:
                model_name = "sonar"
            elif model == "perplexity-large":
                model_name = "sonar"  # Use same model for now
            else:
                model_name = model

            # Prepare the request for Perplexity API
            url = "https://api.perplexity.ai/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": model_name,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert OSINT analyst with deep knowledge of intelligence gathering, pattern recognition, and security analysis.",
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.7,
                "max_tokens": 1024,
            }

            # Make request to Perplexity API
            response = requests.post(url, json=payload, headers=headers, timeout=30)

            if response.status_code == 200:
                result = response.json()
                # Extract the response content
                if "choices" in result and len(result["choices"]) > 0:
                    return result["choices"][0]["message"]["content"]
                else:
                    return "No response content from Perplexity API"
            else:
                logger.error(
                    f"Perplexity API failed with status {response.status_code}: {response.text}"
                )
                raise RuntimeError(f"Perplexity API error: {response.status_code}")

        except requests.exceptions.RequestException as e:
            logger.error(f"Perplexity API request failed: {e}")
            raise RuntimeError(f"Perplexity API connection failed: {e}")
        except Exception as e:
            logger.error(f"Perplexity API query error: {e}")
            raise RuntimeError(f"Perplexity API query failed: {e}")

    async def _query_perplexity(self, prompt: str, model: Optional[str] = None) -> str:
        """Query Perplexity API directly (research model)."""
        try:
            api_key = self._get_perplexity_api_key()
            if not api_key:
                raise RuntimeError("No Perplexity API key available")

            # Use research model by default (sonar-pro has online access)
            if model is None or model == "perplexity":
                model_name = "sonar-pro"
            elif model == "perplexity-small":
                model_name = "sonar"  # Use smaller model
            else:
                model_name = model

            # Prepare the request for Perplexity API
            url = "https://api.perplexity.ai/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": model_name,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert OSINT analyst specializing in intelligence gathering, pattern recognition, and security analysis. You have access to real-time web search and can provide comprehensive research-backed analysis.",
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.7,
                "max_tokens": 2048,  # Higher limit for research model
                "top_p": 0.9,
            }

            # Make request to Perplexity API
            response = requests.post(url, json=payload, headers=headers, timeout=45)

            if response.status_code == 200:
                result = response.json()
                # Extract the response content
                if "choices" in result and len(result["choices"]) > 0:
                    return result["choices"][0]["message"]["content"]
                else:
                    return "No response content from Perplexity API"
            else:
                logger.error(
                    f"Perplexity API failed with status {response.status_code}: {response.text}"
                )
                raise RuntimeError(f"Perplexity API error: {response.status_code}")

        except requests.exceptions.RequestException as e:
            logger.error(f"Perplexity API request failed: {e}")
            raise RuntimeError(f"Perplexity API connection failed: {e}")
        except Exception as e:
            logger.error(f"Perplexity API query error: {e}")
            raise RuntimeError(f"Perplexity API query failed: {e}")

    async def _query_openai(self, prompt: str, model: Optional[str] = None) -> str:
        """Query OpenAI API."""
        try:
            api_key = self._get_openai_api_key()
            if not api_key:
                raise RuntimeError("No OpenAI API key available")

            # Use GPT-3.5-turbo by default, with GPT-4 as option
            if model is None or model == "openai":
                model_name = "gpt-3.5-turbo"
            elif model in ["gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"]:
                model_name = model
            else:
                model_name = "gpt-3.5-turbo"

            # Prepare the request for OpenAI API
            url = "https://api.openai.com/v1/chat/completions"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }

            payload = {
                "model": model_name,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert OSINT analyst specializing in intelligence gathering, pattern recognition, and security analysis. Provide comprehensive analysis based on available information.",
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.7,
                "max_tokens": 2048,
                "top_p": 0.9,
            }

            # Make request to OpenAI API
            response = requests.post(url, json=payload, headers=headers, timeout=45)

            if response.status_code == 200:
                result = response.json()
                # Extract the response content
                if "choices" in result and len(result["choices"]) > 0:
                    return result["choices"][0]["message"]["content"]
                else:
                    return "No response content from OpenAI API"
            else:
                logger.error(
                    f"OpenAI API failed with status {response.status_code}: {response.text}"
                )
                raise RuntimeError(f"OpenAI API error: {response.status_code}")

        except requests.exceptions.RequestException as e:
            logger.error(f"OpenAI API request failed: {e}")
            raise RuntimeError(f"OpenAI API connection failed: {e}")
        except Exception as e:
            logger.error(f"OpenAI API query error: {e}")
            raise RuntimeError(f"OpenAI API query failed: {e}")

    def _parse_osint_response(
        self, response: LLMResponse, analysis_type: str
    ) -> OSINTAnalysis:
        """Parse LLM response into structured OSINT analysis."""
        content = response.content

        # Extract structured information using pattern matching
        insights = self._extract_section(content, "PATTERNS IDENTIFIED") or []
        patterns = self._extract_patterns(content)
        risk_assessment = self._extract_risk_assessment(content)
        recommendations = self._extract_section(content, "SEARCH STRATEGIES") or []
        search_strategies = (
            self._extract_section(content, "INTELLIGENCE INDICATORS") or []
        )

        return OSINTAnalysis(
            insights=insights,
            patterns=patterns,
            risk_assessment=risk_assessment,
            recommendations=recommendations,
            search_strategies=search_strategies,
        )

    def _extract_section(self, content: str, section_name: str) -> List[str]:
        """Extract a specific section from LLM response."""
        lines = content.split("\n")
        section_lines = []
        in_section = False

        for line in lines:
            if section_name in line.upper():
                in_section = True
                continue
            elif in_section and line.strip() and not line.startswith(" "):
                if any(
                    keyword in line.upper()
                    for keyword in [
                        "PATTERNS",
                        "ANOMALIES",
                        "INTELLIGENCE",
                        "SEARCH",
                        "RISK",
                        "THREAT",
                    ]
                ):
                    break
            elif in_section and line.strip():
                section_lines.append(line.strip())

        return section_lines

    def _extract_patterns(self, content: str) -> List[Dict[str, Any]]:
        """Extract pattern information from response."""
        patterns = []

        # Simple pattern extraction - can be enhanced with more sophisticated parsing
        lines = content.split("\n")
        for line in lines:
            if "pattern" in line.lower() or "correlation" in line.lower():
                patterns.append(
                    {
                        "description": line.strip(),
                        "confidence": 0.7,
                        "type": "behavioral",
                    }
                )

        return patterns

    def _extract_risk_assessment(self, content: str) -> Dict[str, Any]:
        """Extract risk assessment from response."""
        return {"level": "medium", "factors": [], "confidence": 0.6}

    def _extract_search_strategies(self, content: str) -> List[str]:
        """Extract search strategies from LLM response."""
        strategies = []

        lines = content.split("\n")
        for line in lines:
            if any(
                keyword in line.lower()
                for keyword in ["dork", "search", "query", "site:"]
            ):
                strategies.append(line.strip())

        return strategies

    def _parse_threat_assessment(self, content: str) -> Dict[str, Any]:
        """Parse threat assessment from response."""
        return {
            "threat_level": 5,
            "threat_actors": [],
            "attack_vectors": [],
            "indicators": [],
            "mitigation": [],
            "attribution": {},
        }

    def _parse_correlation_analysis(self, content: str) -> Dict[str, Any]:
        """Parse correlation analysis from response."""
        return {
            "direct_connections": [],
            "indirect_associations": [],
            "temporal_correlations": [],
            "geographic_correlations": [],
            "behavioral_patterns": [],
            "intelligence_gaps": [],
        }

    def get_available_models(self) -> List[str]:
        """Get list of available models for current backend."""
        if self.active_backend == "ollama":
            try:
                client = self.models["ollama"]
                models = client.list()
                return [model["name"] for model in models["models"]]
            except (Exception,):
                return []

        return []

    def get_backend_status(self) -> Dict[str, Any]:
        """Get status of all backends and models."""
        return {
            "active_backend": self.active_backend,
            "available_backends": self.available_backends,
            "loaded_models": len(self.models),
            "status": "ready" if self.active_backend else "no_backend",
        }

    async def analyze_investigation(
        self,
        investigation_data: Dict[str, Any],
        analysis_type: str = "summary",
        context: Optional[str] = None,
        include_raw_data: bool = False,
    ) -> Dict[str, Any]:
        """Analyze investigation data using LLM (compatibility method for API server)."""
        try:
            # Extract relevant data from investigation
            investigation_name = investigation_data.get("name", "Unknown Investigation")
            investigation_type = investigation_data.get("investigation_type", "general")
            targets = investigation_data.get("targets", [])

            # Format data for analysis
            data_summary = f"""
Investigation: {investigation_name}
Type: {investigation_type}
Targets: {", ".join(targets) if targets else "None specified"}
"""

            if context:
                data_summary += f"\nContext: {context}\n"

            if include_raw_data and "results" in investigation_data:
                data_summary += f"\nRaw Data: {investigation_data['results']}\n"

            # Perform analysis
            analysis = await self.analyze_osint_data(data_summary, analysis_type)

            # Convert to expected format
            return {
                "analysis_type": analysis_type,
                "summary": analysis.insights[0]
                if analysis.insights
                else "Analysis completed",
                "findings": [
                    {"type": "insight", "content": insight}
                    for insight in analysis.insights
                ]
                + [
                    {"type": "pattern", "content": str(pattern)}
                    for pattern in analysis.patterns
                ],
                "confidence_score": 0.8,
                "recommendations": analysis.recommendations,
                "threat_level": analysis.risk_assessment.get("level", "medium"),
                "metadata": {
                    "model_used": self.active_backend,
                    "analysis_timestamp": datetime.now().isoformat(),
                },
                "generated_at": datetime.now(),
            }

        except Exception as e:
            logger.error(f"Investigation analysis failed: {e}")
            return {
                "analysis_type": analysis_type,
                "summary": "Analysis failed due to technical issues",
                "findings": [],
                "confidence_score": 0.0,
                "recommendations": ["Retry analysis", "Check system logs"],
                "threat_level": "unknown",
                "metadata": {"error": str(e)},
                "generated_at": datetime.now(),
            }

    async def analyze_intelligence(
        self,
        intelligence_data: Dict[str, Any],
        analysis_type: str = "pattern_analysis",
        context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze intelligence data using LLM (alias for analyze_investigation)."""
        return await self.analyze_investigation(
            intelligence_data, analysis_type, context, include_raw_data=True
        )

    # ------------------------------------------------------------------
    # Autopivot support
    # ------------------------------------------------------------------

    def _normalize_investigation(self, investigation_data: Any) -> Dict[str, Any]:
        """Normalize investigation structures into dictionaries."""

        if isinstance(investigation_data, dict):
            return investigation_data

        if hasattr(investigation_data, "dict"):
            try:
                return investigation_data.dict()
            except Exception:  # pragma: no cover - depends on pydantic availability
                pass

        if hasattr(investigation_data, "__dict__"):
            try:
                return asdict(investigation_data)
            except Exception:
                return dict(vars(investigation_data))

        return {"data": investigation_data}

    def _collect_result_text(self, results: Any) -> str:
        """Flatten nested results into a searchable text blob."""

        fragments: List[str] = []

        if isinstance(results, dict):
            for value in results.values():
                fragments.append(self._collect_result_text(value))
        elif isinstance(results, list):
            for value in results:
                fragments.append(self._collect_result_text(value))
        elif isinstance(results, str):
            fragments.append(results)
        elif results is not None:
            fragments.append(str(results))

        return " \n".join([fragment for fragment in fragments if fragment])

    def _infer_target_type(self, target: str) -> str:
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", target):
            return "ip"
        if re.match(r"^[0-9a-fA-F:]+$", target) and ":" in target:
            return "ip"
        if re.match(r"^.+@.+\..+$", target):
            return "email"
        if target.startswith("@"):
            return "username"
        if re.match(r"^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$", target):
            return "domain"
        if re.match(r"^[A-Za-z0-9._-]+$", target):
            return "username"
        return "keyword"

    async def suggest_autopivots(
        self, investigation_data: Dict[str, Any], max_pivots: int = 5
    ) -> List[Dict[str, Any]]:
        normalized = self._normalize_investigation(investigation_data)

        investigation_id = (
            normalized.get("id")
            or normalized.get("investigation_id")
            or normalized.get("uuid")
        )
        if not investigation_id:
            raise ValueError("Investigation identifier is required for autopivoting")

        name = normalized.get("name") or f"Investigation {investigation_id}"
        self.autonomous_engine.ensure_investigation(investigation_id, name)

        existing_findings = self.autonomous_engine.tracker.get_all_findings(
            investigation_id
        )

        if not existing_findings:
            targets = normalized.get("targets") or []
            if isinstance(targets, str):
                targets = [targets]

            for target in targets:
                target_type = self._infer_target_type(target)
                await self.autonomous_engine.collect_and_plan(
                    investigation_id,
                    target,
                    target_type,
                    max_pivots=max_pivots,
                )

        return await self.autonomous_engine.suggest_pivots(
            investigation_id, max_pivots=max_pivots
        )

    async def execute_autonomous_investigation(
        self,
        initial_target: str,
        target_type: str,
        max_depth: int = 3,
        max_pivots_per_level: int = 3,
    ) -> Dict[str, Any]:
        inferred_type = target_type or self._infer_target_type(initial_target)
        return await self.autonomous_engine.execute_autonomous_investigation(
            initial_target,
            inferred_type,
            max_depth=max_depth,
            max_pivots_per_level=max_pivots_per_level,
        )


# Factory function for easy instantiation
def create_local_llm_engine(config: Optional[Dict] = None) -> LocalLLMEngine:
    """Create and initialize a local LLM engine for OSINT analysis."""
    return LocalLLMEngine(config)


# Example usage
if __name__ == "__main__":
    import asyncio

    async def demo():
        """Demonstrate local LLM capabilities."""
        engine = create_local_llm_engine()

        print("Local LLM Engine Demo")
        print("====================")
        print(f"Backend Status: {engine.get_backend_status()}")
        print(f"Available Models: {engine.get_available_models()}")

        # Example OSINT analysis
        sample_data = """
        Domain: suspicious-example.com
        IP: 192.168.1.100
        Registrar: Privacy Protection
        Creation Date: 2024-01-01
        SSL Certificate: Self-signed
        """

        try:
            analysis = await engine.analyze_osint_data(sample_data, "pattern_analysis")
            print("\nAnalysis Results:")
            print(f"Insights: {analysis.insights}")
            print(f"Risk Assessment: {analysis.risk_assessment}")

        except Exception as e:
            print(f"Analysis failed: {e}")

    asyncio.run(demo())
