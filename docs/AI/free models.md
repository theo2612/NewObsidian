- top 10 
curl -s https://openrouter.ai/api/v1/models \ | jq '.data | map({ id, created_date: (.created | strftime("%Y-%m-%d")), description, context_length: (.top_provider.context_length // 0) }) | sort_by(.created) | .[0:10]'
- all
curl -s https://openrouter.ai/api/v1/models \ | jq '.data | map(select(.pricing.prompt == "0" and .pricing.completion == "0")) | map({id, description, context_length: (.top_provider.context_length // 0)}) | sort_by(.context_length) | reverse'
[
  {
    "id": "google/gemini-2.0-flash-exp:free",
    "description": "Gemini Flash 2.0 offers a significantly faster time to first token (TTFT) compared to [Gemini Flash 1.5](/google/gemini-flash-1.5), while maintaining quality on par with larger models like [Gemini Pro 1.5](/google/gemini-pro-1.5). It introduces notable enhancements in multimodal understanding, coding capabilities, complex instruction following, and function calling. These advancements come together to deliver more seamless and robust agentic experiences.",
    "context_length": 1048576
  },
  {
    "id": "qwen/qwen3-next-80b-a3b-instruct:free",
    "description": "Qwen3-Next-80B-A3B-Instruct is an instruction-tuned chat model in the Qwen3-Next series optimized for fast, stable responses without “thinking” traces. It targets complex tasks across reasoning, code generation, knowledge QA, and multilingual use, while remaining robust on alignment and formatting. Compared with prior Qwen3 instruct variants, it focuses on higher throughput and stability on ultra-long inputs and multi-turn dialogues, making it well-suited for RAG, tool use, and agentic workflows that require consistent final answers rather than visible chain-of-thought.\n\nThe model employs scaling-efficient training and decoding to improve parameter efficiency and inference speed, and has been validated on a broad set of public benchmarks where it reaches or approaches larger Qwen3 systems in several categories while outperforming earlier mid-sized baselines. It is best used as a general assistant, code helper, and long-context task solver in production settings where deterministic, instruction-following outputs are preferred.",
    "context_length": 262144
  },
  {
    "id": "mistralai/devstral-2512:free",
    "description": "Devstral 2 is a state-of-the-art open-source model by Mistral AI specializing in agentic coding. It is a 123B-parameter dense transformer model supporting a 256K context window.\n\nDevstral 2 supports exploring codebases and orchestrating changes across multiple files while maintaining architecture-level context. It tracks framework dependencies, detects failures, and retries with corrections—solving challenges like bug fixing and modernizing legacy systems. The model can be fine-tuned to prioritize specific languages or optimize for large enterprise codebases. It is available under a modified MIT license.",
    "context_length": 262144
  },
  {
    "id": "xiaomi/mimo-v2-flash:free",
    "description": "MiMo-V2-Flash is an open-source foundation language model developed by Xiaomi. It is a Mixture-of-Experts model with 309B total parameters and 15B active parameters, adopting hybrid attention architecture. MiMo-V2-Flash supports a hybrid-thinking toggle and a 256K context window, and excels at reasoning, coding, and agent scenarios. On SWE-bench Verified and SWE-bench Multilingual, MiMo-V2-Flash ranks as the top #1 open-source model globally, delivering performance comparable to Claude Sonnet 4.5 while costing only about 3.5% as much.\n\nUsers can control the reasoning behaviour with the `reasoning` `enabled` boolean. [Learn more in our docs](https://openrouter.ai/docs/use-cases/reasoning-tokens#enable-reasoning-with-default-config).",
    "context_length": 262144
  },
  {
    "id": "qwen/qwen3-coder:free",
    "description": "Qwen3-Coder-480B-A35B-Instruct is a Mixture-of-Experts (MoE) code generation model developed by the Qwen team. It is optimized for agentic coding tasks such as function calling, tool use, and long-context reasoning over repositories. The model features 480 billion total parameters, with 35 billion active per forward pass (8 out of 160 experts).\n\nPricing for the Alibaba endpoints varies by context length. Once a request is greater than 128k input tokens, the higher pricing is used.",
    "context_length": 262000
  },
  {
    "id": "nvidia/nemotron-3-nano-30b-a3b:free",
    "description": "NVIDIA Nemotron 3 Nano 30B A3B is a small language MoE model with highest compute efficiency and accuracy for developers to build specialized agentic AI systems.\n\nThe model is fully open with open-weights, datasets and recipes so developers can easily\ncustomize, optimize, and deploy the model on their infrastructure for maximum privacy and\nsecurity.\n\nNote: For the free endpoint, all prompts and output are logged to improve the provider's model and its product and services. Please do not upload any personal, confidential, or otherwise sensitive information. This is a trial use only. Do not use for production or business-critical systems.",
    "context_length": 256000
  },
  {
    "id": "tngtech/deepseek-r1t-chimera:free",
    "description": "DeepSeek-R1T-Chimera is created by merging DeepSeek-R1 and DeepSeek-V3 (0324), combining the reasoning capabilities of R1 with the token efficiency improvements of V3. It is based on a DeepSeek-MoE Transformer architecture and is optimized for general text generation tasks.\n\nThe model merges pretrained weights from both source models to balance performance across reasoning, efficiency, and instruction-following tasks. It is released under the MIT license and intended for research and commercial use.",
    "context_length": 163840
  },
  {
    "id": "deepseek/deepseek-r1-0528:free",
    "description": "May 28th update to the [original DeepSeek R1](/deepseek/deepseek-r1) Performance on par with [OpenAI o1](/openai/o1), but open-sourced and with fully open reasoning tokens. It's 671B parameters in size, with 37B active in an inference pass.\n\nFully open-source model.",
    "context_length": 163840
  },
  {
    "id": "tngtech/deepseek-r1t2-chimera:free",
    "description": "DeepSeek-TNG-R1T2-Chimera is the second-generation Chimera model from TNG Tech. It is a 671 B-parameter mixture-of-experts text-generation model assembled from DeepSeek-AI’s R1-0528, R1, and V3-0324 checkpoints with an Assembly-of-Experts merge. The tri-parent design yields strong reasoning performance while running roughly 20 % faster than the original R1 and more than 2× faster than R1-0528 under vLLM, giving a favorable cost-to-intelligence trade-off. The checkpoint supports contexts up to 60 k tokens in standard use (tested to ~130 k) and maintains consistent <think> token behaviour, making it suitable for long-context analysis, dialogue and other open-ended generation tasks.",
    "context_length": 163840
  },
  {
    "id": "tngtech/tng-r1t-chimera:free",
    "description": "TNG-R1T-Chimera is an experimental LLM with a faible for creative storytelling and character interaction. It is a derivate of the original TNG/DeepSeek-R1T-Chimera released in April 2025 and is available exclusively via Chutes and OpenRouter.\n\nCharacteristics and improvements include:\n\nWe think that it has a creative and pleasant personality.\nIt has a preliminary EQ-Bench3 value of about 1305.\nIt is quite a bit more intelligent than the original, albeit a slightly slower.\nIt is much more think-token consistent, i.e. reasoning and answer blocks are properly delineated.\nTool calling is much improved.\n\nTNG Tech, the model authors, ask that users follow the careful guidelines that Microsoft has created for their \"MAI-DS-R1\" DeepSeek-based model. These guidelines are available on Hugging Face (https://huggingface.co/microsoft/MAI-DS-R1).",
    "context_length": 163840
  },
  {
    "id": "meta-llama/llama-3.1-405b-instruct:free",
    "description": "The highly anticipated 400B class of Llama3 is here! Clocking in at 128k context with impressive eval scores, the Meta AI team continues to push the frontier of open-source LLMs.\n\nMeta's latest class of model (Llama 3.1) launched with a variety of sizes & flavors. This 405B instruct-tuned version is optimized for high quality dialogue usecases.\n\nIt has demonstrated strong performance compared to leading closed-source models including GPT-4o and Claude 3.5 Sonnet in evaluations.\n\nTo read more about the model release, [click here](https://ai.meta.com/blog/meta-llama-3-1/). Usage of this model is subject to [Meta's Acceptable Use Policy](https://llama.meta.com/llama3/use-policy/).",
    "context_length": 131072
  },
  {
    "id": "nousresearch/hermes-3-llama-3.1-405b:free",
    "description": "Hermes 3 is a generalist language model with many improvements over Hermes 2, including advanced agentic capabilities, much better roleplaying, reasoning, multi-turn conversation, long context coherence, and improvements across the board.\n\nHermes 3 405B is a frontier-level, full-parameter finetune of the Llama-3.1 405B foundation model, focused on aligning LLMs to the user, with powerful steering capabilities and control given to the end user.\n\nThe Hermes 3 series builds and expands on the Hermes 2 set of capabilities, including more powerful and reliable function calling and structured output capabilities, generalist assistant capabilities, and improved code generation skills.\n\nHermes 3 is competitive, if not superior, to Llama-3.1 Instruct models at general capabilities, with varying strengths and weaknesses attributable between the two.",
    "context_length": 131072
  },
  {
    "id": "meta-llama/llama-3.2-3b-instruct:free",
    "description": "Llama 3.2 3B is a 3-billion-parameter multilingual large language model, optimized for advanced natural language processing tasks like dialogue generation, reasoning, and summarization. Designed with the latest transformer architecture, it supports eight languages, including English, Spanish, and Hindi, and is adaptable for additional languages.\n\nTrained on 9 trillion tokens, the Llama 3.2 3B model excels in instruction-following, complex reasoning, and tool use. Its balanced performance makes it ideal for applications needing accuracy and efficiency in text generation across multilingual settings.\n\nClick here for the [original model card](https://github.com/meta-llama/llama-models/blob/main/models/llama3_2/MODEL_CARD.md).\n\nUsage of this model is subject to [Meta's Acceptable Use Policy](https://www.llama.com/llama3/use-policy/).",
    "context_length": 131072
  },
  {
    "id": "meta-llama/llama-3.3-70b-instruct:free",
    "description": "The Meta Llama 3.3 multilingual large language model (LLM) is a pretrained and instruction tuned generative model in 70B (text in/text out). The Llama 3.3 instruction tuned text only model is optimized for multilingual dialogue use cases and outperforms many of the available open source and closed chat models on common industry benchmarks.\n\nSupported languages: English, German, French, Italian, Portuguese, Hindi, Spanish, and Thai.\n\n[Model Card](https://github.com/meta-llama/llama-models/blob/main/models/llama3_3/MODEL_CARD.md)",
    "context_length": 131072
  },
  {
    "id": "google/gemma-3-27b-it:free",
    "description": "Gemma 3 introduces multimodality, supporting vision-language input and text outputs. It handles context windows up to 128k tokens, understands over 140 languages, and offers improved math, reasoning, and chat capabilities, including structured outputs and function calling. Gemma 3 27B is Google's latest open source model, successor to [Gemma 2](google/gemma-2-27b-it)",
    "context_length": 131072
  },
  {
    "id": "z-ai/glm-4.5-air:free",
    "description": "GLM-4.5-Air is the lightweight variant of our latest flagship model family, also purpose-built for agent-centric applications. Like GLM-4.5, it adopts the Mixture-of-Experts (MoE) architecture but with a more compact parameter size. GLM-4.5-Air also supports hybrid inference modes, offering a \"thinking mode\" for advanced reasoning and tool use, and a \"non-thinking mode\" for real-time interaction. Users can control the reasoning behaviour with the `reasoning` `enabled` boolean. [Learn more in our docs](https://openrouter.ai/docs/use-cases/reasoning-tokens#enable-reasoning-with-default-config)",
    "context_length": 131072
  },
  {
    "id": "openai/gpt-oss-20b:free",
    "description": "gpt-oss-20b is an open-weight 21B parameter model released by OpenAI under the Apache 2.0 license. It uses a Mixture-of-Experts (MoE) architecture with 3.6B active parameters per forward pass, optimized for lower-latency inference and deployability on consumer or single-GPU hardware. The model is trained in OpenAI’s Harmony response format and supports reasoning level configuration, fine-tuning, and agentic capabilities including function calling, tool use, and structured outputs.",
    "context_length": 131072
  },
  {
    "id": "openai/gpt-oss-120b:free",
    "description": "gpt-oss-120b is an open-weight, 117B-parameter Mixture-of-Experts (MoE) language model from OpenAI designed for high-reasoning, agentic, and general-purpose production use cases. It activates 5.1B parameters per forward pass and is optimized to run on a single H100 GPU with native MXFP4 quantization. The model supports configurable reasoning depth, full chain-of-thought access, and native tool use, including function calling, browsing, and structured output generation.",
    "context_length": 131072
  },
  {
    "id": "arcee-ai/trinity-mini:free",
    "description": "Trinity Mini is a 26B-parameter (3B active) sparse mixture-of-experts language model featuring 128 experts with 8 active per token. Engineered for efficient reasoning over long contexts (131k) with robust function calling and multi-step agent workflows.",
    "context_length": 131072
  },
  {
    "id": "mistralai/mistral-small-3.1-24b-instruct:free",
    "description": "Mistral Small 3.1 24B Instruct is an upgraded variant of Mistral Small 3 (2501), featuring 24 billion parameters with advanced multimodal capabilities. It provides state-of-the-art performance in text-based reasoning and vision tasks, including image analysis, programming, mathematical reasoning, and multilingual support across dozens of languages. Equipped with an extensive 128k token context window and optimized for efficient local inference, it supports use cases such as conversational agents, function calling, long-document comprehension, and privacy-sensitive deployments. The updated version is [Mistral Small 3.2](mistralai/mistral-small-3.2-24b-instruct)",
    "context_length": 128000
  },
  {
    "id": "nvidia/nemotron-nano-9b-v2:free",
    "description": "NVIDIA-Nemotron-Nano-9B-v2 is a large language model (LLM) trained from scratch by NVIDIA, and designed as a unified model for both reasoning and non-reasoning tasks. It responds to user queries and tasks by first generating a reasoning trace and then concluding with a final response. \n\nThe model's reasoning capabilities can be controlled via a system prompt. If the user prefers the model to provide its final answer without intermediate reasoning traces, it can be configured to do so.",
    "context_length": 128000
  },
  {
    "id": "nvidia/nemotron-nano-12b-v2-vl:free",
    "description": "NVIDIA Nemotron Nano 2 VL is a 12-billion-parameter open multimodal reasoning model designed for video understanding and document intelligence. It introduces a hybrid Transformer-Mamba architecture, combining transformer-level accuracy with Mamba’s memory-efficient sequence modeling for significantly higher throughput and lower latency.\n\nThe model supports inputs of text and multi-image documents, producing natural-language outputs. It is trained on high-quality NVIDIA-curated synthetic datasets optimized for optical-character recognition, chart reasoning, and multimodal comprehension.\n\nNemotron Nano 2 VL achieves leading results on OCRBench v2 and scores ≈ 74 average across MMMU, MathVista, AI2D, OCRBench, OCR-Reasoning, ChartQA, DocVQA, and Video-MME—surpassing prior open VL baselines. With Efficient Video Sampling (EVS), it handles long-form videos while reducing inference cost.\n\nOpen-weights, training data, and fine-tuning recipes are released under a permissive NVIDIA open license, with deployment supported across NeMo, NIM, and major inference runtimes.",
    "context_length": 128000
  },
  {
    "id": "qwen/qwen3-4b:free",
    "description": "Qwen3-4B is a 4 billion parameter dense language model from the Qwen3 series, designed to support both general-purpose and reasoning-intensive tasks. It introduces a dual-mode architecture—thinking and non-thinking—allowing dynamic switching between high-precision logical reasoning and efficient dialogue generation. This makes it well-suited for multi-turn chat, instruction following, and complex agent workflows.",
    "context_length": 40960
  },
  {
    "id": "allenai/molmo-2-8b:free",
    "description": "Molmo2-8B is an open vision-language model developed by the Allen Institute for AI (Ai2) as part of the Molmo2 family, supporting image, video, and multi-image understanding and grounding. It is based on Qwen3-8B and uses SigLIP 2 as its vision backbone, outperforming other open-weight, open-data models on short videos, counting, and captioning, while remaining competitive on long-video tasks.",
    "context_length": 36864
  },
  {
    "id": "qwen/qwen-2.5-vl-7b-instruct:free",
    "description": "Qwen2.5 VL 7B is a multimodal LLM from the Qwen Team with the following key enhancements:\n\n- SoTA understanding of images of various resolution & ratio: Qwen2.5-VL achieves state-of-the-art performance on visual understanding benchmarks, including MathVista, DocVQA, RealWorldQA, MTVQA, etc.\n\n- Understanding videos of 20min+: Qwen2.5-VL can understand videos over 20 minutes for high-quality video-based question answering, dialog, content creation, etc.\n\n- Agent that can operate your mobiles, robots, etc.: with the abilities of complex reasoning and decision making, Qwen2.5-VL can be integrated with devices like mobile phones, robots, etc., for automatic operation based on visual environment and text instructions.\n\n- Multilingual Support: to serve global users, besides English and Chinese, Qwen2.5-VL now supports the understanding of texts in different languages inside images, including most European languages, Japanese, Korean, Arabic, Vietnamese, etc.\n\nFor more details, see this [blog post](https://qwenlm.github.io/blog/qwen2-vl/) and [GitHub repo](https://github.com/QwenLM/Qwen2-VL).\n\nUsage of this model is subject to [Tongyi Qianwen LICENSE AGREEMENT](https://huggingface.co/Qwen/Qwen1.5-110B-Chat/blob/main/LICENSE).",
    "context_length": 32768
  },
  {
    "id": "google/gemma-3-12b-it:free",
    "description": "Gemma 3 introduces multimodality, supporting vision-language input and text outputs. It handles context windows up to 128k tokens, understands over 140 languages, and offers improved math, reasoning, and chat capabilities, including structured outputs and function calling. Gemma 3 12B is the second largest in the family of Gemma 3 models after [Gemma 3 27B](google/gemma-3-27b-it)",
    "context_length": 32768
  },
  {
    "id": "google/gemma-3-4b-it:free",
    "description": "Gemma 3 introduces multimodality, supporting vision-language input and text outputs. It handles context windows up to 128k tokens, understands over 140 languages, and offers improved math, reasoning, and chat capabilities, including structured outputs and function calling.",
    "context_length": 32768
  },
  {
    "id": "cognitivecomputations/dolphin-mistral-24b-venice-edition:free",
    "description": "Venice Uncensored Dolphin Mistral 24B Venice Edition is a fine-tuned variant of Mistral-Small-24B-Instruct-2501, developed by dphn.ai in collaboration with Venice.ai. This model is designed as an “uncensored” instruct-tuned LLM, preserving user control over alignment, system prompts, and behavior. Intended for advanced and unrestricted use cases, Venice Uncensored emphasizes steerability and transparent behavior, removing default safety and alignment layers typically found in mainstream assistant models.",
    "context_length": 32768
  },
  {
    "id": "moonshotai/kimi-k2:free",
    "description": "Kimi K2 Instruct is a large-scale Mixture-of-Experts (MoE) language model developed by Moonshot AI, featuring 1 trillion total parameters with 32 billion active per forward pass. It is optimized for agentic capabilities, including advanced tool use, reasoning, and code synthesis. Kimi K2 excels across a broad range of benchmarks, particularly in coding (LiveCodeBench, SWE-bench), reasoning (ZebraLogic, GPQA), and tool-use (Tau2, AceBench) tasks. It supports long-context inference up to 128K tokens and is designed with a novel training stack that includes the MuonClip optimizer for stable large-scale MoE training.",
    "context_length": 32768
  },
  {
    "id": "google/gemma-3n-e4b-it:free",
    "description": "Gemma 3n E4B-it is optimized for efficient execution on mobile and low-resource devices, such as phones, laptops, and tablets. It supports multimodal inputs—including text, visual data, and audio—enabling diverse tasks such as text generation, speech recognition, translation, and image analysis. Leveraging innovations like Per-Layer Embedding (PLE) caching and the MatFormer architecture, Gemma 3n dynamically manages memory usage and computational load by selectively activating model parameters, significantly reducing runtime resource requirements.\n\nThis model supports a wide linguistic range (trained in over 140 languages) and features a flexible 32K token context window. Gemma 3n can selectively load parameters, optimizing memory and computational efficiency based on the task or device capabilities, making it well-suited for privacy-focused, offline-capable applications and on-device AI solutions. [Read more in the blog post](https://developers.googleblog.com/en/introducing-gemma-3n/)",
    "context_length": 8192
  },
  {
    "id": "google/gemma-3n-e2b-it:free",
    "description": "Gemma 3n E2B IT is a multimodal, instruction-tuned model developed by Google DeepMind, designed to operate efficiently at an effective parameter size of 2B while leveraging a 6B architecture. Based on the MatFormer architecture, it supports nested submodels and modular composition via the Mix-and-Match framework. Gemma 3n models are optimized for low-resource deployment, offering 32K context length and strong multilingual and reasoning performance across common benchmarks. This variant is trained on a diverse corpus including code, math, web, and multimodal data.",
    "context_length": 8192
  }
]
