#!/usr/bin/env python3
"""
fuzz_test/bin/script.py

Internal Python backend for the fuzz_test tool.
Steps:
  1. Parse CLI args
  2. Load NL spec (YAML/JSON)
  3. Resolve target function
  4. Generate harness using internal LLM (TODO)
  5. Write temporary harness file
  6. Run fuzzing (atheris/libFuzzer)
  7. Collect results
  8. Print JSON for SWE-agent
"""
import argparse
import importlib
import importlib.util
import inspect
import json
import os
import subprocess
import sys
import tempfile
import traceback
from typing import Any, Dict, Tuple, Callable
from openai import OpenAI
from dotenv import load_dotenv
import os

# automatically load ".env" file from current working directory
load_dotenv()

# now you can use:
api_key = os.getenv("OPENAI_API_KEY")

# Try loading YAML; if not installed, fail gracefully
try:
    import yaml
except ImportError:
    print(json.dumps({"error": "PyYAML not installed"}))
    sys.exit(1)
    
    
def summarize_fuzz_result(fuzz_result: Dict[str, Any],
                          max_log_chars: int = 4000) -> Dict[str, Any]:
    """
    Compress and classify raw fuzz_result for the outer model:
    - 归一化 status
    - 截断 stdout/stderr，避免输出过长
    """
    def extract_crashes_from_stderr(stderr: str) -> list[dict]:
        """
        Scan stderr lines, parse any FUZZ_CRASH_JSON:... entries into dicts.
        """
        crashes = []
        prefix = "FUZZ_CRASH_JSON:"
        for line in stderr.splitlines():
            line = line.strip()
            if not line.startswith(prefix):
                continue
            payload = line[len(prefix):]
            try:
                obj = json.loads(payload)
                crashes.append(obj)
            except Exception:
                # 最坏情况：忽略这条，不让整个工具挂
                continue
        return crashes
    
    # 1. 先根据 error/returncode 归类 status
    if "error" in fuzz_result:
        if fuzz_result.get("error") == "timeout":
            status = "timeout"
        else:
            status = "fuzz_error"
    else:
        rc = fuzz_result.get("returncode", 0)
        if rc == 0:
            status = "ok"
        else:
            # 非零退出码一般说明找到了 crash 或 assertion 失败
            status = "crash"

    def _truncate(s: str | None) -> str:
        if s is None:
            return ""
        if len(s) <= max_log_chars:
            return s
        hidden = len(s) - max_log_chars
        return s[:max_log_chars] + f"\n...[truncated {hidden} chars]"

    return {
        "status": status,
        "returncode": fuzz_result.get("returncode"),
        "stdout": _truncate(fuzz_result.get("stdout", "")),
        "stderr": _truncate(fuzz_result.get("stderr", "")),
        # 下面两个主要用于 debug，不一定每次都有
        "raw_error": fuzz_result.get("error"),
        "traceback": fuzz_result.get("traceback"),
        "crashes": extract_crashes_from_stderr(fuzz_result.get("stderr", "")),
    }
    
def _parse_llm_json(raw: str) -> dict:
    """
    Robustly parse JSON from LLM output.
    Handles cases like:

        ```json
        { ... }
        ```

    or extra text around the JSON.
    """
    s = raw.strip()

    # 1) strip markdown code fences if present
    if s.startswith("```"):
        lines = s.splitlines()
        # 去掉第一行 ``` 或 ```json
        if lines:
            first = lines[0]
            if first.startswith("```"):
                lines = lines[1:]
        # 找到最后一个 ``` 作为结束
        end_idx = None
        for i, line in enumerate(lines):
            if line.strip().startswith("```"):
                end_idx = i
                break
        if end_idx is not None:
            lines = lines[:end_idx]
        s = "\n".join(lines).strip()

    # 2) 先尝试直接解析
    try:
        return json.loads(s)
    except Exception:
        # 3) 再从中间截取第一个 { 到 最后一个 } 尝试
        first = s.find("{")
        last = s.rfind("}")
        if first != -1 and last != -1 and last > first:
            candidate = s[first:last + 1]
            return json.loads(candidate)
        # 如果还是不行，就把原文吐出去方便调试
        raise ValueError(f"LLM returned invalid JSON:\n{raw}")

# ========================================================================
# 1. CLI / Argument Parsing
# ========================================================================
def parse_args():
    parser = argparse.ArgumentParser(description="LLM-assisted fuzz runner")

    parser.add_argument("--target", required=True,
                        help="module:func or path/to/file.py:func")
    parser.add_argument("--spec", required=True,
                        help="YAML/JSON spec file")
    parser.add_argument("--mode", default="quick",
                        choices=["quick", "deep", "debug"],
                        help="Fuzzing mode")

    return parser.parse_args()


# ========================================================================
# 2. Load spec file
# ========================================================================
def load_spec_file(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        print(path)
        raise FileNotFoundError(f"Spec file not found: {path}")

    if path.endswith(".yaml") or path.endswith(".yml"):
        with open(path, "r") as f:
            return yaml.safe_load(f)
    elif path.endswith(".json"):
        with open(path, "r") as f:
            return json.load(f)
    else:
        raise ValueError("Spec file must be YAML or JSON")


# ========================================================================
# 3. Resolve target function
# ========================================================================
def resolve_target(target: str):
    """
    输入示例：
        'pkg.mod:func'
        'path/to/file.py:func'
    输出：
        (target_path, target_function)
    其中：
        - target_path：绝对路径（如果是模块名，则返回 None）
        - target_function：目标函数
    """
    if ":" not in target:
        raise ValueError("Target must be of the form 'module:func' or 'file.py:func'")

    left, func_name = target.split(":", 1)

    # file path case
    if os.path.isfile(left) and left.endswith(".py"):
        abs_path = os.path.abspath(left)
        spec = importlib.util.spec_from_file_location("fuzz_target_module", abs_path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["fuzz_target_module"] = module
        spec.loader.exec_module(module)
        if not hasattr(module, func_name):
            raise ValueError(f"Function '{func_name}' not found in file '{abs_path}'")
        return abs_path, getattr(module, func_name)
    
    # module import path case
    else:
        module = importlib.import_module(left)
        if not hasattr(module, func_name):
            raise ValueError(f"Function '{func_name}' not found in module '{left}'")
        return left, getattr(module, func_name)


# ========================================================================
# 4. Internal LLM-based harness builder (TODO: real LLM integration)
# ========================================================================

def generate_harness_with_llm(module_path, target_func, spec, mode):
    """
    LLM generates:
      - encoder (encode(obj)->bytes)
      - decoder (decode(bytes)->obj)
      - post_condition (post_condition(obj,out)->bool)
      - seeds (list of Python dicts)
    Harness is fixed and NOT generated by LLM.
    """

    func_name = target_func
    signature = str(inspect.signature(target_func))

    # Natural-language spec fields
    issue_description = spec.get("issue_description", {}).get("natural_language", "")
    input_desc = spec.get("input_description", {}).get("natural_language", "")
    pre_cond = spec.get("pre_condition", {}).get("natural_language", "")
    post_cond = spec.get("post_condition", {}).get("natural_language", "")

    # ---------------------------
    # Build PROMPT (very strict)
    # ---------------------------
    system_prompt = """You are an expert generator for fuzzing-harness components. Use atheris-compatible Python.

IMPORTANT:

* You DO NOT generate the fuzz harness.
* You ONLY produce 4 items: encoder, decoder, post_condition, seeds.
* Your entire output MUST be a single JSON object with EXACTLY these fields:

  {
  "encoder": "<python function encode(obj)->bytes>",
  "decoder": "<python function decode(data: bytes)->obj>",
  "post_condition": "<python function post_condition(input_obj, output_obj)->bool>",
  "seeds": [...]
  }

STRICT RULES:

1. encoder(obj) -> bytes

   * Must NEVER raise exceptions.
   * Must be fully deterministic for the same input object.
   * Must implement a REVERSIBLE encoding scheme so that:
     decoder(encoder(obj)) == obj
     for all valid input objects of the schema (up to minor type normalization like int vs bool).
   * Use a two-step encoding:

     * First write a fixed ASCII magic header (e.g. b"ENC1").
     * Then serialize the object (typically as JSON, UTF-8 encoded).
   * JSON serialization (if used) must be deterministic:

     * Use stable key ordering (e.g. sort keys).
     * Avoid any randomness or non-deterministic behavior.
   * The encoder must only produce bytes that the decoder can reliably recognize as "encoded by this encoder".

2. decoder(data: bytes) -> object

   * Must NEVER raise exceptions.
   * Must accept ANY arbitrary byte sequence.
   * Must implement a TWO-PATH decoding strategy:
     (a) Reversible path:
     - If data starts with the magic header used by encoder:
     * Strip the header.
     * Parse the remaining bytes (e.g. JSON decode).
     * If the parsed value matches the expected schema, return it.
     * If parsing fails or the schema does not match, fall back to path (b).
     (b) Fallback path:
     - For any data that is not in the reversible format (wrong header, parsing error, wrong type, etc.),
     return a DEFAULT VALID OBJECT consistent with the input schema.
   * The returned object MUST always be valid to use as arguments to:
     target_function(**obj)
     if the object is a dict, or:
     target_function(obj)
     if the object is not a dict.
   * The decoder MUST ensure that, for any valid object produced by the schema and encoded by encoder,
     decoder(encoder(obj)) == obj
     holds as exactly as possible.

3. post_condition(input_obj, output_obj) -> bool

   * Must NEVER raise exceptions.
   * Must implement the natural-language post-condition described in the prompt.
   * Return True ONLY if the behavior is valid.
   * Return False when behavior violates the expected semantics.
   * Absolutely NO side effects (no I/O, no mutation of global state, no randomness).

4. seeds

   * Must be a list of VALID input objects matching the schema.
   * All seeds MUST be encodable by encoder() AND decodable by decoder().
   * For every seed s, decoder(encoder(s)) MUST return an object equivalent to s.
   * Seeds should be diverse and help fuzzing explore different code paths of the target function.

ADDITIONAL RESTRICTIONS:

* NO commentary, NO explanations, NO markdown.
* NO import statements inside any generated function body.
* If imports are needed (e.g. json), they MUST appear at top level in the code string, before any function definitions.
* The functions must be standalone, pure Python.
* NO randomness (no use of random, time, or any non-deterministic source).
* Only return JSON, not Python code blocks.
    """
    user_prompt = f"""
Target Function:
  module: {module_path}
  name: {func_name}
  signature: {signature}
Issue Description (NL):
{issue_description}

Input description (NL):
{input_desc}

Pre-condition (NL):
{pre_cond}

Post-condition (NL):
{post_cond}

Remember:
- Harness is fixed.
- ONLY generate encoder, decoder, post_condition, seeds.
- Output MUST be valid JSON.
"""
    # get API key from 
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    res = client.chat.completions.create(
        model="gpt-5.1",
        temperature=0.2,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt}
        ],
    )

    raw = res.choices[0].message.content

    try:
        obj = _parse_llm_json(raw)
    except Exception:
        raise ValueError(f"LLM returned invalid JSON:\n{raw}")

    for key in ["encoder", "decoder", "post_condition", "seeds"]:
        if key not in obj:
            raise ValueError(f"Missing key: {key} in LLM output:\n{raw}")

    return {
        "encoder_code": obj["encoder"],
        "decoder_code": obj["decoder"],
        "assertion_code": obj["post_condition"],
        "seeds": obj["seeds"],
        "target_module": module_path,
        "target_function": func_name,
        "signature": signature,
    }# ========================================================================
# ========================================================================
# 5. Write harness to temp file
# ========================================================================
def write_temp_fuzz_dir(enc, dec, assertion, target_path, target_func, seeds=[]):
    """
    Writes encoder.py, decoder.py, assertion.py, and harness.py
    into a fresh temp directory.
    Returns path to harness.py.
    """
    target_path = os.path.abspath(target_path)
    target_function = target_func.__name__
    tmpdir = tempfile.mkdtemp(prefix="fuzz_harness_")

    def write_file(name, code):
        path = os.path.join(tmpdir, name)
        with open(path, "w") as f:
            f.write(code)
        return path

    # 1. Write encoder/decoder/assertion
    write_file("encoder.py", enc)
    write_file("decoder.py", dec)
    write_file("assertion.py", assertion)
    
    # Write seeds.json
    seeds_path = os.path.join(tmpdir, "seeds.json")
    with open(seeds_path, "w", encoding="utf-8") as f:
        json.dump({"seeds": seeds}, f, ensure_ascii=False, indent=2)
        

    # 2. Write fixed harness template
    harness_template = f"""
import sys
import os
import atheris
import json
import traceback
import importlib

# allow importing modules in this temp directory
sys.path.insert(0, '{tmpdir}')

from encoder import encode
from decoder import decode
from assertion import post_condition

# Import target function
TARGET_PATH = '{target_path}'
TARGET_FUNC = '{target_function}'

def _load_target_function():
    spec = TARGET_PATH

    if os.path.isfile(spec) and spec.endswith(".py"):
        module_name = "fuzz_target_module"
        m_spec = importlib.util.spec_from_file_location(module_name, spec)
        module = importlib.util.module_from_spec(m_spec)
        sys.modules[module_name] = module
        m_spec.loader.exec_module(module)
    else:
        # 否则按模块名处理，例如 "pkg.mod.sub"
        module = importlib.import_module(spec)

    if not hasattr(module, TARGET_FUNC):
        raise ValueError(f"Function '{target_function}' not found.")

    return getattr(module, TARGET_FUNC)


target_function = _load_target_function()
def _log_crash(kind, obj, out, exc):
    crash = {{
        "kind": kind,
        "decoded_input_repr": repr(obj),
        "output_repr": repr(out),
        "exception_type": type(exc).__name__ if exc is not None else None,
        "exception_message": str(exc) if exc is not None else None,
        "traceback": traceback.format_exc() if exc is not None else None,
    }}
    try:
        payload = json.dumps(crash, ensure_ascii=False)
    except Exception:
        payload = json.dumps({{"kind": kind, "error": "failed_to_serialize_crash"}})
    print("FUZZ_CRASH_JSON:" + payload, file=sys.stderr, flush=True)


def _prepare_seed_corpus():
    seeds_path = os.path.join('{tmpdir}', 'seeds.json')
    if not os.path.exists(seeds_path):
        return

    try:
        with open(seeds_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        seeds = data.get("seeds", [])
    except Exception:
        return

    corpus_dir = os.path.join('{tmpdir}', 'corpus')
    os.makedirs(corpus_dir, exist_ok=True)

    count = 0
    for seed in seeds:
        try:
            b = encode(seed)
            # 文件名避免冲突
            filename = os.path.join(corpus_dir, 'seed_' + count)
            with open(filename, 'wb') as f:
                f.write(b)
            count += 1
        except Exception:
            # 单个 seed encode 失败也忽略
            continue


def TestOneInput(data):
    obj = None
    out = None

    # 1. decode
    try:
        obj = decode(data)
    except Exception as e:
        _log_crash("decode_exception", obj, out, e)
        raise

    # 2. call target function
    try:
        if isinstance(obj, dict):
            try:
                out = target_function(**obj)
            except TypeError:
                out = target_function(obj)
        else:
            out = target_function(obj)
    except Exception as e:
        _log_crash("exception", obj, out, e)
        raise

    # 3. post-condition
    try:
        ok = post_condition(obj, out)
    except Exception as e:
        _log_crash("post_condition_exception", obj, out, e)
        raise

    if not ok:
        _log_crash("post_condition_failure", obj, out, None)
        raise AssertionError("Post-condition failed")


def main():
    _prepare_seed_corpus()

    # 使用 seeds 的 corpus 目录作为 fuzz 初始 corpus
    corpus_dir = os.path.join('{tmpdir}', 'corpus')
    sys.argv.append(corpus_dir)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
"""
    harness_path = write_file("harness.py", harness_template)
    print("harness written to:", harness_path)
    return harness_path

# ========================================================================
# 6. Run fuzz (atheris)
# ========================================================================
def run_fuzz(harness_path: str, mode: str, seeds: Any) -> Dict[str, Any]:
    """
    call:
        python harness_path
    Collect crash signals, output JSON-friendly info.
    """
    cmd = [sys.executable, harness_path]

    # Quick mode: fewer iterations (Atheris via env var)
    env = os.environ.copy()
    if mode == "quick":
        env["ATHERIS_RUN_TIMEOUT"] = "2"
    elif mode == "debug":
        env["ATHERIS_NO_FUZZ"] = "1"

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=20
        )
        return {
            "stdout": result.stdout.decode("utf-8", errors="ignore"),
            "stderr": result.stderr.decode("utf-8", errors="ignore"),
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "error": "timeout",
            "returncode": None,
            "stdout": "",
            "stderr": ""
        }
    except Exception as e:
        return {
            "error": repr(e),
            "traceback": traceback.format_exc()
        }

# ========================================================================
# 7. Main entry
# ========================================================================
def main():
    args = parse_args()

    try:
        spec = load_spec_file(args.spec)
        left, target_func = resolve_target(args.target)

        # 1. Generate harness using LLM
        harness_info = generate_harness_with_llm(
            module_path=left,
            target_func=target_func,
            spec=spec,
            mode=args.mode
        )
        seeds = harness_info.get("seeds", [])

        # 2. Write harness to temp file
        harness_path = write_temp_fuzz_dir(
            enc=harness_info["encoder_code"],
            dec=harness_info["decoder_code"],
            assertion=harness_info["assertion_code"],
            target_path=left,
            target_func=target_func,
            seeds=seeds
        )
                # 3. Run fuzz
        fuzz_result = run_fuzz(
            harness_path=harness_path,
            mode=args.mode,
            seeds=seeds
        )

        summarized = summarize_fuzz_result(fuzz_result)

        # 4. Combine all info
        output = {
            "status": summarized["status"],

            "target": {
                "module": harness_info["target_module"],
                "function": harness_info["target_function"],
                "signature": harness_info["signature"],
            },

            "harness": {
                "harness_path": harness_path,
                "encoder_code": harness_info["encoder_code"],
                "decoder_code": harness_info["decoder_code"],
                "assertion_code": harness_info["assertion_code"],
                # 如果你觉得太长，可以先不返回 harness_code，或者以后再打开
                # "harness_code": <如果你想，也可以从文件里读回去>,
            },

            # "seeds": seeds,

            "fuzz": {
                "mode": args.mode,
                "result": summarized,
            },
        }

    except Exception as e:
        output = {
            "status": "tool_error",
            "error": repr(e),
            "traceback": traceback.format_exc(),
        }
    def _safe(o):
        if callable(o):
            return f"<function {o.__name__}>"
        return str(o)

    print(json.dumps(output, indent=2, default=_safe))


# ========================================================================
if __name__ == "__main__":
    main()