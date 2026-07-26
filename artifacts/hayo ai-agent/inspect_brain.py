import ast
import os

files = ['llm_brain.py', 'agent.py', 'orchestrator.py', 'warroom_brain.py', 'ai_explorer.py', 'dynamic_engine.py']
base_dir = r"C:\Users\PT\Desktop\HAYO\HAYO_AI_AGENT_RAILWAY\artifacts\hayo ai-agent"

for fname in files:
    fpath = os.path.join(base_dir, fname)
    if not os.path.exists(fpath):
        print(f"File {fname} not found.")
        continue
    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
        tree = ast.parse(f.read())
    print(f"=== {fname} ===")
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            methods = [m.name for m in node.body if isinstance(m, ast.FunctionDef)]
            print(f"  Class: {node.name}")
            print(f"    Methods: {methods[:15]}")
        elif isinstance(node, ast.FunctionDef):
            print(f"  Function: {node.name}")
