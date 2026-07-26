import ast

with open("llm_brain.py", "r", encoding="utf-8", errors="ignore") as f:
    tree = ast.parse(f.read())

print("=== LLM BRAIN DETAILS ===")
for node in tree.body:
    if isinstance(node, ast.ClassDef):
        print(f"\nClass: {node.name}")
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                doc = ast.get_docstring(item)
                first_line = doc.split("\n")[0] if doc else "No docstring"
                print(f"  - {item.name}({', '.join([arg.arg for arg in item.args.args])}): {first_line}")
