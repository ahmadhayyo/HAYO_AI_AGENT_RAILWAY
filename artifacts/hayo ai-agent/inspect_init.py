with open("llm_brain.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

for i, line in enumerate(lines):
    if "class LLMBrain" in line:
        print("Found LLMBrain at line", i+1)
        for j in range(i, min(i+50, len(lines))):
            print(f"{j+1}: {lines[j]}", end="")
        break
