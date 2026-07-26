import json
from llm_brain import LLMBrain

print("Initializing LLMBrain v7...")
brain = LLMBrain(verbose=True)

# Mock chat function to test offline logic instantly
brain.chat = lambda system, user, temperature=0.2: json.dumps({
    "architect_perspective": "Microservices design approved",
    "auditor_perspective": "Security parameters verified",
    "executor_perspective": "Containerized deployment recommended",
    "consensus_plan": {
        "primary_strategy": "Multi-region cluster with automated failover",
        "execution_steps": ["Deploy gateway", "Spin up nodes", "Configure load balancer"],
        "risk_safeguards": ["Enable rate limiting", "mTLS validation"]
    },
    "consensus_confidence": 0.96
})

print("\n1. Testing Semantic Memory Store...")
mem_id = brain.store_episodic_memory("cloud_config", "AWS multi-region failover configuration details", tags=["cloud", "aws"])
hits = brain.query_episodic_memory("AWS failover")
print("Memory Hits:", hits)
assert len(hits) > 0, "Memory retrieval failed"

print("\n2. Testing Adaptive Cognitive Strategy Selector...")
strat = brain.adapt_strategy("Diagnose and repair network timeout error in database layer")
print("Strategy Chosen:", strat["chosen_strategy"])
assert strat["chosen_strategy"] == "TRIAGED_DIAGNOSTIC"

print("\n3. Testing Multi-Agent Consensus Engine...")
consensus = brain.multi_agent_consensus("Design high availability microservice cluster")
print("Consensus Primary Strategy:", consensus["consensus_plan"]["primary_strategy"])
assert consensus["consensus_plan"]["primary_strategy"] == "Multi-region cluster with automated failover"

print("\n4. Testing Code Verification (AST Check)...")
code_res = brain.synthesize_and_verify_code("def add(a, b):\n    return a + b\n")
print("Syntax Valid:", code_res["syntax_valid"])
assert code_res["syntax_valid"] == True

print("\n5. Testing State Export & Persistence...")
saved = brain.save_memory_to_disk("test_brain_memory.json")
print("Saved Memory:", saved)
assert saved == True

report = brain.export_cognitive_report("test_cognitive_report.json")
print("Report Metrics:", report["performance_metrics"])
assert report["performance_metrics"]["semantic_memories_count"] >= 1

print("\n==================================================")
print("✅ ALL UNIT TESTS FOR LLMBRAIN V7 PASSED SUCCESSFULLY!")
print("==================================================")
