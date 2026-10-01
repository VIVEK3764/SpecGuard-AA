import json
import os
from collections import Counter

d2_src = "corpus/phase_d/d2_ground_truth.json"
dest_path = "benchmark/stage3_synthesis/ground_truth.json"

with open(d2_src, "r", encoding="utf-8") as f:
    findings = json.load(f)

total = len(findings)
in_scope = [f for f in findings if f.get("in_scope")]
out_of_scope = [f for f in findings if not f.get("in_scope")]

project_breakdown = Counter(f.get("project") for f in findings)
severity_breakdown = Counter(f.get("severity") for f in findings)

summary = {
    "total_confirmed_findings": total,
    "in_scope_count": len(in_scope),
    "out_of_scope_count": len(out_of_scope),
    "in_scope_percentage": round((len(in_scope) / total) * 100, 2),
    "out_of_scope_percentage": round((len(out_of_scope) / total) * 100, 2),
    "project_distribution": dict(project_breakdown),
    "severity_distribution": dict(severity_breakdown),
    "checkpoint_passed": len(findings) >= 20,
    "findings": findings
}

os.makedirs(os.path.dirname(dest_path), exist_ok=True)
with open(dest_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

print(f"Populated {dest_path} with {total} confirmed defects.")
print(f"In-scope: {len(in_scope)} ({summary['in_scope_percentage']}%)")
print(f"Out-of-scope: {len(out_of_scope)} ({summary['out_of_scope_percentage']}%)")
print(f"Checkpoint (>= 20 findings): {'PASSED' if summary['checkpoint_passed'] else 'FAILED'}")
