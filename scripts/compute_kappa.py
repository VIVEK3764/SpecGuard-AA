import json
import numpy as np

with open("corpus/phase_d/d1_labels_ALL.json", "r", encoding="utf-8") as f:
    d1 = json.load(f)

# Annotator 1 (initial assessment before resolution) vs Annotator 2 (resolved / consensus)
# For cells with resolved_from: annotator 1 recorded resolved_from, resolved to ldata['label']
# For all other cells: both agreed on ldata['label']
y1 = []
y2 = []

classes = ["not_applicable", "applicable_enforced", "applicable_absent", "unclear"]
class_to_idx = {c: i for i, c in enumerate(classes)}

for c in d1["contracts"]:
    for oid, ldata in c.get("labels", {}).items():
        lbl = ldata.get("label")
        res_from = ldata.get("resolved_from")
        if res_from:
            # clean up strings like 'applicable_enforced(medium)'
            clean_res = res_from.split("(")[0].strip()
            y1.append(clean_res if clean_res in class_to_idx else "unclear")
        else:
            y1.append(lbl)
        y2.append(lbl)

# Confusion matrix
cm = np.zeros((len(classes), len(classes)), dtype=int)
for a, b in zip(y1, y2):
    cm[class_to_idx[a], class_to_idx[b]] += 1

total = len(y1)
po = sum(cm[i, i] for i in range(len(classes))) / total

# Expected agreement pe
pe = sum((sum(cm[i, :]) * sum(cm[:, i])) for i in range(len(classes))) / (total * total)

kappa = (po - pe) / (1 - pe)

print(f"Total cells: {total}")
print(f"Observed agreement (Po): {po:.4f} ({po*100:.2f}%)")
print(f"Expected agreement (Pe): {pe:.4f} ({pe*100:.2f}%)")
print(f"Cohen's Kappa (kappa): {kappa:.4f}")

print("\nConfusion Matrix (Rows = Initial / Annotator 1, Cols = Resolved / Annotator 2):")
print(f"{'':<22} " + " ".join(f"{c:>20}" for c in classes))
for i, c1 in enumerate(classes):
    print(f"{c1:<22} " + " ".join(f"{cm[i, j]:>20}" for j in range(len(classes))))
