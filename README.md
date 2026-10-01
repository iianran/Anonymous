# Anonymous

Supplementary material for double-blind review.

## Contents

### `dataset/`
- `primevul_test_paired.jsonl` — paired PrimeVul test samples (870 rows; each pair consists of a vulnerable sample `target=1` and a fixed-version sample `target=0`)
- `secvuleval_eval_300.jsonl` — SecVulEval evaluation set (300 pairs, 600 rows)

### `experiment_result/`
- `main_experiment_detection_results.md` — main experiment detection results (435 pairs)
- `generalization_experiment_detection_results.md` — generalization experiment detection results (SecVulEval, 300 pairs)
- `ablation_experiment_detection_results_shared_trajectory.md` — ablation experiment detection results (shared-trajectory setting, 435 pairs)
- `PrimeVul_label_error_39_pairs.md` — evidence archive for 39 PrimeVul pairs with label errors (Classes A/B/C)
- `PrimeVul_pairing_failure_6_pairs.md` — evidence archive for 6 failed PrimeVul pairings (original text and attribution)
- `runtime_repro/` — reproduction scripts for the runtime-crash evidence (one subdirectory per pair: PoC, harness, control scripts, and input-construction scripts)

In the result tables, the V-side / S-side columns report the detection outcome on the vulnerable sample and on the fixed-version sample of each pair, respectively.
