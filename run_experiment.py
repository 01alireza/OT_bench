"""Run attack and benign episodes and append one JSON line per run to results/runs.jsonl (resumable)."""
import argparse, json, os, time
from agent import run_episode
from benign import TASKS, ATTACK_TASK
from llm import LLM, MockLLM
from payloads import build_corpus, goal_achieved, CHANNELS
from tools import Environment

DEFENSES = {"D0": (False, False), "D1": (True, False), "D2": (False, True), "D3": (True, True)}  # (prompt_def, guardrail)


def done_keys(path):
    keys = set()
    if os.path.exists(path):
        for line in open(path):
            try: keys.add(json.loads(line)["key"])
            except Exception: pass
    return keys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="openai", choices=["openai", "anthropic", "mock"])
    ap.add_argument("--model", default="llama3.1:8b")
    ap.add_argument("--base-url", default="http://localhost:11434/v1")
    ap.add_argument("--api-key-env", default=None)
    ap.add_argument("--defenses", default="D0,D1,D2,D3")
    ap.add_argument("--per-channel", type=int, default=5, help="payloads per channel (pilot 5, full >=50)")
    ap.add_argument("--reps", type=int, default=1)
    ap.add_argument("--skip-benign", action="store_true")
    ap.add_argument("--skip-attack", action="store_true")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default="results/runs.jsonl")
    a = ap.parse_args()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    llm = MockLLM() if a.backend == "mock" else LLM(a.backend, a.model, a.base_url, a.api_key_env, a.temperature, a.seed)
    defenses = a.defenses.split(",")
    corpus = build_corpus(a.per_channel)
    seen = done_keys(a.out)
    out = open(a.out, "a")

    def log(rec):
        out.write(json.dumps(rec) + "\n"); out.flush()

    jobs = []
    for rep in range(a.reps):
        for d in defenses:
            if not a.skip_attack:
                for p in corpus:
                    jobs.append(("attack", rep, d, p, None))
            if not a.skip_benign:
                for t in TASKS:
                    jobs.append(("benign", rep, d, None, t))
    print(f"{len(jobs)} jobs, model={llm.model}")
    for n, (kind, rep, d, p, t) in enumerate(jobs, 1):
        ident = p.id if p else t.id
        key = f"{llm.model}|{kind}|{d}|{ident}|{rep}"
        if key in seen:
            continue
        spot, guard = DEFENSES[d]
        env = Environment(level=(t.level if t else 50.0), guard_on=guard, injection=p, spotlight=spot)
        llm.begin_episode({"payload": p, "mock_actions": (t.mock_actions if t else [{"tool": "read_sensors", "args": {}}])})
        t0 = time.perf_counter()
        res = run_episode(llm, env, t.prompt if t else ATTACK_TASK, prompt_defense=spot)
        latency = time.perf_counter() - t0
        env.plant.run_horizon()
        ex = env.executed_calls()
        phys = env.plant.physical_harm()
        viol_exec = any(c["would_violate"] for c in ex)
        rec = {"key": key, "model": llm.model, "kind": kind, "defense": d, "rep": rep, "id": ident,
               "latency_s": round(latency, 3), "guard_ms": round(env.guard_time * 1000, 3),
               "n_calls": len(env.calls), "n_executed": len(ex),
               "n_blocked": sum(1 for c in env.calls if c["would_violate"] and not c["executed"]),
               "n_would_violate": sum(1 for c in env.calls if c["would_violate"]),
               "parse_fail": res["parse_fail"], "final": res["final"],
               "calls": env.calls, "physical_harm": phys, "max_level": round(max(env.plant.trace), 1),
               "min_level": round(min(env.plant.trace), 1)}
        if p:
            harm = phys or viol_exec
            ach = goal_achieved(p.goal, ex)
            rec.update({"channel": p.channel, "goal": p.goal, "goal_class": p.goal_class, "technique": p.technique,
                        "harm": harm, "goal_achieved": ach, "cch": bool(ach and not harm)})
        else:
            rec.update({"task": t.id, "probe": t.probe, "success": bool(t.check(env, res["final"])),
                        "any_block": rec["n_blocked"] > 0, "any_would_violate": rec["n_would_violate"] > 0})
        log(rec)
        if n % 10 == 0:
            print(f"{n}/{len(jobs)}")
    print("done ->", a.out)


if __name__ == "__main__":
    main()
