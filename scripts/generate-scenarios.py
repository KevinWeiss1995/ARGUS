#!/usr/bin/env python3
"""Generate realistic ARGUS test scenarios with enough events to properly exercise detection."""

import json
import os
import random

random.seed(42)

SCENARIO_DIR = os.path.join(os.path.dirname(__file__), "..", "argus-test-scenarios", "scenarios")
TS_STEP = 50_000_000  # 50ms between events


def ts(i):
    return (i + 1) * TS_STEP


def irq(t, cpu, irq_num=33):
    return {"IrqEntry": {"timestamp_ns": t, "cpu": cpu, "irq": irq_num, "handler_name_hash": 1}}


def slab_alloc(t, cpu, latency_ns=500):
    return {"SlabAlloc": {
        "timestamp_ns": t, "cpu": cpu, "bytes_req": random.choice([64, 128, 256, 512]),
        "bytes_alloc": random.choice([64, 128, 256, 512]), "latency_ns": latency_ns, "numa_node": 0,
    }}


def slab_free(t, cpu):
    return {"SlabFree": {"timestamp_ns": t, "cpu": cpu, "bytes_freed": random.choice([64, 128, 256])}}


def cq(t, cpu, latency_ns=2000, is_error=False):
    return {"CqCompletion": {
        "timestamp_ns": t, "cpu": cpu, "latency_ns": latency_ns,
        "queue_pair_num": random.randint(1, 8), "is_error": is_error, "opcode": 0,
    }}


def napi(t, cpu, budget=64, work_done=None):
    return {"NapiPoll": {
        "timestamp_ns": t, "cpu": cpu, "budget": budget,
        "work_done": work_done or random.randint(1, budget), "dev_name_hash": 0xcafebabe,
    }}


def hw_counter(t, port, counter_type, value):
    return {"HardwareCounter": {"timestamp_ns": t, "port_num": port, "counter": {counter_type: value}}}


def balanced_cpu():
    return random.randint(0, 3)


def jitter(base, pct=0.2):
    return int(base * random.uniform(1 - pct, 1 + pct))


def healthy_mixed_event(i):
    """One normal event, cycling through types."""
    t = ts(i)
    cpu = balanced_cpu()
    choice = i % 5
    if choice == 0:
        return irq(t, cpu)
    elif choice == 1:
        return slab_alloc(t, cpu, jitter(500))
    elif choice == 2:
        return cq(t, cpu, jitter(2000))
    elif choice == 3:
        return napi(t, cpu)
    else:
        return slab_free(t, cpu)


# ---------------------------------------------------------------------------
# Scenario 1: Healthy baseline (200 events, should stay Healthy throughout)
# ---------------------------------------------------------------------------
def gen_healthy_baseline():
    events = [healthy_mixed_event(i) for i in range(200)]
    return {
        "name": "healthy_baseline",
        "description": "200 events of normal operation — balanced IRQs, low latency, no errors. Must stay Healthy.",
        "events": events,
        "expected_states": [
            {"after_event_index": 99, "expected_state": "Healthy"},
            {"after_event_index": 199, "expected_state": "Healthy"},
        ],
    }


# ---------------------------------------------------------------------------
# Scenario 2: Interrupt skew ramp (200 events, gradual skew toward CPU 0)
# ---------------------------------------------------------------------------
def gen_interrupt_skew_ramp():
    events = []
    for i in range(200):
        t = ts(i)
        # 80% of events are IRQs so we accumulate enough data for the skew rule
        is_irq = (i % 5 != 4)
        if is_irq:
            if i < 50:
                cpu = balanced_cpu()
            elif i < 100:
                cpu = 0 if random.random() < 0.80 else random.randint(1, 3)
            else:
                cpu = 0 if random.random() < 0.93 else random.randint(1, 3)
            events.append(irq(t, cpu))
        else:
            if i % 10 == 4:
                events.append(slab_alloc(t, balanced_cpu(), jitter(500)))
            else:
                events.append(cq(t, balanced_cpu(), jitter(2000)))

    return {
        "name": "interrupt_skew_ramp",
        "description": "Gradual IRQ affinity skew — balanced for 50 events, then CPU 0 dominance ramps to 93%.",
        "events": events,
        "expected_states": [
            {"after_event_index": 49, "expected_state": "Healthy"},
            {"after_event_index": 199, "expected_state": "Degraded"},
        ],
    }


# ---------------------------------------------------------------------------
# Scenario 3: RDMA latency spike (200 events, sudden CQ latency jump)
# ---------------------------------------------------------------------------
def gen_rdma_latency_spike():
    events = []
    for i in range(200):
        t = ts(i)
        choice = i % 5

        if choice in (0, 1):
            events.append(irq(t, balanced_cpu()))
        elif choice == 2:
            events.append(slab_alloc(t, balanced_cpu(), jitter(500)))
        elif choice == 3:
            events.append(napi(t, balanced_cpu()))
        else:
            # CQ completion — where the spike happens
            if i < 80:
                lat = jitter(2000)
            elif i < 120:
                lat = jitter(12000)  # rising
            else:
                lat = jitter(30000)  # full spike (15x baseline)
            events.append(cq(t, balanced_cpu(), lat, is_error=(i > 140 and random.random() < 0.1)))

    return {
        "name": "rdma_latency_spike",
        "description": "Normal CQ latency for 80 events, then spike to 15x baseline. Should trigger Degraded.",
        "events": events,
        "expected_states": [
            {"after_event_index": 79, "expected_state": "Healthy"},
            {"after_event_index": 199, "expected_state": "Degraded"},
        ],
    }


# ---------------------------------------------------------------------------
# Scenario 4: Slab pressure cascade (200 events, slab latency explosion + CQ backlog)
# ---------------------------------------------------------------------------
def gen_slab_pressure_cascade():
    events = []
    for i in range(200):
        t = ts(i)

        if i % 5 in (0, 1):
            # Slab allocs — the pressure signal
            if i < 80:
                lat = jitter(500)
            elif i < 120:
                lat = jitter(5000)  # rising
            else:
                lat = jitter(15000)  # 30x baseline → Critical
            events.append(slab_alloc(t, balanced_cpu(), lat))
        elif i % 5 == 2:
            events.append(irq(t, balanced_cpu()))
        elif i % 5 == 3:
            # CQ completions accumulate during pressure
            lat = jitter(2000) if i < 100 else jitter(8000)
            events.append(cq(t, balanced_cpu(), lat, is_error=(i > 150 and random.random() < 0.15)))
        else:
            events.append(napi(t, balanced_cpu()))

    return {
        "name": "slab_pressure_cascade",
        "description": "Slab latency rises 30x while CQ completions back up — should reach Critical.",
        "events": events,
        "expected_states": [
            {"after_event_index": 79, "expected_state": "Healthy"},
            {"after_event_index": 199, "expected_state": "Critical"},
        ],
    }


# ---------------------------------------------------------------------------
# Scenario 5: Link flap critical (200 events, IB link failure + massive CQ latency)
# ---------------------------------------------------------------------------
def gen_link_flap_critical():
    events = []
    for i in range(200):
        t = ts(i)

        if i < 60:
            events.append(healthy_mixed_event(i))
        elif i < 80:
            # Warning signs: HW counters + moderate CQ latency
            if i % 4 == 0:
                events.append(hw_counter(t, 1, "SymbolErrors", (i - 60) * 50))
            elif i % 4 == 1:
                events.append(hw_counter(t, 1, "LinkDowned", (i - 60) // 5))
            elif i % 4 == 2:
                events.append(cq(t, balanced_cpu(), jitter(8000), is_error=random.random() < 0.3))
            else:
                events.append(irq(t, balanced_cpu()))
        else:
            # Full link flap: massive CQ latency, errors, HW counter events
            if i % 6 == 0:
                events.append(hw_counter(t, 1, "LinkDowned", (i - 60) // 3))
            elif i % 6 == 1:
                events.append(hw_counter(t, 1, "PortRcvErrors", (i - 80) * 100))
            elif i % 6 == 2:
                events.append(hw_counter(t, 1, "SymbolErrors", (i - 60) * 200))
            else:
                # CQ completions with massive latency
                lat = jitter(100000)  # 50x baseline
                events.append(cq(t, balanced_cpu(), lat, is_error=random.random() < 0.5))

    return {
        "name": "link_flap_critical",
        "description": "IB link flap at event 60 — HW counter anomalies + massive CQ latency spike to 50x. Should reach Critical.",
        "events": events,
        "expected_states": [
            {"after_event_index": 59, "expected_state": "Healthy"},
            {"after_event_index": 199, "expected_state": "Critical"},
        ],
    }


def write_scenario(scenario):
    path = os.path.join(SCENARIO_DIR, f"{scenario['name']}.json")
    with open(path, "w") as f:
        json.dump(scenario, f, indent=2)
        f.write("\n")
    print(f"  {path} ({len(scenario['events'])} events)")


if __name__ == "__main__":
    os.makedirs(SCENARIO_DIR, exist_ok=True)
    print("Generating ARGUS test scenarios:")
    write_scenario(gen_healthy_baseline())
    write_scenario(gen_interrupt_skew_ramp())
    write_scenario(gen_rdma_latency_spike())
    write_scenario(gen_slab_pressure_cascade())
    write_scenario(gen_link_flap_critical())
    print("Done.")
