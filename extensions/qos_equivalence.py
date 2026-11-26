#!/usr/bin/env python3
"""Evidence-based QoS comparison with cFosSpeed; cannot certify without measured data.

Input JSON must contain paired baseline and candidate trials for the same traffic
scenario and link. Does not execute tests or alter networking. A passing comparison
is not a product-level certification of untested L7 / Windows-process features.
"""
import json
import math
import pathlib
import sys

REQUIRED_SCENARIOS=('idle','saturated_upload','saturated_download','bidirectional','interactive_under_load')
METRICS={'rtt_p95_ms':(1.15,3.0), 'rtt_p99_ms':(1.20,5.0),
         'jitter_p95_ms':(1.20,2.0), 'loss_pct':(1.1,0.1),
         'throughput_down_mbps':(0.92,0.0), 'throughput_up_mbps':(0.92,0.0),
         'cpu_pct':(1.35,5.0)}
LOWER_BETTER={'rtt_p95_ms','rtt_p99_ms','jitter_p95_ms','loss_pct','cpu_pct'}

def valid_num(x):
    if not isinstance(x,(int,float)) or isinstance(x,bool) or x<0:return False
    try:return math.isfinite(x)
    except OverflowError:return False

def evaluate(report):
    """Reject incomplete or incomparable reports, rather than inferring parity."""
    if not isinstance(report,dict):raise ValueError('report must be an object')
    if report.get('schema')!=1:raise ValueError('unsupported schema')
    if not isinstance(report.get('link_id'),str) or len(report['link_id'])<8:raise ValueError('link id missing')
    if not isinstance(report.get('hardware_profile'),str) or not report['hardware_profile']:
        raise ValueError('hardware profile missing')
    if report.get('measured_on_same_link') is not True:raise ValueError('different test links')
    scenarios=report.get('scenarios')
    if not isinstance(scenarios,dict) or any(x not in scenarios for x in REQUIRED_SCENARIOS):
        raise ValueError('missing required scenarios')
    results={};overall=True
    for name in REQUIRED_SCENARIOS:
        value=scenarios[name]
        if not isinstance(value,dict):raise ValueError('scenario invalid: '+name)
        baseline=value.get('cfosspeed');candidate=value.get('iptm')
        if not isinstance(baseline,dict) or not isinstance(candidate,dict):
            raise ValueError('paired measurements required: '+name)
        # At least three independent runs for each configuration, not an average of one.
        for role,trial in [('cfosspeed',baseline),('iptm',candidate)]:
            if type(trial.get('independent_runs'))!=int or trial['independent_runs']<3:
                raise ValueError('three runs required: '+name+'/'+role)
            if not all(valid_num(trial.get(k)) for k in METRICS) or trial['loss_pct']>100 or trial['rtt_p99_ms']<trial['rtt_p95_ms']:
                raise ValueError('invalid or missing metric: '+name+'/'+role)
        checks={}
        for metric,(factor,allowance) in METRICS.items():
            ref=baseline[metric];got=candidate[metric]
            if metric in LOWER_BETTER:
                threshold=max(ref*factor,ref+allowance)
                passed=got<=threshold
            else:
                threshold=ref*factor
                passed=got>=threshold
            checks[metric]={'pass':passed,'reference':ref,'measured':got,'threshold':round(threshold,4)}
            overall=overall and passed
        results[name]=checks
    return {'accepted_comparison':overall,'comparison_complete':True,'scenarios':results,
            'product_equivalence_certified':False,
            'scope':'Comparative kernel-level traffic metrics only; no proof of process/L7 parity'}

if __name__=='__main__':
    try:
        if len(sys.argv)!=2:raise ValueError('Usage: qos_equivalence.py measurements.json')
        path=pathlib.Path(sys.argv[1])
        if path.stat().st_size>512*1024:raise ValueError('report too large')
        data=json.loads(path.read_text())
        print(json.dumps(evaluate(data),sort_keys=True))
    except (OSError,ValueError,TypeError) as e:
        print(json.dumps({'comparison_complete':False,'accepted_comparison':False,'error':str(e)}))
        sys.exit(2)
