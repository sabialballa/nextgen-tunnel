#!/usr/bin/env python3
"""Check intermittent probe policy in a marked VM; no real network mutation.

This simulated-probe regression complements the real carrier-outage acceptance.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if os.geteuid()!=0 or not Path('/etc/nextgen-lab-owned').exists():p.error('marked disposable root VM required')
    source=Path(__file__).resolve().parents[1]/'site_watchdog.py'
    spec=importlib.util.spec_from_file_location('watchdog_policy',source);watch=importlib.util.module_from_spec(spec);spec.loader.exec_module(watch)
    with tempfile.TemporaryDirectory(prefix='nextgen-watchdog-policy-') as tmp:
        work=Path(tmp);watch.STATE=work/'state';(work/'boot').write_text('policy-test-boot')
        (work/'config').write_text(json.dumps(dict(name='ngt-site-main',endpoint='127.0.0.1:51811',remote_routes=['10.79.0.2/32'],peer_public_key='simulated-peer')))
        config=work/'sites/ngt-site-main/wg.conf';config.parent.mkdir(parents=True);config.write_text('simulated owned configuration');config.chmod(0o600)
        mapping={'/etc/nextgen-stack/site.json':work/'config','/proc/sys/kernel/random/boot_id':work/'boot','/var/lib/nextgen-sites':work/'sites'}
        watch.Path=lambda value:mapping.get(str(value),Path(value))
        outcomes=iter([False,False,True,False,False,True,False,False,True,True,True]);calls=[]
        def run(args):
            calls.append(args)
            return subprocess.CompletedProcess(args,0 if 'ping' not in args or next(outcomes) else 1,stdout='',stderr='')
        watch.run=run;states=[]
        for _ in range(11):
            watch.main();states.append(json.loads((watch.STATE/'state.json').read_text()))
        assert states[2]['failures']==2 and states[5]['failures']==4,'isolated successes hid an intermittent outage'
        assert states[7]['engine_restarts']==1,'six failures separated by isolated successes did not trigger recovery'
        assert states[8]['failures']==6 and states[9]['failures']==6,'recovery declared before sustained success'
        assert states[10]['failures']==0 and states[10]['healthy_streak']==3,'sustained success did not clear outage'
        assert sum(c[:2]==['systemctl','restart'] for c in calls)==1,'unbounded restarts'
        report=dict(success=True,kind='simulated probe policy regression, not a real transport recovery',isolated_success_preserves_outage=True,six_intermittent_failures_trigger_one_restart=True,three_consecutive_successes_clear_outage=True)
    a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))

if __name__=='__main__':main()
