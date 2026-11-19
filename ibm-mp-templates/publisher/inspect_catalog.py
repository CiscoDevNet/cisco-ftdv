#!/usr/bin/env python3
"""Read exact published Catalog versions, anonymously or with the current IBM CLI identity."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess


def catalog_read(url, authenticated=False):
    config = ''
    if authenticated:
        result = subprocess.run(['ibmcloud','iam','oauth-tokens','--output','JSON'],capture_output=True,text=True,timeout=60)
        if result.returncode:
            raise ValueError('IBM CLI authentication is unavailable; sign in in your terminal.')
        try:
            token = json.loads(result.stdout)['iam_token']
        except (KeyError, json.JSONDecodeError):
            raise ValueError('IBM CLI did not return an IAM token.') from None
        if not token.lower().startswith('bearer '):
            token = 'Bearer ' + token
        # Keep the token off command arguments, output and evidence files.
        config = 'header = ' + json.dumps('Authorization: ' + token) + '\n'
    result = subprocess.run(['curl','--config','-','--silent','--show-error','--max-time','45','--header','Accept: application/json','--write-out','\n%{http_code}',url],input=config,capture_output=True,text=True,timeout=50)
    if result.returncode:
        raise ValueError('Certificate-verified Catalog download failed: ' + result.stderr.strip())
    payload, status = result.stdout.rsplit('\n',1)
    if status != '200':
        raise ValueError('Catalog read returned HTTP '+status+'. Anonymous 403 does not establish that an allowlisted account lacks access.')
    return json.loads(payload)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('product',choices=('ftdv','fmcv'))
    parser.add_argument('--authenticated',action='store_true',help='Use the current IBM CLI account; never pass a token on the command line')
    parser.add_argument('--output',type=Path,help='Create a new evidence file outside the repository')
    args=parser.parse_args()
    project=Path(__file__).resolve().parents[1]
    module=project/'solutions'/(args.product+'-ibm-tf')
    text=(module/'locals.tf').read_text()
    cid=re.search(rf'{args.product}_catalog_id\s*=\s*"([^"]+)"',text)[1]
    oid=re.search(rf'{args.product}_catalog_offering_id\s*=\s*"([^"]+)"',text)[1]
    url=f'https://cm.globalcatalog.cloud.ibm.com/api/v1-beta/catalogs/{cid}/offerings/{oid}'
    try:
        offering=catalog_read(url,args.authenticated)
        catalog=json.loads((module/(args.product+'-images.json')).read_text())
        versions=[v for kind in offering.get('kinds',[]) for v in kind.get('versions',[]) if v.get('is_consumable') and not v.get('deprecated')]
        result={'checked_at_utc':datetime.now(timezone.utc).isoformat(),'source_url':url,'authenticated':args.authenticated,'reference_access_scope':'selected_accounts' if args.authenticated else 'public','hidden':offering.get('hidden'),'published_approved':offering.get('publish',{}).get('published_approved'),'releases':{}}
        for label,entry in catalog['releases'].items():
            matches=[v for v in versions if v.get('version')==entry['catalog_version']]
            if len(matches)!=1:
                raise ValueError('Expected exactly one consumable version matching '+entry['catalog_version'])
            v=matches[0];metadata=v.get('metadata',{}).get('vsi_vpc',{})
            result['releases'][label]={'catalog_version':v.get('version'),'version_crn':v.get('crn'),'catalog_version_locator':v.get('version_locator'),'catalog_sha256':v.get('sha'),'supported_regions':sorted({x['region'] for x in metadata.get('images',[])}),'minimum_boot_volume_gb':metadata.get('minimum_provisioned_size'),'entitlement':v.get('entitlement'),'state':v.get('state')}
        payload=json.dumps(result,indent=2)+'\n'
        if args.output:
            output=args.output.resolve()
            if output.is_relative_to(project.parent):
                parser.error('Keep account-specific evidence outside the repository')
            with open(output,'x',opener=lambda path,flags:__import__('os').open(path,flags,0o600)) as file:
                file.write(payload)
        print(payload)
        print('Review exact references, digest, intended-account access and plan requirements before updating image JSON. Authenticated success does not establish access for all accounts or guest/profile qualification.')
    except (ValueError,KeyError,OSError,subprocess.TimeoutExpired) as error:
        parser.exit(1,str(error)+'\n')


if __name__=='__main__':
    main()
