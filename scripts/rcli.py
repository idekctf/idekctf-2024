from rcds.backends.rctf.rctf import RCTFAdminV1, FileTooLargeException
from pathlib import Path
import tempfile
import hashlib
import atexit
import yaml
import json
import glob

ROOT = Path('../')
# rctf_site = 'http://docker.homelab:8080'
# token = "1qa5e4nCGYGHwQhhdiL8u1mBc/8vKgWjA0UWz178thrVDwkPAnXwEco+GMJIMVmFh44GuyUV0xBzhKzVYUkBO73NT2cZrbJEzXU2utEYtxJnHYVpKy5y+5x6dFz4"
rctf_site = 'https://ctf.idek.team/'
token = "8bb0tU4HqfRHFLtPk28TrjpOrhjBsh1X80G2Rxjc/hZMiAeB1/bOP3kG59eFHCjIsaC/hIB+ekD9RuLB+9d0ZtdYz3e+0MllRXOaLIJjbPKDCyFsnghk2RdL0q38" 
chal_remote_host = 'chal.idek.team'
chal_remote_port = 1337
instancer_host = 'https://instancer.idek.team/'
admin_bot_host = 'https://admin-bot.idek.team/'

import tarfile
import os.path

def make_tarfile(output_filename, source_dir):
    with tarfile.open(output_filename, "w:gz") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))
    
    with open(output_filename, 'r+b') as f:
        f.seek(4, 0)
        f.write(b'\x00'*4) # zero out the timestamp


class Challenge:

    def __init__(self, name, author, flag, description, category=None, min_points=100, max_points=500, instancer=False, tiebreakEligible=True, id=None, **kwargs):
        self.name = name
        self.author = author
        self.flag = flag
        self.description = description
        self.instancer = instancer
        self.min_points = min_points
        self.max_points = max_points
        self.tiebreakEligible = tiebreakEligible
        self.category = category
        self.id = id

    def to_dict(self):
        return {
            'flag': self.flag,
            'name': self.name,
            'files': [],
            'author': self.author,
            'points': {
                'max': self.max_points,
                'min': self.min_points,
            },
            'category': self.category,
            'description': self.description,
            'tiebreakEligible': self.tiebreakEligible
        }

    @staticmethod
    def parse_meta(path: Path):
        id = str(path).replace('/', '-')
        category = path.parts[0]
        data = yaml.load(open(ROOT / path / 'meta.yaml', 'r').read(), Loader=yaml.CLoader)
        return Challenge(**data, category=category, id=id)

def match(chal_id, chal_dict):
    a = chal_dict.copy()
    a['id'] = chal_id
    return a in UPLOADED_CHALS

def upload_challenge(api: RCTFAdminV1, path: Path):
    meta_path = ROOT / path / 'meta.yaml'
    if not meta_path.exists():
        print("[!] No meta.yaml found", path)
        return
        # raise Exception("No meta.yaml found")
    
    id = str(path).replace('/', '-')
    category = path.parts[0]
    metadata_data = yaml.load(open(meta_path, 'r').read(), Loader=yaml.CLoader)
    if not metadata_data['public']:
        return
    chal = Challenge(**metadata_data, category=category, id=id)
    chal_dict = chal.to_dict()
    chal_id = path.parts[1]
    
    attachments_path = ROOT / path / 'attachments'
    kctf_path = ROOT / path / 'challenge.yaml'
    if kctf_path.exists():
        kctf_data = yaml.load(open(ROOT / path / 'challenge.yaml', 'r').read(), Loader=yaml.CLoader)
        kctf_name = kctf_data['metadata']['name']
        if 'http' in metadata_data and metadata_data['http']:
            chal_dict['description'] += f'''

[http://{kctf_name}.{chal_remote_host}:{chal_remote_port}](http://{kctf_name}.{chal_remote_host}:{chal_remote_port})
'''
        elif 'socat' in metadata_data and metadata_data['socat']:
            chal_dict['description'] += f'''

`socat -,raw,echo=0 tcp:{kctf_name}.{chal_remote_host}:{chal_remote_port}`
'''
        else:
            chal_dict['description'] += f'''

`nc {kctf_name}.{chal_remote_host} {chal_remote_port}`
'''
    if 'admin_bot' in metadata_data:
        chal_dict['description'] += f'''

[Admin Bot]({admin_bot_host}{chal_id})
'''
    if 'instancer' in metadata_data:
        instancer_id = metadata_data.get('instancer_id', chal_id)
        chal_dict['description'] += f'''

[Instancer]({instancer_host}challenge/{instancer_id})
'''
    try:
        if 'attachments' in metadata_data:
            uploads = {}
            for filename in metadata_data['attachments']:
                uploads[filename] = open(attachments_path / filename, 'rb').read()
            urls = api.create_upload(uploads)
            for name in uploads.keys():
                chal_dict['files'].append({
                    'url': urls[name],
                    'name': name
                })
        elif attachments_path.exists():
            dir = tempfile.TemporaryDirectory(delete=False)
            targz_file = f'{chal_id}.tar.gz'
            tar_path = dir.name + '/' + targz_file
            make_tarfile(tar_path, str(attachments_path))
            filedata = open(tar_path, 'rb').read()
            uploads = {targz_file: filedata}
            urls = api.create_upload(uploads)
            for name in uploads.keys():
                chal_dict['files'].append({
                    'url': urls[name],
                    'name': name
                })
    except FileTooLargeException:
        print("Failed to upload")

    if match(chal.id, chal_dict):
        return
    
    print(path)
    api.put_challenge(chal.id, chal_dict)


api = RCTFAdminV1(rctf_site, token)

BLACKLIST = ['klodd','scripts','terraform']

print(len(api.list_challenges()))

UPLOADED_CHALS = [data for data in api.list_challenges()]
    
#     api.delete_challenge(data['id'])

for path in glob.glob('*/*', root_dir='../'):
    if any(path.startswith(b) for b in BLACKLIST):
        continue
    
    upload_challenge(api, Path(path))