import base64
import hashlib
import json
import math
import os
import re
import urllib.parse

from .common import InfoExtractor
from ..aes import aes_cbc_decrypt_bytes, aes_cbc_encrypt_bytes, pkcs7_padding, unpad_pkcs7
from ..utils import (
    int_or_none,
    str_or_none,
    traverse_obj,
)


class AknigaIE(InfoExtractor):
    IE_NAME = 'akniga'
    IE_DESC = 'Audiobooks'
    _VALID_URL = r'https?://(?:www\.)?akniga\.org/(?P<id>[\w-]+)'
    _TESTS = [{
        'url': 'https://akniga.org/dik-filip-suvenir',
        'info_dict': {
            'id': 'dik-filip-suvenir',
            'ext': 'm4a',
            'title': 'Дик Филип - Сувенир',
            'description': 'contains:Дик Филип',
        },
        'params': {'skip_download': True},
    }]

    _PASSWORD = 'EKxtcg46V'
    _KEY_LEN = 32
    _IV_LEN = 16

    def _evp_bytes_to_key(self, password, salt, key_len, iv_len):
        derived = b''
        block = b''

        while len(derived) < key_len + iv_len:
            h = hashlib.md5()
            if block:
                h.update(block)
            h.update(password)
            h.update(salt)
            block = h.digest()
            derived += block

        return derived[:key_len]

    def _decrypt_hls_url(self, ciphertext_b64, iv_hex, salt_hex):
        ciphertext = base64.b64decode(ciphertext_b64.replace('\\/', '/'))
        iv = bytes.fromhex(iv_hex) if iv_hex else bytes(self._IV_LEN)
        salt = bytes.fromhex(salt_hex) if salt_hex else bytes(8)

        key = self._evp_bytes_to_key(self._PASSWORD.encode(), salt, self._KEY_LEN, self._IV_LEN)
        decrypted = aes_cbc_decrypt_bytes(ciphertext, key, iv)
        decrypted = unpad_pkcs7(decrypted)

        url = decrypted.decode('utf-8').replace('\\', '').replace('"', '')
        return url

    def _get_assets_password(self):
        chars = [0x79, 0x6d, 0x58, 0x45, 0x4b, 0x7a, 0x76, 0x55, 0x6b, 0x75, 0x6f, 0x35, 0x47, 0x30]
        return ''.join(chr(c) for c in chars)

    def _start_transition(self, security_key):
        pi_str = format(math.pi, '.15f')[:18]
        password = self._get_assets_password()

        even_digit_map = {
            0: 'A',
            2: 'B',
            4: 'C',
            6: 'D',
            8: 'E',
        }

        for char in pi_str:
            if char.isdigit() and int(char) % 2 == 0:
                password += even_digit_map[int(char)]
            else:
                password += char

        salt = os.urandom(8)
        key = self._evp_bytes_to_key(password.encode(), salt, 32, 16)
        iv = os.urandom(16)

        from ..aes import aes_cbc_encrypt_bytes, pkcs7_padding

        data = json.dumps(security_key).encode()
        ciphertext = aes_cbc_encrypt_bytes(data, key, iv)

        result = {
            'ct': base64.b64encode(ciphertext).decode(),
            's': salt.hex(),
        }
        return json.dumps(result)

    def _real_extract(self, url):
        video_id = self._match_id(url)

        init_url = 'https://akniga.org/'

        self._download_webpage(init_url, video_id, 'Initializing session')

        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0',
            'Accept-Language': 'ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3',
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
        }

        webpage = self._download_webpage(
            url, video_id, 'Downloading page',
            headers=headers)

        security_key = self._html_search_regex(
            r"LIVESTREET_SECURITY_KEY\s*=\s*'([a-fA-F0-9]+)'",
            webpage, 'security key')

        bid = self._html_search_regex(
            r'<article[^>]+data-bid=["\']([^"\']+)["\']',
            webpage, 'book id')

        ajax_url = f'https://akniga.org/ajax/b/{bid}'
        hash_value = json.loads(self._start_transition(security_key))

        post_data = urllib.parse.urlencode({
            'bid': bid,
            'hash': json.dumps(hash_value),
            'hls': 'true',
            'security_ls_key': security_key,
        }).encode()

        ajax_headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'X-Requested-With': 'XMLHttpRequest',
            'Origin': 'https://akniga.org',
            'Referer': url,
        }
        ajax_headers.update(headers)

        ajax_resp = self._download_json(
            ajax_url, video_id, 'Downloading AJAX response',
            headers=ajax_headers, data=post_data)

        title = traverse_obj(ajax_resp, ('title',)) or traverse_obj(ajax_resp, ('titleonly',))
        author = ajax_resp.get('author', '')
        performer = ajax_resp.get('performer', '')

        if not performer:
            raw_performer = ajax_resp.get('sTextPerformer', '')
            if raw_performer:
                match = re.search(r'<span>(.*?)</span>', raw_performer)
                if match:
                    performer = match.group(1)

        poster = ajax_resp.get('preview', '')

        items_data = ajax_resp.get('items', '[]')
        tracks = json.loads(items_data)

        duration = 0
        if tracks:
            duration = traverse_obj(tracks[-1], ('time_finish',))

        hres = ajax_resp.get('hres', '')
        if not hres:
            self.report_warning('No hres found in response')
            return {'id': video_id, 'title': video_id, 'formats': []}

        hres_data = json.loads(hres)
        ciphertext = hres_data.get('ct', '')
        iv_hex = hres_data.get('iv', '')
        salt_hex = hres_data.get('s', '')

        m3u8_url = self._decrypt_hls_url(ciphertext, iv_hex or '00' * 16, salt_hex or '00' * 16)

        formats = self._extract_m3u8_formats(m3u8_url, video_id, ext='m4a', entry_protocol='m3u8')
        for f in formats:
            f.setdefault('vcodec', 'none')

        return {
            'id': video_id,
            'title': title or video_id,
            'description': author,
            'uploader': performer,
            'thumbnail': poster,
            'duration': int_or_none(duration),
            'formats': formats,
        }
