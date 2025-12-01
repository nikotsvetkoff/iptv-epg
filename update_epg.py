#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Automatizare EPG:
- Descarcă 2 surse XMLTV online
- Filtrează doar canalele din channels.txt
- Creează fișierul final XML
- Îl comprimă în .gz
- Îl urcă pe GitHub (suprascrie zilnic)
"""

import os
import sys
import time
import gzip
import base64
import logging
import xml.etree.ElementTree as ET
import requests
from typing import List, Tuple, Set

# === CONFIGURARE ===
EPG_URLS = [
    "http://epg.it999.ru/epg2.xml.gz",
    "https://iptvx.one/EPG_NOARCH"
]

CHANNELS_FILE = "channels.txt"  # lista canalelor dorite (tvg-id)

# Config GitHub
GITHUB_REPO = "nikotsvetkoff/iptv-epg"   # repo-ul tău
GITHUB_BRANCH = "main"
GITHUB_PATH_XML = "selected_channels.xml"
GITHUB_PATH_GZ = "selected_channels.xml.gz"
GITHUB_COMMIT_MSG = "Actualizare automată EPG (filtrat + comprimat)"

# Setări rețea
HTTP_TIMEOUT = 30
HTTP_RETRIES = 3
HTTP_BACKOFF = 2.0

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

# === Funcții auxiliare ===
def load_selected_ids(path: str) -> List[str]:
    """Citește lista canalelor din channels.txt"""
    ids: List[str] = []
    if not os.path.exists(path):
        logging.error("Fișierul channels.txt lipsește: %s", path)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ids.append(line.split("#")[0].strip())
    if not ids:
        logging.error("Nu s-au găsit ID-uri în %s", path)
        sys.exit(1)
    logging.info("Am încărcat %d ID-uri de canale", len(ids))
    return ids

def http_get(session: requests.Session, url: str) -> bytes:
    """Descarcă fișierul EPG cu retry și timeout"""
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            resp = session.get(url, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            return resp.content
        except Exception as e:
            logging.warning("Eroare la descărcare (%s), încercarea %d/%d: %s",
                            url, attempt, HTTP_RETRIES, e)
            if attempt < HTTP_RETRIES:
                time.sleep(HTTP_BACKOFF * attempt)
            else:
                raise

def parse_xmltv(content: bytes, is_gzip: bool) -> ET.Element:
    """Dezarhivează și parsează XMLTV"""
    data = gzip.decompress(content) if is_gzip else content
    root = ET.fromstring(data)
    return root

def filter_xmltv(root: ET.Element, wanted_ids: Set[str]) -> Tuple[List[ET.Element], List[ET.Element]]:
    """Filtrează doar canalele și programele dorite"""
    channels: List[ET.Element] = []
    programmes: List[ET.Element] = []
    seen_channel_ids: Set[str] = set()
    seen_programme_keys: Set[Tuple[str, str, str]] = set()

    for ch in root.findall("channel"):
        cid = ch.attrib.get("id")
        if cid and cid in wanted_ids and cid not in seen_channel_ids:
            channels.append(ch)
            seen_channel_ids.add(cid)

    for pr in root.findall("programme"):
        cid = pr.attrib.get("channel")
        if cid and cid in wanted_ids:
            start = pr.attrib.get("start", "")
            stop = pr.attrib.get("stop", "")
            key = (cid, start, stop)
            if key not in seen_programme_keys:
                programmes.append(pr)
                seen_programme_keys.add(key)

    return channels, programmes

def build_final_tv(channels: List[ET.Element], programmes: List[ET.Element]) -> ET.Element:
    """Construiește XMLTV final"""
    tv = ET.Element("tv")
    for ch in channels:
        tv.append(ch)
    for pr in programmes:
        tv.append(pr)
    return tv

def to_xml_bytes(root: ET.Element) -> bytes:
    """Transformă XML în bytes"""
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)

def compress_gzip(data: bytes) -> bytes:
    """Comprimă fișierul XML în .gz"""
    return gzip.compress(data)

def github_get_sha(session: requests.Session, repo: str, branch: str, path: str, token: str) -> str:
    """Obține SHA-ul fișierului existent pe GitHub (pentru overwrite)"""
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    headers = {"Authorization": f"token {token}"}
    params = {"ref": branch}
    resp = session.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
    if resp.status_code == 200:
        return resp.json().get("sha")
    return ""

def github_put_file(session: requests.Session, repo: str, branch: str, path: str, token: str, content_b: bytes, message: str, sha: str = "") -> None:
    """Urcă fișierul pe GitHub"""
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    headers = {"Authorization": f"token {token}"}
    payload = {
        "message": message,
        "content": base64.b64encode(content_b).decode("utf-8"),
        "branch": branch
    }
    if sha:
        payload["sha"] = sha
    resp = session.put(url, headers=headers, json=payload, timeout=HTTP_TIMEOUT)
    resp.raise_for_status()
    logging.info("Fișierul %s a fost urcat pe GitHub.", path)

def main() -> None:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        logging.error("Lipsește GITHUB_TOKEN (trebuie setat ca secret în GitHub Actions)")
        sys.exit(1)

    wanted_ids = set(load_selected_ids(CHANNELS_FILE))
    session = requests.Session()
    session.headers.update({"User-Agent": "EPG-Automation/1.0"})

    all_channels: List[ET.Element] = []
    all_programmes: List[ET.Element] = []

    for url in EPG_URLS:
        logging.info("Descărcare: %s", url)
        content = http_get(session, url)
        root = parse_xmltv(content, is_gzip=url.endswith(".gz"))
        chans, progs = filter_xmltv(root, wanted_ids)
        logging.info("Din sursa %s: %d canale, %d programe", url, len(chans), len(progs))
        all_channels.extend(chans)
        all_programmes.extend(progs)

    logging.info("Construim XMLTV final...")
    final_tv = build_final_tv(all_channels, all_programmes)
    xml_bytes = to_xml_bytes(final_tv)
    gz_bytes = compress_gzip(xml_bytes)
    logging.info("Dimensiuni finale: XML=%.2f MB, GZ=%.2f MB", len(xml_bytes)/1e6, len(gz_bytes)/1e6)

    for path, content in ((GITHUB_PATH_XML, xml_bytes), (GITHUB_PATH_GZ, gz_bytes)):
        sha = github_get_sha(session, GITHUB_REPO, GITHUB_BRANCH, path, token)
        github_put_file(session, GITHUB_REPO, GITHUB_BRANCH, path, token, content, GITHUB_COMMIT_MSG, sha)

    logging.info("Gata. Linkuri RAW:")
    logging.info("XML: https://raw.githubusercontent.com/%s/%s/%s", GITHUB_REPO, GITHUB_BRANCH, GITHUB_PATH_XML)
    logging.info("GZ : https://raw.githubusercontent.com/%s/%s/%s", GITHUB_REPO, GITHUB_BRANCH, GITHUB_PATH_GZ)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error("Eroare fatală: %s", e)
        sys.exit(1)
