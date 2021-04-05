import os
import sys
import requests
import json
import logging
import pyinotify

from requests.api import get
from requests.models import HTTPBasicAuth
from urllib.parse import urljoin


WG_BASE_URL = os.environ.get('WG_BASE_URL')
WG_AUTH_USER = os.environ.get('WG_AUTH_USER')
WG_AUTH_PASS = os.environ.get('WG_AUTH_PASS')


OPN_URL = os.environ.get('OPN_URL')
OPN_KEY = os.environ.get('OPN_KEY')
OPN_SECRET =  os.environ.get('OPN_SECRET')
OPN_SERVER_ID = os.environ.get('OPN_SERVER_ID')

WATCH_FOLDER = os.environ.get('WATCH_FOLDER')
MAPPER_FILE = os.environ.get('MAPPER_FILE')

logging.basicConfig(level=logging.INFO, format="[%(asctime)s][%(levelname)8s][%(funcName)25s:%(lineno)s]: %(message)s")


def get_token(wg_base_url, wg_auth_user, wg_auth_pass):
    r = requests.get(
        urljoin(wg_base_url, "/api/v1.0/auth/oauth2_url"),
        auth=HTTPBasicAuth(wg_auth_user, wg_auth_pass),
    )

    client_id = r.json()["clientId"]
    state = r.json()["state"]

    payload = {"clientid": client_id, "code": "", "state": state}

    r = requests.post(
        urljoin(wg_base_url, "/api/v1.0/auth/oauth2_exchange"),
        json=payload,
        auth=HTTPBasicAuth(wg_auth_user, wg_auth_pass),
    )

    return r.json()


def get_wg_clients(wg_base_url,token, wg_auth_user, wg_auth_pass):
    r = requests.get(
        urljoin(wg_base_url, "/api/v1.0/client"),
        auth=HTTPBasicAuth(wg_auth_user, wg_auth_pass),
        headers={"x-wg-gen-web-auth": token},
    )
    return r.json()

def get_wg_server(wg_base_url, token, wg_auth_user, wg_auth_pass):
    r = requests.get(
        urljoin(wg_base_url, "/api/v1.0/server"),
        auth=HTTPBasicAuth(wg_auth_user, wg_auth_pass),
        headers={"x-wg-gen-web-auth": token},
    )
    return r.json()

def get_id_mapper():
    try:
        f = open(MAPPER_FILE)
        return json.loads(f.read())
    except IOError:
        f = open(MAPPER_FILE, "w+")
        f.write(json.dumps({}))
        return {}
    finally:
        f.close()

def save_id_mapper(data):
    f = open(MAPPER_FILE, "w")
    f.write(json.dumps(data))

def format_adress(address):
    to_return = ""
    for addr in address:
        to_return = to_return + addr + ","

    return to_return[:-1]


def create_opn(data, opn_url, opn_key, opn_secret):
    logging.info(f"Creating new client : {data.get('name')}" )
    j_data = {
        "client": {
            "enabled": "1" if data.get("enable") else "0",
            "name": data.get("name"),
            "psk": data.get("presharedKey"),
            "pubkey": data.get("publicKey"),
            "tunneladdress": format_adress(data.get("address")),
            "serveraddress": "",
            "serverport": "",
            "keepalive": "",
        }
    }
    r = requests.post(
        urljoin(opn_url, "/api/wireguard/client/addClient"),
        json=j_data,
        auth=HTTPBasicAuth(opn_key, opn_secret),
    )
    if r.status_code != 200 or r.json().get('result') != "saved":
        logging.error("Fail to save client to opnsense")
        return None
    return r.json().get("uuid")

def edit_opn(id_opn, data, opn_url, opn_key, opn_secret):
    logging.info(f"Edit client : {data.get('name')}" )
    j_data = {
        "client": {
            "enabled": "1" if data.get("enable") else "0",
            "name": data.get("name"),
            "psk": data.get("presharedKey"),
            "pubkey": data.get("publicKey"),
            "tunneladdress": format_adress(data.get("address")),
            "serveraddress": "",
            "serverport": "",
            "keepalive": "",
        }
    }
    r = requests.post(
        urljoin(opn_url, f"/api/wireguard/client/setClient/{id_opn}"),
        json=j_data,
        auth=HTTPBasicAuth(opn_key, opn_secret),
    )
    if r.status_code != 200 or r.json().get('result') != "saved":
        logging.error("Fail to edit client to opnsense")
        logging.error(r.text)
        return False
    return True


def del_opn(id_opn, opn_url, opn_key, opn_secret):
    logging.info(f"Del client : {id_opn}" )
    r = requests.post(
        urljoin(opn_url, f"/api/wireguard/client/delClient/{id_opn}"),
        auth=HTTPBasicAuth(opn_key, opn_secret),
    )
    if r.status_code != 200 or r.json().get('result') != "deleted":
        logging.error("Fail to del client to opnsense")
        logging.error(r.text)
        return False
    return True


def update_server_client_list(opn_server_id, server_conf, client_list, opn_url, opn_key, opn_secret):
    logging.info(f"Edit server : {opn_server_id}" )

    j_data = {
        "server": {
            "enabled": "1",
            "disableroutes": "0",
            "dns": "",
            "gateway": "",
            "mtu": "",
            "name": "WgGen",
            "port": str(server_conf.get('listenPort')),
            "privkey": server_conf.get('privateKey'),
            "pubkey": server_conf.get('publicKey'),
            "tunneladdress": format_adress(server_conf.get('address')),
            "peers": format_adress(client_list)
        }
    }

    r = requests.post(
        urljoin(opn_url, f"/api/wireguard/server/setServer/{opn_server_id}"),
        json=j_data,
        auth=HTTPBasicAuth(opn_key, opn_secret),
    )
    if r.status_code != 200 or r.json().get('result') != "saved":
        logging.error("Fail to edit server to opnsense")
        logging.error(r.text)
        return False
    return True

def create_server(server_conf, client_list, opn_url, opn_key, opn_secret):
    logging.info(f"Create server" )

    j_data = {
        "server": {
            "enabled": "1",
            "disableroutes": "0",
            "dns": "",
            "gateway": "",
            "mtu": "",
            "name": "WgGen",
            "port": str(server_conf.get('listenPort')),
            "privkey": server_conf.get('privateKey'),
            "pubkey": server_conf.get('publicKey'),
            "tunneladdress": format_adress(server_conf.get('address')),
            "peers": format_adress(client_list)
        }
    }

    r = requests.post(
        urljoin(opn_url, f"/api/wireguard/server/addServer"),
        json=j_data,
        auth=HTTPBasicAuth(opn_key, opn_secret),
    )
    if r.status_code != 200 or r.json().get('result') != "saved":
        logging.error("Fail to create server to opnsense")
        logging.error(r.text)
        return None
    return r.json().get("uuid")

def restart_server(opn_url, opn_key, opn_secret):
    logging.info('Restart Server')
    r = requests.post(
        urljoin(opn_url, f"/api/wireguard/service/restart"),
        auth=HTTPBasicAuth(opn_key, opn_secret),
    )
    if r.status_code != 200:
        logging.error("Fail to restart")
        logging.error(r.text)

def reconfigure_server(opn_url, opn_key, opn_secret):
    logging.info('Reconfigure Server')
    r = requests.post(
        urljoin(opn_url, f"/api/wireguard/service/reconfigure"),
        auth=HTTPBasicAuth(opn_key, opn_secret),
    )
    if r.status_code != 200 or r.json().get('status') != "ok":
        logging.error("Fail to reconfigure")
        logging.error(r.text)


def check_env():
    if WG_BASE_URL is None or WG_AUTH_USER is None or \
        WG_AUTH_PASS is None or OPN_URL is None or \
        OPN_KEY is None or OPN_SECRET is None or \
        WATCH_FOLDER is None or MAPPER_FILE is None:
        reset = 'WG_BASE_URL=\nWG_AUTH_USER=\nWG_AUTH_PASS=\nOPN_URL=\nOPN_KEY=\nOPN_SECRET=\nOPN_SERVER_ID=\nWATCH_FOLDER=/wg_data\nMAPPER_FILE=/data/id_mapper.json'
        logging.fatal('Please set env varriable :')
        print(reset)
        sys.exit(1)
    if OPN_SERVER_ID is not None:
        mapper = get_id_mapper()
        mapper['server'] = OPN_SERVER_ID
        save_id_mapper(mapper)

def loop(notifier):
    logging.info("Trigger")
    wg_token = get_token(WG_BASE_URL, WG_AUTH_USER, WG_AUTH_PASS)
    clients = get_wg_clients(WG_BASE_URL, wg_token, WG_AUTH_USER, WG_AUTH_PASS)
    mapper = get_id_mapper()
    to_edit = []
    to_create = []
    for cli in clients:
        if cli.get("id") in mapper:
            mapper.pop(cli.get("id"))
            to_edit.append(cli)
        else:
            to_create.append(cli)
    to_remove = list(mapper.keys())

    if 'server' in to_remove:
        to_remove.remove('server')


    new_mapper = get_id_mapper()
    # Update clients
    for to_ed in to_edit:
        status = edit_opn(new_mapper[to_ed.get("id")] ,to_ed, OPN_URL, OPN_KEY, OPN_SECRET)
        if not status:
            to_create.append(to_ed)
            new_mapper.pop(to_ed.get("id"))


    # Create new clients
    to_map = {}
    for to_cr in to_create:
        uuid = create_opn(to_cr, OPN_URL, OPN_KEY, OPN_SECRET)
        if uuid is not None:
            to_map[to_cr.get('id')] =  uuid

    

    # Merge mapper
    new_mapper = {**new_mapper, **to_map}

    for to_d in to_remove:
        del_opn(new_mapper[to_d], OPN_URL, OPN_KEY, OPN_SECRET)
        new_mapper.pop(to_d)
    save_id_mapper(new_mapper)

    server_clients = []
    
    for client in new_mapper:
        if client != 'server':
            server_clients.append(new_mapper.get(client))

    server_conf = get_wg_server(WG_BASE_URL, wg_token, WG_AUTH_USER, WG_AUTH_PASS)
    if new_mapper.get('server') is None:
        uuid = create_server(server_conf, server_clients, OPN_URL, OPN_KEY, OPN_SECRET)
        new_mapper['server'] = uuid
        save_id_mapper(new_mapper)
        restart_server(OPN_URL, OPN_KEY, OPN_SECRET)

    else:
        server_id = new_mapper.get('server')
        update_server_client_list(server_id, server_conf, server_clients, OPN_URL, OPN_KEY, OPN_SECRET)
        reconfigure_server(OPN_URL, OPN_KEY, OPN_SECRET)
    
    logging.info("Done")

    
if __name__ == "__main__":
    check_env()
    wm = pyinotify.WatchManager()
    notifier = pyinotify.Notifier(wm)
    wm.add_watch(WATCH_FOLDER, pyinotify.IN_CREATE | pyinotify.IN_MODIFY | pyinotify.IN_MOVED_FROM |  pyinotify.IN_MOVED_TO)
    notifier.loop(callback=loop)
