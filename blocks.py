#!/usr/bin/python3

'''
Based on story https://pastebin.com/HN6hH1j0
'''

import websocket
import time, json
from datetime import datetime, timezone, timedelta
import dateutil, calendar
from telethon import TelegramClient
import requests
import blocksmith, hashlib, base58, codecs

from bitcoinutils.setup import setup
from bitcoinutils.script import Script
from bitcoinutils.keys import P2wpkhAddress, P2wshAddress, P2shAddress, PrivateKey, PublicKey
import binascii

botToken = 'XXXXXXXXXXXXX'
gchatId = 'XXXXXXXXXXXXX'

try:
    import thread
except ImportError:
    import _thread as thread

f = open("webSocketTester.log", "a")

haseum = ""
old_msg=""

def on_message(ws, message):
    try:    
        msg = json.loads(message)    
        #print(msg)
    except:
        ws = websocket.WebSocketApp("wss://ws.blockchain.info/inv",
                                  on_message = on_message,
                                  on_error = on_error,
                                  on_close = on_close,
                                  on_ping=on_ping,
                                  on_pong=on_pong
                                  )
        ws.on_open = on_open

    process_om(msg)

def on_error(ws, error):
    print(error)

def on_close(ws):
    print("### closed ###")

def on_open(ws):
    def run(*args):
        mes = {"op": "blocks_sub"}
        ws.send(json.dumps(mes))        
    thread.start_new_thread(run, ())

def on_ping(ws, message):
    today = str(datetime.now())
    print("{} ### Got a Ping! ###".format(today))
    print(message)

def on_pong(ws, message):
    print("{} ### Send a Pong! ###".format(str(datetime.now())))
    print(message)

def process_om(data):    
    global df, haseum, message, old_msg
    #print(data['x'])

    timex = data['x']['time']
    hss = data['x']['hash']
    mrklRoot = data['x']['mrklRoot']


    print("timex -> ", timex)
    print("hss -> ", hss)    
    print("mrklRoot -> ", mrklRoot)

    key1 = hashlib.sha256(hss.encode('utf-8')).hexdigest()    
    key2 = hashlib.sha256(mrklRoot.encode('utf-8')).hexdigest()

    address1 = blocksmith.BitcoinWallet.generate_address(key1)
    address2 = blocksmith.BitcoinWallet.generate_address(key2)

    comp_address1 = blocksmith.BitcoinWallet.generate_compressed_address(key1)
    comp_address2 = blocksmith.BitcoinWallet.generate_compressed_address(key2)

    print("key1 -> ", key1)
    print("key2 -> ", key2)

    print("address1 -> ", address1)
    print("address2 -> ", address2)

    print("comp_address1 -> ", comp_address1)
    print("comp_address2 -> ", comp_address2)

    pks_to_pkk1 = pk4(key1)
    wif1 = base58(pks_to_pkk1)
    segwitAddr1 = segwitAddress(wif1)

    pks_to_pkk2 = pk4(key2)
    wif2 = base58(pks_to_pkk2)
    segwitAddr2 = segwitAddress(wif2)

    print(segwitAddr1)

    skey = key1+"|"+key2
    saddr1 = address1+"|"+address2
    saddr2 = comp_address1+"|"+comp_address2

    searchAddress(saddr1,skey)
    searchAddress(saddr2,skey)

    saddr3 = segwitAddr1['NativeAddress']+"|"+segwitAddr1['NativeAddress2']+"|"+segwitAddr1['P2SH_P2WPKH_Address']+"|"+segwitAddr1['P2WSHAddress']+"|"+segwitAddr1['P2WSH_P2PK_Address']    
    saddr4 = segwitAddr2['NativeAddress']+"|"+segwitAddr2['NativeAddress2']+"|"+segwitAddr2['P2SH_P2WPKH_Address']+"|"+segwitAddr2['P2WSHAddress']+"|"+segwitAddr2['P2WSH_P2PK_Address']    

    searchAddressSegwit(saddr3,key1)
    searchAddressSegwit(saddr4,key2)

def searchAddress(address,pkey):
    header_web = {
            "Content-Type":"text",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:96.0) Gecko/20100101 Firefox/96.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "id,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": "https://blockchain.info/",
            "Device-Type": "web",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "User-Timezone": "Asia/Jakarta",
            "Content-Type": "application/json",
            "Origin": "https://blockchain.info",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "same-site",
            "Sec-GPC": "1",
            "Pragma": "no-cache",
            "TE": "trailers"
        }
    url = "https://blockchain.info/balance?active="+address
    ret = requests.get(url,headers=header_web).content
    dt = json.loads(ret)
    x = address.split("|")
    pkk = pkey.split("|")
    i=0
    for addr in x:
        final_balance = dt[addr]['final_balance']
        txn = dt[addr]['n_tx']
        pks=pkk[i]
        
        pks_to_pkk = pk4(pks)
        wiiff = base58(pks_to_pkk)
        
        print("private_key -> ", str(pks))
        print("wif -> ", str(wiiff))

        print("searchAddress -> "+addr, str(final_balance))
        print("searchAddress -> "+addr, str(txn))
        #telegram_bot_sendtext(addr +" -> "+ str(final_balance))        
        if (final_balance > 0) or (txn > 0):            
            msg = "Found address "+addr+" with balance "+str(final_balance)+" [ "+pks+" ]" + " [ " + str(wiiff) + " ]"
            if old_msg != message:
                telegram_bot_sendtext(msg)
                old_msg = msg
        i=i+1


def searchAddressSegwit(address,pkey):
    header_web = {
            "Content-Type":"text",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:96.0) Gecko/20100101 Firefox/96.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "id,en-US;q=0.7,en;q=0.3",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": "https://blockchain.info/",
            "Device-Type": "web",
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "User-Timezone": "Asia/Jakarta",
            "Content-Type": "application/json",
            "Origin": "https://blockchain.info",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "same-site",
            "Sec-GPC": "1",
            "Pragma": "no-cache",
            "TE": "trailers"
        }
    url = "https://blockchain.info/balance?active="+address
    ret = requests.get(url,headers=header_web).content
    dt = json.loads(ret)
    x = address.split("|")
    i=0
    for addr in x:
        final_balance = dt[addr]['final_balance']
        txn = dt[addr]['n_tx']
        
        pks_to_pkk = pk4(pkey)
        wiiff = base58(pks_to_pkk)
        
        print("private_key -> ", str(pkey))
        print("wif -> ", str(wiiff))

        print("searchAddress -> "+addr, str(final_balance))
        print("searchAddress -> "+addr, str(txn))
        #telegram_bot_sendtext(addr +" -> "+ str(final_balance))        
        if (final_balance > 0) or (txn > 0):            
            msg = "Found address "+addr+" with balance "+str(final_balance)+" [ "+pkey+" ]" + " [ " + str(wiiff) + " ]"
            if old_message != msg:
                telegram_bot_sendtext(msg)
                old_message = msg
        i=i+1

def segwitAddress(fromwif):
    # always remember to setup the network
    
    addrs = {}

    setup('mainnet')

    # could also instantiate from existing WIF key
    priv = PrivateKey.from_wif('{}'.format(fromwif))

    # compressed is the default
    print("\nPrivate key WIF:", priv.to_wif(compressed=True))
    
    addrs['WIF'] = str(priv.to_wif(compressed=True))

    # get the public key
    pub = priv.get_public_key()
    # compressed is the default
    print("Public key:", pub.to_hex(compressed=True))

    addrs['PublicKey'] = pub.to_hex(compressed=True)

    # get address from public key
    address = pub.get_segwit_address()

    # print the address and hash - default is compressed address
    print("Native Address:", address.to_string())
    addrs['NativeAddress'] = address.to_string()

    segwit_hash = address.to_hash()
    print("Segwit Hash:", segwit_hash)
    print("Segwit Version:", address.get_type())

    # test to_string
    addr2 = P2wpkhAddress.from_hash(segwit_hash)
    print("Created P2wpkhAddress from Segwit Hash and calculate address:")
    print("Native Address:", addr2.to_string())
    addrs['NativeAddress2'] = addr2.to_string()

    #
    # display P2SH-P2WPKH
    #

    # create segwit address
    addr3 = PrivateKey.from_wif('{}'.format(fromwif)).get_public_key().get_segwit_address()
    # wrap in P2SH address
    addr4 = P2shAddress.from_script(addr3.to_script_pub_key())
    print("P2SH(P2WPKH):", addr4.to_string())
    addrs['P2SH_P2WPKH_Address'] = addr4.to_string()

    #
    # display P2WSH
    #
    p2wpkh_key = PrivateKey.from_wif('{}'.format(fromwif))
    script = Script(['OP_1', p2wpkh_key.get_public_key().to_hex(), 'OP_1', 'OP_CHECKMULTISIG'])
    p2wsh_addr = P2wshAddress.from_script(script)
    print("P2WSH of P2PK:", p2wsh_addr.to_string() )
    addrs['P2WSHAddress'] = p2wsh_addr.to_string()

    #
    # display P2SH-P2WSH
    #
    p2sh_p2wsh_addr = P2shAddress.from_script(p2wsh_addr.to_script_pub_key())
    print("P2SH(P2WSH of P2PK):", p2sh_p2wsh_addr.to_string())
    addrs['P2WSH_P2PK_Address'] = p2sh_p2wsh_addr.to_string()

    return addrs

def pk4(private_key_hex):
    PK0 = "{}".format(private_key_hex)
    PK1 = '80'+ PK0
    PK2 = hashlib.sha256(codecs.decode(PK1, 'hex'))
    PK3 = hashlib.sha256(PK2.digest())
    checksum = codecs.encode(PK3.digest(), 'hex')[0:8]
    PK4 = PK1 + str(checksum)[2:10]  #I know it looks wierd
    return PK4

# Define base58
def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add ‘1’ for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

def telegram_bot_sendtext(bot_message):    
    bot_token = botToken
    bot_chatID = gchatId
    send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + bot_chatID + '&parse_mode=Markdown&text=' + bot_message
    response = requests.get(send_text)
    return response.json()    

if __name__ == "__main__":
    ws = websocket.WebSocketApp("wss://ws.blockchain.info/inv",
                              on_message = on_message,
                              on_error = on_error,
                              on_close = on_close,
                              on_ping=on_ping,
                              on_pong=on_pong
                              )
    ws.on_open = on_open
    
    keep_on = True
    while keep_on:
      try:
        ping_data = {"op": "ping_block"}
        #ping_data = {"op": "ping_tx"}
        keep_on = ws.run_forever(ping_interval=15, ping_payload=json.dumps(ping_data))
      except:
        print("[Websocket Error]")

    #ws.run_forever()
