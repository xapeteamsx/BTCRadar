#!/usr/bin/python3

'''
Based on story https://pastebin.com/HN6hH1j0
This material is intended for research purposes only
BTC Donation address: bc1qxnf2y7a8t4nuxhr8k4u8ctyy4cmzzgyea2s2pp
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
import pandas as pd


botToken = 'XXXXXXXXXXXXX'
gchatId = 'XXXXXXXXXXXXX'

try:
    import thread
except ImportError:
    import _thread as thread

f = open("webSocketTester.log", "a")

haseum = ""
pesan=""
msg = ""
old_msg = ""
datapd = {}
old_hash = ""

df = pd.DataFrame(columns=['date','Keys','WIF','Address','comp_address','Segwitaddress1','Segwitaddress2','Segwitaddress3','Segwitaddress4','Segwitaddress5'])


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
        mes = {"op": "unconfirmed_sub"}
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
    global df, haseum, datapd, old_hash
    #print(data['x'])

    now_utc = datetime.utcnow()
    cur_date = now_utc.strftime('%Y-%m-%d')
    df_utc = now_utc.strftime('%Y%m%d')
    reset_time = now_utc.strftime('%H:%M')
    dsave = datetime.strptime(df_utc, "%Y%m%d") - timedelta(days=1)           
    
    pdata = {}
    
    dkey = []    
    dwiff = []    
    daddr1 = []
    daddr2 = []
    daddr1 = []
    daddr2 = []
    daddr3 = []
    daddr4 = []
    daddr5 = []

    timex = data['x']['time']
    hss = data['x']['hash']
    
    '''
    maddress = {}    
    multi_address = {}    
    to_addr = data['x']['out']
    if len(to_addr) > 1:
        for xaddr in to_addr:
            addrx = xaddr['addr']
            if xaddr['spent'] == False:
                keyx = hashlib.sha256(addrx.encode('utf-8')).hexdigest()
                multi_address['address'] = addrx
                multi_address['private_key'] = keyx
                maddress.update(multi_address)
    
    print("multi_address -> ",multi_address)
    print("maddress -> ",maddress)
    '''

    addr = data['x']['out'][0]['addr']
    scr = data['x']['out'][0]['script']
    spent_addr = data['x']['inputs'][0]['prev_out']['addr']
    scr_spent = data['x']['inputs'][0]['prev_out']['script']

    print("timex -> ", timex)
    print("hss -> ", hss)    
    print("addr -> ", addr)
    print("scr -> ", scr)
    print("spent_addr -> ", spent_addr)
    print("scr_spent -> ", scr_spent)

    key1 = hashlib.sha256(hss.encode('utf-8')).hexdigest()    
    key2 = hashlib.sha256(addr.encode('utf-8')).hexdigest()
    key3 = hashlib.sha256(scr.encode('utf-8')).hexdigest()
    key4 = hashlib.sha256(spent_addr.encode('utf-8')).hexdigest()
    key5 = hashlib.sha256(scr_spent.encode('utf-8')).hexdigest()

    address1 = blocksmith.BitcoinWallet.generate_address(key1)
    address2 = blocksmith.BitcoinWallet.generate_address(key2)
    address3 = blocksmith.BitcoinWallet.generate_address(key3)
    address4 = blocksmith.BitcoinWallet.generate_address(key4)
    address5 = blocksmith.BitcoinWallet.generate_address(key5)

    comp_address1 = blocksmith.BitcoinWallet.generate_compressed_address(key1)
    comp_address2 = blocksmith.BitcoinWallet.generate_compressed_address(key2)
    comp_address3 = blocksmith.BitcoinWallet.generate_compressed_address(key3)
    comp_address4 = blocksmith.BitcoinWallet.generate_compressed_address(key4)
    comp_address5 = blocksmith.BitcoinWallet.generate_compressed_address(key5)

    '''
    print("key1 -> ", key1)
    print("key2 -> ", key2)
    print("key3 -> ", key3)
    print("key4 -> ", key4)
    print("key5 -> ", key5)

    print("address1 -> ", address1)
    print("address2 -> ", address2)
    print("address3 -> ", address3)
    print("address4 -> ", address4)
    print("address5 -> ", address5)

    print("comp_address1 -> ", comp_address1)
    print("comp_address2 -> ", comp_address2)
    print("comp_address3 -> ", comp_address3)
    print("comp_address3 -> ", comp_address3)
    print("comp_address5 -> ", comp_address5)
    '''

    pks_to_pkk1 = pk4(key1)
    wif1 = base58(pks_to_pkk1)
    segwitAddr1 = segwitAddress(wif1)

    pks_to_pkk2 = pk4(key2)
    wif2 = base58(pks_to_pkk2)
    segwitAddr2 = segwitAddress(wif2)

    pks_to_pkk3 = pk4(key3)
    wif3 = base58(pks_to_pkk3)
    segwitAddr3 = segwitAddress(wif3)

    pks_to_pkk4 = pk4(key4)
    wif4 = base58(pks_to_pkk4)
    segwitAddr4 = segwitAddress(wif4)

    pks_to_pkk5 = pk4(key5)
    wif5 = base58(pks_to_pkk5)
    segwitAddr5 = segwitAddress(wif5)
    
    skey = key1+"|"+key2+"|"+key3+"|"+key4+"|"+key5    
    wiff = wif1+"|"+wif2+"|"+wif3+"|"+wif4+"|"+wif5    
    saddr1 = address1+"|"+address2+"|"+address3+"|"+address4+"|"+address5
    saddr2 = comp_address1+"|"+comp_address2+"|"+comp_address3+"|"+comp_address4+"|"+comp_address5

    saddr3 = segwitAddr1['NativeAddress']+"|"+segwitAddr1['NativeAddress2']+"|"+segwitAddr1['P2SH_P2WPKH_Address']+"|"+segwitAddr1['P2WSHAddress']+"|"+segwitAddr1['P2WSH_P2PK_Address']    
    saddr4 = segwitAddr2['NativeAddress']+"|"+segwitAddr2['NativeAddress2']+"|"+segwitAddr2['P2SH_P2WPKH_Address']+"|"+segwitAddr2['P2WSHAddress']+"|"+segwitAddr2['P2WSH_P2PK_Address']    
    saddr5 = segwitAddr3['NativeAddress']+"|"+segwitAddr2['NativeAddress2']+"|"+segwitAddr2['P2SH_P2WPKH_Address']+"|"+segwitAddr3['P2WSHAddress']+"|"+segwitAddr3['P2WSH_P2PK_Address']    
    saddr6 = segwitAddr4['NativeAddress']+"|"+segwitAddr4['NativeAddress2']+"|"+segwitAddr3['P2SH_P2WPKH_Address']+"|"+segwitAddr4['P2WSHAddress']+"|"+segwitAddr4['P2WSH_P2PK_Address']    
    saddr7 = segwitAddr5['NativeAddress']+"|"+segwitAddr5['NativeAddress2']+"|"+segwitAddr4['P2SH_P2WPKH_Address']+"|"+segwitAddr5['P2WSHAddress']+"|"+segwitAddr5['P2WSH_P2PK_Address']    
        
    dict1 = {
        'date': cur_date, 
        'Keys': skey, 
        'WIF': wiff, 
        'Address': saddr1, 
        'comp_address': saddr2,
        'Segwitaddress1': saddr3,
        'Segwitaddress2': saddr4,
        'Segwitaddress3': saddr5,
        'Segwitaddress4': saddr6,
        'Segwitaddress5': saddr7
    }

    #print(dict1)
    
    if old_hash != hss:
        djs = pd.DataFrame(dict1,columns=['date','Keys','WIF','Address','comp_address','Segwitaddress1','Segwitaddress2','Segwitaddress3','Segwitaddress4','Segwitaddress5'],index=[0]).rename_axis(columns='No')
        if df.empty:
            df = pd.concat([djs], ignore_index=True)
        else:
            df = pd.concat([df,djs], ignore_index=True)
        old_hash = hss

    df.drop_duplicates()

    #print(df)

    fn = 'btc-'+str(df_utc)+'.csv'
    last_date = dsave.strftime('%Y%m%d')
    fn2 = 'btc-'+str(last_date)+'.csv'

    if str(reset_time) == '00:01':
        df.to_csv(fn2)
    '''
    if df.size > 20:
        df.to_csv(fn)
    '''
    
    '''
    search address in our current dataframe
    '''    
    search_address = addr = data['x']['out']
    for saddr in search_address:
        addr = saddr['addr']
        print("searchAddress -> ",addr)
        dff = searchDataFrame(df, addr)
        if dff.size > 0:            
            wif_df = dff["WIF"]
            pk_df = dff["Keys"]        
            msg = "Found address "+addr+" [ "+pk_df+" ]" + " [ " + wif_df +"] "
            if old_msg != msg:
                telegram_bot_sendtext(msg)
                old_msg = msg

    '''
    search address in blockchain.info
    '''    
    searchAddress(saddr1,skey)
    searchAddress(saddr2,skey)

    searchAddress(saddr3,skey)
    searchAddress(saddr4,skey)
    searchAddress(saddr5,skey)
    searchAddress(saddr6,skey)
    searchAddress(saddr7,skey)

def searchAddress(address,pkey):
    global old_msg,msg

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
            msg = "Found address "+addr+" with balance "+str(final_balance)+" [ "+pks+" ]" + " [ " + str(wiiff)
            if old_msg != msg:
                telegram_bot_sendtext(msg)
                old_msg = msg
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

def searchDataFrame(df, term):
    result = df.loc[df['Address','comp_address','Segwitaddress1', 'Segwitaddress2', 'Segwitaddress3', 'Segwitaddress4', 'Segwitaddress5'] == "{}".format(term)]
    print("searchDataFrame -> ", result)
    if result.size > 0:
        print("Found in DataFrame -> ", df)
        return df
    else: return result

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
    # Add ???1??? for each 2 leading zeros
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
        ping_data = {"op": "ping"}
        keep_on = ws.run_forever(ping_interval=15, ping_payload=json.dumps(ping_data))
      except:
        print("[Websocket Error]")

    #ws.run_forever()
