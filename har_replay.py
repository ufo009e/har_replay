#!/usr/bin/python
#coding=UTF-8
#Written by ENE Bean Wu
import json
import sys
from haralyzer import HarParser
import re
import time
import threading
import SocketServer
import binascii
import argparse
import logging
import base64
import os
import socket

logging.basicConfig(format='%(asctime)s %(message)s')

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--harfile", type=str, required=True, help="specify the har file")
parser.add_argument("-d", "--postdatamatch", type=str, choices=["0", "1"], help="if check the post data when matching the response, enable=1, disable=0, default is 0", default="0")
parser.add_argument("-e", "--encode", type=str, choices=["0", "1"], help="if keep encode method in response, keep=0, chage to utf-8=1, default is 1", default="1")
parser.add_argument("-q", "--querystringamatch", type=str, choices=["0", "1"], help="if check the querystring when matching the request, enable=1, disable=0, default is 0", default="0")
parser.add_argument("-l", "--listenport", type=int, help="set local port this script listens on, example: -p 80 default is 8080", default="8080")
parser.add_argument("-c", "--changehost", type=str, help="change hostname appears in all request in all response body to the string configured here. Must contains ip and port. Always strip host in Location header. Example: -c 192.168.5.133:8080", default="NO")
parser.add_argument("-r", "--replacestring", type=str, help="replace string in header and response. example: -r test123@test456,david@jessie means change test123 to test456 and change david to jessie. Supports python re regex. example -r '//.+?/@//192.168.5.133:8080/'", default=None)
parser.add_argument("-o", "--useonce", type=str, help="try to replay the response follow the same order of har. It could be useful when you have same request with different response. When you want to restart the whole process, send request with url blademaster to reset the order. (curl x.x.x.x:8080/blademaster), enable=1, default is 1 -- ensabled. also can specify which method+url for use once only, split them by \",\". For example -o \"GET:/login.php,POST:/123.php\" or add the useonce list in flight witout restarting the script (curl x.x.x.x:8888/add_use_once_list@url1.html,url2.html)", default="1")
parser.add_argument("-m", "--regxmatch", type=str, help="In some cases browser generates random code and the response need to matches the code. . Supports python re regex, The format is request_regex@response_regex. example -m 'jQuery\w+\_\w+@jQuery\w+\_\w+' means use regex 'jQuery\w+\_\w+' to find the matched value in request and use 'jQuery\w+\_\w+' to find matches in response and replace it with the extracted value in request matches.", default=None)

args = parser.parse_args()
if not args.changehost == "NO":
    if not ':' in args.changehost:
        args.changehost = args.changehost + ':' + str(args.listenport)
        #print "No port in -c changehost option"
        #os._exit(0)

file_list = args.harfile.split(',')
### CREATE A TIMELINE OF ALL THE ENTRIES ###
entries = []
for i in file_list:
    with open(i, 'r') as f:
        har_text = f.read()
    if args.encode == "1":
        #IE and firefox encode has strange way to encode none english charater. "头" utf8 hex is e5a4b4, but IE and firefox change it to c3a5c2a4c2b4, so need to fix it here
        hex = har_text.encode("hex")
        n = 2
        hex = ' '.join([hex[j:j+n] for j in range(0, len(hex), n)])
        hex_r = re.sub(r'c3 a(\w) c2 (\w{2}) c2 (\w{2})',r'e\1\2\3',hex).replace(' ','')
        har_text = hex_r.decode('hex')
        encodlist=os.popen('grep \'"name": "Content-Type"\' ' + i + ' -A 1|grep -iPo \'charset=.*"\'|sort -u|grep -iv "utf-8"').readlines()
        for encode in encodlist:
            replacestring = encode.strip().replace('"','').split('=')[1]
            har_text = har_text.replace(replacestring, 'UTF-8')
    har_parser = HarParser(json.loads(har_text))
    
    
    #for page in har_parser.pages:
    for entry in har_parser.har_data['entries']:
        entries.append(entry)
print "Found requests number: " + str(len(entries))

#generates dic has entries list ID, started_time and url. Then can always use entries list ID to match request and response.
#{0: ['2019-01-31T01:51:06.305Z', 'POST:/dvwa/vulnerabilities/xss_r/?name=test','username=123&passowrd=123']}    
start_time_dict = {}
for i in range(len(entries)):
    start_time_dict[i] = []
    start_time_dict[i].append(str(entries[i]['startedDateTime']))
    #print entries[i]['request']['url']
    url_match = re.search(r'(http://|https://)(.*?\/)(.*)',str(entries[i]['request']['url']))
    url = '/' + url_match.group(3)
    if args.querystringamatch == '0':
        url = str(url.split('?')[0])
    #need to remove '#' from uri. HAR file may record it but browser nenver sends it over tcp
    url = re.sub(r'#.*','',url)
    method = str(entries[i]['request']['method'])    
    start_time_dict[i].append(method + ":" + url)
    if 'postData' in entries[i]['request'].keys():
        start_time_dict[i].append(entries[i]['request']['postData']['text'])
    else:
        start_time_dict[i].append('')

#sort url with started time    
time_sorted_list = sorted(start_time_dict.items(),key=lambda item:item[1][0])

method_url_list = []
for b in time_sorted_list:
    method_url_list.append(b[1][1])
    if 'POST' in b[1][1] or 'PUT' in b[1][1]:
        if 'Content-Disposition' in b[1][2]:
            print "Found request " + b[1][1] + " multipart-form data"
        else:
            print "Found request " + b[1][1] + " data " + b[1][2]
    else:
        print "Found request " + b[1][1]
    

#found uri with same method and url,     
duplicate_uri = {}    
for c in method_url_list:
    if method_url_list.count(c) > 1:
        duplicate_uri[c] = method_url_list.count(c)
if args.useonce == '1':
    print "\033[1;35mUse_once request: \n" + '\n'.join(duplicate_uri.keys()) + '\033[0m '
    print "\033[1;33mUse once is enabled, use command curl x.x.x.x:%s/blademaster to reset use_once list before each testing.\033[0m "%args.listenport
elif len(args.useonce) > 1:
    print "\033[1;35mUse_once request: \n" + args.useonce.replace(',','\n') + '\033[0m '
    print "\033[1;33mUse once is enabled, use command curl x.x.x.x:%s/blademaster to reset use_once list before each testing.\033[0m "%args.listenport

#generates use once list, and always keep last uri id out of use once list.
use_once_list = []        
for key, value in duplicate_uri.items():
    count = 1
    for d in time_sorted_list:
        if d[1][1] == key and count < value:
            use_once_list.append(d[0]) 
            #if d[1][1] in args.useonce:
            #    print d
            count += 1
used_list = []    

host_list = []
for a in entries:
    for b in a['request']['headers']:
        if b['name'].lower() == 'host':
            if not str(b['value']) in host_list:
                host_list.append(str(b['value']))


def replace_str(data):
    if not args.replacestring == None:
        replace_list = args.replacestring.split(',')
    for string in replace_list:
        data = re.sub(string.split('@')[0],string.split('@')[1],data)
    return data

def generate_response(match_id,receive_method_url):
    tmp = "HTTP/1.1 %s \r\n"%entries[match_id]['response']['status']
    for header_line in entries[match_id]['response']['headers']:
        if str(header_line['name'].lower()) == "location":
            tmp = tmp + str(header_line['name']) + ": " + re.sub(r'(http://|https://).*?\/','/',str(header_line['value'])) + "\r\n"
        elif str(header_line['name'].lower()) == "content-type" and args.encode == '1' and 'text/html' in str(header_line['value'].lower()) and not 'charset' in str(header_line['value'].lower()):
            tmp = tmp + str(header_line['name']) + ": " + str(header_line['value']) + "; charset=utf-8" +"\r\n"
        elif not (str(header_line['value']).lower() == "gzip" or str(header_line['value']).lower() == "chunked" or str(header_line['name']).lower() == "content-length"):
            tmp = tmp + str(header_line['name']) + ": " + str(header_line['value']) + "\r\n"
        else:
            pass
    if not args.replacestring == None:
        tmp = replace_str(tmp)
    if 'text' in entries[match_id]['response']['content'].keys():
        if 'charset=' in str(entries[match_id]['response']['content']['mimeType']).lower():
            charset_line = str(entries[match_id]['response']['content']['mimeType'])
            match=re.search(r'charset=.*',charset_line)
            encode_type = match.group().replace('charset=','').lower()
        else:
            encode_type = 'utf-8'
        if 'encoding' in entries[match_id]['response']['content'].keys() or 'image' in entries[match_id]['response']['content']["mimeType"]:
            data = base64.b64decode(str(entries[match_id]['response']['content']['text']))
            tmp = tmp + "Content-Length: " + str(len(data)) + '\r\n\r\n'
            #tmp = tmp + data + '\r\n'
            tmp = tmp + data
        else: 
            data = entries[match_id]['response']['content']['text'].encode(encode_type,'ignore').replace('https','http')
            if not args.changehost == 'NO':
                for host in host_list:
                    data = data.replace(host, args.changehost)
                #data = re.sub(r'(http://|https://).*?\/','/',data)
                #data = re.sub(r'//.*?\/','/',data)
            if not args.replacestring == None:
                data = replace_str(data)
            if args.regxmatch and '@' in args.regxmatch:
                global jqstr
                if jqstr != '':
                    regx = args.regxmatch.split('@')[1]
                    data = re.sub(regx,jqstr,data)
            tmp = tmp + "Content-Length: " + str(len(data)) + '\r\n\r\n'
            #tmp = tmp + data + '\r\n'
            tmp = tmp + data
            #print(tmp)
    else:
        tmp = tmp + 'Content-Length: 0' +'\r\n\r\n'
    
    if args.useonce == '1' and match_id in use_once_list:
        used_list.append(match_id)
    elif len(args.useonce) >1 and match_id in use_once_list and receive_method_url in args.useonce.split(','):
        used_list.append(match_id)
        print used_list
    return tmp
        
def find_match(receive_method,receive_url,receive_data,receive_cookie):
    match_id = None
    #print "receive_method %s receive_url %s receive_data %s receive_cookie %s"%(receive_method,receive_url,receive_data,receive_cookie)
    for request in time_sorted_list:
        receive_method_url = receive_method.replace(' ','') + ":" + receive_url.replace(' ','')
        #print "request %s data %s"%(request[1][1],request[1][2])
        if args.postdatamatch == '1':            
            if request[1][1] ==  receive_method_url and receive_data == request[1][2]:
                if args.useonce == '1' or len(args.useonce) > 1:
                    if request[0] in used_list:
                        continue
                    else:
                        match_id = request[0]
                else:
                    match_id = request[0]
                reply = generate_response(match_id,receive_method_url)
                return reply
                break
        else:
            #if request[0] == 363:
            #    print "enter else request[1][1] " + request[1][1] + " received url " + receive_method_url
            if request[1][1] == receive_method_url:
                #if request[0] == 363:
                #    print "enter else request[1][1] " + request[1][1] + " received url " + receive_method_url
                if args.useonce == '1' or len(args.useonce) > 1:
                    if request[0] in used_list:
                        continue
                    else:
                        match_id = request[0]
                else:
                    match_id = request[0]
                reply = generate_response(match_id,receive_method_url)
                return reply
                break
    if match_id == None:
        reply = "HTTP/1.1 200 OK\r\nContent-Length: 35\r\nContent-Type: text/plain\r\n\r\nNo matched replay for this request\n"
        return reply

class MySockServer(SocketServer.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        while 1:
            try:    
                #sleep to avoid cpu spike
                time.sleep(0.1)
                receive = self.request.recv(4096)
                if len(receive) > 3:
                    receive_match = re.search(r'\s.+?\s',receive)
                    if not receive_match:
                        logging.warning( " Receive <<<<<<<<< No http url, maybe a request splited in multiple packets." )
                        continue
                    receive_url = receive_match.group().replace(' ', '')
                    if args.regxmatch and '@' in args.regxmatch:
                        global jqstr
                        jqstr = ''
                        jq = re.search(args.regxmatch.split('@')[0],receive_url)
                        if jq:
                            jqstr = jq.group()
                            logging.warning( " Receive <<<<<<<<< detected regxmatch string %s." % jqstr)
                    if args.querystringamatch == '0':
                        receive_url = str(receive_url.split('?')[0])
                    if 'blademaster' in receive_url:
                        #reset used_list
                        global used_list
                        used_list = []
                        print "\033[1;35mReset use_once list \033[0m "
                        self.request.sendall("HTTP/1.1 200 OK\r\nContent-Length: 21\r\nContent-Type: text/plain\r\n\r\nRested use once list\n")
                        continue
                    elif 'add_use_once_list@' in receive_url:
                        add_use_once_list = receive_url.split('@')[1:]
                        args.useonce = args.useonce + ',' + ','.join(add_use_once_list)
                        print "\033[1;35mUpdated use once list to " + args.useonce + " \033[0m"
                        self.request.sendall("HTTP/1.1 200 OK\r\nContent-Length: 22\r\nContent-Type: text/plain\r\n\r\nupdated use once list\n")
                        continue
                    receive_match = re.search(r'\w+\s',receive)
                    receive_method = receive_match.group().replace(' ', '')
                    http_method_list = ['GET','POST','HEAD','OPTIONS','PUT','PATCH','DELETE','TRACE','CONNECT']
                    if not receive_method in http_method_list:
                        continue
                    match = re.search(r'Cookie:.+?\r\n',receive)
                    if match:    
                        receive_cookie = match.group()
                    else:
                        receive_cookie = ''
                    if "POST" in receive_method or "PUT" in receive_method:
                        receive_match = re.search(r'\n.+$',receive)    
                        if receive_match:
                            receive_data = receive_match.group().replace('\n', '')    
                        else:
                            receive_data = ''
                        logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url + " receive_data " + receive_data )
                    else:
                        receive_data = ''
                        logging.warning( " Receive <<<<<<<<< method " + receive_method + " receive_url " + receive_url)
                    response = find_match(receive_method,receive_url,receive_data,receive_cookie)
                    if 'No matched replay for this request' in response:
                        logging.warning( '\033[1;35m Send >>>>>>> No matched response for ' + receive_method  + " receive_url " + receive_url + '\033[0m ')
                    else:
                        logging.warning( " Send >>>>>>> Found matched replay method " + receive_method  + " receive_url " + receive_url)
                    self.request.sendall(response)    
            except socket.error as msg:
                #logging.warning( msg )
                pass
            
if __name__ == "__main__":        
    #create socket to receive and send data
    print "\n========================================"
    if args.changehost == 'NO':
        print "\033[1;33mWarning: better to set ip for domains below in hosts file\n"
        for z in host_list:
            print z.split(':')[0]
        print "\033[0m \n========================================"
    
    logging.warning(" READY! Listen on port " + str(args.listenport) +" Waiting for request")                    
    server = SocketServer.ThreadingTCPServer(('0.0.0.0', args.listenport), MySockServer)
    server.allow_reuse_address=True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print "\nSee you next time ......"
        server.shutdown()
        server.server_close()
        os._exit(0)

