#!/usr/bin/env python3
#Developed by Casey Reid
#This code is not supported By Tenable
import click
import requests
import pprint
import time
import os
import pickle
import sys
import json
import csv
import smtplib
import getpass
import sqlite3
from sqlite3 import Error

requests.packages.urllib3.disable_warnings()

@click.group()
def cli():
    click.echo("Hey Listen!")


@cli.command(help="Enter or Reset your Keys")
def keys():
    #assumption is that the user keys didn't work or don't exist
    print("Hey you don't have any Keys!")
    access_key = getpass.getpass("Please provide your Access Key : ")
    secret_key = getpass.getpass("Please provide your Secret Key : ")

    dicts = {"Access Key": access_key, "Secret Key": secret_key}

    pickle_out = open("keys.pickle", "wb")
    pickle.dump(dicts, pickle_out)
    pickle_out.close()

    print("Now you have keys, re-run your command")
    sys.exit()


@cli.command(help="Enter or Overwrite your SMTP information")
def smtp():
    print("Hey you don't have any SMTP information!")
    server = input("Enter the Email servers address : ")
    port = input("Enter the port your Email server uses : ")
    from_email = input("Enter your Email Address : ")
    password = getpass.getpass("Enter your email password : ")

    dicts = {"Server": server, "Port": port, "From Email": from_email, "Password": password}

    pickle_out = open("smtp.pickle", "wb")
    pickle.dump(dicts, pickle_out)
    pickle_out.close()

    print("Your SMTP settings have been saved")


def grab_smtp():
    #grab SMTP information

    print("pulling from file")
    pickle_in = open("smtp.pickle", "rb")
    smtp_info = pickle.load(pickle_in)
    server = smtp_info["Server"]
    port = smtp_info["Port"]
    from_email = smtp_info["From Email"]
    password = smtp_info["Password"]

    return server, port, from_email, password


def error_msg():
    print("Check your API keys or your internet connection")


def grab_headers():
    access_key = ''
    secret_key = ''

    #check for API keys; if none, get them from the user by calling save_keys()
    if os.path.isfile('./keys.pickle') is False:
        keys()
    else:
        pickle_in = open("keys.pickle", "rb")
        actual_keys = pickle.load(pickle_in)
        access_key = actual_keys["Access Key"]
        secret_key = actual_keys["Secret Key"]

    #set the header
    headers = {'Content-type':'application/json','X-ApiKeys':'accessKey='+access_key+';secretKey='+secret_key}
    return headers


def get_data(url_mod):
    url = "https://cloud.tenable.com"
    headers = grab_headers()
    try:
        r = requests.request('GET', url + url_mod, headers=headers, verify=False)

        if r.status_code == 200:
            data = r.json()
            #print(r.headers)
            return data
        elif r.status_code == 404:
            click.echo('Check your query...')
            click.echo(r)
        elif r.status_code == 429:
            click.echo("Too many requests at a time... Threading is unbound right now.")
        elif r.status_code == 400:
            pass
        else:
            click.echo("Something went wrong...Don't be trying to hack me now")
            click.echo(r)
    except ConnectionError:
        print("Check your connection...You got a connection error")
    #Trying to catch API errors


def delete_data(url_mod):
    url = "https://cloud.tenable.com"
    headers = grab_headers()
    try:
        r = requests.request('DELETE', url + url_mod, headers=headers, verify=False)
        if r.status_code == 200:
            print("Your object was Deleted")
            return r
        elif r.status_code == 202:
            print("Your object was Deleted")
            return r
        elif r.status_code == 404:
            click.echo('Check your query...')
            click.echo(r)
        elif r.status_code == 429:
            click.echo("Too many requests at a time... Threading is unbound right now.")
        elif r.status_code == 400:
            pass
        if r.status_code == 409:
            click.echo("Scan is still Stopping or not ready to be deleted.  You're gunna have to wait")
        else:
            click.echo("Something went wrong...Don't be trying to hack me now")
            click.echo(r)
    except ConnectionError:
        print("Check your connection...You got a connection error")


def special_get(url_mod,querystring):
    url = "https://cloud.tenable.com"
    headers = grab_headers()
    try:
        r = requests.request('GET', url + url_mod, headers=headers, params=querystring, verify=False)

        if r.status_code == 200:
            data = r.json()
            # print(r.headers)
            return data
        elif r.status_code == 404:
            click.echo('Check your query...')
            click.echo(r)
        elif r.status_code == 429:
            click.echo("Too many requests at a time... Threading is unbound right now.")
        elif r.status_code == 400:
            pass
        else:
            click.echo("Something went wrong...Don't be trying to hack me now")
            click.echo(r)
    except ConnectionError:
        print("Check your connection...You got a connection error")


def quick_post(url_mod):
    url = "https://cloud.tenable.com"
    headers = grab_headers()

    try:
        data = requests.post(url + url_mod, headers=headers, verify=False)
        if data.status_code == 200:
            print("Success!")
        elif data.status_code == 409:
            print("I can't do that right now...Check the current status")

        elif data.status_code == 404:
            print("Yeah...This scan either doesn't exist or is in a changing state")
        else:
            print("It's possible this is already stopped")


    except:
        print("Ahh now you've done it...")
        print("double check your id")


def post_data(url_mod,payload):
    #Set the URL endpoint
    url = "https://cloud.tenable.com"

    #grab headers for auth
    headers = grab_headers()

    #send Post request to API endpoint
    r = requests.post(url + url_mod, json=payload, headers=headers, verify=False)
    #retreive data in json format
    data = r.json()

    return data


def lumin_post(url_mod,payload):
    #Set the URL endpoint
    url = "https://cloud.tenable.com"

    #grab headers for auth
    headers = grab_headers()

    #send Post request to API endpoint
    r = requests.post(url + url_mod, json=payload, headers=headers, verify=False)
    #retreive data in json format
    data = r.status_code

    return data


def tag_post(url_mod,payload):
    #Set the URL endpoint
    url = "https://cloud.tenable.com"

    #grab headers for auth
    headers = grab_headers()

    #send Post request to API endpoint
    r = requests.post(url + url_mod, json=payload, headers=headers, verify=False)
    #retreive data in json format
    data = r.json()

    resp = r.status_code

    return data, resp


def put_data(url_mod,payload):
    #Set the URL endpoint
    url = "https://cloud.tenable.com"

    #grab headers for auth
    headers = grab_headers()

    #send Post request to API endpoint
    r = requests.put(url + url_mod, data=payload, headers=headers, verify=False)
    #retreive data in json format
    return


def get_licensed():
    data = get_data('/workbenches/asset-stats?date_range=90&filter.0.filter=is_licensed&filter.0.quality=eq&filter.0.value=true')
    number_of_assets = data['scanned']
    return number_of_assets


def asset_export():
    # Set the payload to the maximum number of assets to be pulled at once
    thirty_days = time.time() - 7776000#2660000
    pay_load = {"chunk_size": 100, "filters": {"last_assessed": int(thirty_days)}}
    try:
        # request an export of the data
        export = post_data("/assets/export", pay_load)

        # grab the export UUID
        ex_uuid = export['export_uuid']
        print('Requesting Asset Export with ID : ' + ex_uuid)

        # now check the status
        status = get_data('/assets/export/' + ex_uuid + '/status')

        # status = get_data('/vulns/export/89ac18d9-d6bc-4cef-9615-2d138f1ff6d2/status')
        print("Status : " + str(status["status"]))

        # set a variable to True for our While loop
        not_ready = True

        # loop to check status until finished
        while not_ready is True:
            # Pull the status, then pause 5 seconds and ask again.
            if status['status'] == 'PROCESSING' or 'QUEUED':
                time.sleep(5)
                status = get_data('/assets/export/' + ex_uuid + '/status')
                print("Status : " + str(status["status"]))

            # Exit Loop once confirmed finished
            if status['status'] == 'FINISHED':
                not_ready = False

            # Tell the user an error occured
            if status['status'] == 'ERROR':
                print("Error occurred")



        #Crete a new connection to our database
        database = r"navi.db"
        conn = new_db_connection(database)

        create_asset_table = """CREATE TABLE IF NOT EXISTS assets (
                            ip_address text,
                            hostname text,
                            fqdn text,
                            uuid text PRIMARY KEY,
                            first_found text,
                            last_found text, 
                            operating_system text,
                            mac_address text, 
                            agent_uuid text,
                            last_licensed_scan_date text
                            );"""
        create_table(conn, create_asset_table)
        #create a table for tags
        create_tags_table = """CREATE TABLE IF NOT EXISTS tags (
                            tag_id integer PRIMARY KEY,
                            asset_uuid text,
                            asset_ip,
                            tag_key text,
                            tag_uuid text,
                            tag_value text,
                            tag_added_date text
                            );"""
        create_table(conn, create_tags_table)
        tag_id = 0
        with conn:

            # loop through all of the chunks
            for x in range(len(status['chunks_available'])):
                print("Parsing Chunk {} ...Finished".format(x+1))
                chunk_data = get_data('/assets/export/' + ex_uuid + '/chunks/' + str(x+1))

                for assets in chunk_data:
                    #create a blank list to append asset details
                    csv_list = []

                    #Try block to ignore assets without IPs
                    try:
                        #Capture the first IP
                        try:
                            ip = assets['ipv4s'][0]
                            csv_list.append(ip)
                        except:
                            csv_list.append(" ")
                        #try block to skip if there isn't a hostname
                        try:
                            csv_list.append(assets['hostnames'][0])

                        except:
                            # If there is no hostname add a space so columns still line up
                            csv_list.append(" ")

                        try:
                            csv_list.append(assets['fqdns'][0])
                        except:
                            csv_list.append(" ")

                        try:
                            id = assets['id']
                            csv_list.append(id)
                        except:
                            csv_list.append(" ")
                        try:

                            csv_list.append(assets['first_seen'])
                        except:
                            csv_list.append(" ")
                        try:

                            csv_list.append(assets['last_seen'])
                        except:
                            csv_list.append(" ")
                        try:
                            csv_list.append(assets['operating_systems'][0])
                        except:
                            csv_list.append(" ")

                        try:
                            csv_list.append(assets['mac_addresses'][0])
                        except:
                            csv_list.append(" ")

                        try:
                            csv_list.append(assets['agent_uuid'])
                        except:
                            csv_list.append(" ")

                        try:
                            csv_list.append(assets["last_licensed_scan_date"])
                        except:
                            csv_list.append(" ")

                        try:
                            insert_assets(conn, csv_list)
                        except Error as e:
                            print(e)

                        #cycle through each tag and added it to its own table

                        for t in assets["tags"]:
                            tag_list = []
                            tag_id = tag_id +1
                            tag_list.append(tag_id)
                            tag_list.append(id)
                            tag_list.append(ip)

                            tag_key = t['key']
                            tag_list.append(tag_key)

                            tag_uuid = t['uuid']
                            tag_list.append(tag_uuid)

                            tag_value = t['value']
                            tag_list.append(tag_value)

                            tag_added_date = t['added_at']
                            tag_list.append(tag_added_date)

                            try:
                                insert_tags(conn, tag_list)
                            except Error as e:
                                print(e)

                    except IndexError:
                        pass


    except KeyError:
        print("Well this is a bummer; you don't have permissions to download Asset data :( ")


def vuln_export():
    # Set the payload to the maximum number of assets to be pulled at once
    thirty_days = time.time() - 2660000
    pay_load = {"num_assets": 5000, "filters": {"last_found": int(thirty_days)}}
    try:
        # request an export of the data
        export = post_data("/vulns/export", pay_load)

        # grab the export UUID
        ex_uuid = export['export_uuid']
        print('Requesting Vulnerability Export with ID : ' + ex_uuid)

        # now check the status
        status = get_data('/vulns/export/' + ex_uuid + '/status')

        # status = get_data('/vulns/export/89ac18d9-d6bc-4cef-9615-2d138f1ff6d2/status')
        print("Status : " + str(status["status"]))

        # set a variable to True for our While loop
        not_ready = True

        # loop to check status until finished
        while not_ready is True:
            # Pull the status, then pause 5 seconds and ask again.
            if status['status'] == 'PROCESSING' or 'QUEUED':
                time.sleep(5)
                status = get_data('/vulns/export/' + ex_uuid + '/status')
                print("Status : " + str(status["status"]))

            # Exit Loop once confirmed finished
            if status['status'] == 'FINISHED':
                not_ready = False

            # Tell the user an error occured
            if status['status'] == 'ERROR':
                print("Error occurred")



        #Crete a new connection to our database
        database = r"navi.db"
        conn = new_db_connection(database)
        drop_tables(conn)
        create_vuln_table = """CREATE TABLE IF NOT EXISTS vulns (
                            navi_id integer PRIMARY KEY,
                            asset_ip text, 
                            asset_uuid text, 
                            asset_hostname text, 
                            first_found text, 
                            last_found text, 
                            output text, 
                            plugin_id text, 
                            plugin_name text, 
                            plugin_family text, 
                            port text, 
                            protocol text, 
                            severity text, 
                            scan_completed text, 
                            scan_started text, 
                            scan_uuid text, 
                            schedule_id text, 
                            state text
                            );"""
        create_table(conn, create_vuln_table)

        with conn:
            navi_id = 0
            # loop through all of the chunks
            for x in range(len(status['chunks_available'])):
                print("Parsing Chunk {} ...Finished".format(x+1))

                chunk_data = get_data('/vulns/export/' + ex_uuid + '/chunks/' + str(x+1))
                #print(chunk_data)
                for vulns in chunk_data:
                    #create a blank list to append asset details
                    list = []
                    navi_id = navi_id + 1
                    #Try block to ignore assets without IPs
                    try:
                        list.append(navi_id)
                        try:
                            ipv4 = vulns['asset']['ipv4']
                            list.append(ipv4)
                        except:
                            list.append(" ")

                        try:
                            asset_uuid = vulns['asset']['uuid']
                            list.append(asset_uuid)
                        except:
                            list.append(" ")

                        try:
                            hostname = vulns['asset']['hostname']
                            list.append(hostname)
                        except:
                            list.append(" ")

                        try:
                            first_found = vulns['first_found']
                            list.append(first_found)
                        except:
                            list.append(" ")

                        try:
                            last_found = vulns['last_found']
                            list.append(last_found)
                        except:
                            list.append(" ")

                        try:
                            output = vulns['output']
                            list.append(output)
                        except:
                            list.append(" ")

                        try:
                            plugin_id = vulns['plugin']['id']
                            list.append(plugin_id)
                        except:
                            list.append(" ")

                        try:
                            plugin_name = vulns['plugin']['name']
                            list.append(plugin_name)
                        except:
                            list.append(" ")

                        try:
                            plugin_family = vulns['plugin']['family']
                            list.append(plugin_family)
                        except:
                            list.append(" ")
                        try:
                            port = vulns['port']['port']
                            list.append(port)
                        except:
                            list.append(" ")
                        try:
                            protocol = vulns['port']['protocol']
                            list.append(protocol)
                        except:
                            list.append(" ")

                        try:
                            severity = vulns['severity']
                            list.append(severity)
                        except:
                            list.append(" ")
                        try:
                            scan_completed = vulns['scan']['completed_at']
                            list.append(scan_completed)
                        except:
                            list.append(" ")

                        try:
                            scan_started = vulns['scan']['started_at']
                            list.append(scan_started)
                        except:
                            list.append(" ")

                        try:
                            scan_uuid = vulns['scan']['uuid']
                            list.append(scan_uuid)
                        except:
                            list.append(" ")

                        try:
                            schedule_id = vulns['scan']['schedule_id']
                            list.append(schedule_id)
                        except:
                            list.append(" ")

                        try:
                            state = vulns['state']
                            list.append(state)
                        except:
                            list.append(" ")
                        try:
                            insert_vulns(conn, list)
                        except Error as e:
                            print(e)

                    except:
                        print("skipped one")
                        pass
    except KeyError:
        print("Well this is a bummer; you don't have permissions to download Asset data :( ")


def new_db_connection(db_file):
    #create a connection to our database
    conn = None
    try:
        #A database file will be created if one doesn't exist
        conn = sqlite3.connect(db_file)
        #print(sqlite3.version)
    except Error as E:
        print(E)
    #return the connection for use.
    return conn


def create_table(conn, table_information):
    try:
        c = conn.cursor()
        c.execute(table_information)
    except Error as e:
        print(e)


def insert_assets(conn,assets):
    sql = '''INSERT or IGNORE into assets(ip_address, hostname, fqdn, uuid, first_found, last_found, operating_system,
                       mac_address, agent_uuid, last_licensed_scan_date) VALUES(?,?,?,?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute(sql, assets)
    #return cur.lastrowid


def insert_tags(conn,tags):
    sql = '''INSERT or IGNORE into tags(tag_id, asset_uuid, asset_ip, tag_key, tag_uuid, tag_value, tag_added_date) VALUES(?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute(sql, tags)
    #return cur.lastrowid


def drop_tables(conn):

    try:

        drop_tag = '''DROP TABLE tags'''
        drop_assets = '''DROP TABLE assets'''
        drop_vulns = '''DROP TABLE vulns'''
        cur = conn.cursor()
        cur.execute(drop_tag)
        cur.execute(drop_assets)
        cur.execute(drop_vulns)
    except:
        pass


def insert_vulns(conn,vulns):
    sql = '''INSERT or IGNORE into vulns(
                            navi_id,
                            asset_ip, 
                            asset_uuid, 
                            asset_hostname, 
                            first_found, 
                            last_found, 
                            output, 
                            plugin_id, 
                            plugin_name, 
                            plugin_family, 
                            port, 
                            protocol, 
                            severity, 
                            scan_completed, 
                            scan_started, 
                            scan_uuid, 
                            schedule_id, 
                            state
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''

    cur = conn.cursor()
    cur.execute(sql, vulns)
    #return cur.lastrowid


def plugin_by_ip(ip,plugin):
    try:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            try:
                cur = conn.cursor()
                cur.execute("SELECT output from vulns where asset_ip=\"%s\" and plugin_id=%s" % (ip,plugin))

                rows = cur.fetchall()


                print(rows[0][0])
            except:
                pass

    except Error as e:
        print(e)


def find_by_plugin(plugin):
    try:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_id=%s;" % (plugin))

            rows = cur.fetchall()

            for row in rows:
                print("\nIP Address: " + row[0])
                print("UUID : " + row[1])
                print("\n---Plugin " + plugin + " Output---\n")
                print(row[2])
                print("---End plugin Ouput ---")
    except Error as e:
        print(e)


def print_data(data):
    try:
        #there may be multiple outputs
        for output in data['outputs']:
            print(output['plugin_output'], '\n')

    except:
        pass


def nessus_scanners():
    try:
        data = get_data('/scanners')

        for x in range(len(data["scanners"])):
            print(str(data["scanners"][x]["name"]) + " : " + str(data["scanners"][x]["id"]))
    except:
        print("You may not have access...Check permissions...or Keys")


def webscan(targets, scanner_id, template):

    #create the scan payload based on the answers we received
    payload = dict(uuid=template, settings={"name": "Scripted Web App Scan of: " + str(targets),
                                            "enabled": "true",
                                            "scanner_id": scanner_id,
                                            "text_targets": targets})
    #setup the scan
    scan_data = post_data('/scans', payload)

    # pull scan ID after Creation
    scan_id = scan_data["scan"]["id"]

    #let the user no the scan ID so they can pause or stop the scan
    print(targets, " : ", scan_id)
    return


def find_target_group(tg_name):
    data = get_data('/target-groups')
    group_id = 0
    for group in data['target_groups']:
        try:
            if group['name'] == tg_name:
                group_id = group['id']

        except:
            pass
    return group_id


def create_target_group(tg_name, tg_list):

    #Check to see if the Target group exists
    group_id = find_target_group(tg_name)
    # turn the list back into a string seperated by a comma
    trgstring = ','.join(tg_list)
    print()
    print("These are the IPs that will be added to the target Group:")
    print(tg_list)

    if group_id != 0:
        #create Put payload requires a weird string instead of a dict
        payload = "{\"name\":\"" + tg_name + "\",\"members\":\"" + trgstring + "\",\"type\":\"system\"}"
        put_data('/target-groups/'+str(group_id), payload)
    else:
        print("The Target group doesn't exist")
        #create payload
        payload = dict({"name":tg_name, "members": str(trgstring),"type":"system","acls":[{"type":"default", "permissions":64}]})
        try:
            post_data('/target-groups', payload)
        except:
            print("An Error Occurred")


def csv_export():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:

        #Create our headers - We will Add these two our list in order
        header_list = ["IP Address", "Hostname", "FQDN", "UUID", "First Found", "Last Found", "Operating System",
                       "Mac Address", "Tags", "Info", "Low", "Medium", "High", "Critical"]
        cur = conn.cursor()
        cur.execute("SELECT * from assets;")

        data = cur.fetchall()

        #Crete a csv file object
        with open('asset_data_new.csv', mode='w') as csv_file:
            agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

            #write our Header information first
            agent_writer.writerow(header_list)

            #Loop through each asset
            for assets in data:

                agent_writer.writerow(assets)


def agent_export():
    data = get_data('/scanners')

    # get US cloud Scanner ID
    for scanner in range(len(data['scanners'])):
        if data['scanners'][scanner]['name'] == 'US Cloud Scanner':
            scan_id = data['scanners'][scanner]['id']

            # pull agent data from the US cloud Scanner
            agents = get_data('/scanners/' + str(scan_id) + '/agents')

            with open('agent_data.csv', mode='w') as csv_file:
                agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

                header_list = ["Agent Name","IP Address","Platform","Last connected", "Last scanned","Status"]
                agent_writer.writerow(header_list)
                # cycle through the agents and display the useful information
                for a in range(len(agents['agents'])):
                    name = agents['agents'][a]['name']
                    ip = agents['agents'][a]['ip']
                    platform = agents['agents'][a]['platform']

                    last_connect = agents['agents'][a]['last_connect']
                    connect_time = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(last_connect))
                    try:
                        last_scanned = agents['agents'][a]['last_scanned']
                        scanned_time = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(last_scanned))
                    except:
                        scanned_time = "Not Yet Scanned"
                    status = agents['agents'][a]['status']

                    agent_writer.writerow([name, ip, platform, connect_time, scanned_time, status])
    return


def webapp_export():

    # Crete a csv file object
    with open('webapp_data.csv', mode='w') as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')
        # write our Header information first
        header_list = ["Hostname", "Critical", "High", "Medium", "Low", "Scan Note"]
        agent_writer.writerow(header_list)

        data = get_data('/scans')
        #cycle through all of the scans and pull out the webapp scan IDs

        for scans in data['scans']:
            csv_list = []
            if scans['type'] == 'webapp':
                scan_details = get_data('/scans/'+str(scans['id']))
                try:
                    hostname = scan_details['hosts'][0]['hostname']
                except:
                    hostname = " "
                try:
                    message = scan_details['notes'][0]['message']
                except:
                    message = " "
                try:
                    critical = scan_details['hosts'][0]['critical']
                except:
                    critical = 0
                try:
                    high = scan_details['hosts'][0]['high']
                except:
                    high = 0
                try:
                    medium  = scan_details['hosts'][0]['medium']
                except:
                    medium = 0
                try:
                    low = scan_details['hosts'][0]['low']
                except:
                    low = 0

                if message != "Job expired while pending status.":
                    csv_list.append(hostname)

                    csv_list.append(critical)
                    csv_list.append(high)
                    csv_list.append(medium)
                    csv_list.append(low )
                    csv_list.append(message)
                    agent_writer.writerow(csv_list)


def consec_export():
    data = get_data('/container-security/api/v2/images?limit=1000')
    with open('consec_data.csv', mode='w') as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

        header_list = ["Container Name", "Docker ID", "# of Vulns"]
        agent_writer.writerow(header_list)

        for images in data["items"]:
            name = images["name"]
            docker_id = images["imageHash"]
            vulns = images["numberOfVulns"]
            agent_writer.writerow([name, docker_id, vulns])


def licensed_export():
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        with open('licensed_data.csv', mode='w') as csv_file:
            agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')
            header_list = ["IP Address", "FQDN", "UUID", "Last Licensed Scan Date"]
            agent_writer.writerow(header_list)

            cur = conn.cursor()
            cur.execute("SELECT ip_address, fqdn, uuid, last_licensed_scan_date from assets where last_licensed_scan_date != ' ';")

            data = cur.fetchall()

            for asset in data:

                agent_writer.writerow(asset)


def scan_details(uuid):
    # pull the scan data
    details = get_data('/scans/' + str(uuid))

    print("\nThe Scanner name is : " + str(details["info"]['scanner_name']))
    print("\nThe Name of the scan is " + str(details["info"]["name"]))
    print("\nThe Scan ID is " + str(uuid))
    print("\nThe " + str(details["info"]["hostcount"]) + " host(s) that were scanned are below :\n")
    for x in range(len(details["hosts"])):
        print(details["hosts"][x]["hostname"])

    start_time = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime(details["info"]["scan_start"]))
    print("\nscan start : " + start_time)
    try:
        stop = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime(details["info"]["scan_end"]))
        print("scan finish : " + stop)

        duration = (details["info"]["scan_end"] - details["info"]["scan_start"]) / 60
        print("Duration : " + str(duration) + " Minutes")
    except:
        print("This scan is still running")
    print("Scan Notes Below : ")
    for x in range(len(details["notes"])):
        print("         " + details["notes"][x]["title"])
        print("         " + details["notes"][x]["message"] + "\n")
    return


def send_email(from_email, to_email, msg, mail_server, password, port):
    print(msg)
    try:
        server = smtplib.SMTP(mail_server, port)
        server.ehlo()
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg)
        server.close()

        print('Email sent!')
    except Exception as E:
        print(E)
        print('Something went wrong...Your email information my be incorrect')


def update_tag(c,v,list):
    print("Your tag is being updated")
    tag_data = get_data('/tags/values')
    try:
        for tag in tag_data['values']:
            if tag['category_name'] == str(c):
                if tag['value'] == str(v):
                    try:
                        tag_uuid = tag['uuid']
                        payload = {"action":"add", "assets":list, "tags":[tag_uuid]}
                        data = post_data('/tags/assets/assignments', payload)
                        print("Job UUID : ", data['job_uuid'])
                        print("\nTag should be update within a few minutes\n")
                    except:
                        pass

    except:
        pass


@cli.command(help="Find IP specific Details")
@click.argument('ipaddr')
@click.option('--plugin', default='', help='Find Details on a particular plugin ID')
@click.option('-n', is_flag=True, help='Netstat Established(58561) and Listening and Open Ports(14272)')
@click.option('-p', is_flag=True, help='Patch Information - 66334')
@click.option('-t', is_flag=True, help='Trace Route - 10287')
@click.option('-o', is_flag=True, help='Process Information - 70329')
@click.option('-c', is_flag=True, help='Connection Information - 64582')
@click.option('-s', is_flag=True, help='Services Running - 22964')
@click.option('-r', is_flag=True, help='Local Firewall Rules - 56310')
@click.option('-patches', is_flag=True, help='Missing Patches - 38153')
@click.option('-d', is_flag=True, help="Scan Detail: 19506 plugin output")
@click.option('-software', is_flag=True, help="Find software installed on Unix(22869) of windows(20811) hosts")
@click.option('-outbound', is_flag=True, help="outbound connections found by nnm")
@click.option('-exploit', is_flag=True, help="Display exploitable vulnerabilities")
@click.option('-critical', is_flag=True, help="Display critical vulnerabilities")
@click.option('-details', is_flag=True, help="Details on an Asset: IP, UUID, Vulns, etc")
def ip(ipaddr, plugin, n, p, t, o, c, s, r, patches, d, software, outbound, exploit, critical, details):

    plugin_by_ip(ipaddr, plugin)

    if d:
        click.echo('\nScan Detail')
        click.echo('----------------\n')
        plugin_by_ip(ipaddr, str(19506))


    if n:
        click.echo("\nNetstat info")
        click.echo("Established and Listening")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(58651))
        click.echo("\nNetstat Open Ports")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(14272))


    if p:
        click.echo("\nPatch Information")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(66334))


    if t:
        click.echo("\nTrace Route Info")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(10287))


    if o:
        click.echo("\nProcess Info")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(70329))
        plugin_by_ip(ipaddr, str(110483))


    if patches:
        click.echo("\nMissing Patches")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(38153))
        plugin_by_ip(ipaddr, str(66334))

        click.echo("\nLast Reboot")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(56468))


    if c:
        click.echo("\nConnection info")
        click.echo("----------------\n")
        plugin_by_ip(ipaddr, str(64582))


    if s:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * from vulns where plugin_id='22964';")

            data = cur.fetchall()

            for plugins in data:
                web = plugins[6]#output
                wsplit = web.split("\n")

                server = wsplit[0]
                port = plugins[10]#port number
                proto = plugins[11]#Portocol
                asset = plugins[1]#Ip address

                print(asset, ": Has a Web Server Running :")
                print(server, "is running on: ", port,"/", proto)
                print()


    if r:
        click.echo("Local Firewall Info")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(56310))
        plugin_by_ip(ipaddr, str(61797))


    if software:
        try:
            plugin_by_ip(ipaddr, str(22869))
            plugin_by_ip(ipaddr, str(20811))
        except IndexError:
                print("No Software found")


    if outbound:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * from vulns where plugin_id='16';")

            data = cur.fetchall()
            print("IP Address", " - ", "Port", " - ", "Protocol")
            print("-------------------------------")
            for plugins in data:
                web = plugins[6]#output
                wsplit = web.split("\n")

                server = wsplit[0]
                port = plugins[10]#port number
                proto = plugins[11]#Portocol
                asset = plugins[1]#Ip address
                print(asset, " - ", port, "  - ", proto)

                print()


    if exploit:

        try:
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT uuid from assets where ip_address='" + ipaddr + "';")

                data = cur.fetchall()
                for assets in data:

                    asset_id = assets[0]

                    print("Exploitable Details for : " + ipaddr)
                    print()
                    V = get_data('/workbenches/assets/' + asset_id + '/vulnerabilities?filter.0.quality=eq&filter.0.filter=plugin.attributes.exploit_available&filter.0.value=True')
                    for plugins in range(len(V['vulnerabilities'])):
                        plugin = V['vulnerabilities'][plugins]['plugin_id']
                        # pprint.pprint(plugin)

                        P = get_data('/plugins/plugin/' + str(plugin))
                        # pprint.pprint(P['attributes'])
                        print("\n----Exploit Info----")
                        print(P['name'])
                        print()
                        for attribute in range(len(P['attributes'])):

                            if P['attributes'][attribute]['attribute_name'] == 'cve':
                                cve = P['attributes'][attribute]['attribute_value']
                                print("CVE ID : " + cve)

                            if P['attributes'][attribute]['attribute_name'] == 'description':
                                description = P['attributes'][attribute]['attribute_value']
                                print("Description")
                                print("------------\n")
                                print(description)
                                print()

                            if P['attributes'][attribute]['attribute_name'] == 'solution':
                                solution = P['attributes'][attribute]['attribute_value']
                                print("\nSolution")
                                print("------------\n")
                                print(solution)
                                print()
        except:
            print("No Exploit Details found for: ",ipaddr)


    if critical:
        try:
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT uuid from assets where ip_address='" + ipaddr + "';")

                data = cur.fetchall()
                for assets in data:

                    asset_id = assets[0]

                    print("Critical Vulns for Ip Address :" + ipaddr)
                    print()
                    vulns = get_data("/workbenches/assets/" + asset_id + "/vulnerabilities?date_range=90")
                    for severities in range(len(vulns["vulnerabilities"])):
                        vuln_name = vulns["vulnerabilities"][severities]["plugin_name"]
                        id = vulns["vulnerabilities"][severities]["plugin_id"]
                        severity = vulns["vulnerabilities"][severities]["severity"]
                        state = vulns["vulnerabilities"][severities]["vulnerability_state"]

                        # only pull the critical vulns; critical = severity 4
                        if severity >= 4:
                            print("Plugin Name : " + vuln_name)
                            print("ID : " + str(id))
                            print("Severity : Critical")
                            print("State : " + state)
                            print("----------------\n")
                            plugin_by_ip(str(ipaddr), str(id))
                            print()
        except:
            print("No Critical Vulnerabilities found for : ", ipaddr)


    if details:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT uuid from assets where ip_address='" + ipaddr + "';")

            data = cur.fetchall()
            for assets in data:
                asset_data = get_data('/workbenches/assets/'+assets[0]+'/info')

                try:
                    id = asset_data['info']['id']

                    print("\nTenable ID")
                    print("--------------")
                    print(asset_data['info']['id'])

                    print("\nIdentities")
                    print("--------------")
                    try:
                        for n in range(len(asset_data['info']['netbios_name'])):
                            print("Netbios - ", asset_data['info']['netbios_name'][n])
                    except:
                        pass
                    try:
                        for n in range(len(asset_data['info']['fqdns'])):
                            print("FQDN - ", asset_data['info']['fqdns'][n])
                    except:
                        pass

                    try:
                        for h in range(len(asset_data['info']['hostname'])):
                            print("Host Name -", asset_data['info']['hostname'][h])
                    except:
                        pass

                    print("\nOperating Systems")
                    print("--------------")
                    try:
                        for o in range(len(asset_data['info']['operating_system'])):
                            print(asset_data['info']['operating_system'][o])
                    except:
                        pass

                    try:
                        print("\nIP Addresses:")
                        print("--------------")
                        for i in range(len(asset_data['info']['ipv4'])):
                            print(asset_data['info']['ipv4'][i])
                    except:
                        pass

                    try:
                        print("\nMac Addresses:")
                        print("--------------")
                        for m in range(len(asset_data['info']['mac_address'])):
                            print(asset_data['info']['mac_address'][m])
                    except:
                        pass
                    try:
                        print("\nTags:")
                        print("--------------")
                        for i in range(len(asset_data['info']['tags'])):
                            print(asset_data['info']['tags'][i]["tag_key"], ':', asset_data['info']['tags'][i]['tag_value'])
                    except:
                        pass

                    try:
                        print("\nVulnerability Counts")
                        print("--------------")
                        asset_info = get_data('/workbenches/assets/'+id+'/info')


                        for vuln in asset_info['info']['counts']['vulnerabilities']['severities']:
                            print(vuln["name"]," : ", vuln["count"])

                        try:
                            print("\nExposure Score : ", asset_info['info']['exposure_score'])
                            print("\nAsset Criticality Score :", asset_info['info']['acr_score'])
                        except:
                            pass
                    except:
                        print("Check your API keys or your internet connection")

                    print("\nLast Authenticated Scan Date - ", asset_data['info']['last_authenticated_scan_date'])

                except:
                    pass

@cli.command(help="Export data into a CSV")
@click.option('-assets', is_flag=True, help='Exports all Asset data into a CSV')
@click.option('-agents', is_flag=True, help="Export all Agent data into a CSV")
@click.option('-webapp', is_flag=True, help="Export Webapp Scan Summary into a CSV")
@click.option('-consec', is_flag=True, help="Export Container Security Summary into a CSV")
@click.option('-licensed', is_flag=True, help="Export a List of all the Licensed Assets")
def export(assets, agents, webapp, consec, licensed):
    if assets:
        print("Exporting your data now. Saving asset_data.csv now...")
        print()
        csv_export()

    if agents:
        print("Exporting your data now. Saving agent_data.csv now...")
        print()
        agent_export()

    if webapp:
        print("Exporting your data now. Saving webapp_data.csv now...")
        print()
        webapp_export()

    if consec:
        print("Exporting your data now. Saving consec_data.csv now...")
        print()
        consec_export()

    if licensed:
        print("Exporting your data now. Saving licensed_data.csv now...")
        print()
        licensed_export()


def tag_Checker(uuid, key, value):
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        #This needs to be changed to UUID when the api gets fixed
        cur.execute("SELECT * from tags where asset_ip='" + uuid + "' and tag_key='" + key + "' and tag_value='" + value + "';")

        rows = cur.fetchall()

        length = len(rows)
        if length != 0:
            answer ='yes'
            return 'yes'
        else:
            return 'no'


@cli.command(help="Adjust ACRs in Lumin by tag")
@click.option('--acr', default='', help='Set the ACR')
@click.option('--c', default='', help="Category to use")
@click.option('--v', default='', help="Value to use")
@click.option('--note', default="Navi Generated", help="Enter a Note to your ACR Rule")
#@click.option('--uuid', default='', help="A Value UUID to use")
def lumin(acr, v, c, note):
    if c == '':
        print("We require a Tag Category to update the ACR by Tag")
        exit()

    if v == '':
        print("We require a Tag value to update the ACR by Tag")
        exit()

    if int(acr) in range(1,11):
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            #this needs to be changed to uuid once the api gets fixed
            cur.execute("SELECT asset_ip from tags where tag_key='" + c + "' and tag_value='" + v + "';")

            data = cur.fetchall()

            lumin_list = []
            for asset in data:
                #grab the first record, in this case the uuid
                uuid = asset[0]
                check_for_no = tag_Checker(uuid, "NO", "UPDATE")
                if check_for_no == 'no':
                    check_match = tag_Checker(uuid, c, v)
                    if check_match == 'yes':
                        lumin_list.append(uuid)
                else:
                    pass
            if lumin_list == []:
                print("We did not find a Tag with that Category or Value\n")
                print("If you think this is an error, surround your category and value in \"\"")
                exit()
            else:
                choice = []
                print("\n1. Business Critical")
                biz = "Business Critical"

                print("2. In Scope For Compliance")
                comp = "In Scope For Compliance"

                print("3. Existing Mitigation Control")
                control = "Existing Mitigation Control"

                print("4. Dev Only")
                dev = "Dev Only"

                print("5. Key Drivers does not match")
                driver = "Key Drivers does not match"

                print("6. other\n")
                other = "Other"

                string_choice = input("Please Choose the Reasons for the Asset criticality.\nSeparate multiple choices by a comma: e.g: 1,2,4\n")

                if "1" in string_choice:
                    choice.append(biz)
                if "2" in string_choice:
                    choice.append(comp)
                if "3" in string_choice:
                    choice.append(control)
                if "4" in string_choice:
                    choice.append(dev)
                if "5" in string_choice:
                    choice.append(driver)
                if "6" in string_choice:
                    choice.append(other)

                note = note + " - Navi Generated"
                #this needs to be changed to ID once the api is fixed
                lumin_payload = [{"acr_score": int(acr), "reason": choice, "note": note, "asset":[{"ipv4":lumin_list}]}]
                change_acr = lumin_post('/api/v2/assets/bulk-jobs/acr', lumin_payload)
                if change_acr == 202:
                    print("Success!")
                else:
                    print("Check your Request.  Below is the payload I sent.\n")
                    print(lumin_payload)

                #print(lumin_list, acr, choice, change_acr, lumin_payload)

    else:
        print("You can't have a score below 1 or higher than 10")


def tag_msg():
    print("Remember to run the update command if you want to use your new tag in Navi")


@cli.command(help="Create a Tag Category/Value Pair")
@click.option('--c', default='', help="Create a Tag with the following Category name")
@click.option('--v', default='', help="Create a Tag Value; requires --c and Category Name or UUID")
@click.option('--d', default='This Tag was created/updated by Navi', help="Description for your Tag")
@click.option('--plugin', default='', help="Create a tag by plugin ID")
@click.option('--name', default='', help="Create a Tag by the text found in the Plugin Name")
@click.option('--group', default='', help="Create a Tag based on a Agent Group")
def tag(c, v, d, plugin, name, group):

    if c == '':
        print("Category is required.  Please use the --c command")

    if v == '':
        print("Value is required. Please use the --v command")

    if plugin:
        try:
            tag_list = []
            ip_list = ""
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_id=%s;" % (plugin))

                plugin_data = cur.fetchall()
                for x in plugin_data:

                    ip = x[0]
                    id = x[1]

                    #ensure the ip isn't already in the list
                    if ip not in tag_list:
                        tag_list.append(id)
                        ip_list = ip_list + "," + ip
                else:
                    pass
            if ip_list == '':
                print("\nYour tag resulted in 0 Assets, therefore the tag wasn't created\n")
            else:
                payload = {"category_name":str(c), "value":str(v), "description":str(d), "filters":{"asset":{"and":[{"field":"ipv4","operator":"eq","value":str(ip_list[1:])}]}}}
                data, stat = tag_post('/tags/values', payload)
                print(ip_list)

                if stat == 400:
                    print("Your Tag has not be created; Update functionality hasn't been added yet")
                    print(data['error'])
                    #try to update the tag
                    update_tag(c,v,tag_list)
                else:
                    #pprint.pprint(data)
                    print("\nI've created your new Tag - {} : {}\n".format(c,v))
                    print("The Category UUID is : {}\n".format(data['category_uuid']))
                    print("The Value UUID is : {}\n".format(data['uuid']))
                    print("The following IPs were added to the Tag:")
                    print(ip_list[1:])

        except Error as e:
            print(e)

    if name != '':
        try:
            tag_list = []
            ip_list = ""
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_name LIKE '%"+name+"%';")

                plugin_data = cur.fetchall()
                for x in plugin_data:

                    ip = x[0]
                    id = x[1]
                    if ip not in tag_list:
                        tag_list.append(id)
                        ip_list = ip_list + "," + ip
                    else:
                        pass
                if ip_list == '':
                    print("\nYour tag resulted in 0 Assets, therefore the tag wasn't created\n")
                else:
                    payload = {"category_name":str(c), "value":str(v), "description":str(d), "filters":{"asset":{"and":[{"field":"ipv4","operator":"eq","value":str(ip_list[1:])}]}}}
                    data, stat = tag_post('/tags/values', payload)

                    if stat == 400:
                        print("Your Tag has not be created; Update functionality hasn't been added yet")
                        print(data['error'])
                        #try to update the tag
                        update_tag(c,v,tag_list)
                    else:

                        print("\nI've created your new Tag - {} : {}\n".format(c,v))
                        print("The Category UUID is : {}\n".format(data['category_uuid']))
                        print("The Value UUID is : {}\n".format(data['uuid']))
                        print("The following IPs were added to the Tag:\n")
                        print(ip_list[1:])

        except Error as e:
            print(e)

    if group != '':
        try:
            group_data = get_data('/scanners/1/agent-groups')
            for agent_group in group_data['groups']:
                group_name = agent_group['name']
                group_id = agent_group['id']

                if group_name == group:
                    data = get_data('/scanners/1/agent-groups/'+str(group_id)+'/agents')
                    ip_list = ''

                    for agent in data['agents']:
                        ip_address = agent['ip']
                        ip_list = ip_list + "," + ip_address

                    payload = {"category_name":str(c), "value":str(group), "description":str(d), "filters":{"asset":{"and":[{"field":"ipv4","operator":"eq","value":str(ip_list[1:])}]}}}
                    data2, stat = tag_post('/tags/values', payload)
                    if stat == 400:
                        print("Your Tag has not be created; Update functionality hasn't been added yet\n")
                        print("Delete the current tag to update it.\n")
                        print(data2['error'])

                    else:
                        print("\nI've created your new Tag - {} : {}\n".format(c,v))
                        print("The Category UUID is : {}\n".format(data2['category_uuid']))
                        print("The Value UUID is : {}\n".format(data2['uuid']))
                        print("The following IPs were added to the Tag:")
                        print(ip_list[1:])


        except:
            print("You might not have agent groups, or you are using Nessus Manager.  ")


@cli.command(help="Find Containers, Web Apps, Credential failures, Ghost Assets")
@click.option('--plugin', default='', help='Find Assets where this plugin fired')
@click.option('-docker', is_flag=True, help="Find Running Docker Containers")
@click.option('-webapp', is_flag=True, help="Find Web Servers running")
@click.option('-creds', is_flag=True, help="Find Credential failures")
@click.option('--time', default='', help='Find Assets where the scan duration is over X mins')
@click.option('-ghost', is_flag=True, help='Find Assets that were discovered by a AWS Connector but not scanned')
def find(plugin, docker, webapp, creds, time, ghost):

    if plugin != '':
        if str.isdigit(plugin) != True:
            print("You didn't enter a number")
        else:
            find_by_plugin(plugin)

    if docker:
        print("Searching for RUNNING docker containers...")
        find_by_plugin(str(93561))

    if webapp:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * from vulns where plugin_id='1442';")

            data = cur.fetchall()

            for plugins in data:
                web = plugins[6]#output
                wsplit = web.split("\n")

                server = wsplit[1]
                port = plugins[10]#port number
                proto = plugins[11]#Portocol
                asset = plugins[1]#Ip address

                print(asset, ": Has a Web Server Running :")
                print(server, "is running on: ", port,"/", proto)
                print()

    if creds:
        print("I'm looking for credential issues...Please hang tight")
        find_by_plugin(str(104410))

    if time != '':
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            print("Below are the assets that took longer than " + str(time) + " minutes to scan")
            cur = conn.cursor()
            cur.execute("SELECT * from vulns where plugin_id='19506';")

            data = cur.fetchall()

            for vulns in data:

                output = vulns[6]

                # split the output by carrage return
                parsed_output = output.split("\n")

                # grab the length so we can grab the seconds
                length = len(parsed_output)

                # grab the scan duration- second to the last variable
                duration = parsed_output[length - 2]

                # Split at the colon to grab the numerical value
                seconds = duration.split(" : ")

                # split to remove "secs"
                number = seconds[1].split(" ")

                # grab the number for our minute calculation
                final_number = number[0]

                # convert seconds into minutes
                minutes = int(final_number) / 60

                # grab assets that match the criteria
                if minutes > int(time):

                    try:
                        print("Asset IP: ", vulns[1])
                        print("Asset UUID: ", vulns[2])
                        print("Scan started at: ", vulns[14])
                        print("Scan completed at: ", vulns[13])
                        print("Scan UUID: ", vulns[15])
                        print()
                    except:
                        pass

    if ghost:
        try:
            query = {"date_range":"30","filter.0.filter":"sources","filter.0.quality":"set-hasonly","filter.0.value":"AWS"}
            data = special_get('/workbenches/assets',query)
            print()
            print("\bSource", "IP", "FQDN", "First seen")
            print("----------------------------------\b")
            print()
            for assets in data['assets']:

                for source in assets['sources']:
                        if source['name'] == 'AWS':
                            print(source['name'], assets['ipv4'][0], assets['fqdn'][0], source['first_seen'])

            print()
        except:
            print("Check your API keys or your internet connection")


@cli.command(help="Get the Latest Scan information")
@click.option('-latest', is_flag=True, help="Report the Last Scan Details")
@click.option('--container', default='', help='Report CVSS 7 or above by \'/repository/image/tag\'')
@click.option('--docker', default='', help='Report CVSS 7 or above by Docker ID')
@click.option('--comply', default='', help='Check to see if your container complies with your Corporate Policy')
@click.option('--details', default='', help='Report Scan Details including Vulnerability Counts by Scan ID')
@click.option('--summary', default='', help="Report Scan Summary information by Scan ID")
def report(latest, container, docker, comply, details, summary):
    #get the latest Scan Details
    if latest:
        try:
            data = get_data('/scans')
            l = []
            e = {}
            for x in data["scans"]:
                # keep UUID and Time together
                # get last modication date for duration computation
                epoch_time = x["last_modification_date"]
                # get the scanner ID to display the name of the scanner
                d = x["id"]
                # need to identify type to compare against pvs and agent scans
                scan_type = str(x["type"])
                # don't capture the PVS or Agent data in latest
                while scan_type not in ['pvs', 'agent', 'webapp', 'lce']:
                    # put scans in a list to find the latest
                    l.append(epoch_time)
                    # put the time and id into a dictionary
                    e[epoch_time] = d
                    break

            # find the latest time
            grab_time = max(l)

            # get the scan with the corresponding ID
            grab_uuid = e[grab_time]

            # turn epoch time into something readable
            epock_latest = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(grab_time))
            print("\nThe last Scan run was at " + epock_latest)
            scan_details(str(grab_uuid))
        except:
            error_msg()

    if container:
        try:
            data = get_data('/container-security/api/v2/reports' + str(container))
            try:
                for vulns in data['findings']:
                    if float(vulns['nvdFinding']['cvss_score']) >= 7:
                        print("CVE ID :", vulns['nvdFinding']['cve'])
                        print("CVSS Score : ",vulns['nvdFinding']['cvss_score'])
                        print("----------------------")
                        print("\nDescription : \n\n", vulns['nvdFinding']['description'])
                        print("\nRemediation : \n\n", vulns['nvdFinding']['remediation'])
                        print("----------------------END-------------------------\n")
            except(TypeError):
                print("This Container has no data or is not found")
            except(ValueError):
                pass
        except:
            error_msg()

    if docker:
        try:
            data = get_data('/container-security/api/v1/reports/by_image?image_id='+str(docker))

            try:
                for vulns in data['findings']:
                    if float(vulns['nvdFinding']['cvss_score']) >= 7:
                        print("CVE ID :", vulns['nvdFinding']['cve'])
                        print("CVSS Score : ",vulns['nvdFinding']['cvss_score'])
                        print("-----------------------")
                        print("\nDescription \n\n: ", vulns['nvdFinding']['description'])
                        print("\nRemediation : \n\n", vulns['nvdFinding']['remediation'])
                        print("----------------------END-------------------------\n")
            except(TypeError):
                print("This Container has no data or is not found")
            except(ValueError):
                pass
        except:
            error_msg()

    if comply:
        try:
            data = get_data('/container-security/api/v1/policycompliance?image_id=' + str(comply))
            #data = get_data('/conatiner-security/api/v2/reports/'+ str(comply))
            print("Status : ", data['status'])
        except:
            error_msg()

    if details:
        try:
            data = get_data('/scans/'+str(details))
            try:
                print()
                print("Scan Details for Scan ID : "+details)
                print()
                print("Notes: \b")
                try:
                    print(data['notes'][0]['message'])
                except:
                    pass
                print()
                print("Vulnerability Counts")
                print("--------------------")
                print("Critical : ", data['hosts'][0]['critical'])
                print("high : ", data['hosts'][0]['high'])
                print("medium : ", data['hosts'][0]['medium'])
                print("low : ", data['hosts'][0]['low'])
                try:
                    print("--------------")
                    print("Score : ", data['hosts'][0]['score'])
                except:
                    pass
                print()
                print("Vulnerability Details")
                print("---------------------")

                for vulns in data['vulnerabilities']:
                    if vulns['severity'] != 0:
                        print(vulns['plugin_name'], " : ", vulns['count'])
            except:
                print("Check the scan ID")
        except:
            error_msg()

    if summary:
        try:
            print("\nHere is the Summary of your Scan :")
            print("----------------------------------")
            scan_details(str(summary))
        except:
            error_msg()


@cli.command(help="Test the API ex: /scans ")
@click.argument('url')
def api(url):
    try:
        data = get_data(url)
        pprint.pprint(data)
    except:
        error_msg()


@cli.command(help="Get a List of Scanners, Users, Scans, Assets found in the last 30 days, IP exclusions.  Retreive All containers and Vulnerability Score")
@click.option('-scanners', is_flag=True, help="List all of the Scanners")
@click.option('-users', is_flag=True, help="List all of the Users")
@click.option('-exclusions', is_flag=True, help="List all Exclusions")
@click.option('-containers', is_flag=True, help="List all containers and their Vulnerability  Scores")
@click.option('-logs', is_flag=True, help="List The actor and the action in the log file")
@click.option('-running', is_flag=True, help="List the running Scans")
@click.option('-scans', is_flag=True, help="List all Scans")
@click.option('-nnm', is_flag=True, help="Nessus Network Monitor assets and their vulnerability scores")
@click.option('-assets', is_flag=True, help="Assets found in the last 30 days")
@click.option('-policies', is_flag=True, help="Scan Policies")
@click.option('-connectors', is_flag=True, help="List Connector Details and Status")
@click.option('-agroup', is_flag=True, help="List Access Groups and Status")
@click.option('-status', is_flag=True, help="Print T.io Status and Account info")
@click.option('-agents', is_flag=True, help="Print Agent information")
@click.option('-webapp', is_flag=True, help='Print Web App Scans')
@click.option('-tgroup', is_flag=True, help='Print Target Groups')
@click.option('-licensed', is_flag=True, help='Print License information')
@click.option('-tags', is_flag=True, help='Print Tag Categories and values')
@click.option('-categories', is_flag=True, help='Print all of the Tag Categories and their UUIDs')
def list(scanners, users, exclusions, containers, logs, running, scans, nnm, assets, policies, connectors, agroup, status, agents, webapp, tgroup, licensed, tags, categories):

    if scanners:
        nessus_scanners()

    if users:
        try:
            data = get_data('/users')
            for user in data["users"]:
                print('\n', user["name"].ljust(10)," - ", user["username"],'\n')

        except:
            error_msg()

    if exclusions:
        try:
            data = get_data('/exclusions')
            for x in data["exclusions"]:
                print("\nExclusion Name : ", x["name"], '\n')
                print(x["members"], '\n')

        except:
            print("No Exclusions Set, or there could be an issue with your API keys")

    if containers:
        try:
            data = get_data('/container-security/api/v2/images?limit=1000')
            print("Container Name".ljust(15) +" | " + "Repository ID".ljust(20) + " | " +"Tag".ljust(10) + " | " + "Docker ID".ljust(15) + " | " + "# of Vulns".ljust(10))
            print("-----------------------------------------------------------------------------------")
            try:
                for images in data["items"]:
                    print(str(images["name"]).ljust(15) + " | " + str(images["repoName"]).ljust(20) + " | " + str(images["tag"]).ljust(10) + " | " + str(images["imageHash"]).ljust(15) + " | " + str(images["numberOfVulns"]).ljust(25))
            except:
                pass
        except Exception as E:
            error_msg()
            print(E)

    if logs:
        try:
            data = get_data('/audit-log/v1/events')
            for log in data['events']:
                received = log['received']
                action = log['action']
                actor = log['actor']['name']

                print("Date : " + received)
                print("-------------------")
                print(action, '\n', actor, '\n')
        except:
            error_msg()

    if running:
        try:
            data = get_data('/scans')
            run = 0
            for scan in data['scans']:
                if scan['status'] == "running":
                    run = run + 1
                    name = scan['name']
                    scan_id = scan['id']
                    current_status = scan['status']

                    click.echo("\nScan Name : " + name)
                    print("Scan ID : " + str(scan_id))
                    print("Current status : " + current_status)
                    print("-----------------\n")
            if run == 0:
                print("No running scans")
        except:
            error_msg()

    if scans:
        try:
            data = get_data('/scans')

            for scan in data['scans']:
                name = scan['name']
                scan_id = scan['id']
                scan_status = scan['status']

                print("Scan Name : " + name)
                print("Scan ID : " + str(scan_id))
                print("Current status : " + scan_status)
                print("-----------------\n")

        except:
            error_msg()

    if nnm:
        try:
            # dynamically find the PVS sensor
            nnm_data = get_data('/scans')

            for nnm in nnm_data["scans"]:

                if (str(nnm["type"]) == 'pvs'):
                    nnm_id = nnm["id"]

                    try:
                        data = get_data('/scans/' + str(nnm_id) + '/')
                        print("Here are the assets and their scores last found by Nessus Network Monitor")
                        print("   IP Address     : Score")
                        print("----------------")

                        for host in data["hosts"]:
                            print(str(host["hostname"]) + " :  " + str(host["score"]))

                        print()
                    except:
                        print("No Data found or no Nessus Monitor found")
                        print("check permissions to the scanner")
                else:
                    pass
        except:
            error_msg()

    if assets:
        try:
            data = get_data('/workbenches/assets/?date_range=30')
            l = []
            for x in range(len(data["assets"])):
                for y in range(len(data["assets"][x]["ipv4"])):
                    ip = data["assets"][x]["ipv4"][y]

                    while ip not in l:
                        l.append(ip)
            l.sort()
            print("\nIn the last 30 days, I found " + str(len(l)) + " IP Addresess. See below:\n")
            for z in range(len(l)):
                print(l[z])
            print()
        except:
            error_msg()

    if policies:
        try:
            data = get_data('/policies')
            for policy in data['policies']:
                print(policy['name'])
                print(policy['description'])
                print('Template ID : ', policy['template_uuid'], '\n')
        except:
            error_msg()

    if connectors:
        try:
            data = get_data('/settings/connectors')
            for conn in data["connectors"]:
                print("\nConnector Type: ", conn['type'])
                print("Connector Name: ", conn['name'])
                print("Connector ID: ", conn['id'])
                print("----------------------------")
                print("Schedule: ", conn['schedule']['value'], conn['schedule']['units'])
                try:
                    print("Last Sync Time", conn['last_sync_time'])

                except:
                    pass
                print("Status Message: ",conn['status_message'])
                print("------------------------------------------")
        except :
            error_msg()

    if agroup:
        try:
            data = get_data('/access-groups')
            for group in data["access_groups"]:
                print("\nAccess Group Name: ", group['name'])
                print("Access Group ID: ", group['id'])
                try:
                    print("Created by: ", group['created_by_name'])
                except:
                    pass
                print("---------")
                print("Created at: ", group['created_at'])
                print("Updated at: ", group['updated_at'])
                print("----------------------")
                print("Current Status: ", group['status'])
                print("Percent Complete: ", group['processing_percent_complete'])
                print("---------------------------------")
                print("Rules")
                print("-----------------------------------------")
                details = get_data('/access-groups/'+str(group['id']))
                for rule in details['rules']:
                    print(rule['type'], rule['operator'], rule['terms'])
                print()
        except:
            error_msg()

    if status:
        try:
            data = get_data("/server/properties")
            session_data = get_data("/session")
            #pprint.pprint(data)

            print("\nTenable IO Information")
            print("-----------------------")
            print("Container ID : ", session_data["container_id"])
            print("Container UUID :", session_data["container_uuid"])
            print("Contianer Name : ", session_data["container_name"])
            print("Site ID :", data["analytics"]["site_id"])
            print("Region : ", data["region"])

            print("\nLicense information")
            print("--------------------")
            print("Licensed Assets : ", get_licensed())
            print("Agents Used : ", data["license"]["agents"])
            print("Expiration Date : ", data["license"]["expiration_date"])
            print("Scanners Used : ", data["license"]["scanners"])
            print("Users : ", data["license"]["users"])
            print("\nEnabled Apps")
            print("---------")
            print()
            for key in data["license"]["apps"]:
                print(key)
                print("-----")
                try:
                    print("Expiration: ", data["license"]["apps"][key]["expiration_date"])

                except:
                    pass
                print("Mode: ", data["license"]["apps"][key]["mode"])
                print()

        except:
            error_msg()

    if agents:
        try:
            data = get_data('/scanners/104490/agents')
            print("\b Agent information is pulled from the US Cloud Scanner\b")
            for agent in data['agents']:
                last_connect = agent['last_connect']
                last_connect_time = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(last_connect))

                last_scanned = agent['last_scanned']
                last_scanned_time = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(last_scanned))
                print("Agent Name : ", agent['name'])
                print("-----------------------------")
                print("Agent IP : ", agent['ip'])
                print("Last Connected :", last_connect_time)
                print("Last Scanned : ", last_scanned_time)
                print("Agent Status : ", agent['status'], '\n')
                print("Groups")
                print("-------------")

                try:
                    for group in agent['groups']:
                        print(group['name'])
                except:
                    pass
                print()
        except:
            error_msg()

    if webapp:
        try:
            data = get_data('/scans')

            for scans in data['scans']:
                if scans['type'] == 'webapp':
                    name = scans['name']
                    scan_id = scans['id']
                    scan_status = scans['status']

                    print("Scan Name : " + name)
                    print("Scan ID : " + str(scan_id))
                    print("Current status : " + scan_status)
                    print("-----------------\n")

        except:
            error_msg()

    if tgroup:
        data = get_data('/target-groups')
        try:
            for targets in data['target_groups']:
                print()
                print("Name : ", targets['name'])
                print("Owner : ", targets['owner'])
                print("Target Group ID : ", targets['id'])
                print("Members : ", targets['members'])
                print()
        except:
            error_msg()

    if licensed:
        print("\nLicensed Count : ", get_licensed())
        print()
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT ip_address, fqdn, last_licensed_scan_date from assets where last_licensed_scan_date !=' ';")
            data = cur.fetchall()

            print("IP Address".ljust(15), "Full Qualified Domain Name".ljust(50), "Licensed Date")
            print("-".ljust(91,"-"))
            print()
            for asset in data:
                ipv4 = asset[0]

                fqdn = asset[1]

                licensed_date = asset[2]

                print(str(ipv4).ljust(15), str(fqdn).ljust(50),licensed_date)
        print()

    if tags:
        data = get_data('/tags/values')
        print("\nTags".ljust(30), "Value".ljust(25), "Value UUID")
        print('-'.rjust(92,'-'),"\n")
        for tag_values in data['values']:
            try:
                tag_value = tag_values['value']
                uuid = tag_values['uuid']
            except:
                tag_value = "Value Not Set Yet"
                uuid = "NO Value set"
            print(str(tag_values['category_name']).ljust(25), " : ", str(tag_value).ljust(25), str(uuid).ljust(25))
        print()

    if categories:
        data = get_data('/tags/categories')
        print("\nTag Categories".ljust(30), "Category UUID")
        print('-'.rjust(50,'-'),"\n")
        for cats in data['categories']:

            category_name = cats['name']
            category_uuid = cats['uuid']

            print(str(category_name).ljust(25), " : ", str(category_uuid).ljust(25))
        print()


@cli.command(help="Quickly Scan a Target")
@click.argument('targets')
def scan(targets):
    try:
        print("\nChoose your Scan Template")
        print("1.   Basic Network Scan")
        print("2.   Discovery Scan")
        print("3.   Web App Overview")
        print("4.   Web App Scan")
        option = input("Please enter option #.... ")
        if option == '1':
            template = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"
        elif option == '2':
            template = "bbd4f805-3966-d464-b2d1-0079eb89d69708c3a05ec2812bcf"
        elif option == '3':
            template = "58323412-d521-9482-2224-bdf5e2d65e6a4c67d33d4322677f"
        elif option == '4':
            template = "09805055-a034-4088-8986-aac5e1c57d5f0d44f09d736969bf"
        elif len(option) == 52:
            template = str(option)
        else:
            print("Using Basic scan since you can't follow directions")
            template = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"

        print("Here are the available scanners")
        print("Remember, don't pick a Cloud scanner for an internal IP address")
        print("Remember also, don't chose a Webapp scanner for an IP address")
        nessus_scanners()
        scanner_id = input("What scanner do you want to scan with ?.... ")

        print("creating your scan of : " + targets + "  Now...")

        payload = dict(uuid=template, settings={"name": "Navi-Pro Created Scan of " + targets,
                                                "enabled": "true",
                                                "scanner_id": scanner_id,
                                                "text_targets": targets})
        headers = grab_headers()
        # create a new scan
        r = requests.post('https://cloud.tenable.com/scans', json=payload, headers=headers, verify=False)
        scan_data = r.json()

        # pull scan ID after Creation
        scan = scan_data["scan"]["id"]

        # launch Scan
        r2 = requests.request('POST', 'https://cloud.tenable.com/scans/' + str(scan) + '/launch', headers=headers,
                              verify=False)
        data2 = r2.json()

        # print Scan UUID
        print("A scan started with UUID: " + data2["scan_uuid"])
        print("The scan ID is " + str(scan))

    except:
        error_msg()


@cli.command(help="Create a Web App scan from a CSV file")
@click.argument('csv_input')
def spider(csv_input):
    try:
        # request the User to choose a Scan Template
        print("\nChoose your Scan Template")
        print("1.  Web App Overview")
        print("2   Web App Scan")

        # capture the choice
        option = input("Please enter option #.... ")

        # set the Template ID based on their choice
        if option == '1':
            # Web App Overview template ID
            template = "58323412-d521-9482-2224-bdf5e2d65e6a4c67d33d4322677f"

        elif option == '2':
            # Web App Scan template ID
            template = "09805055-a034-4088-8986-aac5e1c57d5f0d44f09d736969bf"

        # Template ID is 52 chars long; let the user put in their own policy ID
        elif len(option) == 52:
            template = str(option)

        # if anything else is entered outside of these options, make it a Web App policy
        else:
            print("Using Web App scan since you can't follow directions")
            template = "09805055-a034-4088-8986-aac5e1c57d5f0d44f09d736969bf"

        # Grab the scanners so the user can choose which scanner to use
        print("Here are the available scanners")
        print("Remember, Pick A Web App scanner! NOT a Nessus Scanner. ")
        nessus_scanners()

        # capture the users choice - putting in the wrong scanner will cause and error that we haven't programed to catch
        scanner_id = input("What scanner do you want to scan with ?.... ")

        with open(csv_input, 'r', newline='') as csv_file:
            web_apps = csv.reader(csv_file)

            for app in web_apps:
                webscan(app[0], scanner_id, template)
    except:
        error_msg()


@cli.command(help="Enter in a Mac Address to find the Manufacturer")
@click.argument('address')
def mac(address):
    try:
        api_token = "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJtYWN2ZW5kb3JzIiwiZXhwIjoxODU3NzYzODQ1LCJpYXQiOjE1NDMyNjc4NDUsImlzcyI6Im1hY3ZlbmRvcnMiLCJqdGkiOiIzYWNiM2Q0YS1lZjQ2LTQ3NWUtYWJiZS05M2NiMDlkMDU5YzIiLCJuYmYiOjE1NDMyNjc4NDQsInN1YiI6Ijk0NyIsInR5cCI6ImFjY2VzcyJ9.a_dLSCJq-KLjOQL52ZgiuDY08_YE5Wl7QhAJpDpHOKoIesGeMRnPGZAx3TgtfwyQVyy6_ozhy447GGdfKyjDXw"

        headers = {'Content-type': 'application/json', 'Authorization': api_token}

        url = "https://api.macvendors.com/v1/lookup/"

        r = requests.request('GET', url + address, headers=headers, verify=False)
        data = r.json()
        print("Assignment Group:")
        print(data['data']['assignment'])

        print("\nOrganization name:")
        print(data['data']['organization_name'])
    except:
        error_msg()


@cli.command(help="Pause a running Scan")
@click.argument('Scan_id')
def pause(scan_id):
    quick_post('/scans/' + str(scan_id) + '/pause')


@cli.command(help="Resume a paused Scan")
@click.argument('scan_id')
def resume(scan_id):
    quick_post('/scans/' + str(scan_id) +'/resume')


@cli.command(help="Stop a Running Scan")
@click.argument('scan_id')
def stop(scan_id):
    quick_post('/scans/' + str(scan_id) +'/stop')


@cli.command(help="Start a valid Scan")
@click.argument('scan_id')
def start(scan_id):
    quick_post('/scans/' + str(scan_id) + '/launch')


@cli.command(help="Update local repository")
def update():
    vuln_export()
    asset_export()


@cli.command(help="Delete an Object by it's ID")
@click.argument('id')
@click.option('-scan', is_flag=True, help='Delete a Scan by Scan ID')
@click.option('-agroup', is_flag=True, help='Delete an access group by access group ID')
@click.option('-tgroup', is_flag=True, help='Delete a target-group by target-group ID')
@click.option('-policy', is_flag=True, help='Delete a Policy by Policy ID')
@click.option('-asset', is_flag=True, help='Delete an Asset by Asset UUID')
@click.option('-container', is_flag=True, help='Delete a container by \'/repository/image/tag\'')
@click.option('-tag', is_flag=True, help="Delete a Tag by Value UUID")
@click.option('-category', is_flag=True, help="Delete a Tag Category by UUID")
def delete(id, scan, agroup, tgroup, policy, asset, container, tag, category):

    if scan:
        print("I'm deleting your Scan Now")
        delete_data('/scans/'+str(id))

    if agroup:
        print("I'm deleting your Access Group Now")
        delete_data(('/access-groups/'+str(id)))

    if tgroup:
        print("I'm deleting your Target group Now")
        delete_data(('/target-groups/'+str(id)))

    if policy:
        print("I'm deleting your Policy Now")
        delete_data(('/policies/' + str(id)))

    if asset:
        print("I'm deleting your asset Now")
        delete_data('/workbenches/assets/' + str(id))

    if container:
        print("I'm deleting your container")
        delete_data('/container-security/api/v2/images' + str(id))

    if tag:
        print("I'm deleting your Tag Value")
        delete_data('/tags/values/' + str(id))

    if category:
        print("I'm Deleting your Category")
        delete_data('/tags/categories/'+str(id))


@cli.command(help="Get Scan Status")
@click.argument('Scan_id')
def status(scan_id):
    try:
        data = get_data('/scans/'+str(scan_id)+'/latest-status')
        print()
        print("\bLast Status update : "+data['status'])
        print()
    except:
        error_msg()


def add_helper(file,source):
    try:

        with open(file, 'r', newline='') as new_file:
            add_assets = csv.reader(new_file)
            print(add_assets)

            for row in add_assets:
                asset = {}
                ipv4 = []
                macs = []
                fqdns = []
                hostnames = []

                ipv4.append((row[0]))
                asset["ip_address"] = ipv4

                macs.append(row[1])
                asset["mac_address"] = macs

                hostnames.append(row[2])
                asset["hostname"] =hostnames

                fqdns.append(row[3])
                asset["fqdn"] =fqdns

                #create Payload
                payload ={"assets":[asset],"source":source}

                print("Added the following Data : \n")
                print(payload)
                print()

                #request Import Job
                data = post_data('/import/assets', payload)
                print("Your Import ID is : ", data['asset_import_job_uuid'])
    except Error as e:
        print(e)


@cli.command(help="Manually add an asset to Tenable.io")
@click.option('--ip', default='', help="IP address(s) of new asset")
@click.option('--mac', default='', help="Mac Address of new asset")
@click.option('--netbios', default='', help="NetBios of new asset")
@click.option('--fqdn', default='', help='FQDN of new asset')
@click.option('--hostname', default='', help="Hostname of new asset")
@click.option('--list', default='', help="Provide a CSV file in this order: IP, MAC, FQDN, Hostname. Leave fields blank if N/A")
@click.option('--source', default='Navi', help="Provide the source of the information")
def add(ip, mac, netbios, fqdn, hostname, list, source):
    try:
        asset = {}
        ipv4 = []
        macs = []
        fqdns = []
        hostnames = []
        if ip:
            ipv4.append(ip)
            asset["ip_address"] = ipv4

        if mac:
            macs.append(mac)
            asset["mac_address"] = macs

        if netbios:
            asset["netbios_name"] = netbios

        if fqdn:
            fqdns.append(fqdn)
            asset["fqdn"] =fqdns

        if hostname:
            hostnames.append(hostname)
            asset["hostname"] =hostnames

        if list:
           add_helper(list)


        #create Payload
        payload ={"assets":[asset],"source":source}

        print("Added the following Data : \n")
        print(payload)
        print()

        #request Import Job
        data = post_data('/import/assets', payload)
        print("Your Import ID is : ", data['asset_import_job_uuid'])
    except Error as e:
        print(e)
        error_msg()


@cli.command(help="Mail yourself a Report")
@click.option('-latest', is_flag=True, help='Email Vulnerability Summary Information')
@click.option('-consec', is_flag=True, help="Email Container Security Summary Information")
@click.option('-webapp', is_flag=True, help="Email Web Application Scanning Summary Information")
def mail(latest, consec, webapp):
    try:
        #grab SMTP information
        server, port, from_email, password = grab_smtp()
        to_email = input("Please enter the email you wish send this mail to: ")
        subject = input("Please enter the Subject of the email : ")

        subject += " - Emailed by Navi Pro"

        #start the message with the proper heading
        msg = "\r\n".join([
            "From: {}".format(from_email),
            "To: {}".format(to_email),
            "Subject: {}".format(subject),
            "",])

        if latest:
            data = get_data('/scans')
            l = []
            e = {}
            for x in range(len(data["scans"])):
                # keep UUID and Time together
                # get last modication date for duration computation
                epoch_time = data["scans"][x]["last_modification_date"]
                # get the scanner ID to display the name of the scanner
                d = data["scans"][x]["id"]
                # need to identify type to compare against pvs and agent scans
                type = str(data["scans"][x]["type"])
                # don't capture the PVS or Agent data in latest
                while type not in ['pvs', 'agent', 'webapp', 'lce']:
                    # put scans in a list to find the latest
                    l.append(epoch_time)
                    # put the time and id into a dictionary
                    e[epoch_time] = d
                    break

            # find the latest time
            grab_time = max(l)

            # get the scan with the corresponding ID
            grab_uuid = e[grab_time]

            # turn epoch time into something readable
            epock_latest = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(grab_time))
            msg += "\nThe last Scan run was at : {}\n".format(epock_latest)

            # pull the scan data
            details = get_data('/scans/' + str(grab_uuid))

            # pprint.pprint(details)

            scanner_name = details["info"]['scanner_name']
            name = details["info"]["name"]
            hostcount = details["info"]["hostcount"]

            msg += "\nThe Scanner name is : {}"\
                "\nThe Name of the scan is {}"\
                "The {} host(s) that were scanned are below :\n".format(scanner_name, name, hostcount)

            for x in range(len(details["hosts"])):
                hostname = details["hosts"][x]["hostname"]
                msg += "\n {}".format(hostname)

            start = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime(details["info"]["scan_start"]))

            msg += "\n\nScan start : {}".format(start)

            try:
                stop = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime(details["info"]["scan_end"]))
                msg += "Scan finish : ".format(stop)

                duration = (details["info"]["scan_end"] - details["info"]["scan_start"]) / 60
                msg += "Duration : {} Minutes".format(duration)
            except:
                print("This scan is still running")

            msg += "\nScan Notes Below : \n\n"

            for x in range(len(details["notes"])):
                title = details["notes"][x]["title"]
                message = details["notes"][x]["message"]
                msg += "{} \n {}".format(title, message)

            msg += "\n\n"

        if consec:
            consec_data = get_data('/container-security/api/v2/images?limit=1000')
            msg += "\n\nContainer Name - Repo Name - Tag - Docker ID - # of Vulns\n---------------------------------------\n"

            for images in consec_data["items"]:
                name = images["name"]
                docker_id = str(images["imageHash"])
                vulns = str(images["numberOfVulns"])
                repo = str(images["repoName"])
                tag = str(images["tag"])
                msg += "{} : {} : {} : {} : {}\n".format(name, repo, tag, docker_id, vulns)

        if webapp:
            webapp_data = get_data('/scans')

            # cycle through all of the scans and pull out the webapp scan IDs
            msg += "\n\n Web Application Scan Summary\n-----------------------------------------\n"
            for scans in webapp_data['scans']:

                if scans['type'] == 'webapp':
                    scan_details = get_data('/scans/' + str(scans['id']))
                    try:
                        hostname = scan_details['hosts'][0]['hostname']
                    except:
                        hostname = " "
                    try:
                        message = scan_details['notes'][0]['message']
                    except:
                        message = " "
                    try:
                        critical = scan_details['hosts'][0]['critical']
                    except:
                        critical = 0
                    try:
                        high = scan_details['hosts'][0]['high']
                    except:
                        high = 0
                    try:
                        medium = scan_details['hosts'][0]['medium']
                    except:
                        medium = 0
                    try:
                        low = scan_details['hosts'][0]['low']
                    except:
                        low = 0

                    if message != "Job expired while pending status.":
                        msg += "\nFQDN : {}\n" \
                               "Scan Message: " \
                               "{}\n\n" \
                               "Vulnerability Summary\n----------------------\n" \
                               "Critical : {}\n" \
                               "High {}\n" \
                               "Medium {}\n" \
                               "Low {}\n".format(hostname, message, critical, high, medium, low)

        print("Here is a copy of your email that was Sent")
        print(msg)
        send_email(from_email, to_email, msg, server, password, port)
    except Exception as E:
        print("Your Email information may be incorrect")
        print("Run the 'SMTP' command to correct your information")
        print(E)


@cli.command(help="Spin up a http server to extract data from the container")
def http():
    try:
        os.system("python3 -m http.server")
    except:
        print("This feature is for container's only")


@cli.command(help="Open up a Netcat listener to accept files over port 8000")
def listen():
    try:
        print("I'm opening a connection so you can send a file into the container")
        print("use this command on your pc to send data to the connector: nc 0.0.0.0 8000 < \"yourfile.csv\"")
        os.system("nc -l -p 8000 > newfile.csv")
    except:
        print("This command uses netcat and is only meant for Navi running in a docker container")
        print("You probably don't have netcat installed")


if __name__ == '__main__':
    cli()
