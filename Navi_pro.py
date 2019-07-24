#!/usr/bin/env python3
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


requests.packages.urllib3.disable_warnings()


@click.group()
def cli():
    click.echo("Hey Listen!")


@cli.command(help="Enter or Reset your Keys")
def keys():
    #assumption is that the user keys didn't work or don't exist
    print("Hey you don't have any Keys!")
    access_key = input("Please provide your Access Key : ")
    secret_key = input("Please provide your Secret Key : ")

    dicts = {"Access Key": access_key, "Secret Key": secret_key}

    pickle_out = open("keys.pickle", "wb")
    pickle.dump(dicts, pickle_out)
    pickle_out.close()

    print("Now you have keys, re-run your command")
    sys.exit()


def smtp():

    if os.path.isfile('./smtp.pickle') is False:
        print("Hey you don't have any SMTP information!")

        server = input("Enter the Email servers address : ")
        port = input("Enter the port your Email server uses : ")
        from_email = input("Enter your Email Address : ")
        password = input("Enter your email password : ")

        dicts = {"Server": server, "Port": port, "From Email": from_email, "Password": password}

        pickle_out = open("smtp.pickle", "wb")
        pickle.dump(dicts, pickle_out)
        pickle_out.close()

        print("Your SMTP settings have been saved")
        print(dicts)
        return server, port, from_email, password


    else:
        pickle_in = open("smtp.pickle", "rb")
        smtp_info = pickle.load(pickle_in)
        server = smtp_info["Server"]
        port = smtp_info["Port"]
        from_email = smtp_info["From Email"]
        password = smtp_info["Password"]

        return server, port, from_email, password


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
    '''

    :param url_mod: The URL endpoint. Ex: /scans
    :return: Response from API in json format
    '''
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
    '''

    :param url_mod: The URL endpoint. Ex: /scans/<scan-id>/launch
    :return: Response from the API
    '''
    url = "https://cloud.tenable.com"
    headers = grab_headers()
    r = requests.post(url + url_mod, headers=headers, verify=False)

    return r


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


def put_data(url_mod,payload):
    #Set the URL endpoint
    url = "https://cloud.tenable.com"

    #grab headers for auth
    headers = grab_headers()

    #send Post request to API endpoint
    r = requests.put(url + url_mod, data=payload, headers=headers, verify=False)
    #retreive data in json format
    return


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

        #set a variable to True for our While loop
        not_ready = True

        #loop to check status until finished
        while not_ready is True:
            #Pull the status, then pause 5 seconds and ask again.
            if status['status'] == 'PROCESSING' or 'QUEUED':
                time.sleep(5)
                status = get_data('/vulns/export/' + ex_uuid + '/status')
                print("Status : " + str(status["status"]))

            #Exit Loop once confirmed finished
            if status['status'] == 'FINISHED':
                not_ready = False

            #Tell the user an error occured
            if status['status'] == 'ERROR':
                print("Error occurred")


        #create an empty list to put all of our data into.
        data = []

        #loop through all of the chunks
        for x in range(len(status['chunks_available'])):
            chunk_data = get_data('/vulns/export/' + ex_uuid + '/chunks/' + str(x+1))
            data.append(chunk_data)

            with open('tio_vuln_data.txt', 'w') as json_outfile:
                json.dump(chunk_data, json_outfile)

                json_outfile.close()
    except KeyError:
        print("Well this is a bummer; you don't have permissions to download Vuln data :( ")


def asset_export():
    # Set the payload to the maximum number of assets to be pulled at once
    thirty_days = time.time() - 2660000
    pay_load = {"chunk_size": 5000, "filters": {"last_assessed": int(thirty_days)}}
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


        # create an empty list to put all of our data into.
        data = []

        # loop through all of the chunks
        for x in range(len(status['chunks_available'])):
            chunk_data = get_data('/assets/export/' + ex_uuid + '/chunks/' + str(x+1))
            data.append(chunk_data)

            with open('tio_asset_data.txt', 'w') as json_outfile:
                json.dump(chunk_data, json_outfile)

                json_outfile.close()
    except KeyError:
        print("Well this is a bummer; you don't have permissions to download Asset data :( ")


def plugin_by_ip(cmd,plugin):
    try:
        with open('tio_vuln_data.txt') as json_file:
            data = json.load(json_file)

            for x in range(len(data)):
                if data[x]['asset']['ipv4'] == cmd:
                    if str(data[x]['plugin']['id']) == plugin:

                        print(data[x]['output'])
                    else:
                        pass
    except:
        print("Local Cache is corrupt; pulling new data")
        print("This will take a minute or two")
        print("If an export doesn't start check your API keys")
        vuln_export()
        asset_export()


def find_by_plugin(plugin):
    try:
        with open('tio_vuln_data.txt') as json_file:
            data = json.load(json_file)

            for x in range(len(data)):
                if str(data[x]['plugin']['id']) == plugin:
                    print("\nIP : ", data[x]['asset']['ipv4'])
                    print("UUID ", data[x]['asset']['uuid'])
                    print("---Plugin--", plugin, "--Output---")
                    print(data[x]['output'])
                    print("---Output--", plugin, "--End---")
                else:
                    pass
    except:
        print("Local Cache is corrupt; pulling new data")
        print("This will take a minute or two")
        print("If an export doesn't start check your API keys")
        vuln_export()
        asset_export()


def print_data(data):
    try:
        #there may be multiple outputs
        for x in range(len(data['outputs'])):
            click.echo(data['outputs'][x]['plugin_output'])

        #print an extra line in case the user sends multiple commands
        click.echo()

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
    with open('tio_asset_data.txt') as json_file:
        data = json.load(json_file)

        #Create our headers - We will Add these two our list in order
        header_list = ["IP Address", "Hostname", "FQDN", "UUID", "First Found", "Last Found", "Operating System",
                       "Mac Address", "Tags", "Info", "Low", "Medium", "High", "Critical"]

        #Crete a csv file object
        with open('asset_data.csv', mode='w') as csv_file:
            agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

            #write our Header information first
            agent_writer.writerow(header_list)

            #Loop through each asset
            for assets in data:
                #create a blank list to append asset details
                csv_list = []
                #Try block to ignore assets without IPs
                try:
                    #Capture the first IP
                    ip = assets['ipv4s'][0]
                    csv_list.append(ip)

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

                    id = assets['id']
                    csv_list.append(id)
                    csv_list.append(assets['first_seen'])
                    csv_list.append(assets['last_seen'])
                    try:
                        csv_list.append(assets['operating_systems'][0])
                    except:
                        csv_list.append(" ")

                    try:
                        csv_list.append(assets['mac_addresses'][0])
                    except:
                        csv_list.append(" ")

                    try:
                        csv_list.append(assets['tags'][0]['value'])
                    except:
                        csv_list.append(" ")

                    info = get_data('/workbenches/assets/' + id + '/info')

                    for counts in info['info']['counts']['vulnerabilities']['severities']:
                        count = counts['count']
                        csv_list.append(count)

                    agent_writer.writerow(csv_list)

                except IndexError:
                    pass


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

                    last_scanned = agents['agents'][a]['last_scanned']
                    scanned_time = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(last_scanned))

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


def scan_details(uuid):
    # pull the scan data
    details = get_data('/scans/' + str(uuid))

    # pprint.pprint(details)

    print("\nThe Scanner name is : " + str(details["info"]['scanner_name']))
    print("\nThe Name of the scan is " + str(details["info"]["name"]))
    print("The " + str(details["info"]["hostcount"]) + " host(s) that were scanned are below :\n")
    for x in range(len(details["hosts"])):
        print(details["hosts"][x]["hostname"])

    start = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime(details["info"]["scan_start"]))
    print("\nscan start : " + start)
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
        print('Something went wrong...')


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
        click.echo('Scan Detail')
        click.echo('----------------')
        plugin_by_ip(ipaddr, str(19506))

    if n:
        click.echo("Netstat info")
        click.echo("Established and Listening")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(58651))
        click.echo("Netstat Open Ports")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(14272))

    if p:
        click.echo("Patch Information")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(66334))

    if t:
        click.echo("Trace Route Info")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(10287))

    if o:
        click.echo("Process Info")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(70329))

    if patches:
        click.echo("Missing Patches")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(38153))

        click.echo("Last Reboot")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(56468))

    if c:
        click.echo("Connection info")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(64582))

    if s:
        click.echo("Service(s) Running")
        click.echo("----------------")
        with open('tio_vuln_data.txt') as json_file:
            data = json.load(json_file)
            for plugins in data:
                if plugins['plugin']['id'] == 22964:
                    # pprint.pprint(plugins)
                    output = plugins['output']
                    port = plugins['port']['port']
                    proto = plugins['port']['protocol']
                    print(output, ": ", port, proto)
                    print()

    if r:
        click.echo("Local Firewall Info")
        click.echo("----------------")
        plugin_by_ip(ipaddr, str(56310))

    if software:
        try:
            plugin_by_ip(ipaddr, str(22869))
            plugin_by_ip(ipaddr, str(20811))
        except IndexError:
                print("No Software found")

#this needs to be addressed

    if outbound:
        with open('tio_vuln_data.txt') as json_file:
            data = json.load(json_file)
            print("IP Address", " - ", "Port", " - ", "Service")
            print("-------------------------------")
            for x in range(len(data)):
                if data[x]['asset']['ipv4'] == ipaddr:

                    if data[x]['plugin']['id'] == 16:
                        print(data[x]['output'], "   -  ", data[x]['port']['port'], "  - ", data[x]['port']['service'])
                    else:
                        pass
        print()

    if exploit:

        try:

            N = get_data('/workbenches/assets/vulnerabilities?filter.0.quality=eq&filter.0.filter=ipv4&filter.0.value=' + ipaddr)

            asset_id = N['assets'][0]['id']


            print("Exploitable Details for : " + ipaddr)
            print()
            V = get_data(
                            '/workbenches/assets/' + asset_id + '/vulnerabilities?filter.0.quality=eq&filter.0.filter=plugin.attributes.exploit_available&filter.0.value=True')
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
            N = get_data('/workbenches/assets/vulnerabilities?filter.0.quality=eq&filter.0.filter=ipv4&filter.0.value=' + ipaddr)

            asset_id = N['assets'][0]['id']

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
            print("No Critical Vulnerabilities wer found for : ", ipaddr)

    if details:
        with open('tio_asset_data.txt') as json_file:
            data = json.load(json_file)
            #pprint.pprint(data[5])

            for x in range(len(data)):
                try:

                    ip = data[x]['ipv4s'][0]
                    id = data[x]['id']
                    if ip == ipaddr:
                        print("\nTenable UUID")
                        print("--------------")
                        print(data[x]['id'])

                        print("\nIdentities")
                        print("--------------")
                        try:
                            for n in range(len(data[x]['netbios_names'])):
                                print("Netbios - ", data[x]['netbios_names'][n])
                        except:
                            pass
                        try:
                            for n in range(len(data[x]['fqdns'])):
                                print("FQDN - ", data[x]['fqdns'][n])
                        except:
                            pass

                        try:
                            for h in range(len(data[x]['hostnames'])):
                                print("Host Name -", data[x]['hostnames'][h])
                        except:
                            pass

                        print("\nOperating Systems")
                        print("--------------")
                        try:
                            for o in range(len(data[x]['operating_systems'])):
                                print(data[x]['operating_systems'][o])
                        except:
                            pass

                        try:
                            print("\nIP Addresses:")
                            print("--------------")
                            for i in range(len(data[x]['ipv4s'])):
                                print(data[x]['ipv4s'][i])
                        except:
                            pass

                        try:
                            print("\nMac Addresses:")
                            print("--------------")
                            for m in range(len(data[x]['mac_addresses'])):
                                print(data[x]['mac_addresses'][m])
                        except:
                            pass
                        try:
                            print("\nTags:")
                            print("--------------")
                            for i in range(len(data[x]['tags'])):
                                print(data[x]['tags'][i]["key"], ':', data[x]['tags'][i]['value'])
                        except:
                            pass

                        try:
                            print("\nVulnerability Counts")
                            print("--------------")
                            asset_info = get_data('/workbenches/assets/'+id+'/info')


                            for vuln in asset_info['info']['counts']['vulnerabilities']['severities']:
                                print(vuln["name"]," : ", vuln["count"])

                            print("\nExposure Score : ", asset_info['info']['exposure_score'])
                        except:
                            pass

                        print("\nLast Authenticated Scan Date - ", data[x]['last_authenticated_scan_date'])

                except:
                    pass

        # We want the Scan template ID to do a quick re-scan.
        with open('tio_vuln_data.txt') as vuln_file:
            vulndata = json.load(vuln_file)
            for z in range(len(vulndata)):
                if vulndata[z]['plugin']['id'] == 19506:

                    if vulndata[z]['asset']['ipv4'] == ipaddr:

                        print("Scan Date :", vulndata[z]['scan']['completed_at'])
                        print("Scan Template UUID", vulndata[z]['scan']['schedule_uuid'])
                        print("-----------------------------")
                    else:

                        pass


@cli.command(help="Export data into a CSV")
@click.option('-assets', is_flag=True, help='Exports all Asset data into a CSV')
@click.option('-agents', is_flag=True, help="Export all Agent data into a CSV")
@click.option('-webapp', is_flag=True, help="Export Webapp Scan Summary into a CSV")
@click.option('-consec', is_flag=True, help="Export Container Security Summary into a CSV")
def export(assets, agents, webapp, consec):
    if assets:
        print("Exporting your data now.  Saving asset_data.csv now...")
        print()
        csv_export()

    if agents:
        print("Exporting your data now.  Saving agent_data.csv now...")
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

#consider changing the argument to TEXT. Look to see if the length is over that of a Plugin ID and if is a number
#consider breaking these out into their own top level command
@cli.command(help="Create Target Groups ex: Plugin ID or Text to search for")
@click.argument('plugin')
@click.option('-pid', is_flag=True, help='Create Target Group based a plugin ID')
@click.option('-pname', is_flag=True, help='Create Target Group by Text found in the Plugin Name')
@click.option('--pout', default='', help='Create a Target Group by Text found in the Plugin Output: Must supply Plugin ID first')
def group(plugin, pid, pname, pout):
    target_list = []
    if pid:

        try:
            with open('tio_vuln_data.txt') as json_file:
                data = json.load(json_file)

                for x in range(len(data)):
                    if str(data[x]['plugin']['id']) == plugin:
                        #set IP to search with later
                        ip = data[x]['asset']['ipv4']

                        #ensure the ip isn't already in the list
                        if ip not in target_list:
                            target_list.append(ip)
                    else:
                        pass
            #print(target_list)
            create_target_group("Navi_by_plugin-"+str(plugin), target_list)
        except:
            print("Try again..")

    if pname:
        try:
            with open('tio_vuln_data.txt') as json_file:
                data = json.load(json_file)

                for x in range(len(data)):
                    plugin_name = data[x]['plugin']['name']
                    if plugin in plugin_name:
                        ip = data[x]['asset']['ipv4']
                        #print("\nIP : ", ip)
                        if ip not in target_list:
                            target_list.append(ip)
                    else:
                        pass
            #print(target_list)
            create_target_group("Navi_by_Text_in_plugin_name-"+str(plugin), target_list)
        except:
            print("Try again")

    if pout:
        try:
            with open('tio_vuln_data.txt') as json_file:
                data = json.load(json_file)

                for x in range(len(data)):
                    if str(data[x]['plugin']['id']) == plugin:
                        if pout in data[x]['output']:
                            ip = data[x]['asset']['ipv4']
                            #print("\nIP : ", ip)
                            if ip not in target_list:
                                target_list.append(ip)
                    else:
                        pass
            #print(target_list)
            create_target_group("Navi_by_Text_in_plugin_output:"+pout,target_list)
        except:
            print("try again")

    if plugin == 'aws':
        try:
            query = {"date_range": "30", "filter.0.filter": "sources", "filter.0.quality": "set-hasonly",
                     "filter.0.value": "AWS"}
            data = special_get('/workbenches/assets', query)

            for assets in data['assets']:

                ip = assets['ipv4'][0]

                target_list.append(ip)

            #print(target_list)
            create_target_group("Navi_by_AWS_Connector_info",target_list)
        except:
            print("try again")


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
        print("Searching for Web Servers found by NNM...\n")
        with open('tio_vuln_data.txt') as json_file:
            data = json.load(json_file)

            for plugins in data:
                if plugins['plugin']['id'] == 1442:
                    web = plugins['output']
                    wsplit = web.split("\n")

                    server = wsplit[1]
                    port = plugins['port']['port']
                    proto = plugins['port']['protocol']
                    asset = plugins['asset']['ipv4']
                    # pprint.pprint(server)

                    print(asset, ": Has a Web Server Running :")
                    print(server, "is running on: ", port, proto)
                    print()

    if creds:
        print("I'm looking for credential issues...Please hang tight")
        find_by_plugin(str(104410))

    if time != '':
        with open('tio_vuln_data.txt') as json_file:
            data = json.load(json_file)

            # pprint.pprint(data[0])
            print("Below are the asseets that took longer than " + str(time) + " minutes to scan")
            # pprint.pprint(data[0])
            for vulns in data:
                if vulns['plugin']['id'] == 19506:

                    output = vulns['output']
                    #pprint.pprint(vulns)
                    # split the output by carrage return
                    parsed_output = output.split("\n")

                    # grab the length so we can grab the seconds
                    length = len(parsed_output)

                    # grab the scan duration- second to the last varable
                    duration = parsed_output[length - 2]

                    # Split at the colon to grab the numerical value
                    seconds = duration.split(" : ")

                    # split to remove "secs"
                    number = seconds[1].split(" ")

                    # grab the number for our minute calulation
                    final_number = number[0]

                    # convert seconds into minutes
                    minutes = int(final_number) / 60

                    # grab assets that match the criteria
                    if minutes > int(time):

                        try:
                            print("Asset IP: ", vulns['asset']['ipv4'])
                            print("Asset UUID: ", vulns['asset']['uuid'])
                            print("Scan started at: ", vulns['scan']['started_at'])
                            print("Scan completed at: ", vulns['scan']['completed_at'])
                            print("Scan UUID: ", vulns['scan']['uuid'])
                            print()
                        except:
                            pass

    if ghost:

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


@cli.command(help="Get the Latest Scan information")
@click.option('-latest', is_flag=True, help="Report the Last Scan Details")
@click.option('--container', default='', help='Report CVSS 7 or above by Container ID. Use: list -containers to find Containers')
@click.option('--docker', default='', help='Report CVSS 7 or above by Docker ID')
@click.option('--comply', default='', help='Check to see if your container complies with your Corporate Policy')
@click.option('--details', default='', help='Report Scan Details including Vulnerability Counts by Scan ID')
@click.option('--summary', default='', help="Report Scan Summary information by Scan ID")
def report(latest,container,docker,comply, details, summary):
    #get the latest Scan Details
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
        print("\nThe last Scan run was at " + epock_latest)
        scan_details(str(grab_uuid))

    if container:
        querystring = {"image_id": str(container)}
        data = special_get('/container-security/api/v1/reports/by_image', querystring)
        #pprint.pprint(data)

        try:
            for vulns in data['findings']:
                if float(vulns['nvdFinding']['cvss_score']) >= 7:
                    print("CVE ID :", vulns['nvdFinding']['cve'])
                    print("CVSS Score : ",vulns['nvdFinding']['cvss_score'])
                    print("--------------------------------------------------")
                    print("Description : ", vulns['nvdFinding']['description'])
                    print("\nRemediation :", vulns['nvdFinding']['remediation'])
                    print("----------------------END-------------------------\n")
        except(TypeError):
            print("This Container has no data or is not found")
        except(ValueError):
            pass

    if docker:
        data = get_data('/container-security/api/v1/reports/by_image?image_id='+str(docker))

        try:
            for vulns in data['findings']:
                if float(vulns['nvdFinding']['cvss_score']) >= 7:
                    print("CVE ID :", vulns['nvdFinding']['cve'])
                    print("CVSS Score : ",vulns['nvdFinding']['cvss_score'])
                    print("--------------------------------------------------")
                    print("Description : ", vulns['nvdFinding']['description'])
                    print("\nRemediation :", vulns['nvdFinding']['remediation'])
                    print("----------------------END-------------------------\n")
        except(TypeError):
            print("This Container has no data or is not found")
        except(ValueError):
            pass

    if comply:
        data = get_data('/container-security/api/v1/policycompliance?image_id=' + str(comply))

        print("Status : ", data['status'])
        #pprint.pprint(data)

    if details:

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
            #pprint.pprint(data['hosts'])
            print()
            print("Vulnerability Details")
            print("---------------------")

            for vulns in data['vulnerabilities']:
                if vulns['severity'] != 0:
                    print(vulns['plugin_name'], " : ", vulns['count'])
        except:
            print("Check the scan ID")

    if summary:
        print("\nHere is the Summary of your Scan :")
        print("----------------------------------")
        scan_details(str(summary))


@cli.command(help="Test the API ex: /scans ")
@click.argument('url')
def api(url):
    try:
        data = get_data(url)
        pprint.pprint(data)
    except:
        click.echo("\nWell this isn't right.  I think you need API keys\n")
        click.echo("Run the keys command to get new API keys\n")


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
def list(scanners, users, exclusions, containers, logs, running, scans, nnm, assets, policies, connectors, agroup, status, agents, webapp, tgroup):

    if scanners:
        nessus_scanners()

    if users:
        data = get_data('/users')
        for x in range(len(data["users"])):
            print(data["users"][x]["name"])
            print(data["users"][x]["user_name"])

    if exclusions:
        try:
            data = get_data('/exclusions')
            for x in range(len(data["exclusions"])):
                print("Exclusion Name : " + data["exclusions"][x]["name"])
                print(data["exclusions"][x]["members"])

        except:
            print("No Exclusions Set")

    if containers:
        data = get_data('/container-security/api/v2/images?limit=1000')
        print("Container Name : Docker ID : # of Vulns\n")

        for images in data["items"]:

            print(str(images["name"]) + " : " + str(images["imageHash"]) + " : " + str(images["numberOfVulns"]))

    if logs:
        data = get_data('/audit-log/v1/events')
        # pprint.pprint(data['events'])
        for log in range(len(data['events'])):
            received = data['events'][log]['received']
            action = data['events'][log]['action']
            actor = data['events'][log]['actor']['name']

            print("Date : " + received)
            print("-------------------")
            print(action)
            print(actor)
            print()

    if running:
        #run = 0
        try:
            data = get_data('/scans')
            run = 0
            for x in range(len(data['scans'])):
                if data['scans'][x]['status'] == "running":
                    run = run + 1
                    name = data['scans'][x]['name']
                    scan_id = data['scans'][x]['id']
                    current_status = data['scans'][x]['status']

                    click.echo("Scan Name : " + name)
                    print("Scan ID : " + str(scan_id))
                    print("Current status : " + current_status)
            if run == 0:
                print("No running scans")
        except:
            print("You may not have access...Check permissions...or Keys")

    if scans:
        try:
            data = get_data('/scans')

            for x in range(len(data['scans'])):
                name = data['scans'][x]['name']
                scan_id = data['scans'][x]['id']
                scan_status = data['scans'][x]['status']

                print("Scan Name : " + name)
                print("Scan ID : " + str(scan_id))
                print("Current status : " + scan_status)
                print("-----------------\n")

        except:
            print("You may not have access...Check permissions...or Keys")

    if nnm:
        # dynamically find the PVS sensor
        nnm_data = get_data('/scans')

        for x in range(len(nnm_data["scans"])):

            if (str(nnm_data["scans"][x]["type"]) == 'pvs'):
                nnm_id = nnm_data["scans"][x]["id"]

                try:
                    data = get_data('/scans/' + str(nnm_id) + '/')
                    print("Here are the assets and their scores last found by Nessus Network Monitor")
                    print("   IP Address     : Score")
                    print("----------------")

                    for y in range(len(data["hosts"])):
                        print(str(data["hosts"][y]["hostname"]) + " :  " + str(data["hosts"][y]["score"]))

                    print()
                except:
                    print("No Data found or no Nessus Monitor found")
                    print("check permissions to the scanner")
            else:
                pass

    if assets:
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

    if policies:
        data = get_data('/policies')
        for x in range(len(data['policies'])):
            print(data['policies'][x]['name'])
            print(data['policies'][x]['description'])
            print('Template ID : ', data['policies'][x]['template_uuid'])
            print()

    if connectors:
        try:
            data = get_data('/settings/connectors')
            #pprint.pprint(data)
            for conn in data["connectors"]:
                print("\nConnector Type: ", conn['type'])
                print("Connector Name: ", conn['name'])
                print("Connector ID: ", conn['id'])
                print("----------------------------")
                print("Schedule: ", conn['schedule']['value'], conn['schedule']['units'])
                print("Last Sync Time", conn['last_sync_time'])
                print("---------------")
                print("Status Message: ",conn['status_message'])
                print("------------------------------------------")
        except:
            print("No connectors configured")

    if agroup:

        try:
            data = get_data('/access-groups')
            for group in data["access_groups"]:
                print("\nAccess Group Name: ", group['name'])
                print("Access Group ID: ", group['id'])
                #For Some reason there is not a Created by record for every Access Group
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
            print("No Access Groups Configured")

    if status:
        data = get_data("/server/properties")
        #pprint.pprint(data)
        print("\nTenable IO Information")
        print("-----------------------")
        print("Container ID :", data["analytics"]["key"])
        print("Site ID :", data["analytics"]["site_id"])
        print("Region : ", data["region"])

        print("\nLicense information")
        print("--------------------")
        print("Agents Used : ", data["license"]["agents_used"])
        print("Expiration Date : ", data["license"]["expiration_date"])
        print("Scanners Used : ", data["license"]["scanners_used"])
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

    if agents:
        data = get_data('/scanners/104490/agents')
        print("\b Agent information is pulled from the US Cloud Scanner\b")
        for agent in data['agents']:
            last_connect = agent['last_connect']
            last_connect_time = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(last_connect))

            last_scanned = agent['last_scanned']
            last_scanned_time = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(last_scanned))
            print("Agent Name : ", agent['name'])
            print("-----------------------------")
            print("\bAgent IP : ", agent['ip'])
            print("\bLast Connected :", last_connect_time)
            print("\bLast Scanned : ", last_scanned_time)
            print("\bAgent Status : ", agent['status'])
            print()
            print("\bGroups")
            print("-------------")

            try:
                for group in agent['groups']:
                    print(group['name'])
            except:
                pass
            print()

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
            print("You may not have access...Check permissions...or Keys")

    if tgroup:
        data = get_data('/target-groups')
        try:
            for group in data['target_groups']:
                print()
                print("Name : ", group['name'])
                print("Owner : ", group['owner'])
                print("Target Group ID : ", group['id'])
                print("Members : ", group['members'])
                print()
        except:
            print("You may not have Target Groups or permissions")


@cli.command(help="Quickly Scan a Target")
@click.argument('targets')
def scan(targets):
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


@cli.command(help="Create a Web App scan from a CSV file")
@click.argument('csv_input')
def spider(csv_input):

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


@cli.command(help="Enter in a Mac Address to find the Manufacturer")
@click.argument('address')
def mac(address):
    api_token = "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJtYWN2ZW5kb3JzIiwiZXhwIjoxODU3NzYzODQ1LCJpYXQiOjE1NDMyNjc4NDUsImlzcyI6Im1hY3ZlbmRvcnMiLCJqdGkiOiIzYWNiM2Q0YS1lZjQ2LTQ3NWUtYWJiZS05M2NiMDlkMDU5YzIiLCJuYmYiOjE1NDMyNjc4NDQsInN1YiI6Ijk0NyIsInR5cCI6ImFjY2VzcyJ9.a_dLSCJq-KLjOQL52ZgiuDY08_YE5Wl7QhAJpDpHOKoIesGeMRnPGZAx3TgtfwyQVyy6_ozhy447GGdfKyjDXw"

    headers = {'Content-type': 'application/json', 'Authorization': api_token}
    #mac_address = "b8:27:eb:05:cf:76"
    url = "https://api.macvendors.com/v1/lookup/"

    r = requests.request('GET', url + address, headers=headers, verify=False)
    data = r.json()
    print("Assignment Group:")
    print(data['data']['assignment'])

    print("\nOrganization name:")
    print(data['data']['organization_name'])


@cli.command(help="Pause a running Scan")
@click.argument('Scan_id')
def pause(scan_id):
    try:
        data = quick_post('/scans/' + str(scan_id) + '/pause')
        if data.status_code == 200:
            print(" Your Scan was Paused")
        elif data.status_code == 409:
            print("Wait a few seconds and try again")
        elif data.status_code == 404:
            print("yeah, this scan doesn't exist")
        elif data.status_code == 501:
            print("There was an error: ")
            print(data.reason)
        else:
            print("It's possible this is already paused")
    except:
        print("Ahh now you've done it...")
        print("double check your id")


@cli.command(help="Resume a paused Scan")
@click.argument('scan_id')
def resume(scan_id):
    try:
        data = quick_post('/scans/' + str(scan_id) + '/resume')
        if data.status_code == 200:
            print(" Your Scan Resumed")
        elif data.status_code == 409:
            print("Wait a few seconds and try again")
        elif data.status_code == 404:
            print("yeah, this scan doesn't exist")
        else:
            print("It's possible this is already running")


    except:
        print("Ahh now you've done it...")
        print("double check your id")


@cli.command(help="Stop a Running Scan")
@click.argument('scan_id')
def stop(scan_id):
    try:
        data = quick_post('/scans/' + str(scan_id) + '/stop')
        if data.status_code == 200:
            print(" Your Scan was Stopped")
        elif data.status_code == 409:
            print("Wait a few seconds and try again")
        elif data.status_code == 404:
            print("yeah, this scan doesn't exist")
        else:
            print("It's possible this is already stopped")


    except:
        print("Ahh now you've done it...")
        print("double check your id")


@cli.command(help="Start a valid Scan")
@click.argument('scan_id')
def start(scan_id):
    try:
        data = quick_post('/scans/' + str(scan_id) + '/launch')
        if data.status_code == 200:
            print(" Your Scan was Started")
        elif data.status_code == 409:
            print("Wait a few seconds and try again")
        elif data.status_code == 404:
            print("yeah, this scan doesn't exist")
        else:
            print("It's possible this is already started")


    except:
        print("Ahh now you've done it...")
        print("double check your id")


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
def delete(id, scan, agroup, tgroup, policy, asset):

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


@cli.command(help="Get Scan Status")
@click.argument('Scan_id')
def status(scan_id):
    data = get_data('/scans/'+str(scan_id)+'/latest-status')
    print()
    print("\bLast Status update : "+data['status'])
    print()


@cli.command(help="Manually add an asset to Tenable.io")
@click.option('--ip', default='', help="IP address(s) of new asset")
@click.option('--mac', default='', help="Mac Address of new asset")
@click.option('--netbios', default='', help="NetBios of new asset")
@click.option('--fqdn', default='', help='FQDN of new asset')
@click.option('--hostname', default='', help="Hostname of new asset")
def add(ip, mac, netbios, fqdn, hostname):
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

    #create Payload
    payload ={"assets":[asset],"source":"navi"}

    print("Added the following Data : \n")
    print(payload)
    print()

    #request Import Job
    data = post_data('/import/assets', payload)
    print("Your Import ID is : ", data['asset_import_job_uuid'])


@cli.command(help="Mail yourself a Report")
@click.option('-latest', is_flag=True, help='Email Vulnerability Summary Information')
@click.option('-consec', is_flag=True, help="Email Container Security Summary Information")
@click.option('-webapp', is_flag=True, help="Email Web Application Scanning Summary Information")
def mail(latest, consec, webapp):
    server, port, from_email, password = smtp()

    to_email = input("Please enter the email you wish send this mail to: ")
    subject = input("Please enter the Subject of the email : ")

    subject += " - Emailed by Navi Pro"
    '''
    from_email = 'auto.jason.blox@gmail.com'
    #to_email = 'cyberdice113@gmail.com'
    #subject = 'Cyber Exposure Information emailed by Navi Pro'
    mail_server = 'smtp.gmail.com'
    port = 587
    password = ''
    '''
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
        msg += "\n\nContainer Name - Docker ID - # of Vulns\n---------------------------------------\n"

        for images in consec_data["items"]:
            name = images["name"]
            docker_id = str(images["imageHash"])
            vulns = str(images["numberOfVulns"])
            msg += "{} : {} : {}\n".format(name, docker_id, vulns)

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


if __name__ == '__main__':
    cli()
