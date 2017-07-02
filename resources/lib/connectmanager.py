# -*- coding: utf-8 -*-
###############################################################################
from logging import getLogger

# from connect.connectionmanager import ConnectionManager
from downloadutils import DownloadUtils
from dialogs.serverconnect import ServerConnect
from connect.plex_tv import plex_tv_sign_in_with_pin
from userclient import UserClient
from utils import window, settings, tryEncode, language as lang, dialog
from PlexFunctions import GetMachineIdentifier, get_pms_settings, \
    check_connection
import variables as v

###############################################################################

log = getLogger("PLEX."+__name__)

# STATE = connectionmanager.ConnectionState

###############################################################################


def get_plex_login_from_settings():
    """
    Returns a dict:
        'plexLogin': settings('plexLogin'),
        'plexToken': settings('plexToken'),
        'plexhome': settings('plexhome'),
        'plexid': settings('plexid'),
        'myplexlogin': settings('myplexlogin'),
        'plexAvatar': settings('plexAvatar'),
        'plexHomeSize': settings('plexHomeSize')

    Returns strings or unicode

    Returns empty strings '' for a setting if not found.

    myplexlogin is 'true' if user opted to log into plex.tv (the default)
    plexhome is 'true' if plex home is used (the default)
    """
    return {
        'plexLogin': settings('plexLogin'),
        'plexToken': settings('plexToken'),
        'plexhome': settings('plexhome'),
        'plexid': settings('plexid'),
        'myplexlogin': settings('myplexlogin'),
        'plexAvatar': settings('plexAvatar'),
        'plexHomeSize': settings('plexHomeSize')
    }


class ConnectManager(object):
    # Borg
    __shared_state = {}

    def __init__(self):
        # Borg
        self.__dict__ = self.__shared_state

        log.debug('Instantiating')
        self.doUtils = DownloadUtils().downloadUrl
        self.server = UserClient().getServer()
        self.serverid = settings('plex_machineIdentifier')
        # Get Plex credentials from settings file, if they exist
        plexdict = get_plex_login_from_settings()
        self.myplexlogin = plexdict['myplexlogin'] == 'true'
        self.plexLogin = plexdict['plexLogin']
        self.plexToken = plexdict['plexToken']
        self.plexid = plexdict['plexid']
        # Token for the PMS, not plex.tv
        self.pms_token = settings('accessToken')
        if self.plexToken:
            log.debug('Found a plex.tv token in the settings')

    def update_state(self):
        self.state = self.__connect.connect({'updateDateLastAccessed': False})
        return self.get_state()

    def get_sate(self):
        window('emby_state.json', value=self.state)
        return self.state

    def get_server(self, server, options={}):
        self.state = self.__connect.connectToAddress(server, options)
        return self.get_state()

    @classmethod
    def get_address(cls, server):
        return connectionmanager.getServerAddress(server, server['LastConnectionMode'])

    def clear_data(self):
        self.__connect.clearData()

    def select_servers(self):
        """
        Will return selected server or raise RuntimeError
        """
        dia = ServerConnect("script-emby-connect-server.xml",
                            tryEncode(v.ADDON_PATH),
                            "default",
                            "1080i")
        dia.doModal()

        if dia.is_server_selected():
            log.debug("Server selected")
            return dia.get_server()

        elif dia._is_connect_login():
            log.debug("Login to plex.tv")
            try:
                # Login to emby connect
                self._login_connect()
            except RuntimeError:
                pass
            return self.select_servers()

        elif dia.is_manual_server():
            log.debug("Add manual server")
            try:
                # Add manual server address
                return self.manual_server()
            except RuntimeError:
                return self.select_servers()
        else:
            raise RuntimeError("No server selected")

    def manual_server(self):
        # Return server or raise error
        dia = ServerManual("script-emby-connect-server-manual.xml", *XML_PATH)
        dia._set_connect_manager(self.__connect)
        dia.doModal()

        if dia._is_connected():
            return dia.get_server()
        else:
            raise RuntimeError("Server is not connected")

    def _login_connect(self):
        # Return connect user or raise error
        dia = LoginConnect("script-emby-connect-login.xml", *XML_PATH)
        dia._set_connect_manager(self.__connect)
        dia.doModal()

        self.update_state()

        if dia.is_logged_in():
            return dia.get_user()
        else:
            raise RuntimeError("Connect user is not logged in")

    def login(self, server=None):
        # Return user or raise error
        server = server or self.state['Servers'][0]
        server_address = connectionmanager.getServerAddress(server, server['LastConnectionMode'])

        users = "";
        try:
            users = self.emby.getUsers(server_address)
        except Exception as error:
            log.info("Error getting users from server: " + str(error))

        if not users:
            try:
                return self.login_manual(server_address)
            except RuntimeError:
                raise RuntimeError("No user selected")

        dia = UsersConnect("script-emby-connect-users.xml", *XML_PATH)
        dia.set_server(server_address)
        dia.set_users(users)
        dia.doModal()

        if dia.is_user_selected():

            user = dia.get_user()
            username = user['Name']

            if user['HasPassword']:
                log.debug("User has password, present manual login")
                try:
                    return self.login_manual(server_address, username)
                except RuntimeError:
                    return self.login(server)
            else:
                try:
                    user = self.emby.loginUser(server_address, username)
                except Exception as error:
                    log.info("Error logging in user: " + str(error))
                    raise

                self.__connect.onAuthenticated(user)
                return user

        elif dia.is_manual_login():
            try:
                return self.login_manual(server_address)
            except RuntimeError:
                return self.login(server)
        else:
            raise RuntimeError("No user selected")

    def login_manual(self, server, user=None):
        # Return manual login user authenticated or raise error
        dia = LoginManual("script-emby-connect-login-manual.xml", *XML_PATH)
        dia.set_server(server)
        dia.set_user(user)
        dia.doModal()

        if dia.is_logged_in():
            user = dia.get_user()
            self.__connect.onAuthenticated(user)
            return user
        else:
            raise RuntimeError("User is not authenticated")

    def update_token(self, server):

        credentials = self.__connect.credentialProvider.getCredentials()
        self.__connect.credentialProvider.addOrUpdateServer(credentials['Servers'], server)

        for server in self.get_state()['Servers']:
            for cred_server in credentials['Servers']:
                if server['Id'] == cred_server['Id']:
                    # Update token saved in current state
                    server.update(cred_server)
        # Update the token in data.txt
        self.__connect.credentialProvider.getCredentials(credentials)

    def _get_connect_servers(self):

        connect_servers = []
        servers = self.__connect.getAvailableServers()
        for server in servers:
            if 'ExchangeToken' in server:
                result = self.connect_server(server)
                if result['State'] == STATE['SignedIn']:
                    connect_servers.append(server)

        log.info(connect_servers)
        return connect_servers

    def connect_server(self, server):
        return self.__connect.connectToServer(server, {'updateDateLastAccessed': False})

    def pick_pms(self, show_dialog=False):
        """
        Searches for PMS in local Lan and optionally (if self.plexToken set)
        also on plex.tv
            show_dialog=True: let the user pick one
            show_dialog=False: automatically pick PMS based on
                               machineIdentifier

        Returns the picked PMS' detail as a dict:
        {
        'name': friendlyName,      the Plex server's name
        'address': ip:port
        'ip': ip,                   without http/https
        'port': port
        'scheme': 'http'/'https',   nice for checking for secure connections
        'local': '1'/'0',           Is the server a local server?
        'owned': '1'/'0',           Is the server owned by the user?
        'machineIdentifier': id,    Plex server machine identifier
        'accesstoken': token        Access token to this server
        'baseURL': baseURL          scheme://ip:port
        'ownername'                 Plex username of PMS owner
        }

        or None if unsuccessful
        """
        server = None
        # If no server is set, let user choose one
        if not self.server or not self.serverid:
            show_dialog = True
        if show_dialog is True:
            server = self.connectmanager.select_servers()
            log.info("Server: %s", server)
            server = self.__user_pick_pms()
        else:
            server = self.__auto_pick_pms()
        if server is not None:
            self.write_pms_settings(server['baseURL'], server['accesstoken'])
        return server

    @staticmethod
    def write_pms_settings(url, token):
        """
        Sets certain settings for server by asking for the PMS' settings
        Call with url: scheme://ip:port
        """
        xml = get_pms_settings(url, token)
        try:
            xml.attrib
        except AttributeError:
            log.error('Could not get PMS settings for %s' % url)
            return
        for entry in xml:
            if entry.attrib.get('id', '') == 'allowMediaDeletion':
                settings('plex_allows_mediaDeletion',
                         value=entry.attrib.get('value', 'true'))
                window('plex_allows_mediaDeletion',
                       value=entry.attrib.get('value', 'true'))

    def __auto_pick_pms(self):
        """
        Will try to pick PMS based on machineIdentifier saved in file settings
        but only once

        Returns server or None if unsuccessful
        """
        httpsUpdated = False
        checkedPlexTV = False
        server = None
        while True:
            if httpsUpdated is False:
                serverlist = self.__get_server_list()
                for item in serverlist:
                    if item.get('machineIdentifier') == self.serverid:
                        server = item
                if server is None:
                    name = settings('plex_servername')
                    log.warn('The PMS you have used before with a unique '
                             'machineIdentifier of %s and name %s is '
                             'offline' % (self.serverid, name))
                    return
            chk = self._checkServerCon(server)
            if chk == 504 and httpsUpdated is False:
                # Not able to use HTTP, try HTTPs for now
                server['scheme'] = 'https'
                httpsUpdated = True
                continue
            if chk == 401:
                log.warn('Not yet authorized for Plex server %s'
                         % server['name'])
                if self.check_plex_tv_signin() is True:
                    if checkedPlexTV is False:
                        # Try again
                        checkedPlexTV = True
                        httpsUpdated = False
                        continue
                    else:
                        log.warn('Not authorized even though we are signed '
                                 ' in to plex.tv correctly')
                        dialog('ok',
                               lang(29999), '%s %s'
                               % (lang(39214),
                                  tryEncode(server['name'])))
                        return
                else:
                    return
            # Problems connecting
            elif chk >= 400 or chk is False:
                log.warn('Problems connecting to server %s. chk is %s'
                         % (server['name'], chk))
                return
            log.info('We found a server to automatically connect to: %s'
                     % server['name'])
            return server

    def __user_pick_pms(self):
        """
        Lets user pick his/her PMS from a list

        Returns server or None if unsuccessful
        """
        httpsUpdated = False
        while True:
            if httpsUpdated is False:
                serverlist = self.__get_server_list()
                # Exit if no servers found
                if len(serverlist) == 0:
                    log.warn('No plex media servers found!')
                    dialog('ok', lang(29999), lang(39011))
                    return
                # Get a nicer list
                dialoglist = []
                for server in serverlist:
                    if server['local'] == '1':
                        # server is in the same network as client.
                        # Add"local"
                        msg = lang(39022)
                    else:
                        # Add 'remote'
                        msg = lang(39054)
                    if server.get('ownername'):
                        # Display username if its not our PMS
                        dialoglist.append('%s (%s, %s)'
                                          % (server['name'],
                                             server['ownername'],
                                             msg))
                    else:
                        dialoglist.append('%s (%s)'
                                          % (server['name'], msg))
                # Let user pick server from a list
                resp = dialog('select', lang(39012), dialoglist)
                if resp == -1:
                    # User cancelled
                    return

            server = serverlist[resp]
            chk = self._checkServerCon(server)
            if chk == 504 and httpsUpdated is False:
                # Not able to use HTTP, try HTTPs for now
                serverlist[resp]['scheme'] = 'https'
                httpsUpdated = True
                continue
            httpsUpdated = False
            if chk == 401:
                log.warn('Not yet authorized for Plex server %s'
                         % server['name'])
                # Please sign in to plex.tv
                dialog('ok',
                       lang(29999),
                       lang(39013) + server['name'],
                       lang(39014))
                if self.plex_tv_signin() is False:
                    # Exit while loop if user cancels
                    return
            # Problems connecting
            elif chk >= 400 or chk is False:
                # Problems connecting to server. Pick another server?
                # Exit while loop if user chooses No
                if not dialog('yesno', lang(29999), lang(39015)):
                    return
            # Otherwise: connection worked!
            else:
                return server

    @staticmethod
    def write_pms_to_settings(server):
        """
        Saves server to file settings. server is a dict of the form:
        {
        'name': friendlyName,      the Plex server's name
        'address': ip:port
        'ip': ip,                   without http/https
        'port': port
        'scheme': 'http'/'https',   nice for checking for secure connections
        'local': '1'/'0',           Is the server a local server?
        'owned': '1'/'0',           Is the server owned by the user?
        'machineIdentifier': id,    Plex server machine identifier
        'accesstoken': token        Access token to this server
        'baseURL': baseURL          scheme://ip:port
        'ownername'                 Plex username of PMS owner
        }
        """
        settings('plex_machineIdentifier', server['machineIdentifier'])
        settings('plex_servername', server['name'])
        settings('plex_serverowned',
                 'true' if server['owned'] == '1'
                 else 'false')
        # Careful to distinguish local from remote PMS
        if server['local'] == '1':
            scheme = server['scheme']
            settings('ipaddress', server['ip'])
            settings('port', server['port'])
            log.debug("Setting SSL verify to false, because server is "
                      "local")
            settings('sslverify', 'false')
        else:
            baseURL = server['baseURL'].split(':')
            scheme = baseURL[0]
            settings('ipaddress', baseURL[1].replace('//', ''))
            settings('port', baseURL[2])
            log.debug("Setting SSL verify to true, because server is not "
                      "local")
            settings('sslverify', 'true')

        if scheme == 'https':
            settings('https', 'true')
        else:
            settings('https', 'false')
        # And finally do some logging
        log.debug("Writing to Kodi user settings file")
        log.debug("PMS machineIdentifier: %s, ip: %s, port: %s, https: %s "
                  % (server['machineIdentifier'], server['ip'],
                     server['port'], server['scheme']))

    def plex_tv_signin(self):
        """
        Signs (freshly) in to plex.tv (will be saved to file settings)

        Returns True if successful, or False if not
        """
        result = plex_tv_sign_in_with_pin()
        if result:
            self.plexLogin = result['username']
            self.plexToken = result['token']
            self.plexid = result['plexid']
            return True
        return False

    def check_plex_tv_signin(self):
        """
        Checks existing connection to plex.tv. If not, triggers sign in

        Returns True if signed in, False otherwise
        """
        answer = True
        chk = check_connection('plex.tv', token=self.plexToken)
        if chk in (401, 403):
            # HTTP Error: unauthorized. Token is no longer valid
            log.info('plex.tv connection returned HTTP %s' % str(chk))
            # Delete token in the settings
            settings('plexToken', value='')
            settings('plexLogin', value='')
            # Could not login, please try again
            dialog('ok', lang(29999), lang(39009))
            answer = self.plex_tv_signin()
        elif chk is False or chk >= 400:
            # Problems connecting to plex.tv. Network or internet issue?
            log.info('Problems connecting to plex.tv; connection returned '
                     'HTTP %s' % str(chk))
            dialog('ok', lang(29999), lang(39010))
            answer = False
        else:
            log.info('plex.tv connection with token successful')
            settings('plex_status', value=lang(39227))
            # Refresh the info from Plex.tv
            xml = self.doUtils('https://plex.tv/users/account',
                               authenticate=False,
                               headerOptions={'X-Plex-Token': self.plexToken})
            try:
                self.plexLogin = xml.attrib['title']
            except (AttributeError, KeyError):
                log.error('Failed to update Plex info from plex.tv')
            else:
                settings('plexLogin', value=self.plexLogin)
                home = 'true' if xml.attrib.get('home') == '1' else 'false'
                settings('plexhome', value=home)
                settings('plexAvatar', value=xml.attrib.get('thumb'))
                settings('plexHomeSize', value=xml.attrib.get('homeSize', '1'))
                log.info('Updated Plex info from plex.tv')
        return answer

    def check_pms(self):
        """
        Check the PMS that was set in file settings.
        Will return False if we need to reconnect, because:
            PMS could not be reached (no matter the authorization)
            machineIdentifier did not match

        Will also set the PMS machineIdentifier in the file settings if it was
        not set before
        """
        answer = True
        chk = check_connection(self.server, verifySSL=False)
        if chk is False:
            log.warn('Could not reach PMS %s' % self.server)
            answer = False
        if answer is True and not self.serverid:
            log.info('No PMS machineIdentifier found for %s. Trying to '
                     'get the PMS unique ID' % self.server)
            self.serverid = GetMachineIdentifier(self.server)
            if self.serverid is None:
                log.warn('Could not retrieve machineIdentifier')
                answer = False
            else:
                settings('plex_machineIdentifier', value=self.serverid)
        elif answer is True:
            tempServerid = GetMachineIdentifier(self.server)
            if tempServerid != self.serverid:
                log.warn('The current PMS %s was expected to have a '
                         'unique machineIdentifier of %s. But we got '
                         '%s. Pick a new server to be sure'
                         % (self.server, self.serverid, tempServerid))
                answer = False
        return answer

    def __get_server_list(self):
        """
        Returns a list of servers from GDM and possibly plex.tv
        """
        self.discoverPMS(xbmc.getIPAddress(),
                         plexToken=self.plexToken)
        serverlist = self.plx.returnServerList(self.plx.g_PMS)
        log.debug('PMS serverlist: %s' % serverlist)
        return serverlist

    def _checkServerCon(self, server):
        """
        Checks for server's connectivity. Returns check_connection result
        """
        # Re-direct via plex if remote - will lead to the correct SSL
        # certificate
        if server['local'] == '1':
            url = '%s://%s:%s' \
                  % (server['scheme'], server['ip'], server['port'])
            # Deactive SSL verification if the server is local!
            verifySSL = False
        else:
            url = server['baseURL']
            verifySSL = True
        chk = check_connection(url,
                               token=server['accesstoken'],
                               verifySSL=verifySSL)
        return chk

    def discoverPMS(self, IP_self, plexToken=None):
        """
        parameters:
            IP_self         Own IP
        optional:
            plexToken       token for plex.tv
        result:
            self.g_PMS      dict set
        """
        self.g_PMS = {}

        # Look first for local PMS in the LAN
        pmsList = self.PlexGDM()
        log.debug('PMS found in the local LAN via GDM: %s' % pmsList)

        # Get PMS from plex.tv
        if plexToken:
            log.info('Checking with plex.tv for more PMS to connect to')
            self.getPMSListFromMyPlex(plexToken)
        else:
            log.info('No plex token supplied, only checked LAN for PMS')

        for uuid in pmsList:
            PMS = pmsList[uuid]
            if PMS['uuid'] in self.g_PMS:
                log.debug('We already know of PMS %s from plex.tv'
                          % PMS['serverName'])
                # Update with GDM data - potentially more reliable than plex.tv
                self.updatePMSProperty(PMS['uuid'], 'ip', PMS['ip'])
                self.updatePMSProperty(PMS['uuid'], 'port', PMS['port'])
                self.updatePMSProperty(PMS['uuid'], 'local', '1')
                self.updatePMSProperty(PMS['uuid'], 'scheme', 'http')
                self.updatePMSProperty(PMS['uuid'],
                                       'baseURL',
                                       'http://%s:%s' % (PMS['ip'],
                                                         PMS['port']))
            else:
                self.declarePMS(PMS['uuid'], PMS['serverName'], 'http',
                                PMS['ip'], PMS['port'])
            # Ping to check whether we need HTTPs or HTTP
            https = PMSHttpsEnabled('%s:%s' % (PMS['ip'], PMS['port']))
            if https is None:
                # Error contacting url. Skip for now
                continue
            elif https is True:
                self.updatePMSProperty(PMS['uuid'], 'scheme', 'https')
                self.updatePMSProperty(
                    PMS['uuid'],
                    'baseURL',
                    'https://%s:%s' % (PMS['ip'], PMS['port']))
            else:
                # Already declared with http
                pass

        # install plex.tv "virtual" PMS - for myPlex, PlexHome
        # self.declarePMS('plex.tv', 'plex.tv', 'https', 'plex.tv', '443')
        # self.updatePMSProperty('plex.tv', 'local', '-')
        # self.updatePMSProperty('plex.tv', 'owned', '-')
        # self.updatePMSProperty(
        #     'plex.tv', 'accesstoken', plexToken)
        # (remote and local) servers from plex.tv

    def declarePMS(self, uuid, name, scheme, ip, port):
        """
        Plex Media Server handling

        parameters:
            uuid - PMS ID
            name, scheme, ip, port, type, owned, token
        """
        address = ip + ':' + port
        baseURL = scheme + '://' + ip + ':' + port
        self.g_PMS[uuid] = {
            'name': name,
            'scheme': scheme,
            'ip': ip,
            'port': port,
            'address': address,
            'baseURL': baseURL,
            'local': '1',
            'owned': '1',
            'accesstoken': '',
            'enableGzip': False
        }

    def updatePMSProperty(self, uuid, tag, value):
        # set property element of PMS by UUID
        try:
            self.g_PMS[uuid][tag] = value
        except:
            log.error('%s has not yet been declared ' % uuid)
            return False

    def getPMSProperty(self, uuid, tag):
        # get name of PMS by UUID
        try:
            answ = self.g_PMS[uuid].get(tag, '')
        except:
            log.error('%s not found in PMS catalogue' % uuid)
            answ = False
        return answ

    def PlexGDM(self):
        """
        PlexGDM

        parameters:
            none
        result:
            PMS_list - dict() of PMSs found
        """
        import struct

        IP_PlexGDM = '239.0.0.250'  # multicast to PMS
        Port_PlexGDM = 32414
        Msg_PlexGDM = 'M-SEARCH * HTTP/1.0'

        # setup socket for discovery -> multicast message
        GDM = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        GDM.settimeout(2.0)

        # Set the time-to-live for messages to 2 for local network
        ttl = struct.pack('b', 2)
        GDM.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)

        returnData = []
        try:
            # Send data to the multicast group
            GDM.sendto(Msg_PlexGDM, (IP_PlexGDM, Port_PlexGDM))

            # Look for responses from all recipients
            while True:
                try:
                    data, server = GDM.recvfrom(1024)
                    returnData.append({'from': server,
                                       'data': data})
                except socket.timeout:
                    break
        except Exception as e:
            # Probably error: (101, 'Network is unreachable')
            log.error(e)
            import traceback
            log.error("Traceback:\n%s" % traceback.format_exc())
        finally:
            GDM.close()

        pmsList = {}
        for response in returnData:
            update = {'ip': response.get('from')[0]}
            # Check if we had a positive HTTP response
            if "200 OK" not in response.get('data'):
                continue
            for each in response.get('data').split('\n'):
                # decode response data
                update['discovery'] = "auto"
                # update['owned']='1'
                # update['master']= 1
                # update['role']='master'

                if "Content-Type:" in each:
                    update['content-type'] = each.split(':')[1].strip()
                elif "Resource-Identifier:" in each:
                    update['uuid'] = each.split(':')[1].strip()
                elif "Name:" in each:
                    update['serverName'] = tryDecode(
                        each.split(':')[1].strip())
                elif "Port:" in each:
                    update['port'] = each.split(':')[1].strip()
                elif "Updated-At:" in each:
                    update['updated'] = each.split(':')[1].strip()
                elif "Version:" in each:
                    update['version'] = each.split(':')[1].strip()
            pmsList[update['uuid']] = update
        return pmsList

    def getPMSListFromMyPlex(self, token):
        """
        getPMSListFromMyPlex

        get Plex media Server List from plex.tv/pms/resources
        """
        xml = self.doUtils('https://plex.tv/api/resources',
                           authenticate=False,
                           parameters={'includeHttps': 1},
                           headerOptions={'X-Plex-Token': token})
        try:
            xml.attrib
        except AttributeError:
            log.error('Could not get list of PMS from plex.tv')
            return

        import Queue
        queue = Queue.Queue()
        threadQueue = []

        maxAgeSeconds = 2*60*60*24
        for Dir in xml.findall('Device'):
            if 'server' not in Dir.get('provides'):
                # No PMS - skip
                continue
            if Dir.find('Connection') is None:
                # no valid connection - skip
                continue

            # check MyPlex data age - skip if >2 days
            PMS = {}
            PMS['name'] = Dir.get('name')
            infoAge = time() - int(Dir.get('lastSeenAt'))
            if infoAge > maxAgeSeconds:
                log.debug("Server %s not seen for 2 days - skipping."
                          % PMS['name'])
                continue

            PMS['uuid'] = Dir.get('clientIdentifier')
            PMS['token'] = Dir.get('accessToken', token)
            PMS['owned'] = Dir.get('owned', '1')
            PMS['local'] = Dir.get('publicAddressMatches')
            PMS['ownername'] = Dir.get('sourceTitle', '')
            PMS['path'] = '/'
            PMS['options'] = None

            # Try a local connection first
            # Backup to remote connection, if that failes
            PMS['connections'] = []
            for Con in Dir.findall('Connection'):
                if Con.get('local') == '1':
                    PMS['connections'].append(Con)
            # Append non-local
            for Con in Dir.findall('Connection'):
                if Con.get('local') != '1':
                    PMS['connections'].append(Con)

            t = Thread(target=self.pokePMS,
                       args=(PMS, queue))
            threadQueue.append(t)

        maxThreads = 5
        threads = []
        # poke PMS, own thread for each PMS
        while True:
            # Remove finished threads
            for t in threads:
                if not t.isAlive():
                    threads.remove(t)
            if len(threads) < maxThreads:
                try:
                    t = threadQueue.pop()
                except IndexError:
                    # We have done our work
                    break
                else:
                    t.start()
                    threads.append(t)
            else:
                sleep(50)

        # wait for requests being answered
        for t in threads:
            t.join()

        # declare new PMSs
        while not queue.empty():
            PMS = queue.get()
            self.declarePMS(PMS['uuid'], PMS['name'],
                            PMS['protocol'], PMS['ip'], PMS['port'])
            self.updatePMSProperty(
                PMS['uuid'], 'accesstoken', PMS['token'])
            self.updatePMSProperty(
                PMS['uuid'], 'owned', PMS['owned'])
            self.updatePMSProperty(
                PMS['uuid'], 'local', PMS['local'])
            # set in declarePMS, overwrite for https encryption
            self.updatePMSProperty(
                PMS['uuid'], 'baseURL', PMS['baseURL'])
            self.updatePMSProperty(
                PMS['uuid'], 'ownername', PMS['ownername'])
            log.debug('Found PMS %s: %s'
                      % (PMS['uuid'], self.g_PMS[PMS['uuid']]))
            queue.task_done()

    def pokePMS(self, PMS, queue):
        data = PMS['connections'][0].attrib
        if data['local'] == '1':
            protocol = data['protocol']
            address = data['address']
            port = data['port']
            url = '%s://%s:%s' % (protocol, address, port)
        else:
            url = data['uri']
            if url.count(':') == 1:
                url = '%s:%s' % (url, data['port'])
            protocol, address, port = url.split(':', 2)
            address = address.replace('/', '')

        xml = self.doUtils('%s/identity' % url,
                           authenticate=False,
                           headerOptions={'X-Plex-Token': PMS['token']},
                           verifySSL=False,
                           timeout=10)
        try:
            xml.attrib['machineIdentifier']
        except (AttributeError, KeyError):
            # No connection, delete the one we just tested
            del PMS['connections'][0]
            if len(PMS['connections']) > 0:
                # Still got connections left, try them
                return self.pokePMS(PMS, queue)
            return
        else:
            # Connection successful - correct PMS?
            if xml.get('machineIdentifier') == PMS['uuid']:
                # process later
                PMS['baseURL'] = url
                PMS['protocol'] = protocol
                PMS['ip'] = address
                PMS['port'] = port
                queue.put(PMS)
                return
        log.info('Found a PMS at %s, but the expected machineIdentifier of '
                 '%s did not match the one we found: %s'
                 % (url, PMS['uuid'], xml.get('machineIdentifier')))

    def returnServerList(self, data):
        """
        Returns a nicer list of all servers found in data, where data is in
        g_PMS format, for the client device with unique ID ATV_udid

        Input:
            data                    e.g. self.g_PMS

        Output: List of all servers, with an entry of the form:
        {
        'name': friendlyName,      the Plex server's name
        'address': ip:port
        'ip': ip,                   without http/https
        'port': port
        'scheme': 'http'/'https',   nice for checking for secure connections
        'local': '1'/'0',           Is the server a local server?
        'owned': '1'/'0',           Is the server owned by the user?
        'machineIdentifier': id,    Plex server machine identifier
        'accesstoken': token        Access token to this server
        'baseURL': baseURL          scheme://ip:port
        'ownername'                 Plex username of PMS owner
        }
        """
        serverlist = []
        for key, value in data.items():
            serverlist.append({
                'name': value.get('name'),
                'address': value.get('address'),
                'ip': value.get('ip'),
                'port': value.get('port'),
                'scheme': value.get('scheme'),
                'local': value.get('local'),
                'owned': value.get('owned'),
                'machineIdentifier': key,
                'accesstoken': value.get('accesstoken'),
                'baseURL': value.get('baseURL'),
                'ownername': value.get('ownername')
            })
        return serverlist
