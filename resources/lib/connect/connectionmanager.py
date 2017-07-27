# -*- coding: utf-8 -*-
###############################################################################
from logging import getLogger
from hashlib import md5
import requests
from struct import pack
import socket
import time
from datetime import datetime
import xml.etree.ElementTree as etree
from Queue import Queue
from threading import Thread

from xbmc import sleep

import credentials as cred
from utils import tryDecode
from PlexFunctions import PMSHttpsEnabled


###############################################################################

# Disable annoying requests warnings
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

log = getLogger("PLEX."+__name__)

###############################################################################

CONNECTIONSTATE = {
    'Unavailable': 0,
    'ServerSelection': 1,
    'ServerSignIn': 2,
    'SignedIn': 3,
    'ConnectSignIn': 4,
    'ServerUpdateNeeded': 5
}

CONNECTIONMODE = {
    'Local': 0,
    'Remote': 1,
    'Manual': 2
}

# multicast to PMS
IP_PLEXGDM = '239.0.0.250'
PORT_PLEXGDM = 32414
MSG_PLEXGDM = 'M-SEARCH * HTTP/1.0'

###############################################################################


def getServerAddress(server, mode):

    modes = {
        CONNECTIONMODE['Local']: server.get('LocalAddress'),
        CONNECTIONMODE['Remote']: server.get('RemoteAddress'),
        CONNECTIONMODE['Manual']: server.get('ManualAddress')
    }
    return (modes.get(mode) or
            server.get('ManualAddress',
                       server.get('LocalAddress',
                                  server.get('RemoteAddress'))))


class ConnectionManager(object):
    default_timeout = 30
    apiClients = []
    minServerVersion = "1.7.0.0"
    connectUser = None
    # Token for plex.tv
    plexToken = None

    def __init__(self, appName, appVersion, deviceName, deviceId,
                 capabilities=None, devicePixelRatio=None):
        log.debug("Instantiating")

        self.credentialProvider = cred.Credentials()
        self.appName = appName
        self.appVersion = appVersion
        self.deviceName = deviceName
        self.deviceId = deviceId
        self.capabilities = capabilities
        self.devicePixelRatio = devicePixelRatio

    def setFilePath(self, path):
        # Set where to save persistant data
        self.credentialProvider.setPath(path)

    def _getAppVersion(self):
        return self.appVersion

    def _getCapabilities(self):
        return self.capabilities

    def _getDeviceId(self):
        return self.deviceId

    def _connectUserId(self):
        return self.credentialProvider.getCredentials().get('ConnectUserId')

    def _connectToken(self):
        return self.credentialProvider.getCredentials().get('ConnectAccessToken')

    def getServerInfo(self, id_):

        servers = self.credentialProvider.getCredentials()['Servers']
        
        for s in servers:
            if s['Id'] == id_:
                return s

    def _getLastUsedServer(self):

        servers = self.credentialProvider.getCredentials()['Servers']

        if not len(servers):
            return

        try:
            servers.sort(key=lambda x: datetime.strptime(x['DateLastAccessed'], "%Y-%m-%dT%H:%M:%SZ"), reverse=True)
        except TypeError:
            servers.sort(key=lambda x: datetime(*(time.strptime(x['DateLastAccessed'], "%Y-%m-%dT%H:%M:%SZ")[0:6])), reverse=True)

        return servers[0]

    def _mergeServers(self, list1, list2):

        for i in range(0, len(list2), 1):
            try:
                self.credentialProvider.addOrUpdateServer(list1, list2[i])
            except KeyError:
                continue

        return list1

    def _connectUser(self):
        
        return self.connectUser

    def _resolveFailure(self):

        return {
            'State': CONNECTIONSTATE['Unavailable'],
            'ConnectUser': self._connectUser()
        }

    def _getMinServerVersion(self, val=None):

        if val is not None:
            self.minServerVersion = val

        return self.minServerVersion

    def _updateServerInfo(self, server, systemInfo):

        if server is None or systemInfo is None:
            return

        server['Id'] = systemInfo.attrib['machineIdentifier']

        if systemInfo.get('LocalAddress'):
            server['LocalAddress'] = systemInfo['LocalAddress']
        if systemInfo.get('WanAddress'):
            server['RemoteAddress'] = systemInfo['WanAddress']
        if systemInfo.get('MacAddress'):
            server['WakeOnLanInfos'] = [{'MacAddress': systemInfo['MacAddress']}]

    def _getHeaders(self, request):
        headers = request.setdefault('headers', {})
        headers['Accept'] = '*/*'
        headers['Content-type'] = request.get(
            'contentType',
            "application/x-www-form-urlencoded")

    def requestUrl(self, request):
        """
        request: dict with the following (optional) keys:
            type:       GET, POST, ... (mandatory)
            url:        (mandatory)
            timeout
            verify:     set to False to disable SSL certificate check

        ...and all the other requests settings
        """
        self._getHeaders(request)
        request['timeout'] = request.get('timeout') or self.default_timeout

        action = request['type']
        request.pop('type', None)

        log.debug("Requesting %s" % request)

        try:
            r = self._requests(action, **request)
            log.info("ConnectionManager response status: %s" % r.status_code)
            r.raise_for_status()
        except requests.RequestException as e:
            # Elaborate on exceptions?
            log.error(e)
            raise
        else:
            try:
                return etree.fromstring(r.content)
            except etree.ParseError:
                # Read response to release connection
                log.error('Could not parse PMS response: %s' % r.content)
                raise requests.RequestException

    def _requests(self, action, **kwargs):

        if action == "GET":
            r = requests.get(**kwargs)
        elif action == "POST":
            r = requests.post(**kwargs)

        return r

    def getEmbyServerUrl(self, baseUrl, handler):
        return "%s/emby/%s" % (baseUrl, handler)

    def getConnectUrl(self, handler):
        return "https://connect.emby.media/service/%s" % handler

    @staticmethod
    def _findServers(foundServers):
        servers = []
        for server in foundServers:
            if '200 OK' not in server['data']:
                continue
            ip = server['from'][0]
            info = {'LastCONNECTIONMODE': CONNECTIONMODE['Local']}
            for line in server['data'].split('\n'):
                if line.startswith('Name:'):
                    info['Name'] = tryDecode(line.split(':')[1].strip())
                elif line.startswith('Port:'):
                    info['Port'] = line.split(':')[1].strip()
                elif line.startswith('Resource-Identifier:'):
                    info['Id'] = line.split(':')[1].strip()
                elif line.startswith('Updated-At:'):
                    pass
                elif line.startswith('Version:'):
                    pass
            # Need to check whether we need HTTPS or only HTTP
            https = PMSHttpsEnabled('%s:%s' % (ip, info['Port']))
            if https is None:
                # Error contacting url. Skip for now
                continue
            elif https is True:
                info['LocalAddress'] = 'https://%s:%s' % (ip, info['Port'])
            else:
                info['LocalAddress'] = 'http://%s:%s' % (ip, info['Port'])
            servers.append(info)
        return servers

    def _serverDiscovery(self):
        """
        PlexGDM
        """
        servers = []
        # setup socket for discovery -> multicast message
        try:
            GDM = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            GDM.settimeout(2.0)

            # Set the time-to-live for messages to 2 for local network
            ttl = pack('b', 2)
            GDM.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        except (socket.error, socket.herror, socket.gaierror):
            log.error('Socket error, abort PlexGDM')
            return servers
        try:
            # Send data to the multicast group
            GDM.sendto(MSG_PLEXGDM, (IP_PLEXGDM, PORT_PLEXGDM))
            # Look for responses from all recipients
            while True:
                try:
                    data, server = GDM.recvfrom(1024)
                    servers.append({'from': server, 'data': data})
                except socket.timeout:
                    break
        except:
            # Probably error: (101, 'Network is unreachable')
            log.error('Could not find Plex servers using PlexGDM')
            import traceback
            log.error("Traceback:\n%s" % traceback.format_exc())
        finally:
            GDM.close()
        return servers

    def connectToAddress(self, address, options=None):
        log.debug('connectToAddress %s with options %s' % (address, options))

        def _onFail():
            log.error("connectToAddress %s failed with options %s" %
                      (address, options))
            return self._resolveFailure()

        try:
            publicInfo = self._tryConnect(address, options=options)
        except Exception:
            return _onFail()
        else:
            server = {
                'ManualAddress': address,
                'LastCONNECTIONMODE': CONNECTIONMODE['Manual'],
                'options': options
            }
            self._updateServerInfo(server, publicInfo)
            server = self.connectToServer(server, options)
            if server is False:
                return _onFail()
            else:
                return server

    def onAuthenticated(self, result, options={}):

        credentials = self.credentialProvider.getCredentials()
        for s in credentials['Servers']:
            if s['Id'] == result['ServerId']:
                server = s
                break
        else: # Server not found?
            return

        if options.get('updateDateLastAccessed') is not False:
            server['DateLastAccessed'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')

        server['UserId'] = result['User']['Id']
        server['AccessToken'] = result['AccessToken']

        self.credentialProvider.addOrUpdateServer(credentials['Servers'], server)
        self._saveUserInfoIntoCredentials(server, result['User'])
        self.credentialProvider.getCredentials(credentials)

    def _tryConnect(self, url, timeout=None, options=None):
        request = {
            'type': 'GET',
            'url': '%s/identity' % url,
            'timeout': timeout
        }
        if options:
            request.update(options)
        return self.requestUrl(request)

    def _addAppInfoToConnectRequest(self):
        return "%s/%s" % (self.appName, self.appVersion)

    def __get_PMS_servers_from_plex_tv(self):
        """
        Retrieves Plex Media Servers from plex.tv/pms/resources
        """
        servers = []
        try:
            xml = self.requestUrl({
                'url': 'https://plex.tv/api/resources?includeHttps=1',
                'type': 'GET',
                'headers': {'X-Plex-Token': self.plexToken},
                'timeout': 5.0,
                'verify': True})
        except requests.RequestException:
            log.error('Could not get list of PMS from plex.tv')
            return servers

        maxAgeSeconds = 2*60*60*24
        for device in xml.findall('Device'):
            if 'server' not in device.attrib.get('provides'):
                # No PMS - skip
                continue
            cons = device.find('Connection')
            if cons is None:
                # no valid connection - skip
                continue
            # check MyPlex data age - skip if >2 days
            server = {'Name': device.attrib.get('name')}
            infoAge = time.time() - int(device.attrib.get('lastSeenAt'))
            if infoAge > maxAgeSeconds:
                log.info("Server %s not seen for 2 days - skipping."
                         % server['Name'])
                continue
            server['Id'] = device.attrib['clientIdentifier']
            server['ConnectServerId'] = device.attrib['clientIdentifier']
            # server['AccessToken'] = device.attrib['accessToken']
            server['ExchangeToken'] = device.attrib['accessToken']
            # One's own Plex home?
            server['UserLinkType'] = 'Guest' if device.attrib['owned'] == '0' \
                else 'LinkedUser'
            # Foreign PMS' user name
            server['UserId'] = device.attrib.get('sourceTitle')
            for con in cons:
                if con.attrib['local'] == '1':
                    # Local LAN address; there might be several!!
                    server['LocalAddress'] = con.attrib['uri']
                else:
                    server['RemoteAddress'] = con.attrib['uri']

            # Additional stuff, not yet implemented
            server['local'] = device.attrib.get('publicAddressMatches')

            servers.append(server)
        return servers

    def _getConnectServers(self, credentials):

        log.info("Begin getConnectServers")
        
        servers = []

        if not credentials.get('ConnectAccessToken') or not credentials.get('ConnectUserId'):
            return servers

        url = self.getConnectUrl("servers?userId=%s" % credentials['ConnectUserId'])
        request = {

            'type': "GET",
            'url': url,
            'headers': {
                'X-Connect-UserToken': credentials['ConnectAccessToken']
            }
        }
        for server in self.requestUrl(request):

            servers.append({

                'ExchangeToken': server['AccessKey'],
                'ConnectServerId': server['Id'],
                'Id': server['SystemId'],
                'Name': server['Name'],
                'RemoteAddress': server['Url'],
                'LocalAddress': server['LocalAddress'],
                'UserLinkType': "Guest" if server['UserType'].lower() == "guest" else "LinkedUser",
            })

        return servers

    def getAvailableServers(self):
        log.info("Begin getAvailableServers")

        credentials = self.credentialProvider.getCredentials()
        servers = list(credentials['Servers'])

        if self.plexToken:
            connectServers = self.__get_PMS_servers_from_plex_tv()
            self._mergeServers(servers, connectServers)
        foundServers = self._findServers(self._serverDiscovery())
        self._mergeServers(servers, foundServers)

        servers = self._filterServers(servers, connectServers)

        try:
            servers.sort(key=lambda x: datetime.strptime(x['DateLastAccessed'], "%Y-%m-%dT%H:%M:%SZ"), reverse=True)
        except TypeError:
            servers.sort(key=lambda x: datetime(*(time.strptime(x['DateLastAccessed'], "%Y-%m-%dT%H:%M:%SZ")[0:6])), reverse=True)

        credentials['Servers'] = servers
        self.credentialProvider.getCredentials(credentials)

        return servers

    def _filterServers(self, servers, connectServers):
        
        filtered = []

        for server in servers:
            # It's not a connect server, so assume it's still valid
            if server.get('ExchangeToken') is None:
                filtered.append(server)
                continue

            for connectServer in connectServers:
                if server['Id'] == connectServer['Id']:
                    filtered.append(server)
                    break
        else:
            return filtered

    def _getConnectPasswordHash(self, password):

        password = self._cleanConnectPassword(password)
        
        return md5(password).hexdigest()

    def _saveUserInfoIntoCredentials(self, server, user):

        info = {
            'Id': user['Id'],
            'IsSignedInOffline': True
        }

        self.credentialProvider.addOrUpdateUser(server, info)

    def _compareVersions(self, a, b):
        """
            -1 a is smaller
            1 a is larger
            0 equal
        """
        a = a.split('.')
        b = b.split('.')

        for i in range(0, max(len(a), len(b)), 1):
            try:
                aVal = a[i]
            except IndexError:
                aVal = 0

            try:    
                bVal = b[i]
            except IndexError:
                bVal = 0

            if aVal < bVal:
                return -1

            if aVal > bVal:
                return 1

        return 0

    def connectToServer(self, server, options=None):
        tests = [
            CONNECTIONMODE['Manual'],
            CONNECTIONMODE['Local'],
            CONNECTIONMODE['Remote']
        ]
        return self._testNextCONNECTIONMODE(tests, 0, server, options)

    def _stringEqualsIgnoreCase(self, str1, str2):

        return (str1 or "").lower() == (str2 or "").lower()

    def _testNextCONNECTIONMODE(self, tests, index, server, options):
        if index >= len(tests):
            log.info("Tested all connection modes. Failing server connection.")
            return self._resolveFailure()

        mode = tests[index]
        log.debug('Testing connection %s with options %s' % (mode, options))
        address = getServerAddress(server, mode)
        enableRetry = False
        skipTest = False
        timeout = self.default_timeout

        if mode == CONNECTIONMODE['Local']:
            enableRetry = True
            timeout = 8

            if self._stringEqualsIgnoreCase(address, server.get('ManualAddress')):
                log.info("skipping LocalAddress test because it is the same as ManualAddress")
                skipTest = True

        elif mode == CONNECTIONMODE['Manual']:

            if self._stringEqualsIgnoreCase(address, server.get('LocalAddress')):
                enableRetry = True
                timeout = 8

        if skipTest or not address:
            log.info("skipping test at index: %s" % index)
            return self._testNextCONNECTIONMODE(tests, index+1, server, options)

        log.info("testing connection mode %s with server %s" % (mode, server.get('Name')))
        try:
            result = self._tryConnect(address, timeout, options)
        
        except Exception:
            log.error("test failed for connection mode %s with server %s" % (mode, server.get('Name')))

            if enableRetry:
                # TODO: wake on lan and retry
                return self._testNextCONNECTIONMODE(tests, index+1, server, options)
            else:
                return self._testNextCONNECTIONMODE(tests, index+1, server, options)
        else:

            if self._compareVersions(self._getMinServerVersion(),
                                     result.attrib['version']) == 1:
                log.warn("minServerVersion requirement not met. Server version: %s" % result.attrib['version'])
                return {
                    'State': CONNECTIONSTATE['ServerUpdateNeeded'],
                    'Servers': [server]
                }
            else:
                log.info("calling onSuccessfulConnection with connection mode %s with server %s"
                        % (mode, server.get('Name')))
                return self._onSuccessfulConnection(server, result, mode, options)

    def _onSuccessfulConnection(self, server, systemInfo, CONNECTIONMODE, options):

        credentials = self.credentialProvider.getCredentials()

        if credentials.get('ConnectAccessToken') and options.get('enableAutoLogin') is not False:
            
            if self._ensureConnectUser(credentials) is not False:

                if server.get('ExchangeToken'):
                    
                    self._addAuthenticationInfoFromConnect(server, CONNECTIONMODE, credentials, options)

        return self._afterConnectValidated(server, credentials, systemInfo, CONNECTIONMODE, True, options)

    def _afterConnectValidated(self, server, credentials, systemInfo, CONNECTIONMODE, verifyLocalAuthentication, options):

        if options.get('enableAutoLogin') is False:
            server['UserId'] = None
            server['AccessToken'] = None
        
        elif (verifyLocalAuthentication and server.get('AccessToken') and 
            options.get('enableAutoLogin') is not False):

            if self._validateAuthentication(server, CONNECTIONMODE, options) is not False:
                return self._afterConnectValidated(server, credentials, systemInfo, CONNECTIONMODE, False, options)

            return

        self._updateServerInfo(server, systemInfo)
        server['LastCONNECTIONMODE'] = CONNECTIONMODE

        if options.get('updateDateLastAccessed') is not False:
            server['DateLastAccessed'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')

        self.credentialProvider.addOrUpdateServer(credentials['Servers'], server)
        self.credentialProvider.getCredentials(credentials)

        result = {
            'Servers': [],
            'ConnectUser': self._connectUser()
        }
        result['State'] = CONNECTIONSTATE['SignedIn'] if (server.get('AccessToken') and options.get('enableAutoLogin') is not False) else CONNECTIONSTATE['ServerSignIn']
        result['Servers'].append(server)

        # Connected
        return result

    def _validateAuthentication(self, server, CONNECTIONMODE, options={}):

        url = getServerAddress(server, CONNECTIONMODE)
        request = {

            'type': "GET",
            'url': self.getEmbyServerUrl(url, "System/Info"),
            'ssl': options.get('ssl'),
            'headers': {
                'X-MediaBrowser-Token': server['AccessToken']
            }
        }
        try:
            systemInfo = self.requestUrl(request)
            self._updateServerInfo(server, systemInfo)

            if server.get('UserId'):
                user = self.requestUrl({

                    'type': "GET",
                    'url': self.getEmbyServerUrl(url, "users/%s" % server['UserId']),
                    'ssl': options.get('ssl'),
                    'headers': {
                        'X-MediaBrowser-Token': server['AccessToken']
                    }
                })

        except Exception:
            server['UserId'] = None
            server['AccessToken'] = None
            return False

    def loginToConnect(self, username, password):

        if not username:
            raise AttributeError("username cannot be empty")

        if not password:
            raise AttributeError("password cannot be empty")

        md5 = self._getConnectPasswordHash(password)
        request = {
            'type': "POST",
            'url': self.getConnectUrl("user/authenticate"),
            'data': {
                'nameOrEmail': username,
                'password': md5
            },
        }
        try:
            result = self.requestUrl(request)
        except Exception as e: # Failed to login
            log.error(e)
            return False
        else:
            credentials = self.credentialProvider.getCredentials()
            credentials['ConnectAccessToken'] = result['AccessToken']
            credentials['ConnectUserId'] = result['User']['Id']
            credentials['ConnectUser'] = result['User']['DisplayName']
            self.credentialProvider.getCredentials(credentials)
            # Signed in
            self._onConnectUserSignIn(result['User'])
        
        return result

    def _onConnectUserSignIn(self, user):

        self.connectUser = user
        log.info("connectusersignedin %s" % user)

    def _getConnectUser(self, userId, accessToken):

        if not userId:
            raise AttributeError("null userId")

        if not accessToken:
            raise AttributeError("null accessToken")

        url = self.getConnectUrl('user?id=%s' % userId)

        return self.requestUrl({
            
            'type': "GET",
            'url': url,
            'headers': {
                'X-Connect-UserToken': accessToken
            }
        })

    def _addAuthenticationInfoFromConnect(self, server, CONNECTIONMODE, credentials, options={}):

        if not server.get('ExchangeToken'):
            raise KeyError("server['ExchangeToken'] cannot be null")

        if not credentials.get('ConnectUserId'):
            raise KeyError("credentials['ConnectUserId'] cannot be null")

        url = getServerAddress(server, CONNECTIONMODE)
        url = self.getEmbyServerUrl(url, "Connect/Exchange?format=json")
        auth = ('MediaBrowser Client="%s", Device="%s", DeviceId="%s", Version="%s"'
                % (self.appName, self.deviceName, self.deviceId, self.appVersion))
        try:
            auth = self.requestUrl({

                'url': url,
                'type': "GET",
                'ssl': options.get('ssl'),
                'params': {
                    'ConnectUserId': credentials['ConnectUserId']
                },
                'headers': {
                    'X-MediaBrowser-Token': server['ExchangeToken'],
                    'X-Emby-Authorization': auth
                }
            })
        except Exception:
            server['UserId'] = None
            server['AccessToken'] = None
            return False
        else:
            server['UserId'] = auth['LocalUserId']
            server['AccessToken'] = auth['AccessToken']
            return auth

    def _ensureConnectUser(self, credentials):

        if self.connectUser and self.connectUser['Id'] == credentials['ConnectUserId']:
            return

        elif credentials.get('ConnectUserId') and credentials.get('ConnectAccessToken'):

            self.connectUser = None

            try:
                result = self._getConnectUser(credentials['ConnectUserId'], credentials['ConnectAccessToken'])
                self._onConnectUserSignIn(result)
            except Exception:
                return False

    def connect(self, options=None):

        log.info("Begin connect")

        servers = self.getAvailableServers()
        return self._connectToServers(servers, options)

    def _connectToServers(self, servers, options):

        log.info("Begin connectToServers, with %s servers" % len(servers))

        if len(servers) == 1:
            result = self.connectToServer(servers[0], options)
            if result and result.get('State') == CONNECTIONSTATE['Unavailable']:
                result['State'] = CONNECTIONSTATE['ConnectSignIn'] if result['ConnectUser'] == None else CONNECTIONSTATE['ServerSelection']

            log.info("resolving connectToServers with result['State']: %s" % result)
            return result

        firstServer = self._getLastUsedServer()
        # See if we have any saved credentials and can auto sign in
        if firstServer:
            
            result = self.connectToServer(firstServer, options)
            if result and result.get('State') == CONNECTIONSTATE['SignedIn']:
                return result

        # Return loaded credentials if exists
        credentials = self.credentialProvider.getCredentials()
        self._ensureConnectUser(credentials)

        return {
            'Servers': servers,
            'State': CONNECTIONSTATE['ConnectSignIn'] if (not len(servers) and not self._connectUser()) else CONNECTIONSTATE['ServerSelection'],
            'ConnectUser': self._connectUser()
        }

    def _cleanConnectPassword(self, password):

        password = password or ""

        password = password.replace("&", '&amp;')
        password = password.replace("/", '&#092;')
        password = password.replace("!", '&#33;')
        password = password.replace("$", '&#036;')
        password = password.replace("\"", '&quot;')
        password = password.replace("<", '&lt;')
        password = password.replace(">", '&gt;')
        password = password.replace("'", '&#39;')

        return password

    def clearData(self):

        log.info("connection manager clearing data")

        self.connectUser = None
        credentials = self.credentialProvider.getCredentials()
        credentials['ConnectAccessToken'] = None
        credentials['ConnectUserId'] = None
        credentials['Servers'] = []
        self.credentialProvider.getCredentials(credentials)
