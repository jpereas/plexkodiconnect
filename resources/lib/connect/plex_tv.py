# -*- coding: utf-8 -*-
from logging import getLogger

from xbmc import sleep, executebuiltin

from utils import window, settings, dialog, language as lang, tryEncode
from clientinfo import getXArgsDeviceInfo
from downloadutils import DownloadUtils
import variables as v
import state

###############################################################################
log = getLogger("PLEX."+__name__)

###############################################################################


def my_plex_sign_in(username, password, options):
    """
    MyPlex Sign In

    parameters:
        username - Plex forum name, MyPlex login, or email address
        password
        options - dict() of PlexConnect-options as received from aTV -
                  necessary: PlexConnectUDID
    result:
        username
        authtoken - token for subsequent communication with MyPlex
    """
    # create POST request
    xml = DownloadUtils().downloadUrl(
        'https://plex.tv/users/sign_in.xml',
        action_type='POST',
        headerOptions=getXArgsDeviceInfo(options),
        authenticate=False,
        auth=(username, password))

    try:
        xml.attrib
    except AttributeError:
        log.error('Could not sign in to plex.tv')
        return ('', '')

    el_username = xml.find('username')
    el_authtoken = xml.find('authentication-token')
    if el_username is None or \
       el_authtoken is None:
        username = ''
        authtoken = ''
    else:
        username = el_username.text
        authtoken = el_authtoken.text
    return (username, authtoken)


def check_plex_tv_pin(identifier):
    """
    Checks with plex.tv whether user entered the correct PIN on plex.tv/pin

    Returns False if not yet done so, or the XML response file as etree
    """
    # Try to get a temporary token
    xml = DownloadUtils().downloadUrl(
        'https://plex.tv/pins/%s.xml' % identifier,
        authenticate=False)
    try:
        temp_token = xml.find('auth_token').text
    except:
        log.error("Could not find token in plex.tv answer")
        return False
    if not temp_token:
        return False
    # Use temp token to get the final plex credentials
    xml = DownloadUtils().downloadUrl('https://plex.tv/users/account',
                                      authenticate=False,
                                      parameters={'X-Plex-Token': temp_token})
    return xml


def get_plex_pin():
    """
    For plex.tv sign-in: returns 4-digit code and identifier as 2 str
    """
    code = None
    identifier = None
    # Download
    xml = DownloadUtils().downloadUrl('https://plex.tv/pins.xml',
                                      authenticate=False,
                                      action_type="POST")
    try:
        xml.attrib
    except:
        log.error("Error, no PIN from plex.tv provided")
        return None, None
    code = xml.find('code').text
    identifier = xml.find('id').text
    log.info('Successfully retrieved code and id from plex.tv')
    return code, identifier


def get_plex_login_password():
    """
    Signs in to plex.tv.

    plexLogin, authtoken = get_plex_login_password()

    Input: nothing
    Output:
        plexLogin       plex.tv username
        authtoken       token for plex.tv

    Also writes 'plexLogin' and 'token_plex.tv' to Kodi settings file
    If not logged in, empty strings are returned for both.
    """
    retrievedPlexLogin = ''
    plexLogin = 'dummy'
    authtoken = ''
    while retrievedPlexLogin == '' and plexLogin != '':
        # Enter plex.tv username. Or nothing to cancel.
        plexLogin = dialog('input',
                           lang(29999) + lang(39300),
                           type='{alphanum}')
        if plexLogin != "":
            # Enter password for plex.tv user
            plexPassword = dialog('input',
                                  lang(39301) + plexLogin,
                                  type='{alphanum}',
                                  option='{hide_input}')
            retrievedPlexLogin, authtoken = my_plex_sign_in(
                plexLogin,
                plexPassword,
                {'X-Plex-Client-Identifier': window('plex_client_Id')})
            log.debug("plex.tv username and token: %s, %s"
                      % (plexLogin, authtoken))
            if plexLogin == '':
                # Could not sign in user
                dialog('ok', lang(29999), lang(39302) + plexLogin)
    # Write to Kodi settings file
    settings('plexLogin', value=retrievedPlexLogin)
    settings('plexToken', value=authtoken)
    return (retrievedPlexLogin, authtoken)


def plex_tv_sign_in_with_pin():
    """
    Prompts user to sign in by visiting https://plex.tv/pin

    Writes to Kodi settings file. Also returns:
    {
        'plexhome':          'true' if Plex Home, 'false' otherwise
        'username':
        'avatar':             URL to user avator
        'token':
        'plexid':             Plex user ID
        'homesize':           Number of Plex home users (defaults to '1')
    }
    Returns False if authentication did not work.
    """
    code, identifier = get_plex_pin()
    if not code:
        # Problems trying to contact plex.tv. Try again later
        dialog('ok', lang(29999), lang(39303))
        return False
    # Go to https://plex.tv/pin and enter the code:
    # Or press No to cancel the sign in.
    answer = dialog('yesno',
                    lang(29999),
                    lang(39304) + "\n\n",
                    code + "\n\n",
                    lang(39311))
    if not answer:
        return False
    count = 0
    # Wait for approx 30 seconds (since the PIN is not visible anymore :-))
    while count < 30:
        xml = check_plex_tv_pin(identifier)
        if xml is not False:
            break
        # Wait for 1 seconds
        sleep(1000)
        count += 1
    if xml is False:
        # Could not sign in to plex.tv Try again later
        dialog('ok', lang(29999), lang(39305))
        return False
    # Parse xml
    userid = xml.attrib.get('id')
    home = xml.get('home', '0')
    if home == '1':
        home = 'true'
    else:
        home = 'false'
    username = xml.get('username', '')
    avatar = xml.get('thumb', '')
    token = xml.findtext('authentication-token')
    homeSize = xml.get('homeSize', '1')
    result = {
        'plexhome': home,
        'username': username,
        'avatar': avatar,
        'token': token,
        'plexid': userid,
        'homesize': homeSize
    }
    settings('plexLogin', username)
    settings('plexToken', token)
    settings('plexhome', home)
    settings('plexid', userid)
    settings('plexAvatar', avatar)
    settings('plexHomeSize', homeSize)
    # Let Kodi log into plex.tv on startup from now on
    settings('myplexlogin', 'true')
    settings('plex_status', value=lang(39227))
    return result


def list_plex_home_users(token):
    """
    Returns a list for myPlex home users for the current plex.tv account.

    Input:
        token for plex.tv
    Output:
        List of users, where one entry is of the form:
            "id": userId,
            "admin": '1'/'0',
            "guest": '1'/'0',
            "restricted": '1'/'0',
            "protected": '1'/'0',
            "email": email,
            "title": title,
            "username": username,
            "thumb": thumb_url
        }
    If any value is missing, None is returned instead (or "" from plex.tv)
    If an error is encountered, False is returned
    """
    xml = DownloadUtils.downloadUrl('https://plex.tv/api/home/users/',
                                    authenticate=False,
                                    headerOptions={'X-Plex-Token': token})
    try:
        xml.attrib
    except:
        log.error('Download of Plex home users failed.')
        return False
    users = []
    for user in xml:
        users.append(user.attrib)
    return users


def switch_home_user(userId, pin, token, machineIdentifier):
    """
    Retrieves Plex home token for a Plex home user.
    Returns False if unsuccessful

    Input:
        userId          id of the Plex home user
        pin             PIN of the Plex home user, if protected
        token           token for plex.tv

    Output:
        {
            'username'
            'usertoken'         Might be empty strings if no token found
                                for the machineIdentifier that was chosen
        }

    settings('userid') and settings('username') with new plex token
    """
    log.info('Switching to user %s' % userId)
    url = 'https://plex.tv/api/home/users/' + userId + '/switch'
    if pin:
        url += '?pin=' + pin
        answer = DownloadUtils.downloadUrl(
            url,
            authenticate=False,
            action_type="POST",
            headerOptions={'X-Plex-Token': token})
    try:
        answer.attrib
    except:
        log.error('Error: plex.tv switch HomeUser change failed')
        return False

    username = answer.attrib.get('title', '')
    token = answer.attrib.get('authenticationToken', '')

    # Write to settings file
    settings('username', username)
    settings('accessToken', token)
    settings('userid', answer.attrib.get('id', ''))
    settings('plex_restricteduser',
             'true' if answer.attrib.get('restricted', '0') == '1'
             else 'false')
    state.RESTRICTED_USER = True if \
        answer.attrib.get('restricted', '0') == '1' else False

    # Get final token to the PMS we've chosen
    url = 'https://plex.tv/api/resources?includeHttps=1'
    xml = DownloadUtils.downloadUrl(url,
                                    authenticate=False,
                                    headerOptions={'X-Plex-Token': token})
    try:
        xml.attrib
    except:
        log.error('Answer from plex.tv not as excepted')
        # Set to empty iterable list for loop
        xml = []

    found = 0
    log.debug('Our machineIdentifier is %s' % machineIdentifier)
    for device in xml:
        identifier = device.attrib.get('clientIdentifier')
        log.debug('Found a Plex machineIdentifier: %s' % identifier)
        if (identifier in machineIdentifier or
                machineIdentifier in identifier):
            found += 1
            token = device.attrib.get('accessToken')

    result = {
        'username': username,
    }
    if found == 0:
        log.info('No tokens found for your server! Using empty string')
        result['usertoken'] = ''
    else:
        result['usertoken'] = token
    log.info('Plex.tv switch HomeUser change successfull for user %s'
             % username)
    return result


def ChoosePlexHomeUser(plexToken):
    """
    Let's user choose from a list of Plex home users. Will switch to that
    user accordingly.

    Returns a dict:
    {
        'username':             Unicode
        'userid': ''            Plex ID of the user
        'token': ''             User's token
        'protected':            True if PIN is needed, else False
    }

    Will return False if something went wrong (wrong PIN, no connection)
    """
    # Get list of Plex home users
    users = list_plex_home_users(plexToken)
    if not users:
        log.error("User download failed.")
        return False

    userlist = []
    userlistCoded = []
    for user in users:
        username = user['title']
        userlist.append(username)
        # To take care of non-ASCII usernames
        userlistCoded.append(tryEncode(username))
    usernumber = len(userlist)

    username = ''
    usertoken = ''
    trials = 0
    while trials < 3:
        if usernumber > 1:
            # Select user
            user_select = dialog('select',
                                 lang(29999) + lang(39306),
                                 userlistCoded)
            if user_select == -1:
                log.info("No user selected.")
                settings('username', value='')
                executebuiltin('Addon.OpenSettings(%s)'
                               % v.ADDON_ID)
                return False
        # Only 1 user received, choose that one
        else:
            user_select = 0
        selected_user = userlist[user_select]
        log.info("Selected user: %s" % selected_user)
        user = users[user_select]
        # Ask for PIN, if protected:
        pin = None
        if user['protected'] == '1':
            log.debug('Asking for users PIN')
            pin = dialog('input',
                         lang(39307) + selected_user,
                         '',
                         type='{numeric}',
                         option='{hide_input}')
            # User chose to cancel
            # Plex bug: don't call url for protected user with empty PIN
            if not pin:
                trials += 1
                continue
        # Switch to this Plex Home user, if applicable
        result = switch_home_user(
            user['id'],
            pin,
            plexToken,
            settings('plex_machineIdentifier'))
        if result:
            # Successfully retrieved username: break out of while loop
            username = result['username']
            usertoken = result['usertoken']
            break
        # Couldn't get user auth
        else:
            trials += 1
            # Could not login user, please try again
            if not dialog('yesno',
                          lang(29999),
                          lang(39308) + selected_user,
                          lang(39309)):
                # User chose to cancel
                break
    if not username:
        log.error('Failed signing in a user to plex.tv')
        executebuiltin('Addon.OpenSettings(%s)' % v.ADDON_ID)
        return False
    return {
        'username': username,
        'userid': user['id'],
        'protected': True if user['protected'] == '1' else False,
        'token': usertoken
    }


def get_user_artwork_url(username):
    """
    Returns the URL for the user's Avatar. Or False if something went
    wrong.
    """
    plexToken = settings('plexToken')
    users = list_plex_home_users(plexToken)
    url = ''
    # If an error is encountered, set to False
    if not users:
        log.info("Couldnt get user from plex.tv. No URL for user avatar")
        return False
    for user in users:
        if username in user['title']:
            url = user['thumb']
    log.debug("Avatar url for user %s is: %s" % (username, url))
    return url
