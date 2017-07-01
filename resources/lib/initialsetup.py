# -*- coding: utf-8 -*-
###############################################################################
from logging import getLogger
from xbmc import executebuiltin

from utils import settings, language as lang, advancedsettings_xml, dialog
from connectmanager import ConnectManager

import state
from migration import check_migration

###############################################################################
log = getLogger("PLEX."+__name__)

###############################################################################


def setup(self):
    """
    Initial setup. Run once upon startup.

    Check server, user, direct paths, music, direct stream if not direct
    path.
    """
    log.info("Initial setup called")
    connectmanager = ConnectManager()

    # Get current Kodi video cache setting
    cache, _ = advancedsettings_xml(['cache', 'memorysize'])
    if cache is None:
        # Kodi default cache
        cache = '20971520'
    else:
        cache = str(cache.text)
    log.info('Current Kodi video memory cache in bytes: %s' % cache)
    settings('kodi_video_cache', value=cache)

    # Do we need to migrate stuff?
    check_migration()

    # Optionally sign into plex.tv. Will not be called on very first run
    # as plexToken will be ''
    settings('plex_status', value=lang(39226))
    if connectmanager.plexToken and connectmanager.myplexlogin:
        connectmanager.check_plex_tv_signin()

    # If a Plex server IP has already been set
    # return only if the right machine identifier is found
    if connectmanager.server:
        log.info("PMS is already set: %s. Checking now..." % self.server)
        if connectmanager.check_pms():
            log.info("Using PMS %s with machineIdentifier %s"
                     % (self.server, self.serverid))
            connectmanager.write_pms_settings(self.server, self.pms_token)
            return

    # If not already retrieved myplex info, optionally let user sign in
    # to plex.tv. This DOES get called on very first install run
    if not connectmanager.plexToken and connectmanager.myplexlogin:
        connectmanager.plex_tv_signin()

    server = connectmanager.connectmanager.pick_pms()
    if server is not None:
        # Write our chosen server to Kodi settings file
        connectmanager.write_pms_to_settings(server)

    # User already answered the installation questions
    if settings('InstallQuestionsAnswered') == 'true':
        return

    # Additional settings where the user needs to choose
    # Direct paths (\\NAS\mymovie.mkv) or addon (http)?
    goToSettings = False
    if dialog('yesno',
              lang(29999),
              lang(39027),
              lang(39028),
              nolabel="Addon (Default)",
              yeslabel="Native (Direct Paths)"):
        log.debug("User opted to use direct paths.")
        settings('useDirectPaths', value="1")
        state.DIRECT_PATHS = True
        # Are you on a system where you would like to replace paths
        # \\NAS\mymovie.mkv with smb://NAS/mymovie.mkv? (e.g. Windows)
        if dialog('yesno', heading=lang(29999), line1=lang(39033)):
            log.debug("User chose to replace paths with smb")
        else:
            settings('replaceSMB', value="false")

        # complete replace all original Plex library paths with custom SMB
        if dialog('yesno', heading=lang(29999), line1=lang(39043)):
            log.debug("User chose custom smb paths")
            settings('remapSMB', value="true")
            # Please enter your custom smb paths in the settings under
            # "Sync Options" and then restart Kodi
            dialog('ok', heading=lang(29999), line1=lang(39044))
            goToSettings = True

        # Go to network credentials?
        if dialog('yesno',
                  heading=lang(29999),
                  line1=lang(39029),
                  line2=lang(39030)):
            log.debug("Presenting network credentials dialog.")
            from utils import passwordsXML
            passwordsXML()
    # Disable Plex music?
    if dialog('yesno', heading=lang(29999), line1=lang(39016)):
        log.debug("User opted to disable Plex music library.")
        settings('enableMusic', value="false")

    # Download additional art from FanArtTV
    if dialog('yesno', heading=lang(29999), line1=lang(39061)):
        log.debug("User opted to use FanArtTV")
        settings('FanartTV', value="true")
    # Do you want to replace your custom user ratings with an indicator of
    # how many versions of a media item you posses?
    if dialog('yesno', heading=lang(29999), line1=lang(39718)):
        log.debug("User opted to replace user ratings with version number")
        settings('indicate_media_versions', value="true")

    # If you use several Plex libraries of one kind, e.g. "Kids Movies" and
    # "Parents Movies", be sure to check https://goo.gl/JFtQV9
    dialog('ok', heading=lang(29999), line1=lang(39076))

    # Need to tell about our image source for collections: themoviedb.org
    dialog('ok', heading=lang(29999), line1=lang(39717))
    # Make sure that we only ask these questions upon first installation
    settings('InstallQuestionsAnswered', value='true')

    if goToSettings is False:
        # Open Settings page now? You will need to restart!
        goToSettings = dialog('yesno', heading=lang(29999), line1=lang(39017))
    if goToSettings:
        state.PMS_STATUS = 'Stop'
        executebuiltin('Addon.OpenSettings(plugin.video.plexkodiconnect)')
