# -*- coding: utf-8 -*-

###############################################################################
from logging import getLogger

from xbmc import Player

from downloadutils import DownloadUtils as DU
from plexbmchelper.subscribers import LOCKER
import playqueue as PQ
import variables as v
import state

###############################################################################

LOG = getLogger("PLEX." + __name__)

###############################################################################


@LOCKER.lockthis
def playback_cleanup():
    """
    PKC cleanup after playback ends/is stopped
    """
    # We might have saved a transient token from a user flinging media via
    # Companion (if we could not use the playqueue to store the token)
    LOG.debug('playback_cleanup called')
    state.PLEX_TRANSIENT_TOKEN = None
    for playerid in state.ACTIVE_PLAYERS:
        status = state.PLAYER_STATES[playerid]
        # Remember the last played item later
        state.OLD_PLAYER_STATES[playerid] = dict(status)
        # Stop transcoding
        if status['playmethod'] == 'Transcode':
            LOG.debug('Tell the PMS to stop transcoding')
            DU().downloadUrl(
                '{server}/video/:/transcode/universal/stop',
                parameters={'session': v.PKC_MACHINE_IDENTIFIER})
        # Kodi will not clear the playqueue (because there is not really any)
        # if there is only 1 item in it
        if len(PQ.PLAYQUEUES[playerid].items) == 1:
            PQ.PLAYQUEUES[playerid].clear()
        # Reset the player's status
        status = dict(state.PLAYSTATE)
    # As all playback has halted, reset the players that have been active
    state.ACTIVE_PLAYERS = []
    LOG.debug('Finished PKC playback cleanup')


class PKC_Player(Player):
    def __init__(self):
        Player.__init__(self)
        LOG.info("Started playback monitor.")

    def onPlayBackStarted(self):
        """
        Will be called when xbmc starts playing a file.
        """
        pass

    def onPlayBackPaused(self):
        """
        Will be called when playback is paused
        """
        pass

    def onPlayBackResumed(self):
        """
        Will be called when playback is resumed
        """
        pass

    def onPlayBackSeek(self, time, seekOffset):
        """
        Will be called when user seeks to a certain time during playback
        """
        pass

    def onPlayBackStopped(self):
        """
        Will be called when playback is stopped by the user
        """
        LOG.debug("ONPLAYBACK_STOPPED")
        if state.PKC_CAUSED_STOP is True:
            state.PKC_CAUSED_STOP = False
            LOG.debug('PKC caused this playback stop - ignoring')
        else:
            playback_cleanup()

    def onPlayBackEnded(self):
        """
        Will be called when playback ends due to the media file being finished
        """
        LOG.debug("ONPLAYBACK_ENDED")
        playback_cleanup()
