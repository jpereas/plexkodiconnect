# -*- coding: utf-8 -*-
###############################################################################
import logging
from threading import Thread
from Queue import Queue
from urlparse import parse_qsl

from xbmc import sleep

from utils import window, thread_methods
import state
import entrypoint

###############################################################################
log = logging.getLogger("PLEX."+__name__)

###############################################################################


@thread_methods
class Monitor_Window(Thread):
    """
    Monitors window('plex_command') for new entries that we need to take care
    of, e.g. for new plays initiated on the Kodi side with addon paths.

    Possible values of window('plex_command'):
        'play_....': to start playback using playback_starter

    Adjusts state.py accordingly
    """
    # Borg - multiple instances, shared state
    def __init__(self, callback=None):
        self.mgr = callback
        self.playback_queue = Queue()
        Thread.__init__(self)

    @staticmethod
    def __execute(value):
        """
        Kick off with new threads. Pass in a string with the information url-
        encoded:
            function=<function-name in entrypoint.py>
            params=<function parameters> (optional)
        """
        values = dict(parse_qsl(value))
        function = values.get('function')
        params = values.get('params')
        log.debug('Execution called for function %s with parameters %s'
                  % (function, params))
        function = getattr(entrypoint, function)
        try:
            if params is not None:
                function(params)
            else:
                function()
        except:
            log.error('Failed to execute function %s with params %s'
                      % (function, params))
            raise

    def run(self):
        thread_stopped = self.thread_stopped
        queue = self.playback_queue
        log.info("----===## Starting Kodi_Play_Client ##===----")
        while not thread_stopped():
            if window('plex_command'):
                value = window('plex_command')
                window('plex_command', clear=True)
                if value.startswith('play_'):
                    queue.put(value)
                elif value.startswith('exec_'):
                    t = Thread(target=self.__execute, args=(value[5:], ))
                    t.start()
                elif value == 'SUSPEND_LIBRARY_THREAD-True':
                    state.SUSPEND_LIBRARY_THREAD = True
                elif value == 'SUSPEND_LIBRARY_THREAD-False':
                    state.SUSPEND_LIBRARY_THREAD = False
                elif value == 'STOP_SYNC-True':
                    state.STOP_SYNC = True
                elif value == 'STOP_SYNC-False':
                    state.STOP_SYNC = False
                elif value == 'PMS_STATUS-Auth':
                    state.PMS_STATUS = 'Auth'
                elif value == 'PMS_STATUS-401':
                    state.PMS_STATUS = '401'
                elif value == 'SUSPEND_USER_CLIENT-True':
                    state.SUSPEND_USER_CLIENT = True
                elif value == 'SUSPEND_USER_CLIENT-False':
                    state.SUSPEND_USER_CLIENT = False
                elif value.startswith('PLEX_TOKEN-'):
                    state.PLEX_TOKEN = value.replace('PLEX_TOKEN-', '') or None
                elif value.startswith('PLEX_USERNAME-'):
                    state.PLEX_USERNAME = \
                        value.replace('PLEX_USERNAME-', '') or None
                else:
                    raise NotImplementedError('%s not implemented' % value)
            else:
                sleep(50)
        # Put one last item into the queue to let playback_starter end
        queue.put(None)
        log.info("----===## Kodi_Play_Client stopped ##===----")
