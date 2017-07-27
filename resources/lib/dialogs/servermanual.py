# -*- coding: utf-8 -*-
###############################################################################
from logging import getLogger

import xbmcgui

import connect.connectionmanager as connectionmanager
from utils import language as lang, tryDecode

###############################################################################
log = getLogger("PLEX."+__name__)

CONN_STATE = connectionmanager.CONNECTIONSTATE
ACTION_PARENT_DIR = 9
ACTION_PREVIOUS_MENU = 10
ACTION_BACK = 92
CONNECT = 200
CANCEL = 201
ERROR_TOGGLE = 202
ERROR_MSG = 203
VERIFY_SSL = 204
HOST_SSL_PATH = 205
PMS_IP = 208
PMS_PORT = 209
ERROR = {
    'Invalid': 1,
    'Empty': 2
}
###############################################################################


class ServerManual(xbmcgui.WindowXMLDialog):
    _server = None
    error = None

    def onInit(self):
        self.connect_button = self.getControl(CONNECT)
        self.cancel_button = self.getControl(CANCEL)
        self.error_toggle = self.getControl(ERROR_TOGGLE)
        self.error_msg = self.getControl(ERROR_MSG)

        self.host_field = self.getControl(PMS_IP)
        self.port_field = self.getControl(PMS_PORT)
        self.verify_ssl_radio = self.getControl(VERIFY_SSL)
        self.host_ssl_path_radio = self.getControl(HOST_SSL_PATH)

        self.port_field.setText('32400')
        self.setFocus(self.host_field)
        self.verify_ssl_radio.setSelected(True)
        self.host_ssl_path_radio.setSelected(False)
        self.host_ssl_path = None

        self.host_field.controlUp(self.cancel_button)
        self.host_field.controlDown(self.port_field)
        self.port_field.controlUp(self.host_field)
        self.port_field.controlDown(self.verify_ssl_radio)
        self.verify_ssl_radio.controlUp(self.port_field)
        self.verify_ssl_radio.controlDown(self.host_ssl_path_radio)
        self.host_ssl_path_radio.controlUp(self.verify_ssl_radio)
        self.host_ssl_path_radio.controlDown(self.connect_button)
        self.connect_button.controlUp(self.host_ssl_path_radio)
        self.connect_button.controlDown(self.cancel_button)
        self.cancel_button.controlUp(self.connect_button)
        self.cancel_button.controlDown(self.host_field)

    def set_connect_manager(self, connect_manager):
        self.connect_manager = connect_manager

    def is_connected(self):
        return True if self._server else False

    def get_server(self):
        return self._server

    def onClick(self, control):
        if control == CONNECT:
            self._disable_error()

            server = self.host_field.getText()
            port = self.port_field.getText()

            if not server or not port:
                # Display error
                self._error(ERROR['Empty'], lang(30021))
                log.error("Server or port cannot be null")

            elif self._connect_to_server(server, port):
                self.close()

        elif control == CANCEL:
            self.close()
        elif control == HOST_SSL_PATH:
            if self.host_ssl_path_radio.isSelected():
                # Let the user choose path to the certificate (=file)
                self.host_ssl_path = xbmcgui.Dialog().browse(
                    1, lang(29999), 'files', '', False, False, '', False)
                log.debug('Host SSL file path chosen: %s' % self.host_ssl_path)
                if not self.host_ssl_path:
                    self.host_ssl_path_radio.setSelected(False)
                else:
                    self.host_ssl_path = tryDecode(self.host_ssl_path)
            else:
                # User disabled
                # Ensure that we don't have a host certificate set
                self.host_ssl_path = None

    def onAction(self, action):
        if (self.error == ERROR['Empty'] and
                self.host_field.getText() and self.port_field.getText()):
            self._disable_error()
        if action in (ACTION_BACK, ACTION_PARENT_DIR, ACTION_PREVIOUS_MENU):
            self.close()

    def _connect_to_server(self, server, port):
        """Returns True if we could connect, False otherwise"""
        url = "%s:%s" % (server, port)
        self._message("%s %s..." % (lang(30023), url))
        options = {
            'verify': True if self.verify_ssl_radio.isSelected() else False
        }
        if self.host_ssl_path:
            options['cert'] = self.host_ssl_path
        result = self.connect_manager.connectToAddress(url, options)
        log.debug('Received the following results: %s' % result)
        if result['State'] == CONN_STATE['Unavailable']:
            self._message(lang(30204))
            return False
        else:
            self._server = result['Servers'][0]
            return True

    def _message(self, message):
        """Displays a message popup just underneath the dialog"""
        self.error_msg.setLabel(message)
        self.error_toggle.setVisibleCondition('True')

    def _error(self, state, message):
        """Displays an error message just underneath the dialog"""
        self.error = state
        self.error_msg.setLabel(message)
        self.error_toggle.setVisibleCondition('True')

    def _disable_error(self):
        """Disables the message popup just underneath the dialog"""
        self.error = None
        self.error_toggle.setVisibleCondition('False')
