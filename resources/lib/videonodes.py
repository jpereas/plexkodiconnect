# -*- coding: utf-8 -*-
###############################################################################
from logging import getLogger
from shutil import copytree
import xml.etree.ElementTree as etree
from os import makedirs

import xbmc
from xbmcvfs import exists

from utils import window, settings, language as lang, tryEncode, indent, \
    normalize_nodes, exists_dir, tryDecode
import variables as v

###############################################################################

log = getLogger("PLEX."+__name__)

###############################################################################
# Paths are strings, NOT unicode!


class VideoNodes(object):

    def commonRoot(self, order, label, tagname, roottype=1):

        if roottype == 0:
            # Index
            root = etree.Element('node', attrib={'order': "%s" % order})
        elif roottype == 1:
            # Filter
            root = etree.Element('node', attrib={'order': "%s" % order, 'type': "filter"})
            etree.SubElement(root, 'match').text = "all"
            # Add tag rule
            rule = etree.SubElement(root, 'rule', attrib={'field': "tag", 'operator': "is"})
            etree.SubElement(rule, 'value').text = tagname
        else:
            # Folder
            root = etree.Element('node', attrib={'order': "%s" % order, 'type': "folder"})

        etree.SubElement(root, 'label').text = label
        etree.SubElement(root, 'icon').text = "special://home/addons/plugin.video.plexkodiconnect/icon.png"

        return root

    def viewNode(self, indexnumber, tagname, mediatype, viewtype, viewid, delete=False):
        # Plex: reassign mediatype due to Kodi inner workings
        # How many items do we get at most?
        limit = window('fetch_pms_item_number')
        mediatypes = {
            'movie': 'movies',
            'show': 'tvshows',
            'photo': 'photos',
            'homevideo': 'homevideos',
            'musicvideos': 'musicvideos'
        }
        mediatype = mediatypes[mediatype]

        if viewtype == "mixed":
            dirname = "%s-%s" % (viewid, mediatype)
        else:
            dirname = viewid

        # Returns strings
        path = tryDecode(xbmc.translatePath(
            "special://profile/library/video/"))
        nodepath = tryDecode(xbmc.translatePath(
            "special://profile/library/video/Plex-%s/" % dirname))

        if delete:
            if exists_dir(nodepath):
                from shutil import rmtree
                rmtree(nodepath)
                log.info("Sucessfully removed videonode: %s." % tagname)
            return

        # Verify the video directory
        if not exists_dir(path):
            copytree(
                src=tryDecode(xbmc.translatePath(
                    "special://xbmc/system/library/video")),
                dst=tryDecode(xbmc.translatePath(
                    "special://profile/library/video")))

        # Create the node directory
        if mediatype != "photos":
            if not exists_dir(nodepath):
                # folder does not exist yet
                log.debug('Creating folder %s' % nodepath)
                makedirs(nodepath)

        # Create index entry
        nodeXML = "%sindex.xml" % nodepath
        # Set windows property
        path = "library://video/Plex-%s/" % dirname
        for i in range(1, indexnumber):
            # Verify to make sure we don't create duplicates
            if window('Plex.nodes.%s.index' % i) == path:
                return

        if mediatype == "photos":
            path = "plugin://plugin.video.plexkodiconnect?mode=browseplex&key=/library/sections/%s&id=%s" % (viewid, viewid)

        window('Plex.nodes.%s.index' % indexnumber, value=path)

        # Root
        if not mediatype == "photos":
            if viewtype == "mixed":
                specialtag = "%s-%s" % (tagname, mediatype)
                root = self.commonRoot(order=0,
                                       label=specialtag,
                                       tagname=tagname,
                                       roottype=0)
            else:
                root = self.commonRoot(order=0,
                                       label=tagname,
                                       tagname=tagname,
                                       roottype=0)
            try:
                indent(root)
            except:
                pass
            etree.ElementTree(root).write(nodeXML, encoding="UTF-8")

        nodetypes = {
            '1': "all",
            '2': "recent",
            '3': "recentepisodes",
            '4': "inprogress",
            '5': "inprogressepisodes",
            '6': "unwatched",
            '7': "nextepisodes",
            '8': "sets",
            '9': "genres",
            '10': "random",
            '11': "recommended",
            '12': "ondeck",
            '13': 'browsefiles'
        }
        mediatypes = {
            # label according to nodetype per mediatype
            'movies':
                {
                    '1': tagname,
                    '2': 30174,
                    # '4': 30177,
                    # '6': 30189,
                    '8': 39501,
                    '9': 135,
                    '10': 30227,
                    '11': 30230,
                    '12': 39500,
                    '13': 39702
                },

            'tvshows':
                {
                    '1': tagname,
                    # '2': 30170,
                    '3': 30174,
                    # '4': 30171,
                    # '5': 30178,
                    # '7': 30179,
                    '9': 135,
                    '10': 30227,
                    # '11': 30230,
                    '12': 39500,
                    '13': 39702
                },

            'homevideos':
                {
                    '1': tagname,
                    '2': 30251,
                    '11': 30253,
                    '13': 39702
                },

            'photos':
                {
                    '1': tagname,
                    '2': 30252,
                    '8': 30255,
                    '11': 30254,
                    '13': 39702
                },

            'musicvideos':
                {
                    '1': tagname,
                    '2': 30256,
                    '4': 30257,
                    '6': 30258,
                    '13': 39702
                }
        }

        # Key: nodetypes, value: sort order in Kodi
        sortorder = {
            '1': '3',  # "all",
            '2': '2',  # "recent",
            '3': '2',  # "recentepisodes",
            # '4': # "inprogress",
            # '5': # "inprogressepisodes",
            # '6': # "unwatched",
            # '7': # "nextepisodes",
            '8': '7',  # "sets",
            '9': '6',  # "genres",
            '10': '8',  # "random",
            '11': '5',  # "recommended",
            '12': '1',  # "ondeck"
            '13': '9'  # browse by folder
        }

        nodes = mediatypes[mediatype]
        for node in nodes:

            nodetype = nodetypes[node]
            nodeXML = "%s%s_%s.xml" % (nodepath, viewid, nodetype)
            # Get label
            stringid = nodes[node]
            if node != "1":
                label = lang(stringid)
                if not label:
                    label = xbmc.getLocalizedString(stringid)
            else:
                label = stringid

            # Set window properties
            if (mediatype == "homevideos" or mediatype == "photos") and nodetype == "all":
                # Custom query
                path = ("plugin://plugin.video.plexkodiconnect/?id=%s&mode=browseplex&type=%s"
                        % (viewid, mediatype))
            elif (mediatype == "homevideos" or mediatype == "photos"):
                # Custom query
                path = ("plugin://plugin.video.plexkodiconnect/?id=%s&mode=browseplex&type=%s&folderid=%s"
                        % (viewid, mediatype, nodetype))
            elif nodetype == "nextepisodes":
                # Custom query
                path = "plugin://plugin.video.plexkodiconnect/?id=%s&mode=nextup&limit=%s" % (tagname, limit)
            # elif v.KODIVERSION == 14 and nodetype == "recentepisodes":
            elif nodetype == "recentepisodes":
                # Custom query
                path = ("plugin://plugin.video.plexkodiconnect/?id=%s&mode=recentepisodes&type=%s&tagname=%s&limit=%s"
                    % (viewid, mediatype, tagname, limit))
            elif v.KODIVERSION == 14 and nodetype == "inprogressepisodes":
                # Custom query
                path = "plugin://plugin.video.plexkodiconnect/?id=%s&mode=inprogressepisodes&limit=%s" % (tagname, limit)
            elif nodetype == 'ondeck':
                # PLEX custom query
                if mediatype == "tvshows":
                    path = ("plugin://plugin.video.plexkodiconnect/?id=%s&mode=ondeck&type=%s&tagname=%s&limit=%s"
                        % (viewid, mediatype, tagname, limit))
                elif mediatype =="movies":
                    # Reset nodetype; we got the label
                    nodetype = 'inprogress'
            elif nodetype == 'browsefiles':
                path = 'plugin://plugin.video.plexkodiconnect?mode=browseplex&key=/library/sections/%s/folder' % viewid
            else:
                path = "library://video/Plex-%s/%s_%s.xml" % (dirname, viewid, nodetype)

            if mediatype == "photos":
                windowpath = "ActivateWindow(Pictures,%s,return)" % path
            else:
                if v.KODIVERSION >= 17:
                    # Krypton
                    windowpath = "ActivateWindow(Videos,%s,return)" % path
                else:
                    windowpath = "ActivateWindow(Video,%s,return)" % path

            if nodetype == "all":

                if viewtype == "mixed":
                    templabel = "%s-%s" % (tagname, mediatype)
                else:
                    templabel = label

                embynode = "Plex.nodes.%s" % indexnumber
                window('%s.title' % embynode, value=templabel)
                window('%s.path' % embynode, value=windowpath)
                window('%s.content' % embynode, value=path)
                window('%s.type' % embynode, value=mediatype)
            else:
                embynode = "Plex.nodes.%s.%s" % (indexnumber, nodetype)
                window('%s.title' % embynode, value=label)
                window('%s.path' % embynode, value=windowpath)
                window('%s.content' % embynode, value=path)

            if mediatype == "photos":
                # For photos, we do not create a node in videos but we do want the window props
                # to be created.
                # To do: add our photos nodes to kodi picture sources somehow
                continue

            if exists(tryEncode(nodeXML)):
                # Don't recreate xml if already exists
                continue

            # Create the root
            if (nodetype in ("nextepisodes", "ondeck", 'recentepisodes', 'browsefiles') or mediatype == "homevideos"):
                # Folder type with plugin path
                root = self.commonRoot(order=sortorder[node], label=label, tagname=tagname, roottype=2)
                etree.SubElement(root, 'path').text = path
                etree.SubElement(root, 'content').text = "episodes"
            else:
                root = self.commonRoot(order=sortorder[node], label=label, tagname=tagname)
                if nodetype in ('recentepisodes', 'inprogressepisodes'):
                    etree.SubElement(root, 'content').text = "episodes"
                else:
                    etree.SubElement(root, 'content').text = mediatype

                # Elements per nodetype
                if nodetype == "all":
                    etree.SubElement(root, 'order', {'direction': "ascending"}).text = "sorttitle"
                
                elif nodetype == "recent":
                    etree.SubElement(root, 'order', {'direction': "descending"}).text = "dateadded"
                    etree.SubElement(root, 'limit').text = limit
                    if settings('MovieShowWatched') == 'false':
                        rule = etree.SubElement(root,
                                                'rule',
                                                {'field': "playcount",
                                                 'operator': "is"})
                        etree.SubElement(rule, 'value').text = "0"
                
                elif nodetype == "inprogress":
                    etree.SubElement(root, 'rule', {'field': "inprogress", 'operator': "true"})
                    etree.SubElement(root, 'limit').text = limit
                    etree.SubElement(
                        root,
                        'order',
                        {'direction': 'descending'}
                    ).text = 'lastplayed'

                elif nodetype == "genres":
                    etree.SubElement(root, 'order', {'direction': "ascending"}).text = "sorttitle"
                    etree.SubElement(root, 'group').text = "genres"
                
                elif nodetype == "unwatched":
                    etree.SubElement(root, 'order', {'direction': "ascending"}).text = "sorttitle"
                    rule = etree.SubElement(root, "rule", {'field': "playcount", 'operator': "is"})
                    etree.SubElement(rule, 'value').text = "0"

                elif nodetype == "sets":
                    etree.SubElement(root, 'order', {'direction': "ascending"}).text = "sorttitle"
                    etree.SubElement(root, 'group').text = "tags"

                elif nodetype == "random":
                    etree.SubElement(root, 'order', {'direction': "ascending"}).text = "random"
                    etree.SubElement(root, 'limit').text = limit

                elif nodetype == "recommended":
                    etree.SubElement(root, 'order', {'direction': "descending"}).text = "rating"
                    etree.SubElement(root, 'limit').text = limit
                    rule = etree.SubElement(root, 'rule', {'field': "playcount", 'operator': "is"})
                    etree.SubElement(rule, 'value').text = "0"
                    rule2 = etree.SubElement(root, 'rule',
                        attrib={'field': "rating", 'operator': "greaterthan"})
                    etree.SubElement(rule2, 'value').text = "7"

                elif nodetype == "recentepisodes":
                    # Kodi Isengard, Jarvis
                    etree.SubElement(root, 'order', {'direction': "descending"}).text = "dateadded"
                    etree.SubElement(root, 'limit').text = limit
                    rule = etree.SubElement(root, 'rule', {'field': "playcount", 'operator': "is"})
                    etree.SubElement(rule, 'value').text = "0"

                elif nodetype == "inprogressepisodes":
                    # Kodi Isengard, Jarvis
                    etree.SubElement(root, 'limit').text = limit
                    rule = etree.SubElement(root, 'rule',
                        attrib={'field': "inprogress", 'operator':"true"})

            try:
                indent(root)
            except:
                pass
            etree.ElementTree(root).write(nodeXML, encoding="UTF-8")

    def singleNode(self, indexnumber, tagname, mediatype, itemtype):
        tagname = tryEncode(tagname)
        cleantagname = tryDecode(normalize_nodes(tagname))
        nodepath = tryDecode(xbmc.translatePath(
            "special://profile/library/video/"))
        nodeXML = "%splex_%s.xml" % (nodepath, cleantagname)
        path = "library://video/plex_%s.xml" % cleantagname
        if v.KODIVERSION >= 17:
            # Krypton
            windowpath = "ActivateWindow(Videos,%s,return)" % path
        else:
            windowpath = "ActivateWindow(Video,%s,return)" % path

        # Create the video node directory
        if not exists_dir(nodepath):
            # We need to copy over the default items
            copytree(
                src=tryDecode(xbmc.translatePath(
                    "special://xbmc/system/library/video")),
                dst=tryDecode(xbmc.translatePath(
                    "special://profile/library/video")))

        labels = {
            'Favorite movies': 30180,
            'Favorite tvshows': 30181,
            'channels': 30173
        }
        label = lang(labels[tagname])
        embynode = "Plex.nodes.%s" % indexnumber
        window('%s.title' % embynode, value=label)
        window('%s.path' % embynode, value=windowpath)
        window('%s.content' % embynode, value=path)
        window('%s.type' % embynode, value=itemtype)

        if exists(tryEncode(nodeXML)):
            # Don't recreate xml if already exists
            return

        if itemtype == "channels":
            root = self.commonRoot(order=1,
                                   label=label,
                                   tagname=tagname,
                                   roottype=2)
            etree.SubElement(root, 'path').text = "plugin://plugin.video.plexkodiconnect/?id=0&mode=channels"
        else:
            root = self.commonRoot(order=1, label=label, tagname=tagname)
            etree.SubElement(root, 'order', {'direction': "ascending"}).text = "sorttitle"

        etree.SubElement(root, 'content').text = mediatype

        try:
            indent(root)
        except:
            pass
        etree.ElementTree(root).write(nodeXML, encoding="UTF-8")

    def clearProperties(self):

        log.info("Clearing nodes properties.")
        plexprops = window('Plex.nodes.total')
        propnames = [
            "index","path","title","content",
            "inprogress.content","inprogress.title",
            "inprogress.content","inprogress.path",
            "nextepisodes.title","nextepisodes.content",
            "nextepisodes.path","unwatched.title",
            "unwatched.content","unwatched.path",
            "recent.title","recent.content","recent.path",
            "recentepisodes.title","recentepisodes.content",
            "recentepisodes.path","inprogressepisodes.title",
            "inprogressepisodes.content","inprogressepisodes.path"
        ]

        if plexprops:
            totalnodes = int(plexprops)
            for i in range(totalnodes):
                for prop in propnames:
                    window('Plex.nodes.%s.%s' % (str(i), prop), clear=True)
