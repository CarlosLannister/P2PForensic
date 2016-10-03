#P2P Emule Forensic module
#Lazarus technology

# Contact: Carlos Cilleruelo [carlos.cilleruelo <at> edu [dot] uah [dot] es]


import jarray
import inspect
import os
import binascii 
from emule import *
import string
import time
from bencoder import *

from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from java.awt import BorderLayout
from javax.swing import BorderFactory
from javax.swing import JTextArea
from javax.swing import JScrollPane
from javax.swing import JButton
from javax.swing import JToolBar
from javax.swing import JPanel
from javax.swing import JFrame
from javax.swing import JCheckBox
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import IngestModuleGlobalSettingsPanel
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.autopsy.coreutils import Logger
from java.lang import IllegalArgumentException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils


# This will work in 4.0.1 and beyond
# from org.sleuthkit.autopsy.casemodule.services import Blackboard



class EmuleIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "P2P Forensic module"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "P2P clients forensic analysis"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return EmuleDataSourceIngestModule()



class EmuleDataSourceIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(EmuleIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None


    def startUp(self, context):
        self.context = context

        #self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".exe")
        #if not os.path.exists(self.path_to_exe):
        #    raise IngestModuleException("EXE was not found in module folder")
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
		# raise IngestModuleException("Oh No!")


    def process(self, dataSource, progressBar):

   
        fileManager = Case.getCurrentCase().getServices().getFileManager()

        skCase = Case.getCurrentCase().getSleuthkitCase();

        #Menu elements for Emule

        try:
            self.log(Level.INFO, "Begin Create New Artifacts")
            artID_eu = skCase.addArtifactType( "TSK_EMULE", "Emule User Info")
        except:     
            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
            artID_eu = skCase.getArtifactTypeID("TSK_EMULE")

        try: 
            artID_usage = skCase.addArtifactType( "TSK_EMULE_USAGE", "Emule Usage Info")
        except:   
            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
            artID_usage = skCase.getArtifactTypeID("TSK_EMULE_USAGE")

        try:
            artID_files = skCase.addArtifactType( "TSK_FILES", "Emule Files Downloaded")
        except:     
            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
            artID_files = skCase.getArtifactTypeID("TSK_FILES")

        try:
            artID_ed2k = skCase.addArtifactType( "TSK_ED2K", "Emule Ongoing Downloads")
        except:     
            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
            artID_ed2k = skCase.getArtifactTypeID("TSK_ED2K")

        try:
            artID_incoming_folder = skCase.addArtifactType( "TSK_INCOMING_FOLDER", "Incoming Folder")
        except:     
            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
            artID_incoming_folder = skCase.getArtifactTypeID("TSK_INCONMING_FOLDER")

        #Menu elements for Torrent clients

        try:
            artID_torrent_ongoing = skCase.addArtifactType( "TSK_TORRENT_ONGOING", "Torrent Ongoing downloads")
        except:     
            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
            artID_torrent_ongoing = skCase.getArtifactTypeID("TSK_TORRENT_ONGOING")

        try:
            artID_torrent_added = skCase.addArtifactType( "TSK_TORRENTS", "Torrents added")
        except:     
            self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
            artID_torrent_added = skCase.getArtifactTypeID("TSK_TORRENTS")

        #Menu Items

        try:
            attID_torrent_name = skCase.addArtifactAttributeType("TSK_TORRENT_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Torrent Name")
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Torrent Name. ==> ")

        try:
            attID_incoming_file = skCase.addArtifactAttributeType("TSK_MD5_HASH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "MD5 Hash")
        except:     
            self.log(Level.INFO, "Attributes Creation Error, MD5 Hash. ==> ")

        try:
            attID_incoming_file = skCase.addArtifactAttributeType("TSK_CREATED_TIME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Created Time")
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Created time. ==> ")

        try:
            attID_ed2k_link = skCase.addArtifactAttributeType("TSK_EMULE_SEARCHES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Emule Searches")
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Emule Searches. ==> ")

        try:
            attID_ed2k_link = skCase.addArtifactAttributeType("TSK_ED2K_LINK", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "ED2K Link")
        except:     
            self.log(Level.INFO, "Attributes Creation Error, ED2K Link. ==> ")

        try:
            attID_ed2k_partfile = skCase.addArtifactAttributeType("TSK_ED2K_PARTFILE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Partfile")
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Partfile. ==> ")

        try:
            attID_username = skCase.addArtifactAttributeType("TSK_EMULE_USERNAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Nickname")
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Nickname. ==> ")

        try:
            attID_version = skCase.addArtifactAttributeType("TSK_EMULE_VERSION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Emule Version")           
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Emule version ")

        try:
            attID_language = skCase.addArtifactAttributeType("TSK_EMULE_LANGUAGE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Emule Language")           
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Emule language")

        try:
            attID_incoming_dir = skCase.addArtifactAttributeType("TSK_EMULE_INCOMING", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Incoming Dir")           
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Incoming Dir")

        try:
            attID_userhash = skCase.addArtifactAttributeType("TSK_EMULE_USERHASH", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Userhash")
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Userhash")

        try:
            attID_completed_files = skCase.addArtifactAttributeType("TSK_EMULE_COMPLETED_FILES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Completed Files")           
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Completed Files ")

        try:
            attID_downloaded_bytes = skCase.addArtifactAttributeType("TSK_EMULE_DOWNLOADED_BYTES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Downloaded Bytes")           
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")

        try:
            attID_filename = skCase.addArtifactAttributeType("TSK_EMULE_FILENAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Filename")           
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")

        try:
            attID_filesize = skCase.addArtifactAttributeType("TSK_EMULE_ED2K_FILESIZE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Filesize")           
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")
        
        try:
            attID_partfile = skCase.addArtifactAttributeType("TSK_EMULE_ED2K_PARTFILE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Partfile")           
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")

        try:
            attID_request = skCase.addArtifactAttributeType("TSK_EMULE_ED2K_REQUEST", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Requests")           
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")

        try:
            attID_accepted = skCase.addArtifactAttributeType("TSK_EMULE_ED2K_ACCEPTED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Accepted Requests")           
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")

        try:
            attID_uploaded = skCase.addArtifactAttributeType("TSK_EMULE_ED2K_UPLOADED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Uploaded")           
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")

        try:
            attID_priority = skCase.addArtifactAttributeType("TSK_EMULE_ED2K_PRIORITY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Priority")           
        except:     
            self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")


        #Emule User Info
        artID_eu = skCase.getArtifactTypeID("TSK_EMULE")
        artID_eu_evt = skCase.getArtifactType("TSK_EMULE")
        attID_fn = skCase.getAttributeType("TSK_EMULE_USERNAME")
        attID_userhash = skCase.getAttributeType("TSK_EMULE_USERHASH")
        attID_ev = skCase.getAttributeType("TSK_EMULE_VERSION")
        attID_ln = skCase.getAttributeType("TSK_EMULE_LANGUAGE")
        attID_inc = skCase.getAttributeType("TSK_EMULE_INCOMING")


        #Emule usage info
        attID_usage = skCase.getArtifactTypeID("TSK_EMULE_USAGE")
        attID_usage_evt = skCase.getArtifactType("TSK_EMULE_USAGE")
        attID_emule_searches = skCase.getAttributeType("TSK_EMULE_SEARCHES")
        attID_cf = skCase.getAttributeType("TSK_EMULE_COMPLETED_FILES")
        attID_db = skCase.getAttributeType("TSK_EMULE_DOWNLOADED_BYTES")


        #Emule File Downloads
        attID_files = skCase.getArtifactTypeID("TSK_FILES")
        attID_files_evt = skCase.getArtifactType("TSK_FILES")
        attID_filename = skCase.getAttributeType("TSK_EMULE_FILENAME")
        attID_filesize = skCase.getAttributeType("TSK_EMULE_ED2K_FILESIZE")
        attID_uploaded = skCase.getAttributeType("TSK_EMULE_ED2K_UPLOADED")
        attID_request = skCase.getAttributeType("TSK_EMULE_ED2K_REQUEST")
        attID_accepted = skCase.getAttributeType("TSK_EMULE_ED2K_ACCEPTED")
        attID_priority = skCase.getAttributeType("TSK_EMULE_ED2K_PRIORITY")
        attID_partfile = skCase.getAttributeType("TSK_EMULE_ED2K_PARTFILE")


        #Ongoing Downloads - ED2K links
        artID_ed2k = skCase.getArtifactTypeID("TSK_ED2K")
        artID_ed2k_evt = skCase.getArtifactType("TSK_ED2K")
        attID_ed2k_link = skCase.getAttributeType("TSK_ED2K_LINK")
        attID_ed2k_partfile = skCase.getAttributeType("TSK_ED2K_PARTFILE")

        #Incoming folder
        artID_incoming_folder = skCase.getArtifactTypeID("TSK_INCOMING_FOLDER")
        artID_incoming_evt = skCase.getArtifactType("TSK_INCOMING_FOLDER")
        attID_md5_hash = skCase.getAttributeType("TSK_MD5_HASH")
        attID_crtime = skCase.getAttributeType("TSK_CREATED_TIME")


        #Torrent 
        artID_torrent_added  = skCase.getArtifactTypeID("TSK_TORRENTS")
        artID_torrent_evt = skCase.getArtifactType("TSK_TORRENTS")

        artID_torrent_ongoing = skCase.getArtifactTypeID("TSK_TORRENT_ONGOING")
        artID_torrentOng_evt = skCase.getArtifactTypeID("TSK_TORRENT_ONGOING")
        attID_torrent_name = skCase.getAttributeType("TSK_TORRENT_NAME")



        emuleConfigFiles = fileManager.findFiles(dataSource, "%", "/AppData/Local/eMule/config")

        self.log(Level.INFO, "P2P Emule Module Starting")

        fileCount = 0;

        incomingDir = ''
        
        for file in emuleConfigFiles:
            
            #Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            #Emule Settings 
            if "preferences.ini" in file.getName():
                configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                ContentUtils.writeToFile(file, File(configFilesPath))

                f = open(configFilesPath, 'r')
                incomingDir = ''

                for line in f:
                    if "Nick=" in line and "IRC" not in line:
                        nick = line.rsplit('=', 1)[1]
                    if "AppVersion=" in line:
                        appVersion = line.rsplit('=', 1)[1]
                    if "Language=" in line:
                        lang = line.rsplit('=', 1)[1]
                        intLang = int(lang) 
                        if intLang == 1034: 
                            lang = "Spanish"
                        if intLang == 1033:
                            lang = "English - USA"
                        if intLang == 2057:
                            lang = "English - UK"

                        #TODO add more id to lang 
                        #choices = {'a': 1, 'b': 2}
                        #result = choices.get(key, 'default')

                    if "IncomingDir=" in line:
                        incomingDir = line.rsplit('=', 1)[1]


                art = file.newArtifact(artID_eu)
                art.addAttributes(((BlackboardAttribute(attID_fn, EmuleIngestModuleFactory.moduleName, nick)), \
                (BlackboardAttribute(attID_userhash, EmuleIngestModuleFactory.moduleName, '')), \
                (BlackboardAttribute(attID_ev, EmuleIngestModuleFactory.moduleName, appVersion)), \
                (BlackboardAttribute(attID_ln, EmuleIngestModuleFactory.moduleName, lang)), \
                (BlackboardAttribute(attID_inc, EmuleIngestModuleFactory.moduleName, incomingDir))))

                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, artID_eu_evt, None))
                f.close()
                

            #Emule statiscts
            if "statistics.ini" in file.getName():
                configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                ContentUtils.writeToFile(file, File(configFilesPath))

                f2 = open(configFilesPath, 'r')

                for line in f2:
                    if "DownCompletedFiles=" in line:
                        completedFiles = line.rsplit('=', 1)[1]

                    if "TotalDownloadedBytes=" in line:
                        donwladedBytes = line.rsplit('=', 1)[1]

                art = file.newArtifact(attID_usage)

                art.addAttributes(((BlackboardAttribute(attID_cf, EmuleIngestModuleFactory.moduleName, completedFiles)), \
                (BlackboardAttribute(attID_db, EmuleIngestModuleFactory.moduleName, donwladedBytes))))

                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, attID_usage_evt, None))

            #Emule Userhash 
            if "preferences.dat" in file.getName():
                configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                ContentUtils.writeToFile(file, File(configFilesPath))

                fobj = open(configFilesPath, "rb")

                block = (fobj.read(17))
                block = binascii.hexlify(block)
                userHash = (block[2:34])

                art = file.newArtifact(artID_eu)
                art.addAttribute(BlackboardAttribute(attID_userhash, EmuleIngestModuleFactory.moduleName, userHash))
                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, artID_eu_evt, None))

                fobj.close()

            #Search words last used
            if "AC_SearchStrings.dat" in file.getName():
                configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                ContentUtils.writeToFile(file, File(configFilesPath))
                f = open(configFilesPath)
                searches = '' 
                for line in f: 
                    searches = line.replace("\00", "")
                    searches = searches.encode('ascii',errors='ignore')
                    if len(str(searches)) > 0:
                        art = file.newArtifact(attID_usage)
                        art.addAttribute(BlackboardAttribute(attID_emule_searches, EmuleIngestModuleFactory.moduleName, searches.strip()))
                        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, attID_usage_evt, None))

            #Ongoing downloads
            if "downloads.txt" in file.getName():
                configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                ContentUtils.writeToFile(file, File(configFilesPath))
                f = open(configFilesPath, "r")

                for line in f:
                    ed2k = line.replace("\00", "")
                    if "part" in ed2k:
                        art = file.newArtifact(artID_ed2k)

                        ed2k = ed2k.split('part')
                        partfile = ed2k[0] + "part"
                        ed2kLinks = ed2k[1].strip()

                        art.addAttribute(BlackboardAttribute(attID_ed2k_link, EmuleIngestModuleFactory.moduleName, ed2kLinks))
                        art.addAttribute(BlackboardAttribute(attID_ed2k_partfile, EmuleIngestModuleFactory.moduleName, partfile))
                        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, artID_ed2k_evt, None))

            
            #Information about all files that have been downloaded 
            if "known.met" in file.getName():
                configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                ContentUtils.writeToFile(file, File(configFilesPath))

                fobj = open(configFilesPath, "rb")
                filesize = os.path.getsize(configFilesPath)

                for i in range(filesize):  
                    fobj.seek(i,0)
                    charakter = (fobj.read(4))

                    if charakter == b"\x02\x01\x00\x01": # TAG Filename in known.met file
                        block = getblockofdata(i,fobj, filesize)
                        filename = carvefilename(block)
                        filesizeentry = carvefilesize(block)
                        totalupload = carvetotalupload(block)
                        requests = carverequests(block)
                        acceptedrequests = carveacceptedrequests(block)
                        uploadpriority = carveuploadpriority(block)
                        partfile = carvepartfile(block)
            
                        art = file.newArtifact(attID_files)

                        art.addAttributes(((BlackboardAttribute(attID_filename, EmuleIngestModuleFactory.moduleName, filename)), \
                        (BlackboardAttribute(attID_filesize, EmuleIngestModuleFactory.moduleName, str(filesizeentry))), \
                        (BlackboardAttribute(attID_uploaded, EmuleIngestModuleFactory.moduleName, str(totalupload))), \
                        (BlackboardAttribute(attID_request, EmuleIngestModuleFactory.moduleName, str(requests))), \
                        (BlackboardAttribute(attID_accepted, EmuleIngestModuleFactory.moduleName, str(acceptedrequests))), \
                        (BlackboardAttribute(attID_priority, EmuleIngestModuleFactory.moduleName, str(uploadpriority))), \
                        (BlackboardAttribute(attID_partfile, EmuleIngestModuleFactory.moduleName, str(partfile)))))
           
                        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, attID_files_evt, None))   


        
        # If incoming dir is located 
        if incomingDir:
            incoming = incomingDir.split(':')
            incoming = str(incoming[1]).replace("\\", "/").strip()
            incomingFiles = fileManager.findFiles(dataSource, "%", str(incoming))

            for file in incomingFiles:

                # Check if the user pressed cancel while we were busy
                if self.context.isJobCancelled():
                    return IngestModule.ProcessResult.OK

                if not ("." == file.getName()) and not (".." == file.getName()):
                    md5 = file.getMd5Hash()
                    crtime = str(file.getCrtime())
                    crtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(crtime)))
                    if md5 is None:
                        md5 = ''
                    art = file.newArtifact(artID_incoming_folder)
                    art.addAttribute(BlackboardAttribute(attID_md5_hash, EmuleIngestModuleFactory.moduleName, md5))
                    art.addAttribute(BlackboardAttribute(attID_crtime, EmuleIngestModuleFactory.moduleName, crtime))
                    IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, artID_incoming_evt, None))   


        #Utorrent Forensic \Roaming\uTorrent
        uTorrentForensic = fileManager.findFiles(dataSource, "%", "/Roaming/uTorrent")

        for file in uTorrentForensic:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            # Files added to uTorrent, potentialy downloaded
            if ".torrent" in file.getName():
                art = file.newArtifact(artID_torrent_added)
                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, artID_torrent_evt, None))   
            
            # Current downloads 
            if "resume.dat" in file.getName():
                try:
                    configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                    ContentUtils.writeToFile(file, File(configFilesPath))

                    f = open(configFilesPath, "rb")
                    d = decode(f.read())

                    for line in d:
                        if not (".fileguard" == line) and not ("rec" == line):
                            self.log(Level.INFO, line)
                            art = file.newArtifact(artID_torrent_ongoing)
                            art.addAttribute(BlackboardAttribute(attID_torrent_name, EmuleIngestModuleFactory.moduleName, str(line)))
                    IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, artID_torrentOng_evt, None))            
                except:   
                    self.log(Level.INFO, "Error parsing resume.dat file")
                
        #BitTorrent Forensic \Roaming\uTorrent
        BitTorrentForensic = fileManager.findFiles(dataSource, "%", "/Roaming/BitTorrent")

        for file in BitTorrentForensic:
            self.log(Level.INFO, str(file.getName()))
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            # Files added to uTorrent, potentialy downloaded
            if ".torrent" in file.getName():
                art = file.newArtifact(artID_torrent_added)
                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, artID_torrent_evt, None))   
            
            # Current downloads 
            if "resume.dat" in file.getName():
                try:
                    configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                    ContentUtils.writeToFile(file, File(configFilesPath))

                    f = open(configFilesPath, "rb")
                    d = decode(f.read())

                    for line in d:
                        if not (".fileguard" == line) and not ("rec" == line):
                            self.log(Level.INFO, line)
                            art = file.newArtifact(artID_torrent_ongoing)
                            art.addAttribute(BlackboardAttribute(attID_torrent_name, EmuleIngestModuleFactory.moduleName, str(line)))
                    IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, artID_torrentOng_evt, None))            
                except:   
                    self.log(Level.INFO, "Error parsing resume.dat file")

        #Post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "P2P Forensic Module Finish", "Found files")
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK;

