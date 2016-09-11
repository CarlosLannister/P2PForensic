# Sample module in the public domain. Feel free to use this as a template
# for your modules (and you can remove this header and take complete credit
# and liability)
#
# Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Simple data source-level ingest module for Autopsy.
# Search for TODO for the things that you need to change
# See http://sleuthkit.org/autopsy/docs/api-docs/3.1/index.html for documentation

import jarray
import inspect
import os
import binascii 
from emule import *

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


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
# TODO: Rename this to something more specific. Search and replace for it because it is used a few times
class EmuleIngestModuleFactory(IngestModuleFactoryAdapter):

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "P2P Forensic Emule module"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Emule Forensic Extraction"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        # TODO: Change the class name to the name you'll make below
        return EmuleDataSourceIngestModule()


# Data Source-level ingest module.  One gets created per data source.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
class EmuleDataSourceIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(EmuleIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        self.context = context

        #self.path_to_exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".exe")
        #if not os.path.exists(self.path_to_exe):
        #    raise IngestModuleException("EXE was not found in module folder")
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
		# raise IngestModuleException("Oh No!")

    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/4.3/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    # TODO: Add your analysis code in here.
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()
   
        fileManager = Case.getCurrentCase().getServices().getFileManager()


        skCase = Case.getCurrentCase().getSleuthkitCase();

        try:
             self.log(Level.INFO, "Begin Create New Artifacts")
             artID_ef = skCase.addArtifactType( "TSK_EMULE", "Emule Forensic")
        except:     
             self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
             artID_pf = skCase.getArtifactTypeID("TSK_EMULE")

        try:
             self.log(Level.INFO, "Begin Create New Artifacts")
             artID_ed2k = skCase.addArtifactType( "TSK_FILES", "Emule Files Downloaded")
        except:     
             self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
             artID_ed2k = skCase.getArtifactTypeID("TSK_FILES")

        try:
             self.log(Level.INFO, "Begin Create New Artifacts")
             artID_ed2k = skCase.addArtifactType( "TSK_ED2K", "Emule Ongoing Downloads")
        except:     
             self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
             artID_ed2k = skCase.getArtifactTypeID("TSK_ED2K")


        try:
            attID_ed2k_link = skCase.addArtifactAttributeType("TSK_ED2K", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "ED2K Link")
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Nickname. ==> ")


        # Create the attribute type, if it exists then catch the error
        try:
            attID_ef_username = skCase.addArtifactAttributeType("TSK_EMULE_USERNAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Nickname")
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Nickname. ==> ")

        try:
            attID_ef_version = skCase.addArtifactAttributeType("TSK_EMULE_VERSION", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Emule Version")           
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Emule version ")

        try:
            attID_ef_language = skCase.addArtifactAttributeType("TSK_EMULE_LANGUAGE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Emule Language")           
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Emule language")

        try:
            attID_ef_incoming_dir = skCase.addArtifactAttributeType("TSK_EMULE_INCOMING", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Incoming Dir")           
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Incoming Dir")

        try:
            attID_ef_completed_files = skCase.addArtifactAttributeType("TSK_EMULE_COMPLETED_FILES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Completed Files")           
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Completed Files ")

        try:
            attID_ef_downloaded_bytes = skCase.addArtifactAttributeType("TSK_EMULE_DONLOADED_BYTES", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Downloaded Bytes")           
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")


        try:
            attID_ed2k_filename = skCase.addArtifactAttributeType("TSK_EMULE_FILENAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Filename")           
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")

        try:
            attID_ed2k_filesize = skCase.addArtifactAttributeType("TSK_EMULE_ED2K_FILESIZE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Filesize")           
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")
        
        try:
            attID_ed2k_partfile = skCase.addArtifactAttributeType("TSK_EMULE_ED2K_PARTFILE", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Partfile")           
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")

        try:
            attID_ed2k_request = skCase.addArtifactAttributeType("TSK_EMULE_ED2K_REQUEST", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Requests")           
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")

        try:
            attID_ed2k_accepted = skCase.addArtifactAttributeType("TSK_EMULE_ED2K_ACCEPTED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Accepted Requests")           
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")

        try:
            attID_ed2k_uploaded = skCase.addArtifactAttributeType("TSK_EMULE_ED2K_UPLOADED", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Uploaded")           
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")

        try:
            attID_ed2k_priority = skCase.addArtifactAttributeType("TSK_EMULE_ED2K_PRIORITY", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Priority")           
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Downloaded Bytes")




        artID_ef = skCase.getArtifactTypeID("TSK_EMULE")
        artID_ef_evt = skCase.getArtifactType("TSK_EMULE")
        attID_pf_fn = skCase.getAttributeType("TSK_EMULE_USERNAME")
        attID_pf_an = skCase.getAttributeType("TSK_EMULE_VERSION")
        attID_ef_ln = skCase.getAttributeType("TSK_EMULE_LANGUAGE")
        attID_ef_id = skCase.getAttributeType("TSK_EMULE_INCOMING")
        attID_ef_cf = skCase.getAttributeType("TSK_EMULE_COMPLETED_FILES")
        attID_ef_db = skCase.getAttributeType("TSK_EMULE_DONLOADED_BYTES")

        artID_ed2k_files = skCase.getArtifactTypeID("TSK_FILES")
        artID_ed2k_files_evt = skCase.getArtifactType("TSK_FILES")
        attID_ed2k_filename = skCase.getAttributeType("TSK_EMULE_FILENAME")
        attID_ed2k_filesize = skCase.getAttributeType("TSK_EMULE_ED2K_FILESIZE")
        attID_ed2k_uploaded = skCase.getAttributeType("TSK_EMULE_ED2K_UPLOADED")
        attID_ed2k_request = skCase.getAttributeType("TSK_EMULE_ED2K_REQUEST")
        attID_ed2k_accepted = skCase.getAttributeType("TSK_EMULE_ED2K_ACCEPTED")
        attID_ed2k_priority = skCase.getAttributeType("TSK_EMULE_ED2K_PRIORITY")
        attID_ed2k_partfile = skCase.getAttributeType("TSK_EMULE_ED2K_PARTFILE")


        artID_ed2k = skCase.getArtifactTypeID("TSK_ED2K")
        artID_ed2k_evt = skCase.getArtifactType("TSK_ED2K")
        attID_ed2k_link = skCase.getAttributeType("TSK_ED2K")


        emuleTorrentConfigFiles = fileManager.findFiles(dataSource, "%", "Local/eMuleTorrent")
        emuleConfigFiles = fileManager.findFiles(dataSource, "%", "/AppData/Local/eMule/config")

        self.log(Level.INFO, "P2P emule Starting")
        reportPath = os.path.join(Case.getCurrentCase().getCaseDirectory() + "/Reports", "userInfo.csv")
        report = open(reportPath, 'w')

        fileCount = 0;



        for file in emuleConfigFiles:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + str(file.getName()))
            

            #Settings 
            if "preferences.ini" in file.getName():
                configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                ContentUtils.writeToFile(file, File(configFilesPath))

                f = open(configFilesPath, 'r')

                for line in f:
                    if "Nick=" in line and "IRC" not in line:
                        nick = line.rsplit('=', 1)[1]
                        report.write(str(line))
                    if "AppVersion=" in line:
                        appVersion = line.rsplit('=', 1)[1]
                        report.write(str(line))
                    if "Language=" in line:
                        lang = line.rsplit('=', 1)[1]

                        if int(lang) == 1034: 
                            lang = "Spanish"

                        report.write("Language=" + lang +"\n")

                    if "IncomingDir=" in line:
                        incomingDir = line.rsplit('=', 1)[1]


                art = file.newArtifact(artID_ef)
                art.addAttributes(((BlackboardAttribute(attID_pf_fn, EmuleIngestModuleFactory.moduleName, nick)), \
                (BlackboardAttribute(attID_pf_an, EmuleIngestModuleFactory.moduleName, appVersion)), \
                (BlackboardAttribute(attID_ef_ln, EmuleIngestModuleFactory.moduleName, lang)), \
                (BlackboardAttribute(attID_ef_id, EmuleIngestModuleFactory.moduleName, incomingDir)), \
                (BlackboardAttribute(attID_ef_cf, EmuleIngestModuleFactory.moduleName, '')), \
                (BlackboardAttribute(attID_ef_db, EmuleIngestModuleFactory.moduleName, ''))))

                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, artID_ef_evt, None))
                f.close()
                

            if "statistics.ini" in file.getName():
                configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                ContentUtils.writeToFile(file, File(configFilesPath))

                f2 = open(configFilesPath, 'r')

                for line in f2:
                    if "DownSessionCompletedFiles=" in line:
                        completedFiles = line.rsplit('=', 1)[1]

                    if "TotalDownloadedBytes=" in line:
                        donwladedBytes = line.rsplit('=', 1)[1]

                art = file.newArtifact(artID_ef)

                art.addAttributes(((BlackboardAttribute(attID_ef_cf, EmuleIngestModuleFactory.moduleName, completedFiles)), \
                (BlackboardAttribute(attID_ef_db, EmuleIngestModuleFactory.moduleName, donwladedBytes))))

                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, artID_ef_evt, None))

            #Userhash 
            if "Preferences.dat" in file.getName():
                configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                ContentUtils.writeToFile(file, File(configFilesPath))

            #Search words last used
            if "AC_SearchStrings.dat" in file.getName():
                configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                ContentUtils.writeToFile(file, File(configFilesPath))

            
            #ongoing downloads
            if "downloads.txt" in file.getName():
                configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                ContentUtils.writeToFile(file, File(configFilesPath))
                f = open(configFilesPath, "r")

                for line in f:
                    ed2k = line.replace("\00", "")
                    if "part" in ed2k:
                        self.log(Level.INFO, "Testing9 ed2k")
                        self.log(Level.INFO, ed2k)

                        art = file.newArtifact(artID_ed2k)
                        art.addAttribute(BlackboardAttribute(attID_ed2k_link, EmuleIngestModuleFactory.moduleName, ed2k))
                        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, artID_ed2k_evt, None))

            
            #Information about all files that have been downloaded 
            if "known.met" in file.getName():
                

                configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                ContentUtils.writeToFile(file, File(configFilesPath))

                fobj = open(configFilesPath, "rb")
                filesize = os.path.getsize(configFilesPath)

                for i in range(filesize):  # i = index. Offset to actual serach position in fileobject
                    fobj.seek(i,0)
                    charakter = (fobj.read(4))

                    
                    if charakter == b"\x02\x01\x00\x01":
                        block = getblockofdata(i,fobj, filesize)
                        filename = carvefilename(block)
                        filesizeentry = carvefilesize(block)
                        totalupload = carvetotalupload(block)
                        requests = carverequests(block)
                        acceptedrequests = carveacceptedrequests(block)
                        uploadpriority = carveuploadpriority(block)
                        partfile = carvepartfile(block)
            
                        art = file.newArtifact(artID_ed2k_files)

                        art.addAttributes(((BlackboardAttribute(attID_ed2k_filename, EmuleIngestModuleFactory.moduleName, filename)), \
                        (BlackboardAttribute(attID_ed2k_filesize, EmuleIngestModuleFactory.moduleName, str(filesizeentry))), \
                        (BlackboardAttribute(attID_ed2k_uploaded, EmuleIngestModuleFactory.moduleName, str(totalupload))), \
                        (BlackboardAttribute(attID_ed2k_request, EmuleIngestModuleFactory.moduleName, str(requests))), \
                        (BlackboardAttribute(attID_ed2k_accepted, EmuleIngestModuleFactory.moduleName, str(acceptedrequests))), \
                        (BlackboardAttribute(attID_ed2k_priority, EmuleIngestModuleFactory.moduleName, str(uploadpriority))), \
                        (BlackboardAttribute(attID_ed2k_partfile, EmuleIngestModuleFactory.moduleName, str(partfile)))))
           
                        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, artID_ed2k_files_evt, None))   




        self.log(Level.INFO, "Fin ")
        report.close()
        #Post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Sample Jython Data Source Ingest Module", "Found %d files" % fileCount)
        IngestServices.getInstance().postMessage(message)



        return IngestModule.ProcessResult.OK;

