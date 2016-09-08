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

        emuleConfigFiles = fileManager.findFiles(dataSource, "%", "/AppData/Local/eMule/config")

        skCase = Case.getCurrentCase().getSleuthkitCase();
        try:
             self.log(Level.INFO, "Begin Create New Artifacts")
             artID_pf = skCase.addArtifactType( "TSK_EMULE", "Emule Forensic")
        except:     
             self.log(Level.INFO, "Artifacts Creation Error, some artifacts may not exist now. ==> ")
             artID_pf = skCase.getArtifactTypeID("TSK_EMULE")

                # Create the attribute type, if it exists then catch the error
        try:
            attID_pf_fn = skCase.addArtifactAttributeType("TSK_EMULE_ED2K", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "ED2K Link")
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Prefetch File Name. ==> ")

        try:
            attID_pf_an = skCase.addArtifactAttributeType("TSK_PREFETCH_ACTUAL_FILE_NAME", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, "Actual File Name")           
        except:     
             self.log(Level.INFO, "Attributes Creation Error, Actual File Name. ==> ")


        #sharedFiles sharedDir
        #AC_SearchStrings.dat StoredSearches.dat 
        #emfriends.met

        artID_pf = skCase.getArtifactTypeID("TSK_EMULE")
        artID_pf_evt = skCase.getArtifactType("TSK_EMULE")
        attID_pf_fn = skCase.getAttributeType("TSK_EMULE_ED2K")
        attID_pf_an = skCase.getAttributeType("TSK_PREFETCH_ACTUAL_FILE_NAME")

        emuleTorrentConfigFiles = fileManager.findFiles(dataSource, "%", "Local/eMuleTorrent")

        self.log(Level.INFO, "P2P emule Starting")


        fileCount = 0;
        for file in emuleConfigFiles:
            
            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            self.log(Level.INFO, "Processing file: " + str(file.getName()))
            if "downloads.txt" in file.getName():
                configFilesPath = os.path.join(Case.getCurrentCase().getTempDirectory(), str(file.getName()))
                ContentUtils.writeToFile(file, File(configFilesPath))

                #art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)


                #art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), EmuleIngestModuleFactory.moduleName, "Emule5 Info"))
                #IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None))

                #att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME, EmuleIngestModuleFactory.moduleName, str(file.getName()))
                #art.addAttribute(att)

                self.log(Level.INFO, "Path")

                self.log(Level.INFO, configFilesPath)
  
                f = open(configFilesPath, 'r')
                reportPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "report")
                report = open(reportPath, 'w')

                art = file.newArtifact(artID_pf)
                name = str(file.getName())



                for i, line in enumerate(f):
                    if i > 4:
                        self.log(Level.INFO, "Linea3 ")
                        line = line.strip()
                        report.write(line + "\n")
                        art.addAttributes(((BlackboardAttribute(attID_pf_fn, EmuleIngestModuleFactory.moduleName, line)), \
                        (BlackboardAttribute(attID_pf_an, EmuleIngestModuleFactory.moduleName, name))))


                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(EmuleIngestModuleFactory.moduleName, artID_pf_evt, None))
           

                f.close()
                report.close()

        self.log(Level.INFO, "Fin ")
        #Post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
            "Sample Jython Data Source Ingest Module", "Found %d files" % fileCount)
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK;