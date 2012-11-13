/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file RegRipperModule.cpp
 * Contains the implementation for the reg ripper reporting module.
 * This module runs the RegRipper executable against the common set of
 * Windows registry files (i.e., NTUSER, SYSTEM, SAM and SOFTWARE).
 */

// System includes
#include <string>
#include <sstream>

// Framework includes
#include "TskModuleDev.h"

// Poco includes
#include "Poco/String.h"
#include "Poco/StringTokenizer.h"
#include "Poco/File.h"
#include "Poco/Process.h"
#include "Poco/PipeStream.h"
#include "Poco/FileStream.h"
#include "Poco/StreamCopier.h"
#include "Poco/Path.h"
#include "Poco/RegularExpression.h"

static std::string ripExePath;
static std::string outPath;
static std::string errPath;
static enum RegType
{
    NTUSER,
    SYSTEM,
    SAM,
    SOFTWARE,
    ALL
};

/**
 * Parse RegRipper output from a specific output file for matches on the valueName. The 
 * function will return all lines in the file that match the valueName followed byt one 
 * of the potential RegRipper seperators. This may not always find all lines of a plugin
 * writer uses a new seperator.
 * @param regRipperFileName The full path to a regRipper output file.
 * @param valueName The name of the value to search for. Will support regex matches that
 * come before a seperator.
 * @return A vector of matching lines from the file.
 */
static std::vector<std::string> getRegRipperValues(const std::string& regRipperFileName, const std::string& valueName){
    Poco::FileInputStream inStream(regRipperFileName);
    std::vector<std::string> results;

    std::string line;

    std::stringstream pattern;
    pattern << valueName << "[\\s\\->=:]+";

    Poco::RegularExpression regex(pattern.str(), 0, true);
    Poco::RegularExpression::Match match;

    getline(inStream, line);

    while(!line.empty()){
        int nummatches = regex.match(line, match, 0);
        if(nummatches > 0){
            results.push_back(line.substr(match.offset + match.length, line.size()));
        }
        getline(inStream, line);
    }
    inStream.close();
    return results;
}



/**
 * Searches the RegRipper output for operating system information then posts it to the
 * blackboard.
 */

static void getOSInfo(){
    
    std::string condition("WHERE files.dir_type = 5 AND UPPER(files.name) = 'SOFTWARE'");
    TskImgDB& imgDB = TskServices::Instance().getImgDB();
    
    TskBlackboard& blackboard = TskServices::Instance().getBlackboard();

    std::vector<uint64_t> fileIds = imgDB.getFileIds(condition);

    TskFileManager& fileManager = TskServices::Instance().getFileManager();

    // Iterate over the files running RegRipper on each one.
    for (std::vector<uint64_t>::iterator it = fileIds.begin(); it != fileIds.end(); it++)
    {
        // Create a file object for the id
        std::auto_ptr<TskFile> pFile(fileManager.getFile(*it));

        // Create the output file if it does not exist.
        std::stringstream outFilePath;
        outFilePath << outPath << "\\" << pFile->getName() << "_" 
            << pFile->getId() << ".txt";
        
        vector<std::string> names = getRegRipperValues(outFilePath.str(), "ProductName");
        TskBlackboardArtifact osart = pFile->createArtifact(TSK_OS_INFO);
        for(int i = 0; i < names.size(); i++){
            osart.addAttribute(TskBlackboardAttribute(TSK_NAME, "RegRipperModule", "", names[i]));
        }
        vector<std::string> versions = getRegRipperValues(outFilePath.str(), "CSDVersion");
        for(int i = 0; i < versions.size(); i++){
            osart.addAttribute(TskBlackboardAttribute(TSK_VERSION, "RegRipperModule", "", versions[i]));
        }
    }

    condition = "WHERE files.dir_type = 5 AND UPPER(files.name) = 'SYSTEM'";
    
    fileIds = imgDB.getFileIds(condition);

    // Iterate over the files running RegRipper on each one.
    for (std::vector<uint64_t>::iterator it = fileIds.begin(); it != fileIds.end(); it++)
    {
        // Create a file object for the id
        std::auto_ptr<TskFile> pFile(fileManager.getFile(*it));

        // Create the output file if it does not exist.
        std::stringstream outFilePath;
        outFilePath << outPath << "\\" << pFile->getName() << "_" 
            << pFile->getId() << ".txt";
        
        vector<std::string> names = getRegRipperValues(outFilePath.str(), "ProcessorArchitecture");
        TskBlackboardArtifact osart = pFile->createArtifact(TSK_OS_INFO);
        for(int i = 0; i < names.size(); i++){
            if(names[i].compare("AMD64") == 0)
                osart.addAttribute(TskBlackboardAttribute(TSK_PROCESSOR_ARCHITECTURE, "RegRipperModule", "", "x86-64"));
            else
                osart.addAttribute(TskBlackboardAttribute(TSK_PROCESSOR_ARCHITECTURE, "RegRipperModule", "", names[i]));
        }
    }
}

static TskModule::Status runRegRipper(RegType type)
{
    std::string condition("WHERE files.dir_type = 5 AND UPPER(files.name) = '");
    std::string fileName;
    std::string pluginFile;

    switch (type)
    {
    case NTUSER:
        fileName = "NTUSER.DAT";
        pluginFile = "ntuser";
        break;
    case SYSTEM:
        fileName = "SYSTEM";
        pluginFile = "system";
        break;
    case SOFTWARE:
        fileName = "SOFTWARE";
        pluginFile = "software";
        break;
    case SAM:
        fileName = "SAM";
        pluginFile = "sam";
        break;
    default:
        std::wstringstream msg;
        msg << L"RegRipperModule - Unknown type: " << type;
        LOGERROR(msg.str());
        return TskModule::FAIL;
    }

    condition.append(fileName);
    condition.append("'");

    try 
    {
        // Get the file ids matching our condition
        TskImgDB& imgDB = TskServices::Instance().getImgDB();
        std::vector<uint64_t> fileIds = imgDB.getFileIds(condition);

        TskFileManager& fileManager = TskServices::Instance().getFileManager();

        // Iterate over the files running RegRipper on each one.
        for (std::vector<uint64_t>::iterator it = fileIds.begin(); it != fileIds.end(); it++)
        {
            Poco::Process::Args cmdArgs;
            cmdArgs.push_back("-f");
            cmdArgs.push_back(pluginFile);

            // Create a file object for the id
            std::auto_ptr<TskFile> pFile(fileManager.getFile(*it));

            // Confirm that we have the right file name since the query can return
            // files that are similar to the ones we want.
            if (Poco::icompare(pFile->getName(), fileName) != 0)
                continue;

            // Save the file content so that we can run RegRipper against it
            fileManager.saveFile(pFile.get());

            cmdArgs.push_back("-r");
            cmdArgs.push_back(pFile->getPath());

            // Create the output file if it does not exist.
            std::stringstream outFilePath;
            outFilePath << outPath << "\\" << pFile->getName() << "_" 
                << pFile->getId() << ".txt";
            Poco::File outFile(outFilePath.str());

            if (!outFile.exists())
            {
                outFile.createFile();
            }

            std::wstringstream msg;
            msg << L"RegRipperModule - Analyzing hive " << pFile->getPath().c_str() << L"/" << pFile->getName().c_str() << " to " << outFile.path().c_str();
            LOGINFO(msg.str());

            Poco::Pipe outPipe;
            Poco::Pipe errPipe;

            // Launch RegRipper
            Poco::ProcessHandle handle = Poco::Process::launch(ripExePath, cmdArgs, NULL, &outPipe, &errPipe);

            // Copy output from Pipe to the output file.
            Poco::PipeInputStream istr(outPipe);
            Poco::FileOutputStream ostr(outFile.path(), std::ios::out|std::ios::app);
            Poco::PipeInputStream errIstr(errPipe);
            Poco::FileOutputStream errOstr(errPath, std::ios::out|std::ios::app);

            while (istr)
            {
                Poco::StreamCopier::copyStream(istr, ostr);
            }

            while (errIstr)
            {
                Poco::StreamCopier::copyStream(errIstr, errOstr);
            }
            
            // The process should be finished. Check its exit code.
            int exitCode = Poco::Process::wait(handle);

            // If RegRipper fails on a particular file, we log a warning and continue.
            if (exitCode != 0)
            {
                std::wstringstream msg;
                msg << L"RegRipperModule::runRegRipper - RegRipper failed on file: "
                    << pFile->getName().c_str();
                LOGWARN(msg.str());            
            }
        }
    }
    catch (std::exception& ex)
    {
        std::wstringstream msg;
        msg << L"RegRipperModule::runRegRipper - Error: " << ex.what();
        LOGERROR(msg.str());
        return TskModule::FAIL;
    }

    return TskModule::OK;
}


extern "C" 
{
    /**
     * Module identification function. 
     *
     * @return The name of the module.
     */
    TSK_MODULE_EXPORT const char *name()
    {
        return "RegRipper";
    }

    /**
     * Module identification function. 
     *
     * @return A description of the module.
     */
    TSK_MODULE_EXPORT const char *description()
    {
        return "Runs the RegRipper executable against the common set of Windows registry files (i.e., NTUSER, SYSTEM, SAM and SOFTWARE)";
    }

    /**
     * Module identification function. 
     *
     * @return The version of the module.
     */
    TSK_MODULE_EXPORT const char *version()
    {
        return "1.0.0";
    }

    /**
     * Module initialization function. Receives a string of intialization arguments, 
     * typically read by the caller from a pipeline configuration file. 
     * Returns TskModule::OK or TskModule::FAIL. Returning TskModule::FAIL indicates 
     * the module is not in an operational state.  
     *
     * @param args An optional semicolon separated list of arguments:
     *      -e Path to the RegRipper executable
     *      -o Directory in which to place RegRipper output
     * @return TskModule::OK if initialization succeeded, otherwise TskModule::FAIL.
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(const char* arguments)
    {
        std::string args(arguments);

        // Split the incoming arguments
        Poco::StringTokenizer tokenizer(args, ";");

        std::vector<std::string> vectorArgs(tokenizer.begin(), tokenizer.end());
        std::vector<std::string>::const_iterator it;

        for (it = vectorArgs.begin(); it < vectorArgs.end(); it++)
        {
            if ((*it).find("-e") == 0)
            {
                ripExePath = (*it).substr(3);
                if (ripExePath.empty())
                {
                    LOGERROR(L"RegRipperModule::initialize - missing argument to -e option.");
                    return TskModule::FAIL;
                }
                
            }
            else if ((*it).find("-o") == 0)
            {
                outPath = (*it).substr(3);
                if (outPath.empty())
                {
                    LOGERROR(L"RegRipperModule::initialize - missing argument to -o option.");
                    return TskModule::FAIL;
                }
            }
        }
        
        if (ripExePath.empty())
        {
            ripExePath = GetSystemProperty(TskSystemProperties::PROG_DIR);
            ripExePath.append(".\\RegRipper\\rip.exe");
        }

        // strip off quotes if they were passed in via XML
        if (ripExePath[0] == '"')
            ripExePath.erase(0, 1);
        if (ripExePath[ripExePath.size()-1] == '"')
            ripExePath.erase(ripExePath.size()-1, 1);

        std::wstringstream msg;
        msg << L"RegRipperModule - Using exec: " << ripExePath.c_str();
        LOGINFO(msg.str());

        if (outPath.empty())
        {
            outPath = GetSystemProperty(TskSystemProperties::MODULE_OUT_DIR);

            if (outPath.empty())
            {
                LOGERROR(L"RegRipperModule::initialize - Empty output path.");
                return TskModule::FAIL;
            }
    
            outPath.append("\\RegRipper");
        }

        std::wstringstream msg1;
        msg1 << L"RegRipperModule - Using output: " << outPath.c_str();
        LOGINFO(msg1.str());

        try
        {
            // Confirm that the RegRipper executable exists in the given path
            Poco::File ripExe(ripExePath);

            if (!ripExe.exists() || !ripExe.canExecute())
            {
                std::wstringstream msg;
                msg << L"RegRipperModule::initialize - " << ripExePath.c_str()
                    << " does not exist or is not executable.";
                LOGERROR(msg.str());
                return TskModule::FAIL;
            }
        }
        catch(std::exception& ex)
        {
            std::wstringstream msg;
            msg << L"RegRipperModule::initialize rip.exe location - Unexpected error: "
                << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        try {
            // Create an output folder to store results
            Poco::File outDir(outPath);

            outDir.createDirectory();
        }
        catch(std::exception& ex)
        {
            std::wstringstream msg;
            msg << L"RegRipperModule::initialize output location - Unexpected error: "
                << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        
        // Create the error output file if it does not exist.
        std::stringstream errFilePath;
        errFilePath << outPath << "\\RegRipperError";

        try {
            // Create an output folder to store results
            Poco::File errDir(errFilePath.str());

            errDir.createDirectory();
        }
        catch(std::exception& ex)
        {
            std::wstringstream msg;
            msg << L"RegRipperModule::initialize error output location - Unexpected error: "
                << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        outPath.append("\\RegRipperOutput");
        try {
            // Create an output folder to store results
            Poco::File outDir(outPath);

            outDir.createDirectory();
        }
        catch(std::exception& ex)
        {
            std::wstringstream msg;
            msg << L"RegRipperModule::initialize output location - Unexpected error: "
                << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        errFilePath << "\\RegRipperError.txt";
        Poco::File errFile(errFilePath.str());

        if (!errFile.exists())
        {
            errFile.createFile();
        }
        errPath = errFilePath.str();

        return TskModule::OK;
    }

    /**
     * Module execution function. Returns TskModule::OK, TskModule::FAIL, or TskModule::STOP. 
     * Returning TskModule::FAIL indicates error performing its job. Returning TskModule::STOP
     * is a request to terminate execution of the reporting pipeline.
     *
     * @returns TskModule::OK on success, TskModule::FAIL on error, or TskModule::STOP.
     */
    TskModule::Status TSK_MODULE_EXPORT report()
    {
        TskModule::Status status = TskModule::OK;

        try
        {
            if (runRegRipper(NTUSER) != TskModule::OK)
                return TskModule::FAIL;
            if (runRegRipper(SYSTEM) != TskModule::OK)
                return TskModule::FAIL;
            if (runRegRipper(SAM) != TskModule::OK)
                return TskModule::FAIL;
            if (runRegRipper(SOFTWARE) != TskModule::OK)
                return TskModule::FAIL;

            getOSInfo();
        }
        catch (TskException& tskEx)
        {
            std::wstringstream msg;
            msg << L"RegRipperModule - Caught framework exception: " << tskEx.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (std::exception& ex)
        {
            std::wstringstream msg;
            msg << L"RegRipperModule - Caught exception: " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    /**
     * Module cleanup function. Deletes output directory if it is empty.
     *
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        // Delete output directory if it contains no files.
        std::vector<std::string> fileList;
        Poco::File outDir(outPath);
        outDir.list(fileList);
        bool emptyout = false;
        bool emptyerr = false;

        if (fileList.empty()){
            outDir.remove();
            emptyout = true;
        }

        // Delete output directory if it contains no files.
        Poco::File errFile(errPath);
        Poco::Path errPath(errPath);
        Poco::File errDir(errPath.parent());

        if (errFile.getSize() == 0){
            errFile.remove();
            errDir.remove();
            emptyerr = true;
        }

        if (emptyout && emptyerr){
            Poco::File moduleDir(errPath.parent().parent());
            moduleDir.remove();
        }

        return TskModule::OK;
    }
}