/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
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

static std::string ripExePath;
static std::string outPath;
static enum RegType
{
    NTUSER,
    SYSTEM,
    SAM,
    SOFTWARE,
    ALL
};

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
            if (Poco::icompare(pFile->name(), fileName) != 0)
                continue;

            // Save the file content so that we can run RegRipper against it
            fileManager.saveFile(pFile.get());

            cmdArgs.push_back("-r");
            cmdArgs.push_back(pFile->getPath());

            // Create the output file if it does not exist.
            std::stringstream outFilePath;
            outFilePath << outPath << "\\" << pFile->name() << "_" 
                << pFile->id() << ".txt";
            Poco::File outFile(outFilePath.str());

            if (!outFile.exists())
            {
                outFile.createFile();
            }

            Poco::Pipe outPipe;

            // Launch RegRipper
            Poco::ProcessHandle handle = Poco::Process::launch(ripExePath, cmdArgs, NULL, &outPipe, NULL);

            // Copy output from Pipe to the output file.
            Poco::PipeInputStream istr(outPipe);
            Poco::FileOutputStream ostr(outFile.path(), std::ios::out|std::ios::app);

            while (istr)
            {
                Poco::StreamCopier::copyStream(istr, ostr);
            }
            
            // The process should be finished. Check its exit code.
            int exitCode = Poco::Process::wait(handle);

            // If RegRipper fails on a particular file, we log a warning and continue.
            if (exitCode != 0)
            {
                std::wstringstream msg;
                msg << L"RegRipperModule::runRegRipper - RegRipper failed on file: "
                    << pFile->name().c_str();
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
    TskModule::Status TSK_MODULE_EXPORT initialize(std::string& args)
    {
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
            ripExePath = TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemProperties::PROG_DIR));
            ripExePath.append(".\\RegRipper\\rip.exe");
        }

        if (outPath.empty())
        {
            outPath = TskUtilities::toUTF8(TSK_SYS_PROP_GET(TskSystemProperties::OUT_DIR));

            if (outPath.empty())
            {
                LOGERROR(L"RegRipperModule::initialize - Empty output path.");
                return TskModule::FAIL;
            }
    
            outPath.append("\\RegRipper");
        }

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

            // Create an output folder to store results
            Poco::File outDir(outPath);

            outDir.createDirectory();
        }
        catch(std::exception& ex)
        {
            std::wstringstream msg;
            msg << L"RegRipperModule::initialize - Unexpected error: "
                << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

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
     * Module cleanup function. This is where the module should free any resources 
     * allocated during initialization or execution.
     *
     * @returns TskModule::OK on success and TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        return TskModule::OK;
    }
}